"""Registry domain logic: listing persistence, serialisation, trust state transitions."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import schemas
from .models import AuditEvent, Listing, ListingFacet, Operator, new_id, utcnow
from .netsafety import Fetcher, FetchError, UnsafeURLError, validate_public_url
from .terms import Terms, load_terms

# Statuses visible in public search/get. Deleted is never visible; suspended only on direct GET.
PUBLIC_STATUSES = ("discovered", "claim_pending", "registered", "endpoint_verified", "certified")
FACET_FIELDS = {
    "role": "roles",
    "capability": "capabilities",
    "region": "regions",
    "currency": "currencies",
    "protocol": "supported_protocols",
    "language": "languages",
    "category": "categories",
}


def aware(ts: dt.datetime | None) -> dt.datetime | None:
    """SQLite returns naive datetimes; normalise to UTC-aware."""
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=dt.UTC)
    return ts


def audit(session: Session, actor_type: str, actor_id: str | None, action: str,
          subject_id: str | None = None, result: str = "ok", **detail) -> None:
    session.add(AuditEvent(actor_type=actor_type, actor_id=actor_id, action=action,
                           subject_id=subject_id, result=result, detail=detail))


def normalise_url(url: str | None, field: str) -> str | None:
    """Static SSRF-safe validation for any URL we may later fetch or display as a link."""
    if url is None:
        return None
    try:
        validate_public_url(url)
    except UnsafeURLError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field}: {exc}") from exc
    p = urlsplit(url)
    return urlunsplit((p.scheme, (p.hostname or "").lower().rstrip("."), p.path or "/", p.query, ""))


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def set_facets(listing: Listing, data: dict) -> None:
    for kind, field in FACET_FIELDS.items():
        if field not in data or data[field] is None:
            continue
        # Diff instead of replace: re-inserting an unchanged value would hit the unique constraint
        # before the old row is flushed away.
        wanted = set(data[field])
        listing.facets[:] = [f for f in listing.facets if f.kind != kind or f.value in wanted]
        have = {f.value for f in listing.facets if f.kind == kind}
        for v in sorted(wanted - have):
            listing.facets.append(ListingFacet(kind=kind, value=v))


# ---------- profile blocks, extensions and derived search facets ----------
CARD_STALE_AFTER = dt.timedelta(days=7)
ONAA_EXTENSION_URI = "urn:onaa:a2a-ext:commerce:v0"
_TOKEN = re.compile(r"[^a-z0-9._-]+")


def _norm_urls(obj, path: str = ""):
    """Run every *_url / *_uri string inside a profile block through the SSRF-safe URL validator."""
    if isinstance(obj, dict):
        return {k: (normalise_url(v, f"{path}{k}") if isinstance(v, str) and k.endswith(("_url", "_uri"))
                    else _norm_urls(v, f"{path}{k}.")) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_norm_urls(v, path) for v in obj]
    return obj


def apply_profile(listing: Listing, data: dict, *, partial: bool) -> list[str]:
    """Apply profile blocks / extensions / jwks_uri from a create (partial=False) or PATCH (partial=True) body.

    In a PATCH an explicit null removes a block; a block that is sent replaces the stored one as a whole,
    so agents can evolve their listing without leftover stale sub-fields. Returns the changed field names.
    """
    changed = []
    profile = dict(listing.profile or {})
    for block in schemas.PROFILE_BLOCKS:
        if block not in data or (data[block] is None and not partial):
            continue
        if data[block] is None:
            profile.pop(block, None)
        else:
            profile[block] = _norm_urls(data[block], f"{block}.")
        changed.append(block)
    if changed:
        listing.profile = profile or None
    if "extensions" in data and (data["extensions"] is not None or partial):
        listing.extensions = data["extensions"] or None
        changed.append("extensions")
    if "jwks_uri" in data and (data["jwks_uri"] is not None or partial):
        listing.jwks_uri = normalise_url(data["jwks_uri"], "jwks_uri")
        require_same_host(listing, listing.jwks_uri, "jwks_uri")
        changed.append("jwks_uri")
    if changed:
        set_derived_facets(listing)
    return changed


def _profile_facets(profile: dict) -> dict[str, set[str]]:
    c = profile.get("commerce") or {}
    j = profile.get("jurisdiction") or {}
    i = profile.get("integration") or {}
    out = {
        "accepts": {a["service_type"] for a in c.get("accepts_services", [])},
        "pricing_model": {p["model"] for p in c.get("pricing", [])},
        "quote_mode": {(c.get("quoting") or {}).get("mode")} - {None},
        "payment_terms": set((c.get("payment_terms") or {}).get("terms", [])),
        "payment_method": set((c.get("payment_terms") or {}).get("methods", [])),
        "payment_network": set((c.get("payment_terms") or {}).get("networks", [])),
        "classification": {f"{x['scheme']}:{x['code']}".lower() for x in c.get("classifications", [])},
        "incoterm": {x.lower() for x in c.get("incoterms", [])},
        "op_country": {j.get("operating_country")} - {None},
        "excl_region": set(j.get("excluded_regions", [])),
        "residency": set(j.get("data_residency", [])),
        "compliance": set(j.get("compliance_claims", [])),
        "auth_method": set(i.get("auth_methods", [])),
    }
    return out


def _card_facets(summary: dict | None) -> set[str]:
    vals = set()
    for sk in (summary or {}).get("skills", []):
        for raw in [sk.get("id")] + list(sk.get("tags", [])):
            tok = _TOKEN.sub("-", str(raw or "").lower()).strip("-.")[:120]
            if tok:
                vals.add(tok)
    return set(sorted(vals)[:200])


def set_derived_facets(listing: Listing) -> None:
    wanted = _profile_facets(listing.profile or {})
    wanted["skill"] = _card_facets(listing.card_summary)
    for kind, values in wanted.items():
        set_facet_kind(listing, kind, values)


def set_facet_kind(listing: Listing, kind: str, wanted: set[str]) -> None:
    listing.facets[:] = [f for f in listing.facets if f.kind != kind or f.value in wanted]
    have = {f.value for f in listing.facets if f.kind == kind}
    for v in sorted(wanted - have):
        listing.facets.append(ListingFacet(kind=kind, value=v))


def bump_revision(listing: Listing) -> None:
    listing.revision = (listing.revision or 1) + 1
    listing.updated_at = utcnow()


def get_listing(session: Session, listing_id: str, *, include_hidden: bool = False) -> Listing:
    listing = session.get(Listing, listing_id)
    if listing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "listing not found")
    if listing.lifecycle_status == "deleted" and not include_hidden:
        raise HTTPException(status.HTTP_410_GONE, "listing deleted")
    return listing


def require_owner(listing: Listing, operator: Operator, *, allow_claim_pending: bool = False) -> None:
    if listing.operator_id != operator.id:
        # 403 (not 404) is fine: listing existence is public metadata.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not the owner of this listing")
    if listing.lifecycle_status in ("deleted", "suspended"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"listing is {listing.lifecycle_status}")
    if listing.lifecycle_status == "claim_pending" and not allow_claim_pending:
        # A claim grants no edit rights until endpoint control is proven.
        raise HTTPException(status.HTTP_409_CONFLICT, "claim pending: complete domain verification first")


def require_same_host(listing: Listing, url: str | None, field: str) -> None:
    """Invocation URLs must live on the verified host, so verification covers where buyers connect."""
    if url is not None and listing.endpoint_host and host_of(url) != listing.endpoint_host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{field} must be on the listing's verified host {listing.endpoint_host}")


def ensure_not_taken(session: Session, host: str, operator_id: str | None) -> None:
    """A host whose control another operator has verified cannot be registered by anyone else."""
    stmt = select(Listing.id).where(Listing.endpoint_host == host, verified_predicate(),
                                    Listing.lifecycle_status.in_(PUBLIC_STATUSES))
    if operator_id is not None:
        stmt = stmt.where(Listing.operator_id != operator_id)
    taken = session.scalar(stmt)
    if taken:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"host already endpoint-verified by another operator ({taken}). "
                            "If this is your endpoint, file a report via POST /v1/reports.")


def verified_predicate():
    """SQL predicate: endpoint control is verified and the proof has not expired."""
    from sqlalchemy import or_
    return Listing.endpoint_control_verified.is_(True) & or_(
        Listing.endpoint_verified_until.is_(None), Listing.endpoint_verified_until > utcnow())


def check_listing_quota(session: Session, operator: Operator, limit: int) -> None:
    if limit <= 0:
        return
    count = session.scalar(select(func.count()).select_from(Listing).where(
        Listing.operator_id == operator.id, Listing.lifecycle_status != "deleted"))
    if count >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"listing limit reached ({limit} per operator); contact support to raise it")


def _name_key(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())


def flag_name_collision(session: Session, listing: Listing) -> None:
    """Flag (not block) a new listing whose name matches another operator's verified listing."""
    key = _name_key(listing.display_name)
    if not key:
        return
    for other_name in session.scalars(select(Listing.display_name).where(
            verified_predicate(), Listing.operator_id != listing.operator_id,
            Listing.lifecycle_status.in_(PUBLIC_STATUSES))):
        if _name_key(other_name) == key:
            listing.review_flags = sorted(set(listing.review_flags or []) | {"name_collision_review"})
            return


def active_cert_exists():
    """SQL predicate: listing has an active, unexpired, non-identity certification."""
    from sqlalchemy import exists

    from .models import Certification
    return exists().where(Certification.listing_id == Listing.id, Certification.status == "active",
                          Certification.expires_at > utcnow())


def active_certs(listing: Listing) -> list:
    now = utcnow()
    return [c for c in listing.certifications if c.status == "active" and aware(c.expires_at) > now]


def to_record(listing: Listing, operator: Operator | None = None) -> schemas.RegistryRecord:
    from .verification import is_currently_verified

    verified = is_currently_verified(listing)
    # Certifications build on endpoint control; they are not shown while that proof is lapsed.
    certs = active_certs(listing) if verified else []
    status_ = listing.lifecycle_status
    if status_ in ("certified", "endpoint_verified") and not verified:
        status_ = "registered"
    elif status_ == "certified" and not certs:
        status_ = "endpoint_verified"
    claimed = listing.operator_id is not None and status_ not in ("discovered", "claim_pending")
    card = None
    if listing.agent_card_url:
        card = {
            "url": listing.agent_card_url,
            "sha256": listing.card_hash,
            "fetched_at": aware(listing.card_fetched_at),
            "fetch_result": listing.card_fetch_result,
            "observed_name": listing.card_name,
            "summary": listing.card_summary,
            "stale": listing.card_fetched_at is None or aware(listing.card_fetched_at) < utcnow() - CARD_STALE_AFTER,
            "note": "Linked A2A Agent Card is published by the operator and is the source of truth for skills and "
                    "interfaces; ONAA caches an untrusted summary. Fetch the card yourself before trading.",
        }
    provenance = None
    if listing.source_url:
        provenance = {"source_url": listing.source_url, "discovered_at": aware(listing.discovered_at),
                      "note": "Observed publicly by ONAA; not registered or endorsed by the operator."}
    return schemas.RegistryRecord(
        id=listing.id,
        operator_id=listing.operator_id,
        listing_type=listing.listing_type,
        service_type=listing.service_type,
        roles=listing.facet_values("role"),
        display_name=listing.display_name,
        description=listing.description,
        agent_card_url=listing.agent_card_url,
        endpoint_url=listing.endpoint_url,
        documentation_url=listing.documentation_url,
        terms_url=listing.terms_url,
        sandbox_url=listing.sandbox_url,
        sandbox_available=listing.sandbox_available if listing.listing_type != "agent" else None,
        supported_interfaces=listing.supported_interfaces or [],
        supported_protocols=listing.facet_values("protocol"),
        capabilities=listing.facet_values("capability"),
        regions=listing.facet_values("region"),
        currencies=listing.facet_values("currency"),
        languages=listing.facet_values("language"),
        categories=listing.facet_values("category"),
        regulatory_claims=listing.regulatory_claims or [],
        **{b: (listing.profile or {}).get(b) for b in schemas.PROFILE_BLOCKS},
        extensions=listing.extensions or {},
        jwks_uri=listing.jwks_uri,
        revision=listing.revision or 1,
        trust=schemas.Trust(
            registration_status=status_,
            claimed=claimed,
            endpoint_control_verified=verified,
            endpoint_verified_at=aware(listing.endpoint_verified_at) if verified else None,
            endpoint_verified_until=aware(listing.endpoint_verified_until) if verified else None,
            endpoint_verification_method=listing.endpoint_verification_method if verified else None,
            review_flags=list(listing.review_flags or []),
            registration_method=listing.registration_method
            or ("discovery_import" if listing.source_url and listing.operator_id is None else "operator_account"),
            reachability=listing.reachability or "unknown",
            last_check_result=listing.last_check_result,
            operator_identity_verified=bool(claimed and operator and operator.identity_verified),
            certifications=[schemas.CertificationOut(
                id=c.id, scheme=c.scheme, criteria_version=c.criteria_version, status=c.status,
                issued_at=aware(c.issued_at), expires_at=aware(c.expires_at)) for c in certs],
        ),
        agent_card=card,
        provenance=provenance,
        last_checked_at=aware(listing.last_checked_at),
        status=status_,
        created_at=aware(listing.created_at),
        updated_at=aware(listing.updated_at),
    )


def refresh_card(listing: Listing, fetcher: Fetcher) -> None:
    """Fetch the linked Agent Card and cache hash + minimal metadata (REG-004).

    The card is untrusted data: we parse JSON only to record a hash and observed
    name. Nothing in it is interpreted as an instruction.
    """
    listing.card_fetched_at = utcnow()
    listing.last_checked_at = listing.card_fetched_at
    try:
        res = fetcher.fetch(listing.agent_card_url)
    except UnsafeURLError:
        listing.card_fetch_result = "blocked_unsafe_url"
        return
    except FetchError as exc:
        listing.card_fetch_result = exc.category
        return
    listing.last_check_latency_ms = res.elapsed_ms
    if res.status_code != 200:
        listing.card_fetch_result = f"http_{res.status_code // 100}xx"
        return
    previous_hash = listing.card_hash
    listing.card_hash = hashlib.sha256(res.body).hexdigest()
    try:
        card = json.loads(res.body)
    except (ValueError, UnicodeDecodeError):
        listing.card_fetch_result = "invalid_json"
        return
    if not isinstance(card, dict) or not isinstance(card.get("name"), str):
        listing.card_fetch_result = "missing_required_fields"
        return
    listing.card_name = card["name"][:200]
    listing.card_fetch_result = "ok"
    if listing.card_hash != previous_hash or listing.card_summary is None:
        listing.card_summary = summarize_card(card, listing)
        set_derived_facets(listing)
        bump_revision(listing)


def _s(v, n: int = 200) -> str | None:
    return v[:n] if isinstance(v, str) and v else None


def _strs(v, n: int = 20, size: int = 120) -> list[str]:
    return [x[:size] for x in v[:n] if isinstance(x, str)] if isinstance(v, list) else []


def summarize_card(card: dict, listing: Listing) -> dict:
    """Bounded, string-only summary of an A2A Agent Card (1.0 and 0.3 field names). Untrusted data:
    nothing here is executed or followed; URLs are recorded, never fetched."""
    interfaces = []
    raw_ifaces = card.get("supportedInterfaces") or card.get("additionalInterfaces") or []
    if isinstance(card.get("url"), str):
        raw_ifaces = [{"url": card["url"], "protocolBinding": card.get("preferredTransport"),
                       "protocolVersion": card.get("protocolVersion")}] + list(raw_ifaces)
    for it in raw_ifaces[:8] if isinstance(raw_ifaces, list) else []:
        if isinstance(it, dict) and isinstance(it.get("url"), str):
            interfaces.append({"url": it["url"][:2048],
                               "protocol_binding": _s(it.get("protocolBinding") or it.get("transport"), 40),
                               "protocol_version": _s(it.get("protocolVersion"), 20)})
    skills = []
    for sk in card.get("skills", [])[:64] if isinstance(card.get("skills"), list) else []:
        if isinstance(sk, dict) and isinstance(sk.get("id"), str):
            skills.append({"id": sk["id"][:120], "name": _s(sk.get("name")), "tags": _strs(sk.get("tags")),
                           "input_modes": _strs(sk.get("inputModes"), 10, 80),
                           "output_modes": _strs(sk.get("outputModes"), 10, 80)})
    onaa = None
    caps = card.get("capabilities") if isinstance(card.get("capabilities"), dict) else {}
    for ext in caps.get("extensions", [])[:16] if isinstance(caps.get("extensions"), list) else []:
        if isinstance(ext, dict) and ext.get("uri") == ONAA_EXTENSION_URI and isinstance(ext.get("params"), dict):
            p = ext["params"]
            onaa = {"onaa_protocol": _s(p.get("onaa_protocol"), 20), "roles": _strs(p.get("roles"), 5, 40),
                    "jwks_uri": _s(p.get("jwks_uri"), 2048)}
    warnings = []
    if (card.get("name") or "").strip().lower() != (listing.display_name or "").strip().lower():
        warnings.append("card_name_differs_from_listing")
    if any(host_of(i["url"]) != listing.endpoint_host for i in interfaces if i["url"].startswith("https://")):
        warnings.append("card_interface_off_listing_host")
    if not skills:
        warnings.append("card_has_no_skills")
    return {"name": _s(card.get("name")), "version": _s(card.get("version"), 40),
            "protocol_versions": sorted({i["protocol_version"] for i in interfaces if i["protocol_version"]}),
            "interfaces": interfaces, "skills": skills, "onaa": onaa, "warnings": warnings}


def make_listing_id(listing_type: str) -> str:
    return new_id({"agent": "agt", "service": "svc", "hosting": "hst"}[listing_type])


def check_terms_acceptance(settings, version: str, sha256: str | None) -> Terms:
    """Acceptance must name the current version and, if a hash is sent, the exact current text."""
    if version != settings.terms_version:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"accept_terms_version must equal current terms version '{settings.terms_version}' "
                            "(read it first at GET /v1/terms)")
    terms = load_terms(settings.terms_version)
    if sha256 is not None and sha256 != terms.sha256:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "accept_terms_sha256 does not match the current terms text; fetch GET /v1/terms again")
    return terms
