"""Agent and service listing routes, including domain-control challenges."""

from __future__ import annotations

import datetime as dt
import hmac
import secrets
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..health import probe_listing
from ..logic import (
    FACET_FIELDS,
    PUBLIC_STATUSES,
    active_cert_exists,
    active_certs,
    audit,
    aware,
    check_listing_quota,
    ensure_not_taken,
    flag_name_collision,
    get_listing,
    host_of,
    make_listing_id,
    normalise_url,
    refresh_card,
    require_owner,
    require_same_host,
    set_facets,
    to_record,
    verified_predicate,
)
from ..models import DomainChallenge, Listing, ListingFacet, Operator, utcnow
from ..netsafety import FetchError, UnsafeURLError
from ..security import current_operator, sha256_hex, write_limit
from ..verification import DnsLookupError, dns_record_name, verification_entitlement

MAX_CHALLENGE_ATTEMPTS = 10
CHALLENGE_PATH = "/.well-known/onaa-verification/{cid}.txt"


def _record(session: Session, listing: Listing) -> schemas.RegistryRecord:
    op = session.get(Operator, listing.operator_id) if listing.operator_id else None
    return to_record(listing, op)


def search(session: Session, *, listing_types: tuple[str, ...], q: str | None, filters: dict[str, list[str]],
           service_type: list[str] | None, verified_only: bool, certified_only: bool, claimed_only: bool,
           reachable_only: bool = False,
           status_in: list[str] | None, limit: int, offset: int) -> schemas.SearchPage:
    stmt = select(Listing).where(Listing.listing_type.in_(listing_types))
    allowed = [s for s in (status_in or PUBLIC_STATUSES) if s in PUBLIC_STATUSES]
    stmt = stmt.where(Listing.lifecycle_status.in_(allowed or ["__none__"]))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Listing.display_name).like(like), func.lower(Listing.description).like(like)))
    if service_type:
        stmt = stmt.where(Listing.service_type.in_(service_type))
    for kind, values in filters.items():
        if not values:
            continue
        if kind == "region":
            values = sorted(set(values) | {"GLOBAL"})
        sub = select(ListingFacet.listing_id).where(ListingFacet.kind == kind, ListingFacet.value.in_(values))
        stmt = stmt.where(Listing.id.in_(sub))
    if verified_only:
        stmt = stmt.where(verified_predicate())
    if certified_only:
        stmt = stmt.where(active_cert_exists(), verified_predicate())
    if reachable_only:
        stmt = stmt.where(Listing.reachability != "unreachable")
    if claimed_only:
        stmt = stmt.where(Listing.operator_id.is_not(None), Listing.lifecycle_status != "discovered")
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    # Ranking (MVP): certified, then endpoint-verified, then most recently updated. Same rules for
    # every operator, including any future first-party ONAA services.
    rank = active_cert_exists() & verified_predicate()
    rows = session.scalars(stmt.order_by(rank.desc(), verified_predicate().desc(),
                                         Listing.updated_at.desc(), Listing.id).limit(limit).offset(offset)).all()
    return schemas.SearchPage(items=[_record(session, r) for r in rows], total=total or 0, limit=limit, offset=offset)


def _norm_list(values: list[str] | None, upper: bool = False) -> list[str]:
    out = []
    for v in values or []:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part.upper() if upper else part.lower())
    return out


def build_router(kind: Literal["agents", "services"]) -> APIRouter:
    router = APIRouter(prefix=f"/v1/{kind}", tags=[kind])
    listing_types = ("agent",) if kind == "agents" else ("service", "hosting")
    is_agent = kind == "agents"

    def _load(session: Session, listing_id: str, **kw) -> Listing:
        listing = get_listing(session, listing_id, **kw)
        if listing.listing_type not in listing_types:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "listing not found")
        return listing

    @router.get("", response_model=schemas.SearchPage, summary=f"Search {kind}")
    def list_listings(
        session: Session = Depends(get_session),
        q: Annotated[str | None, Query(max_length=200)] = None,
        role: Annotated[list[str] | None, Query()] = None,
        capability: Annotated[list[str] | None, Query()] = None,
        region: Annotated[list[str] | None, Query()] = None,
        currency: Annotated[list[str] | None, Query()] = None,
        protocol: Annotated[list[str] | None, Query()] = None,
        language: Annotated[list[str] | None, Query()] = None,
        category: Annotated[list[str] | None, Query()] = None,
        type: Annotated[list[str] | None, Query(description="service_type filter (services only)")] = None,
        verified_only: bool = False,
        certified_only: bool = False,
        claimed_only: bool = False,
        reachable_only: Annotated[bool, Query(description="Hide listings whose last 3 health probes failed")] = False,
        status_: Annotated[list[str] | None, Query(alias="status")] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
    ):
        filters = {
            "role": _norm_list(role), "capability": _norm_list(capability), "region": _norm_list(region, True),
            "currency": _norm_list(currency, True), "protocol": _norm_list(protocol),
            "language": _norm_list(language), "category": _norm_list(category),
        }
        return search(session, listing_types=listing_types, q=q, filters=filters,
                      service_type=None if is_agent else (_norm_list(type) or None),
                      verified_only=verified_only, certified_only=certified_only, claimed_only=claimed_only,
                      reachable_only=reachable_only, status_in=_norm_list(status_) or None, limit=limit, offset=offset)

    @router.get("/{listing_id}", response_model=schemas.RegistryRecord)
    def get_one(listing_id: str, session: Session = Depends(get_session)):
        return _record(session, _load(session, listing_id))

    @router.get("/{listing_id}/trust", response_model=schemas.Trust)
    def trust(listing_id: str, session: Session = Depends(get_session)):
        return _record(session, _load(session, listing_id)).trust

    if is_agent:
        @router.post("", status_code=201, response_model=schemas.RegistryRecord,
                     dependencies=[Depends(write_limit)], summary="Register an agent you operate")
        def create(body: schemas.AgentCreate, request: Request, op: Operator = Depends(current_operator),
                   session: Session = Depends(get_session)):
            card_url = normalise_url(body.agent_card_url, "agent_card_url")
            check_listing_quota(session, op, request.app.state.settings.max_listings_per_operator)
            ensure_not_taken(session, host_of(card_url), op.id)
            listing = Listing(
                id=make_listing_id("agent"), operator_id=op.id, listing_type="agent",
                display_name=body.display_name, description=body.description, agent_card_url=card_url,
                endpoint_url=normalise_url(body.endpoint_url, "endpoint_url"), endpoint_host=host_of(card_url),
                documentation_url=normalise_url(body.documentation_url, "documentation_url"),
                terms_url=normalise_url(body.terms_url, "terms_url"), lifecycle_status="registered",
                supported_interfaces=[], regulatory_claims=[],
            )
            require_same_host(listing, listing.endpoint_url, "endpoint_url")
            flag_name_collision(session, listing)
            set_facets(listing, body.model_dump())
            session.add(listing)
            session.flush()
            audit(session, "operator", op.id, "agent.register", listing.id)
            return _record(session, listing)

        @router.patch("/{listing_id}", response_model=schemas.RegistryRecord, dependencies=[Depends(write_limit)])
        def update(listing_id: str, body: schemas.AgentUpdate, op: Operator = Depends(current_operator),
                   session: Session = Depends(get_session)):
            listing = _load(session, listing_id)
            require_owner(listing, op)
            data = body.model_dump(exclude_unset=True)
            if "roles" in data and not data["roles"]:
                raise HTTPException(422, "roles cannot be empty")
            if "endpoint_url" in data:
                require_same_host(listing, data["endpoint_url"], "endpoint_url")
            _apply_scalar_updates(listing, data)
            set_facets(listing, data)
            listing.updated_at = utcnow()
            audit(session, "operator", op.id, "agent.update", listing.id, fields=sorted(data))
            return _record(session, listing)

        @router.post("/{listing_id}/claim", response_model=schemas.RegistryRecord,
                     dependencies=[Depends(write_limit)],
                     summary="Claim a discovered (unclaimed) agent; complete domain verification to finish")
        def claim(listing_id: str, request: Request, op: Operator = Depends(current_operator),
                  session: Session = Depends(get_session)):
            listing = _load(session, listing_id)
            ttl = dt.timedelta(seconds=request.app.state.settings.challenge_ttl_seconds)
            stale_claim = (listing.lifecycle_status == "claim_pending"
                           and aware(listing.updated_at) < utcnow() - ttl)
            if listing.lifecycle_status != "discovered" and not stale_claim:
                raise HTTPException(status.HTTP_409_CONFLICT, "only discovered listings can be claimed")
            check_listing_quota(session, op, request.app.state.settings.max_listings_per_operator)
            # Claim is provisional; ownership is proven only by the domain challenge.
            listing.operator_id = op.id
            listing.lifecycle_status = "claim_pending"
            listing.updated_at = utcnow()
            audit(session, "operator", op.id, "agent.claim", listing.id)
            return _record(session, listing)

        @router.post("/{listing_id}/refresh-card", response_model=schemas.RegistryRecord,
                     dependencies=[Depends(write_limit)], summary="Re-fetch the linked Agent Card (owner only)")
        def refresh(listing_id: str, request: Request, op: Operator = Depends(current_operator),
                    session: Session = Depends(get_session)):
            listing = _load(session, listing_id)
            require_owner(listing, op)
            refresh_card(listing, request.app.state.fetcher)
            audit(session, "operator", op.id, "agent.card_refresh", listing.id,
                  result_category=listing.card_fetch_result)
            return _record(session, listing)
    else:
        @router.post("", status_code=201, response_model=schemas.RegistryRecord,
                     dependencies=[Depends(write_limit)], summary="Register a service (payment, escrow, hosting, ...)")
        def create(body: schemas.ServiceCreate, request: Request, op: Operator = Depends(current_operator),
                   session: Session = Depends(get_session)):
            endpoint = normalise_url(body.endpoint_url, "endpoint_url")
            check_listing_quota(session, op, request.app.state.settings.max_listings_per_operator)
            ensure_not_taken(session, host_of(endpoint), op.id)
            ltype = "hosting" if body.service_type == "hosting" else "service"
            interfaces = []
            for itf in body.supported_interfaces:
                d = itf.model_dump(exclude_none=True)
                for k in ("spec_url", "url"):
                    if k in d:
                        d[k] = normalise_url(d[k], f"supported_interfaces.{k}")
                interfaces.append(d)
            listing = Listing(
                id=make_listing_id(ltype), operator_id=op.id, listing_type=ltype, service_type=body.service_type,
                display_name=body.display_name, description=body.description, endpoint_url=endpoint,
                endpoint_host=host_of(endpoint),
                agent_card_url=normalise_url(body.agent_card_url, "agent_card_url"),
                documentation_url=normalise_url(body.documentation_url, "documentation_url"),
                terms_url=normalise_url(body.terms_url, "terms_url"),
                sandbox_url=normalise_url(body.sandbox_url, "sandbox_url"),
                sandbox_available=body.sandbox_available, supported_interfaces=interfaces,
                regulatory_claims=[c[:200] for c in body.regulatory_claims], lifecycle_status="registered",
            )
            require_same_host(listing, listing.agent_card_url, "agent_card_url")
            for itf in interfaces:
                require_same_host(listing, itf.get("url"), "supported_interfaces.url")
            flag_name_collision(session, listing)
            data = body.model_dump()
            data["roles"] = ["hosting_provider" if ltype == "hosting" else "service_provider"]
            set_facets(listing, data)
            session.add(listing)
            session.flush()
            audit(session, "operator", op.id, "service.register", listing.id, service_type=body.service_type)
            return _record(session, listing)

        @router.patch("/{listing_id}", response_model=schemas.RegistryRecord, dependencies=[Depends(write_limit)])
        def update(listing_id: str, body: schemas.ServiceUpdate, op: Operator = Depends(current_operator),
                   session: Session = Depends(get_session)):
            listing = _load(session, listing_id)
            require_owner(listing, op)
            data = body.model_dump(exclude_unset=True)
            _apply_scalar_updates(listing, data)
            set_facets(listing, data)
            listing.updated_at = utcnow()
            audit(session, "operator", op.id, "service.update", listing.id, fields=sorted(data))
            return _record(session, listing)

    @router.delete("/{listing_id}", status_code=204, summary="Delist immediately (owner only)")
    def delete(listing_id: str, op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
        listing = _load(session, listing_id)
        require_owner(listing, op)
        listing.lifecycle_status = "deleted"
        listing.status_reason = "owner_deleted"
        listing.updated_at = utcnow()
        audit(session, "operator", op.id, f"{kind[:-1]}.delete", listing.id)

    @router.post("/{listing_id}/health-check", response_model=schemas.RegistryRecord,
                 dependencies=[Depends(write_limit)], summary="Probe the endpoint now (owner only)")
    def health_check(listing_id: str, request: Request, op: Operator = Depends(current_operator),
                     session: Session = Depends(get_session)):
        listing = _load(session, listing_id)
        require_owner(listing, op)
        result = probe_listing(listing, request.app.state.fetcher)
        audit(session, "operator", op.id, "listing.health_check", listing.id, result_category=result)
        return _record(session, listing)

    # ---- domain / endpoint control verification (TRUST-001) ----
    @router.post("/{listing_id}/verify-domain", status_code=201, response_model=schemas.ChallengeCreated,
                 dependencies=[Depends(write_limit)], summary="Start a well-known endpoint-control challenge")
    def start_challenge(listing_id: str, request: Request,
                        body: Annotated[schemas.ChallengeStart | None, Body()] = None,
                        op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
        method = (body or schemas.ChallengeStart()).method
        listing = _load(session, listing_id)
        require_owner(listing, op, allow_claim_pending=True)
        if not listing.endpoint_host:
            raise HTTPException(422, "listing has no endpoint host to verify")
        entitlement = verification_entitlement(listing, op)
        if request.app.state.settings.require_verification_entitlement and entitlement is None:
            raise HTTPException(
                status.HTTP_402_PAYMENT_REQUIRED,
                "Endpoint Verified is a separate tier from free listing. Join the Founding Cohort (agent operators) "
                "or apply via POST /v1/certifications/applications with scheme 'endpoint_verified'. "
                "Your listing stays free and searchable either way.")
        token = "onaa-verify-" + secrets.token_urlsafe(32)
        now = utcnow()
        # Any earlier pending challenge for this listing is superseded.
        for old in session.scalars(select(DomainChallenge).where(DomainChallenge.listing_id == listing.id,
                                                                 DomainChallenge.status == "pending")):
            old.status = "superseded"
        chl = DomainChallenge(listing_id=listing.id, operator_id=op.id, host=listing.endpoint_host, method=method,
                              nonce_hash=sha256_hex(token),
                              expires_at=now + dt.timedelta(seconds=request.app.state.settings.challenge_ttl_seconds))
        session.add(chl)
        session.flush()
        audit(session, "operator", op.id, "verification.start", listing.id, challenge_id=chl.id, method=method,
              entitlement=entitlement)
        finish = (f"then call POST /v1/{kind}/{listing.id}/verification-complete with this challenge_id. "
                  "This proves control of the endpoint host only, not legal identity.")
        if method == "dns_txt":
            name = dns_record_name(chl.host)
            return schemas.ChallengeCreated(
                challenge_id=chl.id, method=method, host=chl.host, token=token, dns_record_name=name,
                expires_at=aware(chl.expires_at),
                instructions=f"Publish a DNS TXT record at {name} whose value is exactly the token, " + finish)
        url = f"https://{chl.host}" + CHALLENGE_PATH.format(cid=chl.id)
        return schemas.ChallengeCreated(
            challenge_id=chl.id, method=method, host=chl.host, token=token, challenge_url=url,
            expires_at=aware(chl.expires_at),
            instructions=f"Serve the token as the exact text body (HTTP 200) at {url}, " + finish)

    @router.post("/{listing_id}/verification-complete", response_model=schemas.ChallengeResult,
                 dependencies=[Depends(write_limit)], responses={422: {"model": schemas.ChallengeResult}})
    def complete_challenge(listing_id: str, request: Request,
                           challenge_id: Annotated[str, Body(embed=True, max_length=40)],
                           op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
        listing = _load(session, listing_id)
        require_owner(listing, op, allow_claim_pending=True)
        chl = session.get(DomainChallenge, challenge_id)
        if chl is None or chl.listing_id != listing.id or chl.operator_id != op.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "challenge not found")
        if chl.status != "pending":
            raise HTTPException(status.HTTP_409_CONFLICT, f"challenge is {chl.status}; start a new one")
        if aware(chl.expires_at) <= utcnow():
            chl.status = "expired"
            session.commit()
            raise HTTPException(status.HTTP_410_GONE, "challenge expired; start a new one")
        if chl.host != listing.endpoint_host:
            chl.status = "failed"
            session.commit()
            raise HTTPException(status.HTTP_409_CONFLICT, "listing host changed since challenge was issued")

        chl.attempts += 1
        error = None
        if chl.method == "dns_txt":
            try:
                values = request.app.state.txt_resolver(dns_record_name(chl.host))
                if not any(hmac.compare_digest(sha256_hex(v.strip()), chl.nonce_hash) for v in values):
                    error = "token_mismatch" if values else "txt_record_not_found"
            except DnsLookupError as exc:
                error = exc.category
        else:
            try:
                # No redirects: a redirect to another host must not prove control of this one.
                res = request.app.state.fetcher.fetch(f"https://{chl.host}" + CHALLENGE_PATH.format(cid=chl.id),
                                                      allow_redirects=False)
                if res.status_code != 200:
                    error = f"http_{res.status_code}"
                elif not hmac.compare_digest(sha256_hex(res.body.strip()), chl.nonce_hash):
                    error = "token_mismatch"
            except UnsafeURLError:
                error = "unsafe_url"
            except FetchError as exc:
                error = exc.category

        if error:
            chl.last_error = error
            if chl.attempts >= MAX_CHALLENGE_ATTEMPTS:
                chl.status = "failed"
            audit(session, "operator", op.id, "verification.complete", listing.id, result="failed", error=error)
            session.commit()
            body = schemas.ChallengeResult(challenge_id=chl.id, status=chl.status,
                                           listing_status=listing.lifecycle_status,
                                           endpoint_control_verified=listing.endpoint_control_verified, error=error)
            return JSONResponse(status_code=422, content=body.model_dump(mode="json"))

        now = utcnow()
        chl.status, chl.verified_at = "verified", now
        listing.endpoint_control_verified, listing.endpoint_verified_at = True, now
        listing.endpoint_verified_until = now + dt.timedelta(days=request.app.state.settings.verification_valid_days)
        listing.endpoint_verification_method = chl.method
        if listing.lifecycle_status in ("registered", "claim_pending"):
            listing.lifecycle_status = "endpoint_verified"
        if listing.status_reason == "endpoint_verification_expired":
            listing.status_reason = None
        # Re-verification restores certified status if a certification is still active.
        if listing.lifecycle_status == "endpoint_verified" and active_certs(listing):
            listing.lifecycle_status = "certified"
        listing.updated_at = now
        # Anti-squatting: other operators' unverified listings on this host (and discovered copies of
        # the same card) are superseded by the verified owner.
        others = select(Listing).where(
            Listing.id != listing.id, Listing.endpoint_control_verified.is_(False),
            Listing.lifecycle_status.in_(("discovered", "claim_pending", "registered")),
            or_(and_(Listing.endpoint_host == listing.endpoint_host,
                     Listing.operator_id.is_not(None), Listing.operator_id != op.id),
                and_(Listing.agent_card_url == listing.agent_card_url, Listing.agent_card_url.is_not(None))))
        for other in session.scalars(others):
            other.lifecycle_status = "suspended"
            other.status_reason = f"superseded_by_verified_owner:{listing.id}"
            audit(session, "system", None, "listing.superseded", other.id, by=listing.id)
        probe_listing(listing, request.app.state.fetcher)  # recorded health signal; does not block verification
        audit(session, "operator", op.id, "verification.complete", listing.id, health=listing.last_check_result)
        return schemas.ChallengeResult(challenge_id=chl.id, status=chl.status, listing_status=listing.lifecycle_status,
                                       endpoint_control_verified=True)

    return router


def _apply_scalar_updates(listing: Listing, data: dict) -> None:
    for field in ("display_name", "description", "sandbox_available"):
        if field in data:
            setattr(listing, field, data[field])
    for field in ("documentation_url", "terms_url", "sandbox_url", "endpoint_url"):
        if field in data:
            setattr(listing, field, normalise_url(data[field], field))


__all__ = ["FACET_FIELDS", "build_router"]
