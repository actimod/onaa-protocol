"""Signed trust objects and the transparency log (CERT-011).

* Attestations are built and signed with ``onaa_protocol`` and are ALWAYS TEST-ONLY: the library refuses
  anything else, and this module refuses signing keys whose kid does not start with ``test-``. Real issuance
  keys need founder approval; see the ONAA attestation key management procedure.
* One key per purpose: attestation key, status key, log (checkpoint) key. The root key never touches the
  registry; it signs the issuer manifest offline (scripts/issuer_ceremony_dryrun.py), which the registry only
  serves. At startup the configured signing keys must match the manifest's purposes.
* Status records are re-signed when the certificate's status changes or the stored record is older than
  ``status_reissue_hours``; each lives ``status_validity_days`` (default 7) and verifiers fail closed after.
* Every issue/suspend/reinstate/revoke/expire event is appended to a Merkle log (RFC 9162 hashing) with
  inclusion and consistency proofs, so history cannot be rewritten silently.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from onaa_protocol import jose, trust
from onaa_protocol import transparency as tl
from onaa_protocol.attestation import build_attestation, build_status_record, sign_attestation, sign_status_record
from onaa_protocol.envelope import PROTOCOL_VERSION
from onaa_protocol.jcs import canonicalize
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .models import Certification, Listing, TransparencyEntry, utcnow

ISSUER_MANIFEST_PATH = "/.well-known/onaa/issuer-jwks.json"
CERT_LEVELS = ("protocol_certified", "commerce_certified", "service_certified")
_STATUS_FOR = {"active": "active", "suspended": "suspended", "revoked": "revoked", "expired": "expired"}


class TrustConfigError(RuntimeError):
    pass


def _signer(raw: str | None, purpose: str) -> jose.Signer | None:
    if not raw:
        return None
    try:
        jwk = json.loads(raw)
        key = jose.private_key_from_jwk(jwk)
    except (ValueError, KeyError, TypeError) as exc:
        raise TrustConfigError(f"{purpose} signing key is not a private Ed25519 JWK") from exc
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid.startswith(trust.TEST_KID_PREFIX):
        # Production issuance keys need founder approval; staging accepts test- keys only.
        raise TrustConfigError(f"{purpose} signing key kid must start with 'test-' (staging only)")
    return jose.Signer(key, kid)


@dataclass
class TrustConfig:
    issuer_id: str
    base_url: str
    attestation: jose.Signer | None
    status: jose.Signer | None
    log: jose.Signer | None
    manifest: dict[str, Any] | None
    status_validity: dt.timedelta
    status_reissue: dt.timedelta

    @property
    def manifest_url(self) -> str:
        return self.base_url.rstrip("/") + ISSUER_MANIFEST_PATH

    def status_url(self, att_id: str) -> str:
        return f"{self.base_url.rstrip('/')}/v1/attestations/{att_id}/status"


def load_trust_config(settings) -> TrustConfig:
    cfg = TrustConfig(
        issuer_id=settings.issuer_id, base_url=settings.public_base_url,
        attestation=_signer(settings.attestation_signing_jwk, "attestation"),
        status=_signer(settings.status_signing_jwk, "status"),
        log=_signer(settings.log_signing_jwk, "log"),
        manifest=None,
        status_validity=dt.timedelta(days=settings.status_validity_days),
        status_reissue=dt.timedelta(hours=settings.status_reissue_hours))
    if settings.issuer_manifest:
        try:
            manifest = json.loads(settings.issuer_manifest)
        except ValueError as exc:
            raise TrustConfigError("ONAA_ISSUER_MANIFEST is not JSON") from exc
        if not isinstance(manifest, dict) or manifest.get("issuer_id") != cfg.issuer_id:
            raise TrustConfigError("issuer manifest issuer_id does not match ONAA_ISSUER_ID")
        listed = {k.get("kid"): k for k in manifest.get("keys", []) if isinstance(k, dict)}
        for signer, purpose in ((cfg.attestation, jose.TYP_ATTESTATION), (cfg.status, jose.TYP_ATTESTATION_STATUS),
                                (cfg.log, tl.TYP_CHECKPOINT)):
            if signer is None:
                continue
            entry = listed.get(signer.kid)
            if entry is None or entry.get("onaa_purpose") != purpose or entry.get("onaa_status") != "active" \
                    or entry.get("x") != signer.public_jwk()["x"]:
                raise TrustConfigError(f"signing key {signer.kid} is not an active {purpose} key in the manifest")
        cfg.manifest = manifest
    elif cfg.attestation or cfg.status or cfg.log:
        raise TrustConfigError("signing keys are configured but ONAA_ISSUER_MANIFEST is missing")
    return cfg


def sha256_prefixed(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(obj)).hexdigest()


def _criteria(version: str) -> str:
    """Registry criteria ids look like ``draft-0.1``; attestations carry the bare ``0.1``."""
    v = version.split("-")[-1]
    return v if v.replace(".", "").isdigit() and v.count(".") in (1, 2) else "0.1"


def attestation_scope(listing: Listing, conformance: dict | None) -> dict[str, Any]:
    roles = [r for r in listing.facet_values("role") if r in ("buyer_agent", "seller_agent", "service_provider")]
    scope: dict[str, Any] = {"protocols": [{"name": "onaa", "version": PROTOCOL_VERSION},
                                           {"name": "a2a", "version": "1.0"}]}
    if roles:
        scope["roles"] = roles
    if listing.listing_type == "service" and listing.service_type in ("escrow", "payment", "insurance", "logistics",
                                                                      "inspection", "dispute"):
        scope["service_type"] = listing.service_type
    if conformance:
        scope["conformance"] = conformance
    return scope


def issue_attestation(cfg: TrustConfig, cert: Certification, listing: Listing, *, conformance: dict | None,
                      report_sha256: str | None, now: dt.datetime) -> dict[str, Any] | None:
    """Sign a TEST-ONLY attestation for an approved certification. Refuses without a human approval record."""
    if cert.approval is None or not cert.approval.get("approver"):
        raise ValueError("refusing to sign: no human approval record")
    if cfg.attestation is None:
        return None
    subject: dict[str, Any] = {"subject_type": "service" if listing.listing_type != "agent" else "agent",
                               "subject_id": listing.id}
    if listing.operator_id:
        subject["operator_id"] = listing.operator_id
    if listing.agent_card_url:
        subject["agent_card_url"] = listing.agent_card_url
    evidence = [{"type": "review_record", "sha256": sha256_prefixed(cert.approval)}]
    if report_sha256:
        evidence.insert(0, {"type": "conformance_report", "sha256": report_sha256})
    att = build_attestation(
        id_=cert.id, issuer={"id": cfg.issuer_id, "name": "ONAA Registry (staging)", "jwks_uri": cfg.manifest_url},
        subject=subject, level=cert.scheme, scope=attestation_scope(listing, conformance),
        criteria_version=_criteria(cert.criteria_version), issued_at=now, expires_at=_aware(cert.expires_at),
        status_url=cfg.status_url(cert.id), evidence=evidence, status_at=now)
    return sign_attestation(att, cfg.attestation)


def _aware(ts: dt.datetime | None) -> dt.datetime | None:
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=dt.UTC)
    return ts


def effective_status(cert: Certification, now: dt.datetime | None = None) -> str:
    now = now or utcnow()
    if cert.status == "active" and _aware(cert.expires_at) <= now:
        return "expired"
    return _STATUS_FOR.get(cert.status, "suspended")


def current_status_record(session: Session, cfg: TrustConfig, cert: Certification, *,
                          force: bool = False) -> dict[str, Any] | None:
    """Return a fresh signed status record, re-signing when stale or when the status changed."""
    if cfg.status is None or cert.attestation is None:
        return None
    now = utcnow()
    status = effective_status(cert, now)
    rec = cert.status_record
    signed_at = _aware(cert.status_record_at)
    if not force and rec and rec.get("status") == status and signed_at and now - signed_at < cfg.status_reissue:
        return rec
    rec = build_status_record(cert.id, cfg.issuer_id, status, now, now + cfg.status_validity,
                              reason=(cert.status_reason or None) if status != "active" else None)
    rec = sign_status_record(rec, cfg.status)
    cert.status_record, cert.status_record_at = rec, now
    session.flush()
    return rec


def reissue_status_records(session: Session, cfg: TrustConfig, limit: int = 500) -> int:
    """Bulk job: refresh status records that are due (status changed or older than the re-issue interval)."""
    if cfg.status is None:
        return 0
    n = 0
    certs = session.scalars(select(Certification).where(Certification.attestation.is_not(None))
                            .order_by(Certification.status_record_at.is_(None).desc(),
                                      Certification.status_record_at.asc()).limit(limit)).all()
    for cert in certs:
        before = cert.status_record_at
        current_status_record(session, cfg, cert)
        n += cert.status_record_at != before
    return n


# ------------------------------------------------------------------ transparency log


def append_log(session: Session, cert: Certification, event: str, *, reason: str | None = None,
               at: dt.datetime | None = None) -> TransparencyEntry:
    """Append one event. Rows are insert-only; the leaf index is the next integer (serialised on PostgreSQL)."""
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(7340011)"))  # one appender at a time
    idx = session.scalar(select(func.coalesce(func.max(TransparencyEntry.idx) + 1, 0)))
    entry = tl.build_entry(event=event, attestation_id=cert.id, subject_id=cert.listing_id, level=cert.scheme,
                           status=effective_status(cert), at=at or utcnow(), reason=reason,
                           attestation_sha256=tl.attestation_digest(cert.attestation) if cert.attestation else None)
    row = TransparencyEntry(idx=idx, entry=entry, attestation_id=cert.id,
                            leaf_hash=tl.leaf_hash(tl.leaf_bytes(entry)).hex())
    session.add(row)
    session.flush()
    return row


def leaf_hashes(session: Session, size: int | None = None) -> list[bytes]:
    q = select(TransparencyEntry.leaf_hash).order_by(TransparencyEntry.idx)
    if size is not None:
        q = q.limit(size)
    return [bytes.fromhex(h) for h in session.scalars(q)]


def checkpoint(session: Session, cfg: TrustConfig) -> dict[str, Any] | None:
    if cfg.log is None:
        return None
    hs = leaf_hashes(session)
    cp = tl.build_checkpoint(cfg.issuer_id, len(hs), tl.root_from_hashes(hs), utcnow())
    return tl.sign_checkpoint(cp, cfg.log)


# ------------------------------------------------------------------ status transitions


def set_cert_status(session: Session, cfg: TrustConfig, cert: Certification, new_status: str, reason: str) -> None:
    """Change a certification's status, log it and re-sign its status record immediately."""
    event = {"suspended": "suspend", "revoked": "revoke", "active": "reinstate"}[new_status]
    now = utcnow()
    cert.status, cert.status_reason, cert.status_changed_at = new_status, reason[:200], now
    if new_status == "revoked":
        cert.revoked_at = now
    listing = session.get(Listing, cert.listing_id)
    if listing is not None:
        listing.updated_at = now
    session.flush()
    append_log(session, cert, event, reason=reason, at=now)
    current_status_record(session, cfg, cert, force=True)


def expire_due(session: Session, cfg: TrustConfig) -> list[str]:
    """Mark active certifications past expires_at as expired and log the event once."""
    now = utcnow()
    certs = session.scalars(select(Certification).where(Certification.status == "active",
                                                        Certification.expires_at <= now)).all()
    for cert in certs:
        cert.status, cert.status_reason, cert.status_changed_at = "expired", "validity_period_ended", now
        session.flush()
        append_log(session, cert, "expire", at=now)
        current_status_record(session, cfg, cert, force=True)
    return [c.id for c in certs]


def approval_record(approver: str, application_id: str, criteria_version: str, decided_at: dt.datetime,
                    reason: str) -> dict[str, Any]:
    return {"approver": approver[:120], "application_id": application_id, "criteria_version": criteria_version,
            "decided_at": decided_at.isoformat().replace("+00:00", "Z"), "reason": reason[:500]}
