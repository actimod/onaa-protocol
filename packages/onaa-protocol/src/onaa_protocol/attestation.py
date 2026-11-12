"""Signed trust attestations and status records (spec section 10).

v0.1 produces TEST-ONLY attestations exclusively: real issuance requires explicit
approval by the ONAA maintainers. An attestation is a statement about what was checked, for a scope and
period; it is not a licence, guarantee, insurance or government approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import jose, schemas
from .envelope import format_ts, parse_ts, utcnow
from .errors import AttestationError, ProtocolError, SignatureError
from .jose import public_key_from_jwk, validate_jwks

ATTESTATION_VERSION = "0.1.0"
LEVELS = ("endpoint_verified", "operator_verified", "protocol_certified", "commerce_certified",
          "service_certified", "security_reviewed")
DEFAULT_LIMITATIONS = (
    "TEST-ONLY ONAA Protocol v0.1 attestation. Not a government approval, licence, guarantee or insurance. "
    "Scope limited to the listed criteria, protocols, jurisdictions and dates."
)
DEFAULT_MAX_STATUS_AGE = timedelta(days=7)


def build_attestation(
    *,
    id_: str,
    issuer: dict[str, str],
    subject: dict[str, Any],
    level: str,
    scope: dict[str, Any],
    criteria_version: str,
    issued_at: datetime,
    expires_at: datetime,
    status_url: str,
    evidence: list[dict[str, str]],
    status: str = "active",
    status_at: datetime | None = None,
    test_only: bool = True,
    limitations: str = DEFAULT_LIMITATIONS,
) -> dict[str, Any]:
    """Unsigned attestation. Refuses ``test_only=False`` (no real issuance in v0.1)."""
    if not test_only:
        raise ValueError("ONAA Protocol v0.1 only issues TEST-ONLY attestations (real issuance needs approval)")
    if level not in LEVELS:
        raise ValueError(f"unknown level {level}")
    return {
        "attestation_version": ATTESTATION_VERSION,
        "id": id_,
        "issuer": dict(issuer),
        "subject": dict(subject),
        "level": level,
        "scope": scope,
        "criteria_version": criteria_version,
        "issued_at": format_ts(issued_at),
        "expires_at": format_ts(expires_at),
        "status": status,
        "status_at": format_ts(status_at or issued_at),
        "status_url": status_url,
        "evidence": evidence,
        "test_only": True,
        "limitations": limitations,
    }


def _payload(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if k != "signature"}


def sign_attestation(att: dict[str, Any], signer: jose.Signer) -> dict[str, Any]:
    att["signature"] = jose.sign_detached(_payload(att), signer, jose.TYP_ATTESTATION)
    return att


def build_status_record(attestation_id: str, issuer_id: str, status: str, status_at: datetime,
                        next_update: datetime, *, reason: str | None = None,
                        superseded_by: str | None = None) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "attestation_status_version": ATTESTATION_VERSION,
        "attestation_id": attestation_id,
        "issuer_id": issuer_id,
        "status": status,
        "status_at": format_ts(status_at),
        "next_update": format_ts(next_update),
        "test_only": True,
    }
    if reason:
        rec["reason"] = reason
    if superseded_by:
        rec["superseded_by"] = superseded_by
    return rec


def sign_status_record(rec: dict[str, Any], signer: jose.Signer) -> dict[str, Any]:
    rec["signature"] = jose.sign_detached(_payload(rec), signer, jose.TYP_ATTESTATION_STATUS)
    return rec


@dataclass
class AttestationResult:
    attestation_id: str
    level: str
    subject: dict[str, Any]
    status: str
    status_at: str
    test_only: bool
    warnings: list[str] = field(default_factory=list)


def _lookup(issuer_jwks: dict[str, Any]):
    keys = validate_jwks(issuer_jwks)

    def lookup(kid: str):
        if kid not in keys:
            raise SignatureError("key_not_found", "issuer kid not in issuer JWKS")
        return public_key_from_jwk(keys[kid])

    return lookup


def verify_status_record(rec: Any, issuer_jwks: dict[str, Any]) -> dict[str, Any]:
    errs = schemas.errors("attestation", rec, "#/$defs/statusRecord")
    if errs:
        raise AttestationError("attestation_invalid", "status record schema: " + errs[0].split(":")[0])
    jose.verify_detached(_payload(rec), rec["signature"], _lookup(issuer_jwks), jose.TYP_ATTESTATION_STATUS)
    return rec


def verify_attestation(
    att: Any,
    issuer_jwks: dict[str, Any],
    *,
    trusted_issuers: set[str] | frozenset[str],
    now: datetime | None = None,
    status_record: dict[str, Any] | None = None,
    max_status_age: timedelta | None = DEFAULT_MAX_STATUS_AGE,
    allow_test_only: bool = False,
) -> AttestationResult:
    """Offline verification (spec section 10.4). Raises AttestationError/SignatureError with stable codes.

    ``issuer_jwks`` must come from a trusted channel (pinned configuration), never from the attestation.
    """
    errs = schemas.errors("attestation", att)
    if errs:
        raise AttestationError("attestation_invalid", "schema violation at " + errs[0].split(":")[0])
    if att["issuer"]["id"] not in trusted_issuers:
        raise AttestationError("issuer_untrusted", "issuer is not in the relying party's trust list")
    jose.verify_detached(_payload(att), att["signature"], _lookup(issuer_jwks), jose.TYP_ATTESTATION)
    if att["test_only"] and not allow_test_only:
        raise AttestationError("attestation_test_only", "TEST-ONLY attestation; not valid outside tests")
    now = now or utcnow()
    try:
        issued, expires = parse_ts(att["issued_at"], "issued_at"), parse_ts(att["expires_at"], "expires_at")
        status, status_at = att["status"], parse_ts(att["status_at"], "status_at")
    except ProtocolError as exc:
        raise AttestationError("attestation_invalid", exc.message) from exc
    if expires <= issued:
        raise AttestationError("attestation_invalid", "expires_at must be after issued_at")
    if now < issued:
        raise AttestationError("attestation_not_yet_valid", "attestation is not yet valid")
    warnings: list[str] = []
    if status_record is not None:
        verify_status_record(status_record, issuer_jwks)
        if status_record["attestation_id"] != att["id"] or status_record["issuer_id"] != att["issuer"]["id"]:
            raise AttestationError("attestation_invalid", "status record is for a different attestation")
        try:
            rec_at = parse_ts(status_record["status_at"], "status_at")
            next_update = parse_ts(status_record["next_update"], "next_update")
        except ProtocolError as exc:
            raise AttestationError("attestation_invalid", exc.message) from exc
        if now > next_update:  # section 10.5: a record is usable only until its next_update
            raise AttestationError("attestation_status_stale",
                                   "status record is past its next_update; fetch status_url again")
        if rec_at >= status_at:
            status, status_at = status_record["status"], rec_at
    if status == "revoked":
        raise AttestationError("attestation_revoked", "attestation has been revoked")
    if status == "suspended":
        raise AttestationError("attestation_suspended", "attestation is suspended")
    if status == "superseded":
        raise AttestationError("attestation_superseded", "attestation was superseded by a newer record")
    if status == "expired" or now >= expires:
        raise AttestationError("attestation_expired", "attestation has expired")
    if status == "conditional":
        warnings.append("conditional: issuer recorded open conditions; see status_reason")
    if max_status_age is not None and now - status_at > max_status_age:
        raise AttestationError("attestation_status_stale",
                               "status older than the relying party's max age; fetch status_url")
    return AttestationResult(att["id"], att["level"], att["subject"], status, format_ts(status_at),
                             att["test_only"], warnings)
