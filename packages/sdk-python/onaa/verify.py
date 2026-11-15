"""Independent verification of ONAA attestations (CERT-010). Needs ``pip install 'onaa-sdk[verify]'``.

Trust comes from the ROOT public key you pin, never from the registry you query:

1. the issuer manifest is checked against the pinned root key (and must be fresh);
2. each attestation must be signed by a manifest key assigned to attestations, and be about the subject asked;
3. its status record must be signed by a status key and fresh (fail closed once past ``next_update`` or older
   than ``max_status_age``);
4. the transparency log must contain the attestation's ``issue`` event (inclusion proof against a checkpoint
   signed by a log key), and the log's latest event for it must agree with the status record;
5. optionally, the checkpoint must be consistent with the last one you saw (``state``), so the log cannot have
   been rewritten between your checks.

Every check is fail closed: a missing or invalid object makes the attestation invalid. Staging attestations are
TEST-ONLY and verify only with ``allow_test_only=True``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .client import OnaaClient, OnaaError

try:
    from onaa_protocol import transparency as tl
    from onaa_protocol import trust
    from onaa_protocol.attestation import DEFAULT_MAX_STATUS_AGE, verify_attestation
    from onaa_protocol.envelope import parse_ts, utcnow
    from onaa_protocol.errors import ProtocolError
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("onaa.verify needs the onaa-protocol package: pip install 'onaa-sdk[verify]'") from exc


@dataclass
class AttestationCheck:
    id: str
    level: str | None = None
    status: str | None = None
    valid: bool = False
    error: str | None = None
    detail: str | None = None
    test_only: bool | None = None
    expires_at: str | None = None
    log_index: int | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class VerifyReport:
    subject_id: str
    registry: str
    verified: bool
    attestations: list[AttestationCheck]
    checkpoint: dict[str, Any] | None = None
    error: str | None = None
    note: str = ("Attestations state what was checked for a scope and period. They are not a licence, guarantee, "
                 "insurance or government approval. Talk to the counterparty directly; the registry never relays.")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fail(check: AttestationCheck, code: str, detail: str) -> AttestationCheck:
    check.valid, check.error, check.detail = False, code, detail[:300]
    return check


def check_log(client: OnaaClient, issuer: trust.TrustedIssuer, att: dict[str, Any], status: str,
              *, checkpoint: dict[str, Any]) -> int:
    """Return the log index of the attestation's issue event; raise ValueError(code) on any mismatch."""
    entries = client.transparency_entries(attestation_id=att["id"])["entries"]
    issue = [e for e in entries if e["entry"].get("event") == "issue"]
    if len(issue) != 1:
        raise ValueError("log_missing_issue")
    e = issue[0]
    if e["entry"].get("attestation_sha256") != tl.attestation_digest(att):
        raise ValueError("log_attestation_mismatch")
    leaf = tl.leaf_hash(tl.leaf_bytes(e["entry"]))
    size = checkpoint["tree_size"]
    if e["index"] >= size:
        raise ValueError("log_entry_after_checkpoint")
    proof = client.inclusion_proof(e["index"], size)
    try:
        tl.verify_inclusion(leaf, e["index"], size, [tl.unb64(p) for p in proof["proof"]],
                            tl.unb64(checkpoint["root_hash"]))
    except tl.ProofError as exc:
        raise ValueError("log_inclusion_invalid") from exc
    # The newest logged event for this attestation must agree with the signed status record.
    latest = max((x for x in entries if x["index"] < size), key=lambda x: x["index"])
    logged = latest["entry"].get("status")
    # An attestation can expire before the registry's expiry job logs it; every other difference is a mismatch.
    if logged != status and not (status == "expired" and logged == "active"):
        raise ValueError("log_status_mismatch")
    return e["index"]


def verified_checkpoint(client: OnaaClient, issuer: trust.TrustedIssuer, previous: dict[str, Any] | None = None
                        ) -> dict[str, Any]:
    cp = client.transparency_checkpoint()
    try:
        signed_at = parse_ts(cp.get("timestamp"), "timestamp")
    except (ProtocolError, TypeError) as exc:
        raise ValueError("checkpoint_invalid") from exc
    tl.verify_checkpoint(cp, issuer.lookup(tl.TYP_CHECKPOINT, signed_at))
    if cp["log_id"] != issuer.issuer_id:
        raise ValueError("checkpoint_invalid")
    if previous:
        first, second = previous["tree_size"], cp["tree_size"]
        if first > second:
            raise ValueError("log_shrunk")
        if first:
            proof = client.consistency_proof(first, second)
            try:
                tl.verify_consistency(first, second, [tl.unb64(p) for p in proof["proof"]],
                                      tl.unb64(previous["root_hash"]), tl.unb64(cp["root_hash"]))
            except tl.ProofError as exc:
                raise ValueError("log_inconsistent") from exc
    return cp


def verify_subject(client: OnaaClient, subject_id: str, root_jwk: dict[str, Any], *,
                   allow_test_only: bool = False, level: str | None = None, check_transparency: bool = True,
                   previous_checkpoint: dict[str, Any] | None = None,
                   max_status_age: timedelta | None = DEFAULT_MAX_STATUS_AGE) -> VerifyReport:
    """Verify every attestation the registry lists for ``subject_id``. ``verified`` is True only when at least
    one attestation (of ``level``, if given) passes every check."""
    report = VerifyReport(subject_id=subject_id, registry=client.base_url, verified=False, attestations=[])
    now = utcnow()
    try:
        issuer = trust.verify_manifest(client.issuer_manifest(), root_jwk, now=now, allow_test_only=allow_test_only)
    except (OnaaError, ProtocolError, ValueError) as exc:
        report.error = getattr(exc, "code", None) or "manifest_unavailable"
        return report
    cp = None
    if check_transparency:
        try:
            cp = verified_checkpoint(client, issuer, previous_checkpoint)
            report.checkpoint = {k: cp[k] for k in ("tree_size", "root_hash", "timestamp", "log_id")}
        except (OnaaError, ProtocolError, ValueError) as exc:
            report.error = getattr(exc, "code", None) or str(exc) or "checkpoint_invalid"
            return report
    try:
        listed = client.attestations(subject_id)
    except OnaaError as exc:
        report.error = f"registry_error_{exc.status_code}"
        return report
    for item in listed:
        if level and item.get("level") != level:
            continue
        report.attestations.append(verify_one(client, issuer, item["id"], subject_id, now=now, checkpoint=cp,
                                              allow_test_only=allow_test_only, max_status_age=max_status_age))
    report.verified = any(c.valid for c in report.attestations)
    if not report.attestations and not report.error:
        report.error = "no_attestation"
    return report


def verify_one(client: OnaaClient, issuer: trust.TrustedIssuer, att_id: str, subject_id: str, *, now,
               checkpoint: dict[str, Any] | None, allow_test_only: bool,
               max_status_age: timedelta | None = DEFAULT_MAX_STATUS_AGE) -> AttestationCheck:
    check = AttestationCheck(id=att_id)
    try:
        att = client.attestation(att_id)
        rec = client.attestation_status(att_id)
    except OnaaError as exc:
        return _fail(check, "attestation_unavailable", f"HTTP {exc.status_code}")
    check.level, check.test_only, check.expires_at = att.get("level"), att.get("test_only"), att.get("expires_at")
    check.status = rec.get("status") if isinstance(rec, dict) else None
    try:
        res = verify_attestation(att, issuer_manifest=issuer, status_record=rec, now=now,
                                 allow_test_only=allow_test_only, max_status_age=max_status_age)
    except ProtocolError as exc:
        return _fail(check, exc.code, exc.message)
    if att.get("id") != att_id or (att.get("subject") or {}).get("subject_id") != subject_id:
        return _fail(check, "subject_mismatch", "attestation is about a different subject")
    check.status, check.warnings = res.status, list(res.warnings)
    if checkpoint is not None:
        try:
            check.log_index = check_log(client, issuer, att, rec["status"], checkpoint=checkpoint)
        except (OnaaError, ValueError, KeyError) as exc:
            return _fail(check, str(exc) if isinstance(exc, ValueError) else "log_unavailable",
                         "transparency log check failed")
    check.valid = True
    return check


def verify_offline(attestation: dict[str, Any], status_record: dict[str, Any], manifest: dict[str, Any],
                   root_jwk: dict[str, Any], *, allow_test_only: bool = False, subject_id: str | None = None,
                   max_status_age: timedelta | None = DEFAULT_MAX_STATUS_AGE) -> AttestationCheck:
    """No network: check saved objects against a pinned root key (transparency is not checked here)."""
    check = AttestationCheck(id=str(attestation.get("id")))
    try:
        issuer = trust.verify_manifest(manifest, root_jwk, allow_test_only=allow_test_only)
        res = verify_attestation(attestation, issuer_manifest=issuer, status_record=status_record,
                                 allow_test_only=allow_test_only, max_status_age=max_status_age)
    except ProtocolError as exc:
        return _fail(check, exc.code, exc.message)
    if subject_id and attestation["subject"]["subject_id"] != subject_id:
        return _fail(check, "subject_mismatch", "attestation is about a different subject")
    check.level, check.status, check.valid = res.level, res.status, True
    check.test_only, check.expires_at = attestation["test_only"], attestation["expires_at"]
    check.warnings = list(res.warnings)
    return check
