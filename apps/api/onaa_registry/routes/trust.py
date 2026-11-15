"""Public trust endpoints (CERT-010/011) and verification-operations admin jobs (CERT-009).

Everything public here is verifiable without trusting the registry: attestations, status records and log
checkpoints are signed with keys listed in the root-signed issuer manifest, and the Merkle proofs let anyone
check that an event is in the log and that the log only grew. All objects are TEST-ONLY (staging).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from onaa_protocol import transparency as tl
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import monitoring, schemas, trust_ops
from ..db import get_session
from ..logic import audit, get_listing
from ..models import Certification, TransparencyEntry, VerificationRun
from ..security import require_admin
from .certifications import run_out

router = APIRouter(tags=["trust"])
MAX_ENTRIES = 100


def _json(obj, max_age: int = 60) -> JSONResponse:
    return JSONResponse(obj, headers={"Cache-Control": f"public, max-age={max_age}"})


def _cert(session: Session, att_id: str) -> Certification:
    cert = session.get(Certification, att_id)
    if cert is None or cert.attestation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "attestation not found")
    return cert


@router.get(trust_ops.ISSUER_MANIFEST_PATH, summary="Root-signed issuer key manifest (pin the root key, not this URL)")
def issuer_manifest(request: Request):
    m = request.app.state.trust.manifest
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no issuer manifest configured on this registry")
    return _json(m, 300)


@router.get("/v1/attestations", summary="Attestations for a subject, any status (TEST-ONLY in staging)")
def list_attestations(subject_id: str = Query(max_length=40), session: Session = Depends(get_session)):
    certs = session.scalars(select(Certification).where(Certification.listing_id == subject_id,
                                                        Certification.attestation.is_not(None))
                            .order_by(Certification.issued_at.desc()).limit(20)).all()
    return {"subject_id": subject_id,
            "attestations": [{"id": c.id, "level": c.scheme, "status": trust_ops.effective_status(c),
                              "attestation_url": f"/v1/attestations/{c.id}",
                              "status_url": f"/v1/attestations/{c.id}/status"} for c in certs]}


@router.get("/v1/attestations/{att_id}", summary="Signed TEST-ONLY attestation")
def get_attestation(att_id: str, session: Session = Depends(get_session)):
    return _json(_cert(session, att_id).attestation, 300)


@router.get("/v1/attestations/{att_id}/status", summary="Signed status record (re-issued; max age 7 days)")
def get_status(att_id: str, request: Request, session: Session = Depends(get_session)):
    cert = _cert(session, att_id)
    rec = trust_ops.current_status_record(session, request.app.state.trust, cert)
    if rec is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no status signing key configured")
    return _json(rec, 300)


# ------------------------------------------------------------------ transparency log


@router.get("/v1/transparency/checkpoint", summary="Signed tree head of the attestation transparency log")
def get_checkpoint(request: Request, session: Session = Depends(get_session)):
    cp = trust_ops.checkpoint(session, request.app.state.trust)
    if cp is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no log signing key configured")
    return _json(cp, 10)


def _size(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(TransparencyEntry)) or 0


@router.get("/v1/transparency/entries", summary="Log entries by index range or by attestation id")
def get_entries(start: int = Query(default=0, ge=0), end: int | None = Query(default=None, ge=1),
                attestation_id: str | None = Query(default=None, max_length=40),
                session: Session = Depends(get_session)):
    q = select(TransparencyEntry).order_by(TransparencyEntry.idx)
    if attestation_id:
        q = q.where(TransparencyEntry.attestation_id == attestation_id)
    else:
        end = min(end if end is not None else start + MAX_ENTRIES, start + MAX_ENTRIES)
        q = q.where(TransparencyEntry.idx >= start, TransparencyEntry.idx < end)
    rows = session.scalars(q.limit(MAX_ENTRIES)).all()
    return {"tree_size": _size(session),
            "entries": [{"index": r.idx, "entry": r.entry, "leaf_hash": tl.b64(bytes.fromhex(r.leaf_hash))}
                        for r in rows]}


@router.get("/v1/transparency/proof/inclusion", summary="Merkle inclusion proof (RFC 9162 section 2.1.3)")
def inclusion(index: int = Query(ge=0), tree_size: int = Query(ge=1), session: Session = Depends(get_session)):
    if tree_size > _size(session) or index >= tree_size:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "index/tree_size out of range")
    hs = trust_ops.leaf_hashes(session, tree_size)
    return {"index": index, "tree_size": tree_size, "leaf_hash": tl.b64(hs[index]),
            "proof": [tl.b64(h) for h in tl.inclusion_proof(hs, index)]}


@router.get("/v1/transparency/proof/consistency", summary="Merkle consistency proof (RFC 9162 section 2.1.4)")
def consistency(first: int = Query(ge=1), second: int = Query(ge=1), session: Session = Depends(get_session)):
    if first > second or second > _size(session):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "tree sizes out of range")
    hs = trust_ops.leaf_hashes(session, second)
    return {"first": first, "second": second, "proof": [tl.b64(h) for h in tl.consistency_proof(hs, first)]}


# ------------------------------------------------------------------ admin jobs


@router.post("/v1/admin/jobs/verification-monitor", tags=["admin"],
             summary="Card/JWKS change detection, due unannounced re-checks, expiry and status re-issue")
def verification_monitor(request: Request, detect_limit: int = Query(default=100, ge=0, le=1000),
                         recheck_limit: int = Query(default=20, ge=0, le=200), admin: str = Depends(require_admin),
                         session: Session = Depends(get_session)):
    state = request.app.state
    expired = trust_ops.expire_due(session, state.trust)
    changes = monitoring.run_change_detection(session, state.fetcher, detect_limit) if detect_limit else {}
    rechecks = monitoring.run_due_rechecks(session, state.settings, state.trust, state.conformance_runner,
                                           state.fetcher, recheck_limit) if recheck_limit else {}
    reissued = trust_ops.reissue_status_records(session, state.trust)
    audit(session, "admin", None, "job.verification_monitor", None, expired=len(expired),
          changed=sum(bool(v) for v in changes.values()), rechecked=len(rechecks), reissued=reissued)
    return {"expired": expired, "changes": {k: v for k, v in changes.items() if v}, "rechecks": rechecks,
            "status_records_reissued": reissued}


@router.post("/v1/admin/verification/observations", status_code=201, tags=["admin"],
             summary="Record a card/JWKS observation from another vantage point (cloaking detection)")
def observation(body: schemas.VantageObservation, admin: str = Depends(require_admin),
                session: Session = Depends(get_session)):
    listing = get_listing(session, body.listing_id)
    run = monitoring.record_observation(session, listing, vantage=body.vantage, card_hash=body.card_sha256,
                                        jwks_hash=body.jwks_sha256)
    return {"id": run.id, "mismatch": run.summary.get("mismatch", [])}


@router.get("/v1/admin/listings/{listing_id}/verification-runs", tags=["admin"])
def list_runs(listing_id: str, admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    rows = session.scalars(select(VerificationRun).where(VerificationRun.listing_id == listing_id)
                           .order_by(VerificationRun.created_at.desc()).limit(50)).all()
    listing = get_listing(session, listing_id, include_hidden=True)
    return {"listing_id": listing_id, "review_flags": list(listing.review_flags or []),
            "runs": [run_out(r) for r in rows]}
