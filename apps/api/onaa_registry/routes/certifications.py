from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import monitoring, schemas, trust_ops
from ..db import get_session
from ..logic import audit, aware, get_listing, normalise_url, require_owner
from ..models import Certification, CertificationApplication, Operator, VerificationRun, utcnow
from ..security import current_operator, require_admin, write_limit
from ..verification import in_founding_cohort, is_currently_verified

router = APIRouter(tags=["certifications"])


def run_out(r: VerificationRun | None) -> schemas.VerificationRunOut | None:
    if r is None:
        return None
    return schemas.VerificationRunOut(id=r.id, listing_id=r.listing_id, kind=r.kind, vantage=r.vantage, role=r.role,
                                      verdict=r.verdict, summary=r.summary or {}, report_sha256=r.report_sha256,
                                      created_at=aware(r.created_at))


def _out(a: CertificationApplication, session: Session | None = None) -> schemas.CertificationApplicationOut:
    run = session.get(VerificationRun, a.conformance_run_id) if session is not None and a.conformance_run_id \
        else None
    return schemas.CertificationApplicationOut(
        id=a.id, listing_id=a.listing_id, operator_id=a.operator_id, scheme=a.scheme,
        criteria_version=a.criteria_version, evidence_urls=a.evidence_urls or [], status=a.status,
        decision_reason=a.decision_reason, created_at=aware(a.created_at), decided_at=aware(a.decided_at),
        conformance_run=run_out(run))


@router.post("/v1/certifications/precheck", status_code=201, response_model=schemas.VerificationRunOut,
             dependencies=[Depends(write_limit)],
             summary="Free automated conformance pre-check of your endpoint-verified listing (CERT-009)")
def precheck(body: schemas.PrecheckCreate, request: Request, op: Operator = Depends(current_operator),
             session: Session = Depends(get_session)):
    listing = get_listing(session, body.listing_id)
    require_owner(listing, op)
    if not is_currently_verified(listing):
        # Only hosts whose control was proven can be probed, so the registry cannot be aimed at third parties.
        raise HTTPException(status.HTTP_409_CONFLICT, "complete endpoint verification before a pre-check")
    settings = request.app.state.settings
    last = monitoring.last_precheck_at(session, listing.id)
    if last and (utcnow() - last).total_seconds() < settings.precheck_min_interval_seconds:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "a pre-check for this listing ran recently; retry later")
    run = monitoring.run_conformance(session, settings, request.app.state.conformance_runner, listing,
                                     kind="precheck", scheme=body.scheme)
    return run_out(run)


@router.post("/v1/certifications/applications", status_code=201, response_model=schemas.CertificationApplicationOut,
             dependencies=[Depends(write_limit)], summary="Apply for certification (separate from free listing)")
def apply(body: schemas.CertificationApplicationCreate, request: Request, op: Operator = Depends(current_operator),
          session: Session = Depends(get_session)):
    listing = get_listing(session, body.listing_id)
    require_owner(listing, op, allow_claim_pending=body.scheme == "endpoint_verified")
    if body.scheme not in ("operator_verified", "endpoint_verified") and not is_currently_verified(listing):
        raise HTTPException(status.HTTP_409_CONFLICT, "complete endpoint verification before applying")
    app_ = CertificationApplication(
        listing_id=listing.id, operator_id=op.id, scheme=body.scheme,
        evidence_urls=[normalise_url(u, "evidence_urls") for u in body.evidence_urls], notes=body.notes)
    session.add(app_)
    session.flush()
    if body.scheme in monitoring.SCHEMES_NEEDING_CONFORMANCE:
        # Automated pre-check filed as evidence; it never decides the application by itself.
        run = monitoring.run_conformance(session, request.app.state.settings, request.app.state.conformance_runner,
                                         listing, kind="application", scheme=body.scheme, application_id=app_.id)
        app_.conformance_run_id = run.id
    audit(session, "operator", op.id, "certification.apply", listing.id, application_id=app_.id, scheme=body.scheme)
    return _out(app_, session)


@router.get("/v1/certifications/{application_id}", response_model=schemas.CertificationApplicationOut)
def get_application(application_id: str, op: Operator = Depends(current_operator),
                    session: Session = Depends(get_session)):
    a = session.get(CertificationApplication, application_id)
    if a is None or a.operator_id != op.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    return _out(a, session)


@router.post("/v1/admin/certifications/{application_id}/decision", response_model=schemas.CertificationApplicationOut,
             tags=["admin"], summary="Record a reviewer decision (admin). Live issuance requires founder approval.")
def decide(application_id: str, body: schemas.CertificationDecision, request: Request,
           admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    a = session.get(CertificationApplication, application_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    if a.status != "submitted":
        raise HTTPException(status.HTTP_409_CONFLICT, f"application already {a.status}")
    settings = request.app.state.settings
    run = None
    if body.decision == "approve" and a.scheme in monitoring.SCHEMES_NEEDING_CONFORMANCE:
        if not body.reviewer:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "reviewer is required: certification approval needs a human approval record")
        run = monitoring.latest_passing_run(session, a.listing_id, settings.conformance_max_age_days)
        if run is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "no passing conformance run in the last "
                                f"{settings.conformance_max_age_days} days; ask the operator to run a pre-check")
    now = utcnow()
    a.status = "approved" if body.decision == "approve" else "rejected"
    a.decision_reason, a.decided_at = body.reason, now
    if a.status == "approved":
        listing = get_listing(session, a.listing_id)
        blocked = listing.lifecycle_status in ("suspended", "discovered") or (
            listing.lifecycle_status == "claim_pending" and a.scheme != "endpoint_verified")
        if blocked or listing.operator_id != a.operator_id:
            raise HTTPException(status.HTTP_409_CONFLICT, f"listing is {listing.lifecycle_status}; cannot approve")
        expires = now + dt.timedelta(days=body.valid_days)
        if a.scheme == "endpoint_verified":
            # Grants the right to run the (automated) endpoint challenge; it is not itself a verification.
            listing.verification_entitled_until = expires
        elif a.scheme == "operator_verified":
            # Identity is an operator attribute with its own expiry, not a listing certification.
            op = session.get(Operator, a.operator_id)
            op.identity_verified_until = expires
        else:
            if not is_currently_verified(listing):
                raise HTTPException(status.HTTP_409_CONFLICT, "listing is no longer endpoint-verified")
            # Baselines for change detection come from a fresh observation at issuance time.
            monitoring.observe(listing, request.app.state.fetcher)
            cert = Certification(listing_id=listing.id, application_id=a.id, scheme=a.scheme,
                                 criteria_version=a.criteria_version, issued_at=now, expires_at=expires,
                                 status_changed_at=now, conformance_run_id=run.id if run else None,
                                 baseline_card_hash=listing.card_hash, baseline_jwks_hash=listing.jwks_hash,
                                 approval=trust_ops.approval_record(body.reviewer or admin, a.id, a.criteria_version,
                                                                    now, body.reason))
            session.add(cert)
            session.flush()
            cfg = request.app.state.trust
            att = trust_ops.issue_attestation(cfg, cert, listing, conformance=monitoring.conformance_scope(run),
                                              report_sha256=run.report_sha256 if run else None, now=now)
            if att is not None:  # leave SQL NULL (not JSON null) when nothing was signed
                cert.attestation = att
            trust_ops.append_log(session, cert, "issue", at=now)
            trust_ops.current_status_record(session, cfg, cert)
            monitoring.schedule_next(listing, settings)
            listing.lifecycle_status = "certified"
        listing.updated_at = now
        session.flush()
        session.refresh(listing)
    audit(session, "admin", None, "certification.decide", a.listing_id, application_id=a.id, decision=a.status,
          reviewer=body.reviewer)
    return _out(a, session)


@router.post("/v1/admin/certifications/issued/{cert_id}/status", tags=["admin"],
             summary="Suspend, revoke or reinstate an issued certification (logged and re-signed)")
def change_status(cert_id: str, body: schemas.CertificationStatusChange, request: Request,
                  admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    cert = session.get(Certification, cert_id)
    if cert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certification not found")
    if cert.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "revocation is final")
    if cert.status == body.status:
        raise HTTPException(status.HTTP_409_CONFLICT, f"certification already {cert.status}")
    if body.status == "active":
        listing = get_listing(session, cert.listing_id, include_hidden=True)
        if not is_currently_verified(listing):
            raise HTTPException(status.HTTP_409_CONFLICT, "listing is no longer endpoint-verified")
        # Reinstating accepts the currently observed card/JWKS as the new baseline.
        cert.baseline_card_hash, cert.baseline_jwks_hash = listing.card_hash, listing.jwks_hash
        listing.review_flags = sorted(set(listing.review_flags or []) - set(monitoring.CHANGE_FLAGS))
    trust_ops.set_cert_status(session, request.app.state.trust, cert, body.status, body.reason)
    audit(session, "admin", None, f"certification.{body.status}", cert.listing_id, cert_id=cert.id,
          reviewer=body.reviewer, reason=body.reason)
    return {"id": cert.id, "status": cert.status, "status_reason": cert.status_reason}


@router.get("/v1/admin/operators/{operator_id}/entitlements", response_model=schemas.EntitlementOut, tags=["admin"])
def get_entitlements(operator_id: str, request: Request, admin: str = Depends(require_admin),
                     session: Session = Depends(get_session)):
    return _entitlements(session, request, operator_id)


@router.post("/v1/admin/operators/{operator_id}/founding-cohort", response_model=schemas.EntitlementOut,
             tags=["admin"], summary="Grant or revoke Founding Cohort membership (cap: ONAA_FOUNDING_COHORT_SIZE)")
def founding_cohort(operator_id: str, body: schemas.FoundingCohortGrant, request: Request,
                    admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    op = session.get(Operator, operator_id)
    if op is None or op.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "operator not found")
    if body.grant:
        if not in_founding_cohort(op):
            # Cohort seats are counted as all operators ever admitted, so revocations don't reopen seats silently.
            used = session.scalar(select(func.count()).select_from(Operator).where(
                Operator.founding_cohort_until.is_not(None)))
            if used >= request.app.state.settings.founding_cohort_size:
                raise HTTPException(status.HTTP_409_CONFLICT, "Founding Cohort is full")
        op.founding_cohort_until = utcnow() + dt.timedelta(days=30 * body.months)
    else:
        op.founding_cohort_until = utcnow() if op.founding_cohort_until else None
    audit(session, "admin", None, "operator.founding_cohort", op.id, grant=body.grant)
    return _entitlements(session, request, operator_id)


def _entitlements(session: Session, request: Request, operator_id: str) -> schemas.EntitlementOut:
    op = session.get(Operator, operator_id)
    if op is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "operator not found")
    used = session.scalar(select(func.count()).select_from(Operator).where(Operator.founding_cohort_until.is_not(None)))
    return schemas.EntitlementOut(operator_id=op.id, founding_cohort_until=aware(op.founding_cohort_until),
                                  founding_cohort_active=in_founding_cohort(op), cohort_size_used=used or 0,
                                  cohort_size_limit=request.app.state.settings.founding_cohort_size)
