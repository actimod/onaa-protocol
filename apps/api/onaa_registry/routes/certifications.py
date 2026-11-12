from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, aware, get_listing, normalise_url, require_owner
from ..models import Certification, CertificationApplication, Operator, utcnow
from ..security import current_operator, require_admin, write_limit
from ..verification import in_founding_cohort, is_currently_verified

router = APIRouter(tags=["certifications"])


def _out(a: CertificationApplication) -> schemas.CertificationApplicationOut:
    return schemas.CertificationApplicationOut(
        id=a.id, listing_id=a.listing_id, operator_id=a.operator_id, scheme=a.scheme,
        criteria_version=a.criteria_version, evidence_urls=a.evidence_urls or [], status=a.status,
        decision_reason=a.decision_reason, created_at=aware(a.created_at), decided_at=aware(a.decided_at))


@router.post("/v1/certifications/applications", status_code=201, response_model=schemas.CertificationApplicationOut,
             dependencies=[Depends(write_limit)], summary="Apply for certification (separate from free listing)")
def apply(body: schemas.CertificationApplicationCreate, op: Operator = Depends(current_operator),
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
    audit(session, "operator", op.id, "certification.apply", listing.id, application_id=app_.id, scheme=body.scheme)
    return _out(app_)


@router.get("/v1/certifications/{application_id}", response_model=schemas.CertificationApplicationOut)
def get_application(application_id: str, op: Operator = Depends(current_operator),
                    session: Session = Depends(get_session)):
    a = session.get(CertificationApplication, application_id)
    if a is None or a.operator_id != op.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    return _out(a)


@router.post("/v1/admin/certifications/{application_id}/decision", response_model=schemas.CertificationApplicationOut,
             tags=["admin"], summary="Record a reviewer decision (admin). Live issuance requires founder approval.")
def decide(application_id: str, body: schemas.CertificationDecision, admin: str = Depends(require_admin),
           session: Session = Depends(get_session)):
    a = session.get(CertificationApplication, application_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    if a.status != "submitted":
        raise HTTPException(status.HTTP_409_CONFLICT, f"application already {a.status}")
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
            session.add(Certification(listing_id=listing.id, application_id=a.id, scheme=a.scheme,
                                      criteria_version=a.criteria_version, issued_at=now, expires_at=expires))
            listing.lifecycle_status = "certified"
        listing.updated_at = now
        session.flush()
        session.refresh(listing)
    audit(session, "admin", None, "certification.decide", a.listing_id, application_id=a.id, decision=a.status)
    return _out(a)


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
