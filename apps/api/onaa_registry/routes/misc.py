"""Health, discovery metadata, abuse reports and admin-only discovery import."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import REGISTRY_RECORD_VERSION, __version__, schemas
from ..db import get_session
from ..logic import (
    audit,
    aware,
    ensure_not_taken,
    get_listing,
    host_of,
    make_listing_id,
    normalise_url,
    set_facets,
    to_record,
)
from ..models import AbuseReport, Listing, Operator, utcnow
from ..security import optional_operator, require_admin, write_limit

router = APIRouter()


@router.get("/v1/health", tags=["meta"])
def health(session: Session = Depends(get_session)):
    session.execute(select(1))  # fails loudly if the schema/DB is unavailable
    return {"status": "ok", "version": __version__}


@router.get("/v1/specs", tags=["meta"])
def specs(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    return {
        "registry_record_version": REGISTRY_RECORD_VERSION,
        "openapi": f"{base}/openapi.json",
        "registry_record_schema": f"{base}/v1/specs/registry-record.schema.json",
        "agent_card_note": "ONAA links to operator-published A2A Agent Cards; registry records are not Agent Cards.",
    }


@router.get("/.well-known/onaa-registry.json", tags=["meta"],
            summary="ONAA's own discovery metadata (project convention, NOT an A2A standard document)")
def well_known(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    return {
        "name": "ONAA Registry (Open Network for AI Agents)",
        "registry_record_version": REGISTRY_RECORD_VERSION,
        "api_base": f"{base}/v1",
        "openapi": f"{base}/openapi.json",
        "search": {"agents": f"{base}/v1/agents", "services": f"{base}/v1/services"},
        "trust_levels": ["discovered", "registered", "endpoint_verified", "operator_verified", "certified"],
        "transactions": "Not relayed. Buyers, sellers and providers transact directly over their own endpoints.",
        "status": "development - not a production service",
    }


@router.post("/v1/reports", status_code=201, response_model=schemas.ReportOut, tags=["trust"],
             dependencies=[Depends(write_limit)], summary="Report abuse, impersonation or a broken listing")
def report(body: schemas.ReportCreate, op: Operator | None = Depends(optional_operator),
           session: Session = Depends(get_session)):
    get_listing(session, body.subject_id, include_hidden=True)
    r = AbuseReport(subject_id=body.subject_id, category=body.category, description=body.description,
                    evidence_urls=[normalise_url(u, "evidence_urls") for u in body.evidence_urls],
                    reporter_operator_id=op.id if op else None)
    session.add(r)
    session.flush()
    audit(session, "operator" if op else "anonymous", op.id if op else None, "report.create", body.subject_id,
          report_id=r.id, category=body.category)
    return schemas.ReportOut(id=r.id, subject_id=r.subject_id, category=r.category, state=r.state,
                             created_at=aware(r.created_at))


@router.post("/v1/admin/discovered", status_code=201, response_model=schemas.RegistryRecord, tags=["admin"],
             summary="Import a publicly observed, unclaimed agent (discovery pipeline)")
def import_discovered(body: schemas.DiscoveredCreate, admin: str = Depends(require_admin),
                      session: Session = Depends(get_session)):
    card_url = normalise_url(body.agent_card_url, "agent_card_url")
    ensure_not_taken(session, host_of(card_url), None)
    dup = session.scalar(select(Listing.id).where(Listing.agent_card_url == card_url,
                                                  Listing.lifecycle_status != "deleted"))
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, f"already listed as {dup}")
    now = utcnow()
    listing = Listing(id=make_listing_id("agent"), operator_id=None, listing_type="agent",
                      display_name=body.display_name, agent_card_url=card_url, endpoint_host=host_of(card_url),
                      lifecycle_status="discovered", source_url=normalise_url(body.source_url, "source_url"),
                      discovered_at=now, supported_interfaces=[], regulatory_claims=[])
    set_facets(listing, body.model_dump())
    session.add(listing)
    session.flush()
    audit(session, "admin", None, "discovered.import", listing.id)
    return to_record(listing)


@router.post("/v1/admin/listings/{listing_id}/suspend", response_model=schemas.RegistryRecord, tags=["admin"])
def suspend(listing_id: str, reason: str = "policy", admin: str = Depends(require_admin),
            session: Session = Depends(get_session)):
    listing = get_listing(session, listing_id)
    listing.lifecycle_status = "suspended"
    listing.status_reason = reason[:200]
    listing.updated_at = utcnow()
    audit(session, "admin", None, "listing.suspend", listing.id, reason=reason[:200])
    return to_record(listing)


@router.post("/v1/admin/jobs/expire-verifications", tags=["admin"],
             summary="Clear lapsed endpoint-control proofs now (also runs lazily every minute)")
def run_expiry(admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    from ..verification import expire_verifications

    ids = expire_verifications(session)
    audit(session, "admin", None, "job.expire_verifications", None, count=len(ids))
    return {"expired": ids}


@router.post("/v1/admin/jobs/health-checks", tags=["admin"],
             summary="Probe up to `limit` listings, least recently checked first (cron target)")
def run_health(request: Request, limit: int = 100, admin: str = Depends(require_admin),
               session: Session = Depends(get_session)):
    from ..health import run_health_checks

    results = run_health_checks(session, request.app.state.fetcher, max(1, min(limit, 500)))
    audit(session, "admin", None, "job.health_checks", None, count=len(results))
    return {"checked": results}
