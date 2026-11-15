"""Policy Service API and incident history (docs/REGISTRY_STEWARD.md).

* `POST /v1/policy/requests` - the Registry Steward files every state change here (steward token).
* `GET  /v1/admin/policy/requests`, `POST /v1/admin/policy/requests/{id}/decision` - human decisions.
* `GET  /v1/incidents` - public operational incident history (health records, not sanctions).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import policy
from ..db import get_session
from ..models import Incident, PolicyRequest
from ..security import require_admin, require_steward

router = APIRouter(tags=["policy"])


class PolicyRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(max_length=40)
    subject_id: str | None = Field(default=None, max_length=40)
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str | None = Field(default=None, max_length=1000)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=500)


@router.post("/v1/policy/requests", status_code=201, summary="File a steward change request (policy decides)")
def file_request(body: PolicyRequestIn, request: Request, actor: str = Depends(require_steward),
                 session: Session = Depends(get_session)):
    req = policy.submit(session, request.app.state.settings, actor=actor, action=body.action,
                        subject_id=body.subject_id, params=body.params, rationale=body.rationale)
    return policy.request_out(req)


@router.get("/v1/policy/rules", summary="What the steward may do alone, what needs approval")
def rules():
    return {"rules": policy.ACTION_RULES,
            "note": "auto = applied and audited at once; approval = stored until a human decides; "
                    "anything else is denied"}


@router.get("/v1/admin/policy/requests", tags=["admin"])
def list_requests(decision: str | None = Query(default="pending_approval", max_length=20),
                  limit: int = Query(default=50, ge=1, le=200), admin: str = Depends(require_admin),
                  session: Session = Depends(get_session)):
    q = select(PolicyRequest).order_by(PolicyRequest.created_at.desc()).limit(limit)
    if decision:
        q = q.where(PolicyRequest.decision == decision)
    return {"items": [policy.request_out(r) for r in session.scalars(q)]}


@router.post("/v1/admin/policy/requests/{request_id}/decision", tags=["admin"])
def decide(request_id: str, body: DecisionIn, admin: str = Depends(require_admin),
           session: Session = Depends(get_session)):
    req = session.get(PolicyRequest, request_id)
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy request not found")
    return policy.request_out(policy.decide(session, req, approve=body.decision == "approve", reason=body.reason))


@router.get("/v1/incidents", tags=["trust"], summary="Operational incident history (health records, not sanctions)")
def incidents(listing_id: str | None = Query(default=None, max_length=40),
              state: Literal["open", "resolved"] | None = None,
              limit: int = Query(default=50, ge=1, le=200), session: Session = Depends(get_session)):
    q = select(Incident).order_by(Incident.opened_at.desc()).limit(limit)
    if listing_id:
        q = q.where(Incident.listing_id == listing_id)
    if state:
        q = q.where(Incident.state == state)
    return {"items": [policy.incident_out(i) for i in session.scalars(q)]}
