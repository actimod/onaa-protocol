"""Schema evolution driven by agents: usage statistics, proposals, support and promotion.

Agents can already carry new information in namespaced `extensions` without asking anyone. This router
shows what the network actually uses and lets agents propose promoting a field or token to the core
vocabulary. Promotion is a maintainer decision (admin), informed by support from distinct identities and
observed usage, and lands in a later registry_record_version with a migration note.
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated, get_args

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import REGISTRY_RECORD_VERSION, schemas
from ..db import get_session
from ..logic import PUBLIC_STATUSES, audit, aware
from ..models import Listing, ListingFacet, Operator, VocabularyProposal, utcnow
from ..security import current_operator, require_admin, write_limit

router = APIRouter(tags=["vocabulary"])

FACET_FOR_KIND = {"capability": "capability", "category": "category", "protocol": "protocol",
                  "skill_tag": "skill", "compliance": "compliance"}
RECOMMENDED_PROTOCOL_TOKENS = ["a2a-1.0", "a2a-0.3", "onaa-0.1", "mcp-2026-07-28", "mcp-2025-11-25", "openapi-3.1"]
PROMOTION_POLICY = (
    "Use namespaced `extensions` (com.example/field or x-name/field) for anything new; no approval needed. "
    "Propose promotion with POST /v1/vocabulary/proposals; other agents add support with "
    "POST /v1/vocabulary/proposals/{id}/support. Maintainers review proposals with support from at least "
    f"{5} distinct identities or use by at least {10} public listings. Accepted fields join the core schema "
    "in the next registry_record_version; the old extension key keeps working for one version."
)


def _extension_key_counts(session: Session, limit_rows: int = 5000) -> Counter:
    counts: Counter = Counter()
    for ext in session.scalars(select(Listing.extensions).where(
            Listing.extensions.is_not(None), Listing.lifecycle_status.in_(PUBLIC_STATUSES)).limit(limit_rows)):
        if isinstance(ext, dict):
            counts.update(ext.keys())
    return counts


def _usage(session: Session, kind: str, name: str, ext_counts: Counter | None = None) -> int:
    facet = FACET_FOR_KIND.get(kind)
    if facet:
        return session.scalar(
            select(func.count(func.distinct(ListingFacet.listing_id)))
            .join(Listing, Listing.id == ListingFacet.listing_id)
            .where(ListingFacet.kind == facet, ListingFacet.value == name,
                   Listing.lifecycle_status.in_(PUBLIC_STATUSES))) or 0
    if kind == "field":
        counts = ext_counts if ext_counts is not None else _extension_key_counts(session)
        return sum(c for k, c in counts.items() if k == name or k.split("/", 1)[-1] == name)
    return 0


def _out(session: Session, p: VocabularyProposal, ext_counts: Counter | None = None) -> schemas.VocabularyProposalOut:
    return schemas.VocabularyProposalOut(
        id=p.id, kind=p.kind, name=p.name, description=p.description, example=p.example, status=p.status,
        support_count=len(p.supporters or []), usage_count=_usage(session, p.kind, p.name, ext_counts),
        decision_reason=p.decision_reason, created_at=aware(p.created_at), decided_at=aware(p.decided_at))


@router.get("/v1/vocabulary", summary="Vocabulary in use: canonical values, top tokens, extension keys, proposals")
def vocabulary(top: Annotated[int, Query(ge=1, le=200)] = 50, session: Session = Depends(get_session)):
    used: dict[str, list[dict]] = {}
    for facet in ("capability", "category", "protocol", "skill", "language", "region", "currency", "compliance",
                  "classification", "accepts", "pricing_model", "payment_terms", "payment_method",
                  "payment_network", "op_country", "residency"):
        rows = session.execute(
            select(ListingFacet.value, func.count(func.distinct(ListingFacet.listing_id)).label("n"))
            .join(Listing, Listing.id == ListingFacet.listing_id)
            .where(ListingFacet.kind == facet, Listing.lifecycle_status.in_(PUBLIC_STATUSES))
            .group_by(ListingFacet.value).order_by(func.count(func.distinct(ListingFacet.listing_id)).desc(),
                                                   ListingFacet.value).limit(top)).all()
        used[facet] = [{"value": v, "listings": n} for v, n in rows]
    ext = _extension_key_counts(session)
    open_props = session.scalars(select(VocabularyProposal).where(VocabularyProposal.status == "open")
                                 .order_by(VocabularyProposal.created_at.desc()).limit(top)).all()
    return {
        "registry_record_version": REGISTRY_RECORD_VERSION,
        "canonical": {
            "roles": list(get_args(schemas.Role)),
            "service_types": list(get_args(schemas.ServiceType)),
            "pricing_models": list(get_args(schemas.Pricing.model_fields["model"].annotation)),
            "payment_methods": list(get_args(schemas.PaymentMethodLit)),
            "recommended_protocol_tokens": RECOMMENDED_PROTOCOL_TOKENS,
            "classification_schemes": list(get_args(schemas.Classification.model_fields["scheme"].annotation)),
            "profile_blocks": list(schemas.PROFILE_BLOCKS),
        },
        "in_use": used,
        "extension_keys": [{"key": k, "listings": n} for k, n in ext.most_common(top)],
        "open_proposals": [_out(session, p, ext).model_dump(mode="json") for p in open_props],
        "promotion_policy": PROMOTION_POLICY,
    }


@router.post("/v1/vocabulary/proposals", status_code=201, response_model=schemas.VocabularyProposalOut,
             dependencies=[Depends(write_limit)], summary="Propose a new core field or vocabulary token")
def propose(body: schemas.VocabularyProposalCreate, op: Operator = Depends(current_operator),
            session: Session = Depends(get_session)):
    existing = session.scalar(select(VocabularyProposal).where(VocabularyProposal.kind == body.kind,
                                                               VocabularyProposal.name == body.name))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"already proposed as {existing.id}; add support via "
                            f"POST /v1/vocabulary/proposals/{existing.id}/support")
    open_by_op = session.scalar(select(func.count()).select_from(VocabularyProposal).where(
        VocabularyProposal.proposer_operator_id == op.id, VocabularyProposal.status == "open"))
    if open_by_op >= 10:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "at most 10 open proposals per identity")
    p = VocabularyProposal(kind=body.kind, name=body.name, description=body.description, example=body.example,
                           proposer_operator_id=op.id, supporters=[op.id])
    session.add(p)
    session.flush()
    audit(session, "operator", op.id, "vocabulary.propose", p.id, kind=body.kind, name=body.name)
    return _out(session, p)


@router.get("/v1/vocabulary/proposals", response_model=list[schemas.VocabularyProposalOut])
def list_proposals(status_: Annotated[str | None, Query(alias="status")] = None,
                   kind: Annotated[str | None, Query()] = None,
                   limit: Annotated[int, Query(ge=1, le=200)] = 50, session: Session = Depends(get_session)):
    stmt = select(VocabularyProposal)
    if status_:
        stmt = stmt.where(VocabularyProposal.status == status_)
    if kind:
        stmt = stmt.where(VocabularyProposal.kind == kind)
    ext = _extension_key_counts(session)
    return [_out(session, p, ext) for p in session.scalars(
        stmt.order_by(VocabularyProposal.created_at.desc()).limit(limit))]


@router.post("/v1/vocabulary/proposals/{proposal_id}/support", response_model=schemas.VocabularyProposalOut,
             dependencies=[Depends(write_limit)], summary="Support a proposal (once per identity)")
def support(proposal_id: str, op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
    p = session.get(VocabularyProposal, proposal_id[:40])
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    if p.status != "open":
        raise HTTPException(status.HTTP_409_CONFLICT, f"proposal is {p.status}")
    if op.id not in (p.supporters or []):
        p.supporters = sorted(set(p.supporters or []) | {op.id})
        audit(session, "operator", op.id, "vocabulary.support", p.id)
    return _out(session, p)


@router.post("/v1/admin/vocabulary/proposals/{proposal_id}/decision", response_model=schemas.VocabularyProposalOut,
             tags=["admin"])
def decide(proposal_id: str, body: schemas.VocabularyDecision, admin: str = Depends(require_admin),
           session: Session = Depends(get_session)):
    p = session.get(VocabularyProposal, proposal_id[:40])
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    p.status = "accepted" if body.decision == "accept" else "declined"
    p.decision_reason, p.decided_at = body.reason, utcnow()
    audit(session, "admin", None, "vocabulary.decision", p.id, decision=p.status)
    return _out(session, p)
