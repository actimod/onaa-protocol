from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, aware, normalise_url
from ..models import ApiKey, Listing, Operator, utcnow
from ..security import current_operator, issue_api_key, write_limit

router = APIRouter(prefix="/v1/operators", tags=["operators"])


def _out(op: Operator) -> schemas.OperatorOut:
    return schemas.OperatorOut(id=op.id, display_name=op.display_name, operator_type=op.operator_type,
                               country=op.country, website_url=op.website_url, status=op.status,
                               identity_verified=op.identity_verified, created_at=aware(op.created_at))


@router.post("", status_code=201, response_model=schemas.OperatorCreated, dependencies=[Depends(write_limit)],
             summary="Create an operator account and receive an API key (shown once)")
def create_operator(body: schemas.OperatorCreate, request: Request, session: Session = Depends(get_session)):
    settings = request.app.state.settings
    if body.accept_terms_version != settings.terms_version:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"accept_terms_version must equal current terms version '{settings.terms_version}'")
    op = Operator(display_name=body.display_name, operator_type=body.operator_type, country=body.country,
                  website_url=normalise_url(body.website_url, "website_url"), terms_version=body.accept_terms_version)
    plaintext, digest, prefix = issue_api_key()
    op.keys.append(ApiKey(key_hash=digest, prefix=prefix))
    session.add(op)
    session.flush()
    audit(session, "anonymous", None, "operator.create", op.id)
    return schemas.OperatorCreated(operator=_out(op), api_key=plaintext)


@router.get("/me", response_model=schemas.OperatorOut)
def me(op: Operator = Depends(current_operator)):
    return _out(op)


@router.patch("/me", response_model=schemas.OperatorOut, dependencies=[Depends(write_limit)],
              summary="Update the operator profile (optional linkage of a self-registered agent to a person/org)")
def update_me(body: schemas.OperatorUpdate, op: Operator = Depends(current_operator),
              session: Session = Depends(get_session)):
    op = session.merge(op)
    data = body.model_dump(exclude_unset=True)
    if "website_url" in data:
        data["website_url"] = normalise_url(data["website_url"], "website_url")
    for field in ("display_name", "operator_type", "country", "website_url"):
        if field in data and (data[field] is not None or field in ("country", "website_url")):
            setattr(op, field, data[field])
    audit(session, "operator", op.id, "operator.update", op.id, fields=sorted(data))
    return _out(op)


@router.post("/me/keys/rotate", response_model=schemas.OperatorCreated, dependencies=[Depends(write_limit)],
             summary="Revoke all existing keys and issue a new one")
def rotate_key(op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
    op = session.merge(op)
    now = utcnow()
    for k in op.keys:
        if k.revoked_at is None:
            k.revoked_at = now
    plaintext, digest, prefix = issue_api_key()
    op.keys.append(ApiKey(key_hash=digest, prefix=prefix))
    audit(session, "operator", op.id, "operator.key_rotate", op.id)
    return schemas.OperatorCreated(operator=_out(op), api_key=plaintext)


@router.delete("/me", status_code=204, summary="Deactivate account; delists all owned listings")
def deactivate(op: Operator = Depends(current_operator), session: Session = Depends(get_session)):
    op = session.merge(op)
    op.status = "disabled"
    now = utcnow()
    for k in op.keys:
        k.revoked_at = k.revoked_at or now
    for listing in session.scalars(select(Listing).where(Listing.operator_id == op.id)):
        listing.lifecycle_status = "deleted"
        listing.status_reason = "operator_deactivated"
    audit(session, "operator", op.id, "operator.deactivate", op.id)
