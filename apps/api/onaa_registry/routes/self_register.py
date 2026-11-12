"""Agent self-registration: an AI agent registers itself with no human signup step.

Flow:
1. POST /v1/self-register with the listing payload and accepted terms version. Nothing is listed yet; the
   registry returns a challenge token and a private registration secret.
2. The agent publishes the token on its own endpoint host (well-known file or DNS TXT).
3. POST /v1/self-register/{id}/complete with the secret. On a valid proof the registry creates an agent
   identity (operator_type "agent"), an agent-scoped API key (shown once) and the listing.

The proof is an anti-abuse gate for keyless signup. It is NOT the paid Endpoint Verified tier: the listing starts
as `registered` with `endpoint_control_verified=false`, and trust.registration_method says how it joined.
"""

from __future__ import annotations

import datetime as dt
import hmac
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, aware, to_record
from ..models import ApiKey, Listing, Operator, SelfRegistration, new_id, utcnow
from ..security import client_ip, issue_api_key, sha256_hex, write_limit
from ..verification import CHALLENGE_PATH, check_host_proof, dns_record_name
from .listings import MAX_CHALLENGE_ATTEMPTS, build_agent_listing, build_service_listing
from .operators import _out as operator_out

router = APIRouter(prefix="/v1/self-register", tags=["self-registration"])


def _enabled(request: Request) -> None:
    if not request.app.state.settings.self_registration_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent self-registration is disabled on this registry")


def _build(session: Session, kind: str, payload: dict, operator_id: str | None) -> Listing:
    if kind == "agent":
        return build_agent_listing(session, schemas.AgentCreate(**payload), operator_id, "agent_self_registration")
    return build_service_listing(session, schemas.ServiceCreate(**payload), operator_id, "agent_self_registration")


def _check_agents_per_host(session: Session, host: str, limit: int) -> None:
    if limit <= 0:
        return
    count = session.scalar(
        select(func.count(func.distinct(Listing.operator_id))).join(Operator, Operator.id == Listing.operator_id)
        .where(Listing.endpoint_host == host, Operator.operator_type == "agent", Operator.status == "active",
               Listing.lifecycle_status != "deleted"))
    if count >= limit:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"host {host} already has {count} self-registered agent identities. Use an existing "
                            "agent key (POST /v1/operators/me/keys/rotate) or report a problem via POST /v1/reports.")


@router.post("", status_code=201, response_model=schemas.SelfRegistrationChallenge,
             dependencies=[Depends(_enabled), Depends(write_limit)],
             summary="Agent self-registration, step 1: submit the listing and receive an endpoint-control challenge")
def start(body: schemas.SelfRegistrationStart, request: Request, session: Session = Depends(get_session)):
    settings = request.app.state.settings
    request.app.state.self_register_limiter.check(f"sr:{client_ip(request)}")
    if body.accept_terms_version != settings.terms_version:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"accept_terms_version must equal current terms version '{settings.terms_version}'")
    if (body.agent is None) == (body.service is None):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "provide exactly one of 'agent' or 'service'")
    kind = "agent" if body.agent is not None else "service"
    payload = (body.agent or body.service).model_dump(mode="json")
    # Full validation now (URLs, same-host rules, host not owned by a verified operator); nothing is stored.
    draft = _build(session, kind, payload, None)
    host = draft.endpoint_host
    _check_agents_per_host(session, host, settings.self_registration_agents_per_host)
    now = utcnow()
    pending = session.scalar(select(func.count()).select_from(SelfRegistration).where(
        SelfRegistration.host == host, SelfRegistration.status == "pending", SelfRegistration.expires_at > now))
    if settings.self_registration_pending_per_host > 0 and pending >= settings.self_registration_pending_per_host:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"too many pending self-registrations for {host}; complete one or wait for expiry",
                            headers={"Retry-After": "600"})
    token = "onaa-verify-" + secrets.token_urlsafe(32)
    secret = "onaa_srs_" + secrets.token_urlsafe(32)
    sr = SelfRegistration(id=new_id("sreg"), kind=kind, payload=payload, host=host, method=body.method,
                          nonce_hash=sha256_hex(token), secret_hash=sha256_hex(secret),
                          terms_version=body.accept_terms_version,
                          expires_at=now + dt.timedelta(seconds=settings.self_registration_ttl_seconds))
    session.add(sr)
    session.flush()
    audit(session, "anonymous", None, "self_register.start", sr.id, kind=kind, host=host, method=body.method)
    base = settings.public_base_url.rstrip("/")
    complete_url = f"{base}/v1/self-register/{sr.id}/complete"
    finish = (f"then POST {complete_url} with JSON {{\"registration_secret\": \"...\"}}. You receive an "
              "agent-scoped API key once. Proof here only gates signup; it is not the Endpoint Verified tier.")
    common = dict(registration_id=sr.id, method=body.method, host=host, token=token, registration_secret=secret,
                  expires_at=aware(sr.expires_at), complete_url=complete_url)
    if body.method == "dns_txt":
        name = dns_record_name(host)
        return schemas.SelfRegistrationChallenge(
            **common, dns_record_name=name,
            instructions=f"Publish a DNS TXT record at {name} whose value is exactly the token, " + finish)
    url = f"https://{host}" + CHALLENGE_PATH.format(cid=sr.id)
    return schemas.SelfRegistrationChallenge(
        **common, challenge_url=url,
        instructions=f"Serve the token as the exact text body (HTTP 200, no redirect) at {url}, " + finish)


@router.post("/{registration_id}/complete", status_code=201, response_model=schemas.SelfRegistrationCompleted,
             dependencies=[Depends(_enabled), Depends(write_limit)],
             responses={422: {"model": schemas.SelfRegistrationFailed}},
             summary="Agent self-registration, step 2: prove endpoint control and receive an agent API key")
def complete(registration_id: str, body: schemas.SelfRegistrationComplete, request: Request,
             session: Session = Depends(get_session)):
    settings = request.app.state.settings
    sr = session.get(SelfRegistration, registration_id[:40])
    if sr is None or not hmac.compare_digest(sha256_hex(body.registration_secret), sr.secret_hash):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "self-registration not found")
    if sr.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"self-registration is {sr.status}; start a new one")
    if aware(sr.expires_at) <= utcnow():
        sr.status = "expired"
        session.commit()
        raise HTTPException(status.HTTP_410_GONE, "self-registration expired; start a new one")

    sr.attempts += 1
    error = check_host_proof(request.app.state.fetcher, request.app.state.txt_resolver, host=sr.host,
                             method=sr.method, challenge_id=sr.id, nonce_hash=sr.nonce_hash)
    if error:
        sr.last_error = error
        if sr.attempts >= MAX_CHALLENGE_ATTEMPTS:
            sr.status = "failed"
        audit(session, "anonymous", None, "self_register.complete", sr.id, result="failed", error=error)
        session.commit()
        out = schemas.SelfRegistrationFailed(registration_id=sr.id, status=sr.status, attempts=sr.attempts,
                                             error=error)
        return JSONResponse(status_code=422, content=out.model_dump(mode="json"))

    # Re-check policy at completion time: the host may have been verified or filled up meanwhile.
    _check_agents_per_host(session, sr.host, settings.self_registration_agents_per_host)
    now = utcnow()
    op = Operator(id=new_id("op"), display_name=sr.payload["display_name"], operator_type="agent",
                  terms_version=sr.terms_version)
    listing = _build(session, sr.kind, sr.payload, op.id)
    if listing.endpoint_host != sr.host:
        sr.status = "failed"
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "listing host changed since the challenge was issued")
    plaintext, digest, prefix = issue_api_key()
    op.keys.append(ApiKey(key_hash=digest, prefix=prefix))
    session.add(op)
    session.flush()  # operator row first: listings.operator_id has an FK but no ORM relationship
    session.add(listing)
    # A discovered (unclaimed) copy is retired in favour of the self-registered listing: the same Agent Card, or a
    # discovered provider of the same service type on the proven host.
    same = [Listing.agent_card_url == listing.agent_card_url] if listing.agent_card_url else []
    if listing.service_type:
        same.append(and_(Listing.endpoint_host == listing.endpoint_host,
                         Listing.service_type == listing.service_type))
    if same:
        for dup in session.scalars(select(Listing).where(
                or_(*same), Listing.operator_id.is_(None), Listing.lifecycle_status == "discovered")):
            dup.lifecycle_status = "deleted"
            dup.status_reason = f"claimed_via_self_registration:{listing.id}"
            dup.updated_at = now
            audit(session, "system", None, "listing.claimed_via_self_registration", dup.id, by=listing.id)
    sr.status, sr.completed_at, sr.operator_id, sr.listing_id = "completed", now, op.id, listing.id
    session.flush()
    audit(session, "agent", op.id, "self_register.complete", sr.id, listing_id=listing.id, operator_id=op.id)
    base = settings.public_base_url.rstrip("/")
    kind_path = "agents" if sr.kind == "agent" else "services"
    return schemas.SelfRegistrationCompleted(
        registration_id=sr.id, status="completed", operator=operator_out(op), api_key=plaintext,
        listing=to_record(listing, op),
        next_steps=[
            "Store api_key in a secret manager; it is shown once. Send it as 'Authorization: Bearer <key>'.",
            f"Remove the challenge token from {sr.host}; it is single-use.",
            f"Update your listing: PATCH {base}/v1/{kind_path}/{listing.id}",
            f"Optional: link a person or organisation later with PATCH {base}/v1/operators/me "
            "(needed before paid operator verification).",
            "Optional paid tier: Endpoint Verified via POST /v1/certifications/applications (Founding Cohort free).",
        ])
