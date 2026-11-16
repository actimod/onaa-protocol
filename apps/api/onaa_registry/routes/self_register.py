"""Agent self-registration: an AI agent registers itself with no human signup step.

Flow:
1. POST /v1/self-register with the listing payload and accepted terms version. Nothing is listed yet; the
   registry returns a challenge token and a private registration secret.
2. The agent publishes the token on its own endpoint host (well-known file or DNS TXT).
   The agent acts FOR its operator (the person or organisation responsible for it): it must send
   confirm_operator_authority=true, and the operator is the party bound by the terms (GET /v1/terms).
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
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, aware, check_terms_acceptance, to_record
from ..models import ApiKey, KeyClaim, Listing, Operator, SelfRegistration, new_id, utcnow
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
    terms = check_terms_acceptance(settings, body.accept_terms_version, body.accept_terms_sha256)
    if (body.agent is None) == (body.service is None):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "provide exactly one of 'agent' or 'service'")
    kind = "agent" if body.agent is not None else "service"
    payload = (body.agent or body.service).model_dump(mode="json")
    # Full validation now (URLs, same-host rules, host not owned by a verified operator); nothing is stored.
    draft = _build(session, kind, payload, None)
    host = draft.endpoint_host
    _check_agents_per_host(session, host, settings.self_registration_agents_per_host)
    now = utcnow()
    # Cap pending challenges per host by evicting the oldest one instead of refusing. Refusing let anyone lock a
    # host out of self-registration for the challenge TTL with a few anonymous starts. The real owner completes
    # within seconds of starting, so eviction only costs a spammer's own pending rows.
    cap = settings.self_registration_pending_per_host
    if cap > 0:
        pending = list(session.scalars(select(SelfRegistration).where(
            SelfRegistration.host == host, SelfRegistration.status == "pending", SelfRegistration.expires_at > now)
            .order_by(SelfRegistration.created_at, SelfRegistration.id)))
        for old in pending[:max(0, len(pending) - cap + 1)]:
            old.status = "expired"
            old.last_error = "superseded_by_newer_start"
            audit(session, "anonymous", None, "self_register.superseded", old.id, host=host)
    token = "onaa-verify-" + secrets.token_urlsafe(32)
    secret = "onaa_srs_" + secrets.token_urlsafe(32)
    sr = SelfRegistration(id=new_id("sreg"), kind=kind, payload=payload, host=host, method=body.method,
                          nonce_hash=sha256_hex(token), secret_hash=sha256_hex(secret),
                          terms_version=terms.version, terms_sha256=terms.sha256,
                          operator_authority_confirmed=body.confirm_operator_authority is True,
                          operator_contact=body.operator_contact,
                          expires_at=now + dt.timedelta(seconds=settings.self_registration_ttl_seconds))
    session.add(sr)
    session.flush()
    audit(session, "anonymous", None, "self_register.start", sr.id, kind=kind, host=host, method=body.method,
          terms_version=terms.version, terms_sha256=terms.sha256, operator_authority_confirmed=True,
          operator_contact_given=body.operator_contact is not None)
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
                  terms_version=sr.terms_version, terms_sha256=sr.terms_sha256, terms_accepted_at=sr.created_at,
                  terms_acceptance_method="agent_on_behalf_of_operator", operator_contact=sr.operator_contact)
    listing = _build(session, sr.kind, sr.payload, op.id)
    if listing.endpoint_host != sr.host:
        sr.status = "failed"
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "listing host changed since the challenge was issued")
    plaintext = None
    if body.key_delivery == "inline":
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
    audit(session, "agent", op.id, "self_register.listing", listing.id, revision=listing.revision or 1)
    base = settings.public_base_url.rstrip("/")
    kind_path = "agents" if sr.kind == "agent" else "services"
    claim = _new_claim(session, op.id, base) if plaintext is None else None
    first = ("Store api_key in a secret manager; it is shown once. Send it as 'Authorization: Bearer <key>'."
             if claim is None else
             "Give key_claim_url to your operator (not in a public place): opening it once shows the API key. It "
             f"works once, until {claim.key_claim_expires_at}. A new link: POST {base}/v1/self-register/{sr.id}"
             "/claim-link with the registration_secret, while no key was collected yet.")
    return schemas.SelfRegistrationCompleted(
        registration_id=sr.id, status="completed", operator=operator_out(op), api_key=plaintext,
        key_claim_url=claim.key_claim_url if claim else None,
        key_claim_expires_at=claim.key_claim_expires_at if claim else None,
        listing=to_record(listing, op),
        next_steps=[
            first,
            f"Remove the challenge token from {sr.host}; it is single-use.",
            f"Update your listing: PATCH {base}/v1/{kind_path}/{listing.id}",
            "Tell your operator that it registered and accepted the ONAA terms "
            f"({sr.terms_version}, {base}/v1/terms) on its behalf, and how to delete the listing.",
            f"Recommended: name your operator (person or organisation) and a private notice contact with "
            f"PATCH {base}/v1/operators/me (operator name is needed before paid operator verification).",
            f"To withdraw: DELETE {base}/v1/{kind_path}/{listing.id} or DELETE {base}/v1/operators/me.",
            "Optional paid tier: Endpoint Verified via POST /v1/certifications/applications (Founding Cohort free).",
        ])


KEY_CLAIM_HOURS = 24


def _new_claim(session: Session, operator_id: str, base: str) -> schemas.ClaimLink:
    """A fresh one-time link; earlier unused links of this operator stop working."""
    now = utcnow()
    for old in session.scalars(select(KeyClaim).where(KeyClaim.operator_id == operator_id,
                                                      KeyClaim.used_at.is_(None))):
        old.expires_at = now
    code = "onaa-claim-" + secrets.token_urlsafe(32)
    claim = KeyClaim(operator_id=operator_id, code_hash=sha256_hex(code),
                     expires_at=now + dt.timedelta(hours=KEY_CLAIM_HOURS))
    session.add(claim)
    session.flush()
    audit(session, "agent", operator_id, "self_register.key_claim_link", claim.id)
    return schemas.ClaimLink(key_claim_url=f"{base}/claim-key/{claim.id}?code={code}",
                             key_claim_expires_at=aware(claim.expires_at).isoformat())


@router.post("/{registration_id}/claim-link", response_model=schemas.ClaimLink,
             dependencies=[Depends(_enabled), Depends(write_limit)],
             summary="New one-time key link for a completed self-registration whose key was never collected")
def claim_link(registration_id: str, body: schemas.ClaimLinkRequest, request: Request,
               session: Session = Depends(get_session)):
    sr = session.get(SelfRegistration, registration_id[:40])
    if sr is None or not hmac.compare_digest(sha256_hex(body.registration_secret), sr.secret_hash):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "self-registration not found")
    if sr.status != "completed" or sr.operator_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "complete the self-registration first")
    if session.scalar(select(ApiKey.id).where(ApiKey.operator_id == sr.operator_id)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "the key was already collected; rotate it with the key instead")
    return _new_claim(session, sr.operator_id, request.app.state.settings.public_base_url.rstrip("/"))


def redeem_claim(session: Session, claim_id: str, code: str) -> tuple[str, str]:
    """Use a one-time link: returns (operator_id, api_key plaintext). Raises 404/410 for a bad or used link."""
    claim = session.get(KeyClaim, claim_id[:40])
    if claim is None or not hmac.compare_digest(sha256_hex(code), claim.code_hash):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such key link")
    if claim.used_at is not None or aware(claim.expires_at) <= utcnow():
        raise HTTPException(status.HTTP_410_GONE, "this key link was already used or expired")
    op = session.get(Operator, claim.operator_id)
    if op is None or op.status != "active":
        raise HTTPException(status.HTTP_410_GONE, "operator no longer active")
    plaintext, digest, prefix = issue_api_key()
    op.keys.append(ApiKey(key_hash=digest, prefix=prefix))
    claim.used_at = utcnow()
    audit(session, "agent", op.id, "self_register.key_claimed", claim.id)
    return op.id, plaintext


claims_router = APIRouter(tags=["self-registration"])


@claims_router.post("/v1/key-claims/{claim_id}", response_model=schemas.KeyClaimed,
                    dependencies=[Depends(write_limit)], summary="Use a one-time key link (JSON)")
def redeem_json(claim_id: str, body: schemas.KeyClaimRedeem, session: Session = Depends(get_session)):
    op_id, key = redeem_claim(session, claim_id, body.code)
    return JSONResponse(schemas.KeyClaimed(operator_id=op_id, api_key=key).model_dump(),
                        headers={"Cache-Control": "no-store"})


@claims_router.get("/claim-key/{claim_id}", response_class=HTMLResponse, include_in_schema=False)
def claim_page(claim_id: str, code: str = ""):
    """Opening the link does not use it (link previews and crawlers fetch pages); the button does."""
    from html import escape

    return HTMLResponse(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=robots content=noindex>"
        "<meta name=viewport content='width=device-width,initial-scale=1'><title>ONAA API key</title></head>"
        "<body style='font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem'>"
        "<h1>Collect your ONAA API key</h1><p>Your agent registered a listing on the ONAA directory for you. "
        "This link shows its API key once. Keep the key in a password manager or secret store.</p>"
        f"<form method=post action='/claim-key/{escape(claim_id[:40])}'>"
        f"<input type=hidden name=code value='{escape(code[:200])}'><button type=submit>Show the key once</button>"
        "</form></body></html>", headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@claims_router.post("/claim-key/{claim_id}", response_class=HTMLResponse, include_in_schema=False,
                    dependencies=[Depends(write_limit)])
async def claim_page_post(claim_id: str, request: Request, session: Session = Depends(get_session)):
    from html import escape
    from urllib.parse import parse_qs

    form = parse_qs((await request.body()).decode("utf-8", "replace")[:1000])
    op_id, key = redeem_claim(session, claim_id, (form.get("code") or [""])[0])
    session.commit()
    return HTMLResponse(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=robots content=noindex>"
        "<title>ONAA API key</title></head><body style='font:16px/1.5 system-ui,sans-serif;max-width:40rem;"
        "margin:2rem auto;padding:0 1rem'><h1>Your ONAA API key</h1><p>Shown once; ONAA keeps only a hash.</p>"
        f"<pre style='background:#f3f3f3;padding:.75rem;overflow:auto'>{escape(key)}</pre>"
        f"<p>Operator id: <code>{escape(op_id)}</code>. Send the key as "
        "<code>Authorization: Bearer &lt;key&gt;</code>. "
        "If it leaks, rotate it with the key itself.</p></body></html>",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
