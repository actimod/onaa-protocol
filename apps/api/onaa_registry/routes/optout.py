"""Opt-out for discovered entries (growth DISCOVERY_POLICY section 7; founder decision 2026-11-16).

ONAA lists some publicly documented agents, stores and providers as `discovered` before they register. Anyone can
ask for those entries to be removed, with no account. Because a request alone proves nothing (a competitor could
send it), removal is in two steps:

1. The request hides the matched discovered entries at once and returns a token. Nothing is erased yet.
2. Within OPT_OUT_PROOF_DAYS the host proves control (the token at its well-known path or in a DNS TXT record, as
   for self-registration) with POST /v1/discovered/opt-out/{id}/confirm. Then the content is erased and only
   hashes of the URL/host are kept so the entry is not re-imported. Without proof, the entries come back when the
   window ends.

Abuse limits (founder decision 2026-11-16, live re-verification P1-02): an unproven hide is not renewable. While a
hiding request for a host is running, or for REHIDE_COOLDOWN_DAYS after one expired unproven or was restored by an
admin, a new request for that host hides nothing; it still returns a token so the real owner can prove control and
have the entries erased. Repeat requests never extend a running window. Requests are limited per client IP per day,
and an admin can restore a hide that looks abusive (POST /v1/admin/opt-out/{id}/restore).

Registered listings are never touched by this route. The optional reason text is never stored. Every step is
written to the audit log (counts and ids only).
"""

from __future__ import annotations

import datetime as dt
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..logic import audit, aware, host_of, normalise_url, set_facet_kind, utcnow
from ..models import Listing, OptOutClaim, Suppression
from ..security import client_ip, require_admin, sha256_hex, write_limit
from ..verification import CHALLENGE_PATH, check_host_proof, dns_record_name

router = APIRouter(tags=["opt-out"])

OPT_OUT_PROOF_DAYS = 7
PENDING_PER_HOST = 3
MAX_PROOF_ATTEMPTS = 20
HIDDEN_REASON = "opt_out_pending"
REHIDE_COOLDOWN_DAYS = 30
PROOF_ONLY_NOTE = ("This host already had a removal request without proof that is still running or ended in the last "
                   f"{REHIDE_COOLDOWN_DAYS} days, so nothing was hidden now. Prove control of the host before "
                   "expires_at and POST confirm_url; the matched discovered entries are then erased for good.")


def suppression_keys(url: str | None = None, host: str | None = None) -> list[str]:
    keys = []
    if url:
        keys.append(sha256_hex(f"url:{url}"))
    if host:
        keys.append(sha256_hex(f"host:{host}"))
    return keys


def is_suppressed(session: Session, *, url: str | None, host: str | None) -> bool:
    """True for a permanent opt-out, and also while a request for this URL or host is waiting for proof."""
    keys = suppression_keys(url, host)
    if not keys:
        return False
    if session.scalar(select(Suppression.id).where(Suppression.key_hash.in_(keys))) is not None:
        return True
    if not host:
        return False
    now = utcnow()
    for claim in session.scalars(select(OptOutClaim).where(OptOutClaim.host == host, OptOutClaim.state == "pending",
                                                           OptOutClaim.hides.is_(True))):
        if aware(claim.expires_at) > now and set(keys) & set(claim.key_hashes or []):
            return True
    return False


def _erase(listing: Listing) -> None:
    listing.lifecycle_status = "deleted"
    listing.status_reason = "opted_out"
    listing.display_name = "[removed]"
    for field in ("description", "agent_card_url", "endpoint_url", "documentation_url", "terms_url", "sandbox_url",
                  "source_url", "profile", "extensions", "card_summary", "card_name", "card_hash"):
        setattr(listing, field, None)
    listing.supported_interfaces, listing.regulatory_claims, listing.review_flags = [], [], []
    for kind in {f.kind for f in listing.facets}:
        set_facet_kind(listing, kind, set())
    listing.updated_at = utcnow()


def _hidden(session: Session, claim: OptOutClaim) -> list[Listing]:
    ids = claim.listing_ids or []
    if not ids:
        return []
    return list(session.scalars(select(Listing).where(Listing.id.in_(ids), Listing.lifecycle_status == "suspended",
                                                      Listing.status_reason == HIDDEN_REASON)))


def _matching(session: Session, claim: OptOutClaim) -> list[Listing]:
    """The entries a proof-only request matched (it hid nothing, so they are still listed)."""
    ids = claim.listing_ids or []
    if not ids:
        return []
    return list(session.scalars(select(Listing).where(Listing.id.in_(ids), Listing.operator_id.is_(None),
                                                      Listing.lifecycle_status == "discovered")))


def may_hide(session: Session, host: str) -> bool:
    """False while a hiding request for this host runs, or within REHIDE_COOLDOWN_DAYS after one ended unproven."""
    since = utcnow() - dt.timedelta(days=REHIDE_COOLDOWN_DAYS)
    running = select(OptOutClaim.id).where(OptOutClaim.host == host, OptOutClaim.state == "pending",
                                           OptOutClaim.hides.is_(True))
    recent = select(OptOutClaim.id).where(OptOutClaim.host == host, OptOutClaim.hides.is_(True),
                                          OptOutClaim.state.in_(("expired", "restored")),
                                          OptOutClaim.resolved_at >= since)
    return session.scalar(running.limit(1)) is None and session.scalar(recent.limit(1)) is None


def _restore(session: Session, claim: OptOutClaim, state: str) -> int:
    now = utcnow()
    restored = 0
    for listing in _hidden(session, claim):
        listing.lifecycle_status, listing.status_reason, listing.updated_at = "discovered", None, now
        restored += 1
    claim.state, claim.resolved_at = state, now
    return restored


def expire_opt_outs(session: Session) -> int:
    """Restore the entries of requests whose proof window ended without proof. Returns how many requests."""
    now = utcnow()
    claims = [c for c in session.scalars(select(OptOutClaim).where(OptOutClaim.state == "pending",
                                                                    OptOutClaim.expires_at <= now))]
    for claim in claims:
        restored = _restore(session, claim, "expired")
        audit(session, "system", None, "discovered.opt_out_expired", claim.id, restored=restored)
    return len(claims)


@router.post("/v1/discovered/opt-out", response_model=schemas.OptOutResult, dependencies=[Depends(write_limit)],
             summary="Hide discovered (unregistered) entries for a URL or host; erase them once the host proves "
                     "control")
def opt_out(body: schemas.OptOutRequest, request: Request, session: Session = Depends(get_session)):
    url = normalise_url(body.url, "url")
    host = host_of(url)
    if not host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "url must include a host")
    request.app.state.opt_out_limiter.check(f"optout:{client_ip(request)}")
    expire_opt_outs(session)
    pending = session.scalars(select(OptOutClaim.id).where(OptOutClaim.host == host,
                                                           OptOutClaim.state == "pending")).all()
    if len(pending) >= PENDING_PER_HOST:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "removal requests for this host are already waiting for proof; prove control of the "
                            "host with one of them, or wait until they expire")
    match = (or_(Listing.agent_card_url == url, Listing.documentation_url == url, Listing.endpoint_url == url)
             if body.scope == "url" else Listing.endpoint_host == host)
    hides = may_hide(session, host)
    matched = list(session.scalars(select(Listing).where(match, Listing.operator_id.is_(None),
                                                         Listing.lifecycle_status == "discovered")))
    hidden = []
    if hides:
        for listing in matched:
            listing.lifecycle_status, listing.status_reason, listing.updated_at = "suspended", HIDDEN_REASON, utcnow()
            hidden.append(listing.id)
    token = "onaa-optout-" + secrets.token_urlsafe(32)
    claim = OptOutClaim(host=host, scope=body.scope, nonce_hash=sha256_hex(token),
                        listing_ids=hidden if hides else [m.id for m in matched],
                        key_hashes=suppression_keys(url if body.scope == "url" else None,
                                                    host if body.scope == "host" else None),
                        expires_at=utcnow() + dt.timedelta(days=OPT_OUT_PROOF_DAYS), hides=hides)
    session.add(claim)
    session.flush()
    # The reason text is not stored: it may contain personal data. Only counts and ids are audited.
    audit(session, "anonymous", None, "discovered.opt_out_requested", claim.id, scope=body.scope,
          hidden=len(hidden), hides=hides)
    base = request.app.state.settings.public_base_url.rstrip("/")
    return schemas.OptOutResult(
        status="hidden" if hidden else ("pending" if hides else "proof_required"), removed_listing_ids=hidden,
        request_id=claim.id, token=token,
        expires_at=aware(claim.expires_at).isoformat(),
        well_known_url=f"https://{host}" + CHALLENGE_PATH.format(cid=claim.id), dns_record_name=dns_record_name(host),
        confirm_url=f"{base}/v1/discovered/opt-out/{claim.id}/confirm",
        **({} if hides else {"note": PROOF_ONLY_NOTE}))


@router.post("/v1/discovered/opt-out/{request_id}/confirm", response_model=schemas.OptOutConfirmResult,
             dependencies=[Depends(write_limit)],
             summary="Prove control of the host (well-known file or DNS TXT) to erase the hidden entries for good")
def confirm_opt_out(request_id: str, body: schemas.OptOutConfirm, request: Request,
                    session: Session = Depends(get_session)):
    expire_opt_outs(session)
    claim = session.get(OptOutClaim, request_id)
    if claim is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such removal request")
    if claim.state == "confirmed":
        return schemas.OptOutConfirmResult(status="removed", removed_listing_ids=list(claim.listing_ids or []))
    if claim.state != "pending":
        raise HTTPException(status.HTTP_410_GONE, "this request expired without proof; the entries are listed again. "
                                                  "Send a new removal request")
    if claim.attempts >= MAX_PROOF_ATTEMPTS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many proof attempts for this request")
    claim.attempts += 1
    error = check_host_proof(request.app.state.fetcher, request.app.state.txt_resolver, host=claim.host,
                             method=body.method, challenge_id=claim.id, nonce_hash=claim.nonce_hash)
    if error:
        audit(session, "anonymous", None, "discovered.opt_out_proof", claim.id, result="failed", error=error)
        session.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"proof not found: {error}")
    erased = []
    targets = _hidden(session, claim) if claim.hides else _matching(session, claim)
    for listing in targets:
        _erase(listing)
        erased.append(listing.id)
    for key in claim.key_hashes or []:
        if session.scalar(select(Suppression.id).where(Suppression.key_hash == key)) is None:
            session.add(Suppression(key_hash=key))
    claim.state, claim.resolved_at = "confirmed", utcnow()
    audit(session, "anonymous", None, "discovered.opt_out_confirmed", claim.id, method=body.method,
          removed=len(erased))
    return schemas.OptOutConfirmResult(status="removed", removed_listing_ids=erased)


@router.post("/v1/admin/opt-out/{request_id}/restore", tags=["admin"],
             summary="Admin: list again the entries an unproven removal request hid (suspected abuse)")
def restore_opt_out(request_id: str, admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    claim = session.get(OptOutClaim, request_id)
    if claim is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such removal request")
    if claim.state == "confirmed":
        raise HTTPException(status.HTTP_409_CONFLICT, "the host proved control; the entries were erased")
    if claim.state != "pending":
        return {"request_id": claim.id, "state": claim.state, "restored": 0}
    restored = _restore(session, claim, "restored")
    audit(session, admin, None, "discovered.opt_out_restored", claim.id, restored=restored)
    return {"request_id": claim.id, "state": "restored", "restored": restored}


@router.get("/opt-out", response_class=HTMLResponse, include_in_schema=False)
def opt_out_page(request: Request):
    base = request.app.state.settings.public_base_url.rstrip("/")
    return HTMLResponse(OPT_OUT_PAGE.replace("{base}", base))


OPT_OUT_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ONAA opt-out</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem}
code,pre{background:#f3f3f3;padding:.1rem .3rem;border-radius:4px}pre{padding:.75rem;overflow:auto}</style></head>
<body><h1>Remove a discovered entry from ONAA</h1>
<p>The ONAA registry (Open Network for AI Agents) lists some publicly documented AI agents and service providers
as <strong>discovered, not registered</strong>, using only information they publish themselves (for example an
A2A Agent Card or public API documentation). These entries are not endorsements and the provider has not joined.</p>
<p>If you run one of these services and do not want it listed, ask for removal. No account is needed. Because a
request alone does not show who sent it, removal has two steps:</p>
<ol><li><strong>Hidden now.</strong> Your request hides the matching entries immediately and returns a token.</li>
<li><strong>Erased after proof.</strong> Within 7 days, publish the token on your host (a file at the
<code>well_known_url</code> in the answer, or a DNS TXT record at <code>dns_record_name</code>) and call the
<code>confirm_url</code>. The content is then erased and we keep only a one-way hash of the URL or host so it is
not added again. Without proof, the entries are listed again after 7 days.</li></ol>
<p>To prevent abuse, a host can be hidden without proof only once in 30 days: a new request during a running
request, or within 30 days after one ended without proof, hides nothing but still returns a token, so the real
owner can prove control and have the entries erased. Requests are limited per sender per day, and ONAA may list
entries again if a request looks abusive.</p>
<h2>How to remove it</h2>
<p>Send the URL of your Agent Card, documentation or website:</p>
<pre>curl -X POST {base}/v1/discovered/opt-out \\
  -H 'content-type: application/json' \\
  -d '{"url": "https://your-domain.example/", "scope": "host"}'</pre>
<p>Then publish the returned <code>token</code> and confirm:</p>
<pre>curl -X POST {base}/v1/discovered/opt-out/&lt;request_id&gt;/confirm \\
  -H 'content-type: application/json' -d '{"method": "well_known"}'</pre>
<p><code>scope: "host"</code> covers every discovered entry on that host; <code>scope: "url"</code> only that exact
URL. Please do not include personal data in the optional <code>reason</code>; it is not stored.</p>
<p>Listings that a provider registered itself are not affected; their owner can delete them with their own key.
To report a listing someone else registered for your endpoint, use <code>POST {base}/v1/reports</code> with
category <code>unauthorized_registration</code>.</p>
</body></html>
"""
