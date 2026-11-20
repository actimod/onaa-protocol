"""Stores register with one click: a "verify my store" link sent to the contact address the store publishes itself.

Founder decision 2026-11-17: for stores the default is an email link, not a file upload or DNS record. ONAA (after
founder approval for each send) emails the address the store publishes on its own site or UCP manifest; the
link in that email is single-use and expires. Using it:

1. registers the store under a new operator (the store's API key is shown once),
2. records that the operator confirmed through the store's published address
   (`trust.owner_confirmed_via = "published_email"`, trust level `operator_confirmed_by_email`), which is weaker than
   proving endpoint control (the file or DNS check stays available as the stronger, optional step),
3. gives a Founding Cohort seat while seats last (free verification and certification review), and
4. lets the operator state shipping countries, payment methods, returns and categories, shown as store-stated.

Opening the link only shows a page (link previews and mail scanners fetch links); the button does the work.
"""

from __future__ import annotations

import datetime as dt
import hmac
import secrets
from html import escape
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import schemas
from ..db import get_session
from ..landing import CSS
from ..logic import PUBLIC_STATUSES, apply_profile, audit, aware, bump_revision, normalise_url
from ..models import ApiKey, Listing, Operator, StoreInvite, new_id, utcnow
from ..registrant import LEVEL_LABELS, maybe_join_founding_cohort, weekly_lookups
from ..security import issue_api_key, require_admin, sha256_hex, write_limit
from ..terms import load_terms

router = APIRouter(tags=["store registration"])

GOAL = ("ONAA (Open Network for AI Agents) is an open directory, a phone book for AI agents: buying agents look up "
        "stores, selling agents and service providers there, then deal with them directly, agent to agent. ONAA "
        "helps them find and check each other; it never sits in the trade, handles orders or takes payment.")
INVITE_DAYS = 30
NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"}


class InviteCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320, description="The contact address the store publishes itself")
    email_source_url: str = Field(max_length=2048, description="Page or manifest where the store publishes it")
    days: int = Field(default=INVITE_DAYS, ge=1, le=90)


def _base(request: Request) -> str:
    return request.app.state.settings.public_base_url.rstrip("/")


@router.post("/v1/admin/stores/{store}/invites", status_code=201, tags=["admin"],
             summary="Create a one-time 'verify my store' link for the store's own published contact address")
def create_invite(store: str, body: InviteCreate, request: Request, admin: str = Depends(require_admin),
                  session: Session = Depends(get_session)):
    """Returns the link to put in the email. Nothing is sent: sending is a separate, founder-approved step."""
    from ..stores import find_store

    listing = find_store(session, store)
    if listing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "store not listed")
    if listing.operator_id is not None and listing.lifecycle_status not in ("discovered", "claim_pending"):
        raise HTTPException(status.HTTP_409_CONFLICT, "this store is already registered by its operator")
    email = body.email.strip()
    try:
        ok = "@" in email and schemas.check_operator_contact(email) == email
    except ValueError:
        ok = False
    if not ok:
        raise HTTPException(422, "email must be an email address")
    source = normalise_url(body.email_source_url, "email_source_url")
    code = "onaa-store-" + secrets.token_urlsafe(32)
    inv = StoreInvite(id=new_id("sinv"), listing_id=listing.id, email=email, email_source_url=source,
                      code_hash=sha256_hex(code), expires_at=utcnow() + dt.timedelta(days=body.days))
    session.add(inv)
    session.flush()
    audit(session, "admin", None, "store.invite_created", listing.id, invite_id=inv.id, email_source_url=source)
    return {"invite_id": inv.id, "store_id": listing.id, "verify_url": f"{_base(request)}/verify-store/{inv.id}"
            f"?code={code}", "expires_at": aware(inv.expires_at).isoformat()}


# ---------- pages ----------
def _html(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" '
        f'content="light dark"><title>{escape(title)}</title><style>{CSS}'
        "form label{display:block;margin:.6rem 0 .2rem}form input[type=text],form input[type=url],"
        "form input[type=password],form input[type=number],form select{width:100%;max-width:32rem;padding:.4rem}"
        "pre{white-space:pre-wrap;word-break:break-all}</style></head><body><header><div class=\"wrap bar\">"
        '<a class="logo" href="/">ONAA <span>Open Network for AI Agents</span></a></div></header>'
        f'<main class="wrap">{body}</main></body></html>', headers=NO_STORE)


def _load_invite(session: Session, invite_id: str, code: str) -> tuple[StoreInvite, Listing]:
    inv = session.get(StoreInvite, invite_id[:40])
    if inv is None or not hmac.compare_digest(sha256_hex(code[:200]), inv.code_hash):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such link")
    if inv.used_at is not None:
        raise HTTPException(status.HTTP_410_GONE, "this link was already used")
    if aware(inv.expires_at) <= utcnow():
        raise HTTPException(status.HTTP_410_GONE, "this link expired")
    listing = session.get(Listing, inv.listing_id)
    if listing is None or listing.service_type != "marketplace" or listing.lifecycle_status not in PUBLIC_STATUSES:
        raise HTTPException(status.HTTP_410_GONE, "this store is no longer listed")
    if listing.operator_id is not None and listing.lifecycle_status not in ("discovered", "claim_pending"):
        raise HTTPException(status.HTTP_409_CONFLICT, "this store is already registered")
    return inv, listing


STATUS_TEXT_SHORT = {
    "checkout_ready": "an outside agent searched your catalog and reached a checkout that asks for payment",
    "buyer_step_required": "an outside agent built a checkout; the buyer has to finish a step on your site",
    "auth_required": "your agent endpoint accepts only approved or partner agents",
    "no_checkout": "no agent checkout was found",
    "failed": "the check could not finish (network or protocol error)",
}


def _check_summary(listing: Listing) -> str:
    ac = listing.agent_checkout or {}
    st = ac.get("status")
    when = (ac.get("checked_at") or "")[:10]
    if not st:
        return "ONAA has not run its test checkout on this store yet."
    return f"Last ONAA check ({when}): {STATUS_TEXT_SHORT.get(st, st)}. ONAA's test agent never pays."


@router.get("/verify-store/{invite_id}", response_class=HTMLResponse, include_in_schema=False)
def verify_page(invite_id: str, request: Request, code: str = "", session: Session = Depends(get_session)):
    inv, listing = _load_invite(session, invite_id, code)
    base = _base(request)
    settings = request.app.state.settings
    domain = _domain(listing)
    return _html("Verify your store on ONAA", (
        f'<section class="hero"><h1>Verify {escape(listing.display_name)} on ONAA</h1><p>{escape(GOAL)}</p></section>'
        f'<div class="item"><p>{escape(_check_summary(listing))}</p>'
        f'<p>Today the store is shown to agents as: <em>{escape(LEVEL_LABELS["discovered_unverified"])}</em>.</p>'
        f'<p>This link was sent to the address your store publishes at {escape(inv.email_source_url)}.</p></div>'
        '<h2 class="list-h">One click. Free. Nothing else required.</h2>'
        "<p>Verifying is the only step: no payment, no forms, no extra information.</p><ul>"
        f'<li>Buying agents see <em>{escape(LEVEL_LABELS["operator_confirmed_by_email"])}</em> instead of '
        '"unverified", so they can trust the entry more.</li>'
        "<li>Verified stores are listed ahead of unverified ones when agents' results are otherwise equal.</li>"
        "<li>ONAA re-checks your agent checkout daily instead of weekly.</li>"
        "<li>You get a weekly count of how often agents looked your store up.</li>"
        "<li>Early registrants get ONAA's further verification and certification review free for 12 months.</li>"
        "<li>Optional, any time later: state your shipping countries, payment methods, return policy and "
        "categories (shown to agents as stated by the store).</li>"
        "<li>You can delete the listing at any time. ONAA never takes orders or payments for you.</li></ul>"
        f'<form method="post" action="/verify-store/{escape(inv.id)}">'
        f'<input type="hidden" name="code" value="{escape(code[:200])}">'
        f'<label><input type="checkbox" name="accept_terms" value="{escape(settings.terms_version)}" required> '
        f'I manage this store and accept the ONAA directory terms (<a href="{escape(base)}/v1/terms.md">'
        f'{escape(settings.terms_version)}</a>, a draft).</label>'
        '<p><button type="submit">Verify my store</button></p></form>'
        f'<p class="list-sub">Prefer not to be listed? <a href="{escape(base)}/opt-out">Remove the store</a>. '
        f'Public store page: <a href="{escape(base)}/stores/{escape(domain or listing.id)}">'
        f'{escape(base)}/stores/{escape(domain or listing.id)}</a></p>'))


def _domain(listing: Listing) -> str | None:
    from ..stores import store_domain

    return store_domain(listing)


async def _form(request: Request) -> dict[str, str]:
    raw = parse_qs((await request.body()).decode("utf-8", "replace")[:20_000])
    return {k: v[0] for k, v in raw.items() if v}


@router.post("/verify-store/{invite_id}", response_class=HTMLResponse, include_in_schema=False,
             dependencies=[Depends(write_limit)])
async def verify_submit(invite_id: str, request: Request, session: Session = Depends(get_session)):
    form = await _form(request)
    inv, listing = _load_invite(session, invite_id, form.get("code", ""))
    settings = request.app.state.settings
    if form.get("accept_terms") != settings.terms_version:
        raise HTTPException(422, "accept the current terms to continue")
    terms = load_terms(settings.terms_version)
    now = utcnow()
    op = Operator(id=new_id("op"), display_name=listing.display_name[:200], operator_type="organization",
                  terms_version=terms.version, terms_sha256=terms.sha256, terms_accepted_at=now,
                  terms_acceptance_method="store_email_link", operator_contact=inv.email)
    plaintext, digest, prefix = issue_api_key()
    op.keys.append(ApiKey(key_hash=digest, prefix=prefix))
    session.add(op)
    session.flush()
    cohort = maybe_join_founding_cohort(session, op, settings)
    listing.operator_id = op.id
    listing.lifecycle_status = "registered"
    listing.registration_method = "store_email_link"
    listing.owner_confirmed_via = "published_email"
    listing.owner_confirmed_at = now
    listing.status_reason = None
    bump_revision(listing)
    inv.used_at, inv.operator_id = now, op.id
    for other in session.scalars(select(StoreInvite).where(StoreInvite.listing_id == listing.id,
                                                           StoreInvite.used_at.is_(None),
                                                           StoreInvite.id != inv.id)):
        other.expires_at = now  # one owner: other links for this store stop working
    audit(session, "operator", op.id, "store.registered_by_email_link", listing.id, invite_id=inv.id,
          email_source_url=inv.email_source_url, founding_cohort=cohort, revision=listing.revision)
    session.commit()
    base = _base(request)
    return _html("Your store is verified", (
        f'<section class="hero"><h1>{escape(listing.display_name)} is registered and verified by email</h1>'
        f'<p>Agents now see: <em>{escape(LEVEL_LABELS["operator_confirmed_by_email"])}</em>.'
        + (" You joined the Founding Cohort: verification and certification review are free for 12 months."
           if cohort else "") + "</p></section>"
        '<div class="item"><h2>Your store key (shown once)</h2>'
        f"<pre>{escape(plaintext)}</pre><p>Keep it in a password manager. Use it at "
        f'<a href="{escape(base)}/manage-store">{escape(base)}/manage-store</a> to edit your details and see '
        "how often agents look you up, or with the API as <code>Authorization: Bearer &lt;key&gt;</code>. "
        "If it leaks, rotate it with POST /v1/operators/me/keys/rotate.</p></div>"
        + _edit_form(listing, plaintext)))


# ---------- store-stated details ----------
def _edit_form(listing: Listing, key: str) -> str:
    st = (listing.profile or {}).get("store_stated") or {}
    ret = st.get("returns") or {}

    def val(v) -> str:
        return escape(", ".join(v) if isinstance(v, list) else ("" if v is None else str(v)))

    accepted = ret.get("accepted")
    opts = "".join(f'<option value="{v}"{" selected" if accepted is b else ""}>{t}</option>'
                   for v, b, t in (("", None, "not stated"), ("yes", True, "yes"), ("no", False, "no")))
    return (
        '<h2 class="list-h">Optional: tell agents more about your store</h2>'
        "<p>Not required; your store is already verified. Shown to agents as stated by the store, next to "
        "(never instead of) what ONAA's test checkout observed. "
        "Leave a field empty if you prefer not to say.</p>"
        '<form method="post" action="/manage-store">'
        f'<input type="hidden" name="key" value="{escape(key)}"><input type="hidden" name="listing_id" '
        f'value="{escape(listing.id)}"><input type="hidden" name="action" value="save">'
        f'<label><input type="checkbox" name="ships_worldwide" value="yes"'
        f'{" checked" if st.get("ships_worldwide") else ""}> We ship worldwide</label>'
        '<label for="ships_to">Countries you ship to (ISO codes, comma separated, e.g. US, CA, AU)</label>'
        f'<input type="text" id="ships_to" name="ships_to" value="{val(st.get("ships_to"))}">'
        '<label for="pm">Payment methods (e.g. card, paypal, shop_pay, apple_pay, google_pay, klarna)</label>'
        f'<input type="text" id="pm" name="payment_methods" value="{val(st.get("payment_methods"))}">'
        f'<label for="ra">Do you accept returns?</label><select id="ra" name="returns_accepted">{opts}</select>'
        '<label for="rw">Return window (days after delivery)</label>'
        f'<input type="number" id="rw" name="returns_window_days" min="0" max="3650" '
        f'value="{val(ret.get("window_days"))}">'
        '<label for="ru">Return policy page</label>'
        f'<input type="url" id="ru" name="returns_policy_url" value="{val(ret.get("policy_url"))}">'
        '<label for="su">Shipping policy page</label>'
        f'<input type="url" id="su" name="shipping_policy_url" value="{val(st.get("shipping_policy_url"))}">'
        '<label for="cat">What you sell (e.g. apparel, coffee, electronics)</label>'
        f'<input type="text" id="cat" name="categories" value="{val(st.get("categories"))}">'
        '<p><button type="submit">Save</button></p></form>')


def _split(v: str | None) -> list[str]:
    return [p.strip() for p in (v or "").replace(";", ",").split(",") if p.strip()]


def stated_from_form(form: dict[str, str]) -> dict:
    out: dict = {"ships_to": _split(form.get("ships_to")), "payment_methods": _split(form.get("payment_methods")),
                 "categories": [c.replace(" ", "_") for c in _split(form.get("categories"))]}
    if form.get("ships_worldwide") == "yes":
        out["ships_worldwide"] = True
    ret: dict = {}
    if form.get("returns_accepted") in ("yes", "no"):
        ret["accepted"] = form["returns_accepted"] == "yes"
    days = (form.get("returns_window_days") or "").strip()
    if days:
        ret["window_days"] = int(days) if days.isdigit() else days
    if (form.get("returns_policy_url") or "").strip():
        ret["policy_url"] = form["returns_policy_url"].strip()
    if ret:
        out["returns"] = ret
    if (form.get("shipping_policy_url") or "").strip():
        out["shipping_policy_url"] = form["shipping_policy_url"].strip()
    return out


def _operator_for_key(session: Session, key: str) -> Operator:
    from ..security import KEY_PREFIX

    if not key.startswith(KEY_PREFIX):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "store key required")
    row = session.scalar(select(ApiKey).where(ApiKey.key_hash == sha256_hex(key[:200])))
    if row is None or row.revoked_at is not None or row.operator.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or revoked key")
    return row.operator


@router.get("/manage-store", response_class=HTMLResponse, include_in_schema=False)
def manage_page():
    return _html("Manage your store on ONAA", (
        '<section class="hero"><h1>Manage your store on ONAA</h1><p>Paste the store key you got when you verified '
        "your store.</p></section>"
        '<form method="post" action="/manage-store"><label for="k">Store key</label>'
        '<input type="password" id="k" name="key" autocomplete="off" required>'
        '<p><button type="submit">Open</button></p></form>'))


@router.post("/manage-store", response_class=HTMLResponse, include_in_schema=False,
             dependencies=[Depends(write_limit)])
async def manage_submit(request: Request, session: Session = Depends(get_session)):
    form = await _form(request)
    key = form.get("key", "")
    op = _operator_for_key(session, key)
    stores = list(session.scalars(select(Listing).where(
        Listing.operator_id == op.id, Listing.service_type == "marketplace",
        Listing.lifecycle_status.in_(PUBLIC_STATUSES)).order_by(Listing.created_at, Listing.id)))
    if not stores:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no store is registered with this key")
    listing = next((s for s in stores if s.id == form.get("listing_id")), stores[0])
    note = ""
    if form.get("action") == "save":
        try:
            stated = schemas.StoreStated(**stated_from_form(form)).model_dump(mode="json", exclude_none=True)
        except ValidationError as exc:
            errs = "; ".join(f'{".".join(str(p) for p in e["loc"])}: {e["msg"]}' for e in exc.errors()[:5])
            note = f'<p class="list-sub"><strong>Not saved:</strong> {escape(errs)}</p>'
        except HTTPException as exc:
            note = f'<p class="list-sub"><strong>Not saved:</strong> {escape(str(exc.detail))}</p>'
        else:
            try:
                apply_profile(listing, {"store_stated": stated}, partial=True)
            except HTTPException as exc:
                note = f'<p class="list-sub"><strong>Not saved:</strong> {escape(str(exc.detail))}</p>'
                session.rollback()
            else:
                bump_revision(listing)
                audit(session, "operator", op.id, "service.update", listing.id, fields=["store_stated"],
                      revision=listing.revision)
                session.commit()
                note = '<p class="list-sub"><strong>Saved.</strong> Agents see the change within minutes.</p>'
    week = weekly_lookups(session, listing.id, weeks=4)
    rows = "".join(f'<li>Week of {escape(w["week_starting"])}: {w["total"]} (record fetched {w["detail"]}, '
                   f'"can I buy here?" {w["check"]}, in search results {w["search"]})</li>' for w in week["weeks"])
    from ..registrant import level_of

    base = _base(request)
    domain = _domain(listing)
    return _html("Manage your store on ONAA", (
        f'<section class="hero"><h1>{escape(listing.display_name)}</h1>'
        f'<p>Shown to agents as: <em>{escape(LEVEL_LABELS[level_of(listing)])}</em></p>'
        f'<p><a href="{escape(base)}/stores/{escape(domain or listing.id)}">Public store page</a></p></section>'
        + note
        + f'<div class="item"><h2>Agents looking you up</h2><ul>{rows}</ul>'
          f'<p class="list-sub">{escape(week["note"])}</p></div>'
        + _edit_form(listing, key)
        + "<p class=\"list-sub\">Stronger, optional: prove you control the store's agent endpoint with a DNS TXT "
          f"record (POST {escape(base)}/v1/services/{escape(listing.id)}/verify-domain with your key). To remove the "
          f"store: DELETE {escape(base)}/v1/services/{escape(listing.id)}.</p>"))
