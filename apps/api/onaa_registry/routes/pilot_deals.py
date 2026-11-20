"""After an offer is accepted (founder decisions 2026-11-19).

The deal goes on where the two sides negotiated: on the accepted offer itself. No new chat room is opened and no
contact detail is revealed automatically. Each side's assistant can:

* propose / agree the terms of the handoff: how the buyer pays (one of the listing's payment methods, which may be
  escrow; an optional detail such as the app or provider) and how, when and where it changes hands. When both
  sides agreed the same terms, the deal is ``arranged``.
* write a short message. ONAA stores no contact detail or address in profiles or deals: personal details travel
  only inside a message, when the member wants to share them and under their rules. Every deal message and the
  free-text terms are deleted PERSONAL_RETENTION_DAYS after the deal is done or cancelled, and a deal idle for
  IDLE_DEAL_DAYS is cancelled (deal_rules.purge_personal, cancel_idle).
* cancel (the item goes back on sale), mark it done (both sides: the item is sold), report or block the other side.

Each side follows its own deal rules (..deal_rules): a step under ``ask`` is held until the member approved it,
and the other side only sees that the step waits for them. ONAA takes no part in payment or delivery and does not
judge disputes: members can report or block, and completed / cancelled deals and reports form a light record shown
to people who deal with that member.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select

from .. import deal_rules, hosting, links
from ..logic import audit
from ..models import PilotConversation, PilotItem, PilotMember, PilotOffer, utcnow
from .pilot import (
    PAYMENT_METHODS,
    TRADE_METHODS,
    UNTRUSTED_NOTE,
    Db,
    Member,
    _clean,
    _event,
    _offer_event,
    _personal_details,
    _split,
    pilot_enabled,
)

router = APIRouter(prefix="/v1/market", tags=["pilot"], dependencies=[Depends(pilot_enabled)])

STALE_DAYS = 7  # no handoff agreed this long after acceptance: ask the seller whether to release the item
REPORT_REASONS = ("no_show", "scam", "abuse", "other")
LIVE = ("arranging", "arranged")
TERM_FIELDS = ("payment_method", "payment_detail", "trade_method", "handoff_time", "handoff_place")
PAYMENT_FIELDS = ("payment_method", "payment_detail")
HANDOFF_FIELDS = ("trade_method", "handoff_time", "handoff_place")
DEAL_NOTE = ("ONAA takes no part in payment or delivery and does not judge disputes: the two sides arrange both "
             "directly. Contact details and addresses are shared only when a member chooses to. Be careful paying "
             "someone you do not know.")


class Terms(BaseModel):
    payment_method: Literal[PAYMENT_METHODS] | None = None  # type: ignore[valid-type]
    payment_detail: str | None = Field(default=None, max_length=120,
                                       description="e.g. which app or escrow provider; no account numbers")
    trade_method: Literal[TRADE_METHODS] | None = None  # type: ignore[valid-type]
    handoff_time: str | None = Field(default=None, max_length=120, description="e.g. Sat 3pm, or ships by Fri")
    handoff_place: str | None = Field(default=None, max_length=200,
                                      description="a public meeting place or 'shipping'; a home address goes in "
                                                  "share_address")


class DealActIn(BaseModel):
    action: Literal["propose", "agree", "message", "cancel", "done", "report", "block"]
    terms: Terms | None = None
    text: str | None = Field(default=None, max_length=500, description="message, or a note with any action")
    # The message gives a delivery or meeting address (the server finds phone numbers and emails itself).
    shares_address: bool = False
    reason: Literal[REPORT_REASONS] | None = None  # type: ignore[valid-type]
    # agree: the arrangement.proposal_at of the terms the member saw (required with user_approved), so a newer
    # proposal is never agreed by mistake
    proposal_at: str | None = Field(default=None, max_length=40)
    # The member approved this step (for a self-signed-up server agent: its operator's rules allow it).
    user_approved: bool = False


class RulesIn(BaseModel):
    confirm_deal: Literal["auto", "ask"] | None = None
    confirm_deal_max: dict | None = Field(default=None, description="{amount, currency}: auto confirm buying up to "
                                                                    "this")
    clear_confirm_deal_max: bool = False
    confirm_sale_min: dict | None = Field(default=None, description="{amount, currency}: auto confirm selling at or "
                                                                    "above this")
    clear_confirm_sale_min: bool = False
    only_in_range: bool | None = Field(default=None, description="auto confirm only on listings with a saved price "
                                                                 "range, inside it")
    choose_payment: Literal["auto", "ask"] | None = None
    share_contact: Literal["auto", "ask"] | None = None
    share_address: Literal["auto", "ask"] | None = None
    set_handoff: Literal["auto", "ask"] | None = None
    cancel_deal: Literal["auto", "ask"] | None = None
    confirm_done: Literal["auto", "ask"] | None = None
    user_approved: bool = False


# ------------------------------------------------------------------ rules

PER_ITEM = ("Prices are set per item now (founder decision 2026-11-20), not as an account rule: ask your user for "
            "this item, in bold, whether you may close the deal alone and up to (buying) or from (selling) what "
            "price, and save the answer with save_price_range; with no range you ask before every price.")


@router.get("/rules")
def get_rules(m: Member):
    out = deal_rules.view(m)
    if m.kind != "agent":
        out["rules"] = {k: v for k, v in out["rules"].items()
                        if k not in ("confirm_deal", "only_in_range", *deal_rules.LIMITS)}
        out["prices"] = PER_ITEM
        out["hourly_check"] = {"running": hosting.schedule_running(m, utcnow())}
    return out


@router.patch("/rules")
def set_rules(body: RulesIn, m: Member, session: Db, request: Request):
    if m.kind != "agent" and (body.confirm_deal or body.only_in_range is not None or body.confirm_deal_max
                              or body.confirm_sale_min or body.clear_confirm_deal_max or body.clear_confirm_sale_min):
        raise HTTPException(422, PER_ITEM)
    changes: dict[str, Any] = {k: v for k, v in body.model_dump(include=set(deal_rules.RULES)).items() if v}
    for key in deal_rules.LIMITS:
        lim = getattr(body, key)
        if getattr(body, "clear_" + key):
            changes[key] = None
        elif lim is not None:
            amount, currency = lim.get("amount"), lim.get("currency")
            if (not isinstance(amount, int) or isinstance(amount, bool) or amount < 0
                    or not isinstance(currency, str) or len(currency) != 3):
                raise HTTPException(422, f"{key} needs {{amount: whole number >= 0, currency: 3 letters}}")
            changes[key] = {"amount": amount, "currency": currency.upper()}
    if body.only_in_range is not None:
        changes["only_in_range"] = body.only_in_range
    held = deal_rules.update(m, changes, body.user_approved,
                             base_url=request.app.state.settings.public_base_url)
    if held and not held.get("done"):
        return held
    audit(session, "pilot", m.id, "pilot.deal_rules_changed", m.id, rules=deal_rules.rules_of(m),
          approved=body.user_approved)
    return get_rules(m) | {k: v for k, v in (held or {}).items() if k != "rules"} | {"done": True}


# ------------------------------------------------------------------ deal view (part of an accepted offer)

def record(session, member_id: str) -> dict[str, int]:
    """Light track record across this member's accepted offers: done, cancelled (by them) and reports others made."""
    rows = session.scalars(select(PilotOffer).where(
        PilotOffer.status == "accepted", or_(PilotOffer.buyer_id == member_id, PilotOffer.seller_id == member_id))
        .order_by(PilotOffer.updated_at.desc()).limit(500)).all()
    done = cancelled = reports = 0
    for o in rows:
        role = "buyer" if o.buyer_id == member_id else "seller"
        done += o.deal_state == "done"
        cancelled += o.deal_state == "cancelled" and o.cancelled_by == role
        reports += sum(1 for r in (o.reports or []) if r.get("by") != role)
    return {"deals_done": done, "deals_cancelled_by_them": cancelled, "reports_from_others": reports}


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return t.replace(tzinfo=dt.UTC) if t is not None and t.tzinfo is None else t


def deal_view(session, o: PilotOffer, role: str, other: PilotMember | None, it: PilotItem) -> dict[str, Any]:
    them = "seller" if role == "buyer" else "buyer"
    state = o.deal_state or "arranging"
    live = state in LIVE
    arr = o.arrangement
    out: dict[str, Any] = {"state": state, "accepted_at": o.accepted_at.isoformat() if o.accepted_at else None,
                           "options": {"payment_methods": _split(it.payment_methods),
                                       "trade_methods": _split(it.trade_methods)}}
    if arr:
        agreed = arr.get("agreed_by") or []
        out["arrangement"] = {"terms": arr.get("terms") or {}, "proposed_by": "you" if arr.get("proposed_by") == role
                              else "them", "proposal_at": arr.get("at"), "you_agreed": role in agreed,
                              "they_agreed": them in agreed, "agreed": role in agreed and them in agreed}
    done = o.done_by or []
    out["done"] = {"you": role in done, "them": them in done}
    if live and (o.waiting or {}).get(them):
        out["their_side"] = deal_rules.WAITING_FOR_OTHER
    if state == "cancelled":
        by = o.cancelled_by
        side = (by or "").split(":")[0]  # "buyer:clr" = cancelled by the buyer, cleared from their record
        out["cancelled_by"] = by if by in ("onaa", "idle") else "you" if side == role else "them"
    if live:
        can = ["propose", "message", "cancel", "done", "report", "block"]
        if them in done:
            can.remove("cancel")
        if arr and role not in (arr.get("agreed_by") or []):
            can.insert(1, "agree")
        out["you_can"] = can
    elif state == "done":
        out["you_can"] = ["report", "block"]
    out["next_step"] = _next_step(o, role, state, arr, it)
    if live:  # amp retest 2026-11-20: both AIs offered to turn the hourly check off at the agreed price
        out["next_step"] += (" Keep your user's scheduled check running until this deal is done or cancelled; do not "
                             "suggest turning it off before that.")
    return out


def _next_step(o: PilotOffer, role: str, state: str, arr: dict | None, it: PilotItem) -> str:
    if state == "done":
        return "Done on both sides. The item is marked sold."
    if state == "cancelled" and o.cancelled_by == "onaa":
        return "Cancelled: ONAA took the listing down after review."
    if state == "cancelled" and o.cancelled_by == "idle":
        return (f"Cancelled by ONAA after {deal_rules.IDLE_DEAL_DAYS} days with no activity. The item is back on "
                "sale; start a new offer if both sides still want the deal.")
    if state == "cancelled":
        return "Cancelled. The item is back on sale."
    accepted = _aware(o.accepted_at)
    if (role == "seller" and state == "arranging" and accepted is not None
            and utcnow() - accepted > dt.timedelta(days=STALE_DAYS)):
        return (f"No handoff agreed for {STALE_DAYS} days. Ask your user whether to release the item (deal_action "
                "cancel puts it back on sale) or keep waiting.")
    if state == "arranged":
        return ("Both sides agreed the terms. After the handoff, mark it done (deal_action done); either side can "
                "still cancel. " + DEAL_NOTE)
    if arr and role not in (arr.get("agreed_by") or []):
        return ("The other side proposed terms (arrangement). Show them to your user; agree, or propose different "
                "terms. " + DEAL_NOTE)
    if arr:
        return "Waiting for the other side to agree your proposed terms, or propose others. " + DEAL_NOTE
    return ("Deal accepted and the item reserved. Arrange how the buyer pays (options.payment_methods) and how, when "
            "and where it changes hands with deal_action propose, or write a message (history). Share a phone "
            "number, email or address only in a message, when your user wants to. " + DEAL_NOTE)


# ------------------------------------------------------------------ actions

def _rules_for(action: str, terms: dict[str, Any], text_shares: bool, address: bool) -> list[str]:
    rules: list[str] = []
    if action in ("propose", "agree"):
        if any(terms.get(f) for f in PAYMENT_FIELDS):
            rules.append("choose_payment")
        if any(terms.get(f) for f in HANDOFF_FIELDS):
            rules.append("set_handoff")
    rules += {"cancel": ["cancel_deal"], "done": ["confirm_done"]}.get(action, [])
    if text_shares:
        rules.append("share_contact")
    if address:
        rules.append("share_address")
    return rules


def _ask_text(action: str, terms: dict[str, Any], body: DealActIn, it: PilotItem, found: list[str]) -> str:
    what = {
        "propose": "Propose these terms for '{t}': {terms}?",
        "agree": "Agree these terms for '{t}': {terms}?",
        "message": "Send this message to the other side of '{t}'?",
        "cancel": "Cancel the deal for '{t}'? The item goes back on sale.",
        "done": "Mark the deal for '{t}' as done (received, or handed over and paid)?",
        "report": "Report the other side of '{t}' to ONAA ({r})?",
        "block": "Block the other side of '{t}'? Their messages and offers stop, and an unfinished deal is cancelled.",
    }[action]
    shown = ", ".join(f"{k}={v}" for k, v in terms.items() if v) or "none"
    out = what.format(t=it.title, terms=shown, r=body.reason or "other")
    if found:
        out += f" The text shares your {', '.join(found)}."
    if body.shares_address:
        out += " The text shares an address."
    return out


def _block(session, m: PilotMember, other_id: str) -> None:
    peer = f"onaa-hosted:{other_id}"
    conv = session.scalar(select(PilotConversation).where(PilotConversation.member_id == m.id,
                                                          PilotConversation.peer_agent_id == peer))
    if conv is None:
        conv = PilotConversation(member_id=m.id, peer_agent_id=peer, peer_member_id=other_id, state="blocked")
        session.add(conv)
    conv.state, conv.updated_at = "blocked", utcnow()


def blocked_between(session, a: str, b: str) -> bool:
    """Either member blocked the other (from a deal or in messaging)."""
    # A deal block is keyed "onaa-hosted:<id>", a messaging block by the agent card URL; both carry peer_member_id.
    return session.scalar(select(PilotConversation.id).where(
        PilotConversation.state == "blocked",
        or_((PilotConversation.member_id == a) & or_(PilotConversation.peer_agent_id == f"onaa-hosted:{b}",
                                                     PilotConversation.peer_member_id == b),
            (PilotConversation.member_id == b) & or_(PilotConversation.peer_agent_id == f"onaa-hosted:{a}",
                                                     PilotConversation.peer_member_id == a)))
        .limit(1)) is not None


def _release(session, request: Request, o: PilotOffer, it: PilotItem) -> None:
    """A cancelled deal puts what it took back on sale: the whole listing, or the units of a split deal (2026-11-20).
    A shopping run it filled opens again."""
    if o.split:
        it.quantity, it.updated_at = (it.quantity or 0) + (o.units or 0), utcnow()
        if it.status == "sold":
            it.status = "available"
    else:
        _set_item(session, request, it, "available")
    if o.shopping_id:
        from ..models import PilotShopping

        run = session.get(PilotShopping, o.shopping_id)
        if run is not None and run.status == "filled":
            run.status, run.updated_at = "open", utcnow()


def _set_item(session, request: Request, it: PilotItem, status: str) -> None:
    if it.status == "reserved":
        it.status, it.updated_at = status, utcnow()
        if status == "sold":
            it.links = None  # listing links live only while it is on sale (founder 2026-11-20)
        if status == "available":
            from .pilot_reports import recheck_item

            recheck_item(session, it)
        seller = session.get(PilotMember, it.seller_id)
        if seller is not None:
            hosting.sync_listing(session, request.app.state.settings, seller)


@router.post("/deals/{offer_id}")
def deal_action(offer_id: str, body: DealActIn, m: Member, session: Db, request: Request):
    from .pilot import _offer_out

    o = session.get(PilotOffer, offer_id)
    if o is None or m.id not in (o.buyer_id, o.seller_id) or o.status != "accepted":
        raise HTTPException(404, "deal not found")
    role = "buyer" if o.buyer_id == m.id else "seller"
    other_id = o.seller_id if role == "buyer" else o.buyer_id
    it = session.get(PilotItem, o.item_id)
    state = o.deal_state or "arranging"
    a = body.action
    if a in ("report", "block"):
        if state not in (*LIVE, "done", "cancelled"):
            raise HTTPException(409, f"deal is {state}")
    elif state not in LIVE:
        raise HTTPException(409, f"deal is {state}")
    terms = {k: v for k, v in (body.terms.model_dump() if body.terms else {}).items() if v not in (None, "")}
    for k in ("payment_detail", "handoff_time", "handoff_place"):
        if k in terms:
            terms[k] = _clean(terms[k])
    text = _clean(body.text)

    # validate before asking anyone
    if a == "propose":
        if not terms:
            raise HTTPException(422, "propose needs terms (payment_method, trade_method, handoff_time, ...)")
        if "payment_method" in terms and _split(it.payment_methods) and \
                terms["payment_method"] not in _split(it.payment_methods):
            raise HTTPException(422, f"this listing accepts payment by {', '.join(_split(it.payment_methods))}")
        if "trade_method" in terms and _split(it.trade_methods) and \
                terms["trade_method"] not in _split(it.trade_methods):
            raise HTTPException(422, f"this listing trades by {', '.join(_split(it.trade_methods))}")
    if a == "agree":
        arr = o.arrangement
        if not arr:
            raise HTTPException(409, "nothing proposed yet: propose terms")
        if role in (arr.get("agreed_by") or []):
            raise HTTPException(409, "you already agreed these terms")
        if body.proposal_at is not None and body.proposal_at != arr.get("at"):
            raise HTTPException(409, "the other side proposed new terms since: show your user the current "
                                     "arrangement and ask again")
        terms = arr.get("terms") or {}
    if a == "cancel" and (them := ("seller" if role == "buyer" else "buyer")) in (o.done_by or []):
        raise HTTPException(409, f"the {them} already marked this deal done; if something went wrong, report it")
    if a == "report" and any(r.get("by") == role for r in (o.reports or [])):
        return _offer_out(o, session, m) | {"done": True, "already_reported": True}
    if a == "message" and not text:
        raise HTTPException(422, "message needs text")
    if text and (err := links.too_many(text)):
        raise HTTPException(422, err)
    if a == "report" and body.reason is None:
        raise HTTPException(422, f"report needs a reason: {', '.join(REPORT_REASONS)}")
    found = _personal_details(" ".join(filter(None, [text, *(str(v) for v in terms.values())])))

    ask = _ask_text(a, terms, body, it, found)
    if a in ("report", "block"):  # never on the assistant's own, whatever the rules say
        held = deal_rules.hold(m, [], ask) if not body.user_approved else None
    else:
        held = deal_rules.needs_approval(m, _rules_for(a, terms, bool(found), body.shares_address and bool(text)),
                                         body.user_approved, ask=ask)
        if held is None and a == "agree" and body.user_approved and body.proposal_at is None \
                and deal_rules.needs_approval(m, _rules_for(a, terms, bool(found), False), False, ask=ask):
            raise HTTPException(422, "agree with user_approved needs proposal_at (from arrangement): the terms "
                                     "your user saw")
        if held is not None and a == "agree":
            held["proposal_at"] = (o.arrangement or {}).get("at")
    if held is not None:
        if a not in ("report", "block"):
            o.waiting = {**(o.waiting or {}), role: {"step": a, "at": utcnow().isoformat()}}
        return held

    if a in ("propose", "agree"):
        apply_terms(session, o, role, a, terms, text, found, personal_text=bool(text and body.shares_address))
        session.flush()
        return _offer_out(o, session, m) | {"done": True, "note": UNTRUSTED_NOTE}
    settings = session.info.get("settings")
    now = utcnow()
    waiting = dict(o.waiting or {})
    waiting.pop(role, None)
    o.waiting = waiting or None
    if a == "cancel":
        o.deal_state, o.cancelled_by = "cancelled", role
        _release(session, request, o, it)
    elif a == "done":
        o.done_by = list(dict.fromkeys([*(o.done_by or []), role]))
        if set(o.done_by) >= {"buyer", "seller"}:
            o.deal_state = "done"
            if not o.split:  # a deal on some units left the listing on sale with the rest
                _set_item(session, request, it, "sold")
    elif a == "report":
        o.reports = [*(o.reports or []), {"by": role, "reason": body.reason, "at": now.isoformat()}]
        audit(session, "pilot", m.id, "pilot.deal_reported", o.id, reason=body.reason, about=other_id)
    elif a == "block":
        _block(session, m, other_id)
        if state in LIVE:
            o.deal_state, o.cancelled_by = "cancelled", role
            _release(session, request, o, it)
        audit(session, "pilot", m.id, "pilot.deal_blocked", o.id, about=other_id)
    if a != "block":  # a block is silent to the other side, like in messaging
        ev = _event(role, "deal_" + a, None, text, settings)
        if text and (found or body.shares_address):
            ev["personal"] = True  # deleted PERSONAL_RETENTION_DAYS after the deal ends
        o.history = [*o.history, ev]
        _offer_event(session, o, other_id, "deal_" + a)
    o.updated_at = now
    session.flush()
    return _offer_out(o, session, m) | {"done": True, "note": UNTRUSTED_NOTE}


def apply_terms(session, o: PilotOffer, role: str, a: str, terms: dict[str, Any], text: str | None,
                found: list[str], *, personal_text: bool = False, by_agent: bool = False) -> None:
    """propose or agree terms on a live deal (rules already checked)."""
    now = utcnow()
    waiting = dict(o.waiting or {})
    waiting.pop(role, None)
    o.waiting = waiting or None
    if a == "propose":
        o.arrangement = {"terms": terms, "proposed_by": role, "agreed_by": [role], "at": now.isoformat(),
                         **({"personal": True} if found else {})}
        o.deal_state = "arranging"
    else:
        arr = dict(o.arrangement)
        arr["agreed_by"] = [*(arr.get("agreed_by") or []), role]
        o.arrangement = arr
        if set(arr["agreed_by"]) >= {"buyer", "seller"}:
            o.deal_state = "arranged"
    ev = _event(role, "deal_" + a, None, text, session.info.get("settings"))
    if text and (found or personal_text):
        ev["personal"] = True  # deleted PERSONAL_RETENTION_DAYS after the deal ends
    if by_agent:
        ev["by_agent"] = True
    o.history = [*o.history, ev]
    _offer_event(session, o, o.seller_id if role == "buyer" else o.buyer_id, "deal_" + a)
    o.updated_at = now
