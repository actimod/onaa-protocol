"""Per-member deal rules: what a member's assistant may do on its own after negotiating, and what waits for the
member (founder decision 2026-11-19).

For people (not server agents), confirm_deal is per item since 2026-11-20 (DP-PILOT-PER-ITEM-LIMIT-01): the AI may
confirm a price alone only inside that item's saved price range, and the account-level confirm_deal mode, limits
and only_in_range below apply to server agents only. PATCH /rules refuses them for people.

Every rule is ``auto`` (the assistant may do it alone) or ``ask`` (the member approves each time). All default to
``ask``. ``confirm_deal`` can also carry price limits, by side (retest 2026-11-19: one limit read as "up to" made a
seller's limit a ceiling on what it could sell for): ``confirm_deal_max`` covers buying up to that amount and
``confirm_sale_min`` covers selling at that amount or more; anything outside is ``ask`` again. A member's saved
price range on that listing (price_ranges) also bounds what ``auto`` covers, and ``only_in_range`` limits ``auto``
to listings that have a range, so a limit given for one purchase does not carry over to every later deal.

Enforcement is on the server, for every door (MCP connector, REST, the hosted A2A agent): an action under ``ask``
is held unless the call says the member approved it (``user_approved=true``; for a self-signed-up server agent,
that its operator's rules allow it). The server cannot see the person, so like ``confirmed_sharing`` this makes
the assistant stop and ask, and records who said what.

Loosening a rule (anything to ``auto``, a higher buying limit, a lower selling limit, turning ``only_in_range``
off) returns a one-time confirm link the person opens (rules_confirm.py), since an assistant misled by someone's
message could set ``user_approved`` itself. One case applies at once on ``user_approved`` and the answer tells the
person what changed (founder decision 2026-11-19, after trying the link): auto confirm only inside each listing's
saved price range (``only_in_range``), the usual "you may sell this at X or more". Tightening applies at once.
A self-signed-up server agent has no person in the chat, so its operator's approval (user_approved)
still loosens its rules.

Each side of a deal follows its own rules. The other side never sees them: it only sees that a step is waiting
for the other member's confirmation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from typing import Any

from .models import PilotMember, utcnow

PENDING = "_pending"  # in member.deal_rules: a loosening waiting for the person's confirm link
CONFIRM_MINUTES = 30

RULES: dict[str, str] = {
    "confirm_deal": "Make, counter or accept an offer, approve an order (a binding price). For people this is set "
                    "per item, not here: your AI asks for each item whether it may close the deal alone and up to "
                    "(buying) or from (selling) what price, and saves that as the item's price range; with no range "
                    "it asks you before every price.",
    "choose_payment": "Propose or agree how the buyer pays (a payment method from the listing, and optionally an "
                      "external payment or escrow provider).",
    "share_contact": "Share your saved contact detail, or a message with personal details, with the other side "
                     "of a deal.",
    "share_address": "Share a delivery address with the other side of a deal.",
    "set_handoff": "Propose or agree how, when and where the item or service changes hands.",
    "cancel_deal": "Cancel an agreed deal (the item goes back on sale).",
    "confirm_done": "Mark the deal done (buyer: received it; seller: handed over and paid).",
}
VALUES = ("auto", "ask")
LIMITS = ("confirm_deal_max", "confirm_sale_min")  # buying up to / selling at or above, each {amount, currency}
DEFAULTS: dict[str, Any] = {k: "ask" for k in RULES}

HOLD_NEXT_STEP = ("Nothing was done. Ask your user exactly ask_your_user, in their language, with every amount in "
                  "bold. Only if they say yes in their reply, call again with the same arguments and "
                  "user_approved=true. If your app's own permission check then blocks the call (ONAA did not), give "
                  "your user one exact sentence to type that names the action, the item and the amount, e.g. "
                  "\"Send a **$175** offer on Used road bike\", and try again after they send it. For prices: to stop "
                  "asking on an item, your user can give you a limit for that item (save_price_range).")
AGENT_HOLD_NEXT_STEP = ("Nothing was done. Do it only if your operator's rules allow it; then call again with "
                        "user_approved=true.")
WAITING_FOR_OTHER = "Waiting for the other member to confirm this step with their assistant."


def rules_of(member: PilotMember) -> dict[str, Any]:
    stored = member.deal_rules or {}
    out = {k: (stored.get(k) if stored.get(k) in VALUES else DEFAULTS[k]) for k in RULES}
    for key in LIMITS:
        limit = stored.get(key)
        if (isinstance(limit, dict) and isinstance(limit.get("amount"), int)
                and not isinstance(limit.get("amount"), bool) and isinstance(limit.get("currency"), str)):
            out[key] = {"amount": limit["amount"], "currency": limit["currency"]}
    if stored.get("only_in_range") is True:
        out["only_in_range"] = True
    return out


def _within(amount: int, currency: str | None, limit: dict, side: str) -> bool:
    if currency is None or currency.upper() != limit["currency"].upper():
        return False
    return amount <= limit["amount"] if side == "buy" else amount >= limit["amount"]


def allows(member: PilotMember, rule: str, *, amount: int | None = None, currency: str | None = None,
           side: str = "buy", range_limit: dict | None = None) -> bool:
    """True when the member's assistant may do this alone (rule auto and, for confirm_deal, within every limit that
    applies). side: "buy" or "sell", the member's side of this deal. range_limit: {amount, currency} from the
    member's saved price range on this listing (highest price when buying, lowest when selling), if any."""
    if rule == "confirm_deal" and member.kind != "agent":
        # Founder decision 2026-11-20: no account-wide price limit for people. For each item the AI asks whether it
        # may close the deal alone and up to / from what price; that answer is the saved range on the item, and
        # without one every price is asked. Old account limits ($45, $50 from earlier tests) no longer apply.
        return (range_limit is not None and amount is not None
                and _within(amount, currency, range_limit, side))
    r = rules_of(member)
    if r[rule] != "auto":
        return False
    if rule != "confirm_deal":
        return True
    if r.get("only_in_range") and range_limit is None:
        return False
    limits = [range_limit] if range_limit is not None else []
    if side == "buy" and "confirm_deal_max" in r:
        limits.append(r["confirm_deal_max"])
    elif side == "sell":
        if "confirm_sale_min" in r:
            limits.append(r["confirm_sale_min"])
        elif "confirm_deal_max" in r and range_limit is None:
            return False  # an old single limit says nothing safe about selling: ask
    if not limits:
        return True
    if amount is None:  # a limit the step cannot be checked against means ask, not "no limit"
        return False
    return all(_within(amount, currency, lim, side) for lim in limits)


def needs_approval(member: PilotMember, rules: list[str], user_approved: bool, *, ask: str,
                   amount: int | None = None, currency: str | None = None, side: str = "buy",
                   range_limit: dict | None = None) -> dict[str, Any] | None:
    """None when the action may go ahead; else the hold answer (HTTP 200, nothing done)."""
    held = [r for r in dict.fromkeys(rules)
            if not allows(member, r, amount=amount, currency=currency, side=side, range_limit=range_limit)]
    if not held or user_approved:
        return None
    return hold(member, held, ask)


def hold(member: PilotMember, rules: list[str], ask: str) -> dict[str, Any]:
    agent = member.kind == "agent"
    return {"done": False, "needs_user_approval": True, "rules": rules,
            "ask_your_user": None if agent else ask,
            "next_step": AGENT_HOLD_NEXT_STEP if agent else HOLD_NEXT_STEP}


def view(member: PilotMember) -> dict[str, Any]:
    return {"rules": rules_of(member), "meaning": RULES,
            "note": "auto = your assistant may do it alone; ask = it asks you each time (the default). The other "
                    "side never sees these rules, only that a step waits for you. Turning a rule to auto (or "
                    "loosening a limit) needs a confirm link you open yourself, except letting your assistant confirm "
                    "only inside each listing's saved price range, which applies when you say yes."}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def update(member: PilotMember, changes: dict[str, Any], user_approved: bool, *, base_url: str = "",
           confirmed_by_person: bool = False) -> dict[str, Any] | None:
    """Apply rule changes. Tightening applies at once. Loosening (anything to auto, or a higher/new price limit)
    returns a one-time confirm link for the person (people) or needs user_approved (server agents);
    confirmed_by_person is set only by the confirm page."""
    current = rules_of(member)
    new = {**current, **{k: v for k, v in changes.items() if k in RULES}}
    for key in LIMITS:
        if key in changes:
            if changes[key] is None:
                new.pop(key, None)
            else:
                new[key] = changes[key]
    if "only_in_range" in changes:
        if changes["only_in_range"]:
            new["only_in_range"] = True
        else:
            new.pop("only_in_range", None)
    loosens = [k for k in RULES if new[k] == "auto" and current[k] != "auto"]
    if new["confirm_deal"] == "auto" and "confirm_deal" not in loosens:
        for key, looser in (("confirm_deal_max", lambda a, b: a > b), ("confirm_sale_min", lambda a, b: a < b)):
            old_lim, new_lim = current.get(key), new.get(key)
            if old_lim is not None and (new_lim is None or new_lim["currency"].upper() != old_lim["currency"].upper()
                                        or looser(new_lim["amount"], old_lim["amount"])):
                loosens.append(key)
        if current.get("only_in_range") and not new.get("only_in_range"):
            loosens.append("only_in_range")
    if loosens and member.kind == "agent" and not user_approved:
        return {"done": False, "needs_user_approval": True, "rules": loosens, "ask_your_user": None,
                "next_step": AGENT_HOLD_NEXT_STEP}
    if loosens and member.kind != "agent" and not confirmed_by_person and not _needs_link(new, loosens):
        if not user_approved:
            return hold(member, loosens, "May I change your deal rules so I can do this on my own: "
                                         f"{', '.join(loosens)}? ({_describe(new)})")
        member.deal_rules = new
        member.auto_confirm = new["confirm_deal"] == "auto"
        return {"done": True, "rules_loosened": loosens, "rules": rules_of(member),
                "tell_your_user": f"Your deal rules changed: {_describe(new)}. Say 'set it back to ask' any time.",
                "next_step": "Tell your user tell_your_user in their language before you do anything else."}
    if loosens and member.kind != "agent" and not confirmed_by_person:
        token = secrets.token_urlsafe(24)
        expires = utcnow() + dt.timedelta(minutes=CONFIRM_MINUTES)
        member.deal_rules = {**(member.deal_rules or {}), PENDING: {
            "hash": _token_hash(token), "changes": changes, "rules": loosens, "expires": expires.isoformat()}}
        url = f"{base_url.rstrip('/')}/rules/confirm/{member.id}.{token}"
        names = ", ".join(loosens)
        return {"done": False, "needs_user_confirmation": True, "rules": loosens, "confirm_url": url,
                "expires_in_minutes": CONFIRM_MINUTES,
                "ask_your_user": f"To let me do this on my own from now on ({names}), open this link and press "
                                 f"Confirm: {url} . Nothing changes until you do.",
                "next_step": "Give your user confirm_url exactly as it is, in their language, and stop. Never open "
                             "it yourself; user_approved does not loosen rules. Rules that only make you ask more "
                             "apply at once without a link."}
    member.deal_rules = new
    member.auto_confirm = new["confirm_deal"] == "auto"
    return None


def _needs_link(new: dict[str, Any], loosens: list[str]) -> bool:
    """Founder decision 2026-11-19 (after trying the link): letting the assistant confirm alone inside each
    listing's saved price range (only_in_range) applies at once on the person's yes. Everything else that loosens
    (auto confirm with no range, an account-wide limit, any other rule to auto) keeps the confirm link."""
    return not (new.get("only_in_range") and set(loosens) <= {"confirm_deal", *LIMITS})


def _describe(rules: dict[str, Any]) -> str:
    auto = [k for k in RULES if rules.get(k) == "auto"]
    parts = [f"auto: {', '.join(auto) or 'nothing'}"]
    for key, word in (("confirm_deal_max", "buy alone up to"), ("confirm_sale_min", "sell alone at or above")):
        if rules.get(key):
            parts.append(f"{word} {rules[key]['amount']} {rules[key]['currency']}")
    if rules.get("only_in_range"):
        parts.append("only inside saved price ranges")
    return "; ".join(parts)


def pending(member: PilotMember, token: str) -> dict[str, Any] | None:
    """The loosening waiting behind this confirm token, if the token is right and not expired."""
    p = (member.deal_rules or {}).get(PENDING)
    if not isinstance(p, dict) or not secrets.compare_digest(p.get("hash", ""), _token_hash(token)):
        return None
    try:
        expires = dt.datetime.fromisoformat(p["expires"])
    except (KeyError, TypeError, ValueError):
        return None
    return p if expires > utcnow() else None


def confirm(member: PilotMember, token: str) -> bool:
    """Apply the pending loosening (the person opened the link and pressed Confirm). One use."""
    p = pending(member, token)
    if p is None:
        return False
    update(member, p["changes"], True, confirmed_by_person=True)  # sets deal_rules anew, dropping the pending entry
    return True


# ------------------------------------------------------------------ deal text: kept only while needed

PERSONAL_RETENTION_DAYS = 30
IDLE_DEAL_DAYS = 60
REMOVED = "[removed: deleted 30 days after the deal ended]"
FREE_TEXT_TERMS = ("payment_detail", "handoff_time", "handoff_place")


def _in_pages(session, query, size: int = 500):
    """Every row of query, a page at a time in id order. A single LIMIT without order re-read the same 2,000 closed
    offers on every run once there were more, so newer ones were never cleaned (review 2026-11-19)."""
    from .models import PilotOffer

    last = ""
    while True:
        page = session.scalars(query.where(PilotOffer.id > last).order_by(PilotOffer.id).limit(size)).all()
        yield from page
        if len(page) < size:
            return
        last = page[-1].id


def purge_personal(session, at) -> int:
    """Delete the free text of offers and deals (every history message, and the payment detail, handoff time and
    place of the terms) once the offer closed or the deal was done or cancelled PERSONAL_RETENTION_DAYS ago
    (founder decision 2026-11-19, after the review: not only the messages flagged as personal). Amounts, actions
    and times stay, for the track record. Returns how many texts were deleted."""
    import datetime as dt

    from sqlalchemy import or_, select

    from .models import PilotOffer

    cutoff = at - dt.timedelta(days=PERSONAL_RETENTION_DAYS)
    closed = (PilotOffer.updated_at < cutoff,
              or_(PilotOffer.status.in_(("declined", "withdrawn")), PilotOffer.deal_state.in_(("done", "cancelled"))))
    n = 0
    for o in _in_pages(session, select(PilotOffer).where(*closed)):
        arr = o.arrangement or {}
        terms = arr.get("terms") or {}
        if "personal" in arr or any(terms.get(k) not in (None, "", REMOVED) for k in FREE_TEXT_TERMS):
            n += sum(1 for k in FREE_TEXT_TERMS if terms.get(k) not in (None, "", REMOVED))
            o.arrangement = {**{k: v for k, v in arr.items() if k != "personal"},
                             "terms": {k: (REMOVED if k in FREE_TEXT_TERMS and v not in (None, "") else v)
                                       for k, v in terms.items()}}
        hist = o.history or []
        if not any(e.get("message") not in (None, "", REMOVED) for e in hist):
            continue
        new = []
        for e in hist:
            if e.get("message") not in (None, "", REMOVED):
                e = {**e, "message": REMOVED}
                n += 1
            new.append(e)
        o.history = new  # updated_at stays: the deal itself did not change
    return n


def cancel_idle(session, settings, at) -> int:
    """Cancel deals with no activity for IDLE_DEAL_DAYS that are still being arranged (founder decision
    2026-11-19): the item goes back on sale, both sides are told, and the deal's text is deleted
    PERSONAL_RETENTION_DAYS later like any ended deal. Returns how many were cancelled."""
    import datetime as dt

    from sqlalchemy import or_, select

    from . import hosting, webhooks
    from .models import PilotItem, PilotMember, PilotOffer

    cutoff = at - dt.timedelta(days=IDLE_DEAL_DAYS)
    q = select(PilotOffer).where(PilotOffer.status == "accepted", PilotOffer.updated_at < cutoff,
                                 or_(PilotOffer.deal_state.is_(None),
                                     PilotOffer.deal_state.in_(("arranging", "arranged"))))
    n = 0
    for o in list(_in_pages(session, q)):
        o.deal_state, o.cancelled_by, o.waiting, o.updated_at = "cancelled", "idle", None, at
        o.history = [*(o.history or []), {"by": "onaa", "action": "deal_cancelled_idle", "at": at.isoformat()}]
        it = session.get(PilotItem, o.item_id)
        if o.shopping_id:  # a shopping run this deal filled opens again (2026-11-20)
            from .models import PilotShopping

            run = session.get(PilotShopping, o.shopping_id)
            if run is not None and run.status == "filled":
                run.status, run.updated_at = "open", at
        if it is not None and o.split:  # a deal on some units gives them back; the listing stayed on sale
            it.quantity, it.updated_at = (it.quantity or 0) + (o.units or 0), at
        elif it is not None and it.status == "reserved":
            it.status, it.updated_at = "available", at
            from .routes.pilot_reports import recheck_item

            recheck_item(session, it)
            seller = session.get(PilotMember, it.seller_id)
            if seller is not None:
                hosting.sync_listing(session, settings, seller)
        for to in (o.buyer_id, o.seller_id):
            webhooks.emit(session, to, "offer.updated", {"offer_id": o.id, "item_id": o.item_id,
                                                         "action": "deal_cancelled_idle", "status": o.status,
                                                         "fetch": "GET /v1/market/offers?state=all"})
        n += 1
    return n
