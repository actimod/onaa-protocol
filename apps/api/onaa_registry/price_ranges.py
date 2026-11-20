"""Private price ranges (founder decision 2026-11-19, DP-PILOT-NO-SERVER-NEGOTIATION-01).

ONAA does not negotiate. A member's own AI (ChatGPT, Claude, or the member's own server agent) does the back and
forth through offers and deal actions; the server only relays them and enforces the member's deal rules. Because
a chat assistant forgets between its hourly checks, it can save the range its user gave ("sell for $50, down to
$35"; "buy it, up to $45") as a private note (models.PilotMandate). The server never acts on a range: it only shows
it back to the member's own AI (my_offers your_range, check_inbox my_price_ranges) and never to the other side, and
its deal rules keep anything the AI confirms alone inside it (deal_rules.allows).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import PilotAgentNote, PilotItem, PilotMandate, PilotMember, PilotOffer, PilotWant, utcnow

MAX_RANGES = 30  # active ranges per member
PRIVATE = ("Only your user and you (their AI) see it: ONAA never shows it to anyone else, not the other side and "
           "not other members, and never acts on it. You decide each offer, counter and accept yourself, inside it "
           "and within their deal rules.")
# The limit itself is allowed (founder: "100 or more"); amp retest 2026-11-20: ChatGPT said "strictly above 100",
# "101", and accepted the first offer far below asking.
MEANS = {"sell": "Your user accepts {p} or more ({p} itself included; never say 'above' it or a higher number). It "
                 "is the least they take, never below it, not a price to accept at once: when a first offer is "
                 "well under the asking price, counter at least once (e.g. asking 150, offer 110: counter about "
                 "135) before accepting.",
         "buy": "Your user pays {p} or less ({p} itself included; never say 'below' it or a lower number). It is "
                "the most they pay, never above it, not an opening offer: start below it and move up in steps."}
# What the AI tells its user after saving. "Saved privately" was unclear to the founder (bookshelf retest 2026-11-19).
SAY_TO_USER = ("Saved for you only: your price range is never shown to anyone else. Only I, your AI, use it when "
               "I answer offers.")


def range_for(session: Session, member_id: str, item_id: str, side: str) -> PilotMandate | None:
    return session.scalar(select(PilotMandate).where(
        PilotMandate.member_id == member_id, PilotMandate.item_id == item_id, PilotMandate.side == side,
        PilotMandate.status == "active").order_by(PilotMandate.created_at.desc()).limit(1))


def limit_for(session: Session, member_id: str, item_id: str, side: str) -> dict[str, Any] | None:
    """The member's own saved limit on this listing as {amount, currency}, for their deal rules only: auto confirm
    stays inside it (deal_rules.allows). The server still never makes, counters or accepts anything from it."""
    md = range_for(session, member_id, item_id, side)
    return None if md is None else {"amount": md.limit_price, "currency": md.currency}


def end(md: PilotMandate, reason: str) -> None:
    if md.status == "active":
        md.status, md.ended_reason, md.updated_at = "ended", reason[:40], utcnow()


def view(session: Session, md: PilotMandate) -> dict[str, Any]:
    it = session.get(PilotItem, md.item_id) if md.item_id else None
    w = session.get(PilotWant, md.want_id) if md.want_id else None
    out: dict[str, Any] = {"id": md.id, "side": md.side, "status": md.status, "currency": md.currency,
                           "terms": {k: v for k, v in (md.terms or {}).items() if k != "tried"},
                           "created_at": md.created_at.isoformat()}
    if md.side == "sell":
        out["lowest_price"] = md.limit_price
    else:
        out["highest_price"] = md.limit_price
    out["means"] = _means(md)
    if it is not None:
        out["item"] = {"id": it.id, "title": it.title, "price": it.price, "status": it.status}
    if w is not None:
        out["want"] = {"id": w.id, "title": w.title, "status": w.status}
    if md.status != "active":
        out["ended_reason"] = md.ended_reason
    return out


def for_offer(session: Session, o: PilotOffer, member_id: str, role: str) -> dict[str, Any] | None:
    """The member's own range on this offer's listing, for their own AI only."""
    md = range_for(session, member_id, o.item_id, "sell" if role == "seller" else "buy")
    if md is None:
        return None
    out = {"range_id": md.id, "terms": {k: v for k, v in (md.terms or {}).items() if k != "tried"}, "note": PRIVATE}
    out["lowest_price" if md.side == "sell" else "highest_price"] = md.limit_price
    out["means"] = _means(md)
    return out


def _means(md: PilotMandate) -> str:
    return MEANS[md.side].format(p=f"{md.limit_price} {md.currency}")


def active(session: Session, m: PilotMember) -> list[dict[str, Any]]:
    return [view(session, md) for md in session.scalars(
        select(PilotMandate).where(PilotMandate.member_id == m.id, PilotMandate.status == "active")
        .order_by(PilotMandate.updated_at.desc()).limit(MAX_RANGES))]


def end_for_item(session: Session, item_id: str, reason: str) -> None:
    for md in session.scalars(select(PilotMandate).where(PilotMandate.item_id == item_id,
                                                         PilotMandate.status == "active")):
        end(md, reason)


def purge_notes(session: Session, settings, at: dt.datetime) -> int:
    """Notes written by the retired server negotiator: kept no longer than chat messages, then deleted."""
    days = getattr(settings, "pilot_message_retention_days", 30) or 30
    return session.execute(delete(PilotAgentNote).where(
        PilotAgentNote.created_at < at - dt.timedelta(days=days))).rowcount or 0
