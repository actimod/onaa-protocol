"""Private price ranges: the member's own AI saves the range its user gave, so it can decide offers within it at
its next check (..price_ranges). ONAA never negotiates or acts on a range (DP-PILOT-NO-SERVER-NEGOTIATION-01).

POST /v1/market/ranges          save (or replace) the range for a listing (yours: sell; someone else's: buy) or a want
GET  /v1/market/ranges          your active ranges
DELETE /v1/market/ranges/{id}   remove one
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .. import price_ranges
from ..logic import audit
from ..models import PilotItem, PilotMandate, PilotWant
from .pilot import (
    PAYMENT_METHODS,
    TRADE_METHODS,
    Db,
    Member,
    _clean,
    _personal_details,
    _with_checks,
    pilot_enabled,
)

router = APIRouter(prefix="/v1/market", tags=["pilot"], dependencies=[Depends(pilot_enabled)])

HOW = ("ONAA does not negotiate for your user. You (their AI) do: answer offers with respond_offer, make offers with "
       "make_offer and settle payment and handoff with deal_action, inside this range and your user's deal rules, "
       "whenever you are active: when they talk to you and at their hourly check at minute :00. While the other side "
       "is online, keep going with wait_for_updates (live.keep_waiting) to settle it in one sitting.")


class RangeIn(BaseModel):
    item_id: str | None = Field(default=None, max_length=40, description="your listing (sell) or one to buy")
    want_id: str | None = Field(default=None, max_length=40, description="your want")
    lowest_price: int | None = Field(default=None, ge=0, le=1_000_000_000, description="sell: the least accepted")
    highest_price: int | None = Field(default=None, ge=0, le=1_000_000_000, description="buy: the most paid")
    payment_methods: list[Literal[PAYMENT_METHODS]] | None = Field(  # type: ignore[valid-type]
        default=None, max_length=7, description="acceptable ways to pay")
    payment_detail: str | None = Field(default=None, max_length=120, description="e.g. Venmo; no account numbers")
    trade_methods: list[Literal[TRADE_METHODS]] | None = Field(  # type: ignore[valid-type]
        default=None, max_length=3, description="acceptable ways to hand over")
    handoff_time: str | None = Field(default=None, max_length=120, description="e.g. weekday evenings")
    handoff_place: str | None = Field(default=None, max_length=200, description="a public place, or shipping")


def _terms_in(body: RangeIn) -> dict[str, Any]:
    t: dict[str, Any] = {}
    if body.payment_methods:
        t["payment_methods"] = list(dict.fromkeys(body.payment_methods))
    if body.trade_methods:
        t["trade_methods"] = list(dict.fromkeys(body.trade_methods))
    for k in ("payment_detail", "handoff_time", "handoff_place"):
        v = _clean(getattr(body, k))
        if v:
            t[k] = v
    found = _personal_details(" ".join(str(v) for v in t.values()))
    if found:
        raise HTTPException(422, f"keep personal details out of the range's terms ({', '.join(found)}): your user "
                                 "shares those in a deal message, by choice")
    return t


@router.post("/ranges", status_code=201)
def save(body: RangeIn, m: Member, session: Db):
    if (body.item_id is None) == (body.want_id is None):
        raise HTTPException(422, "give item_id (a listing) or want_id (your want), not both")
    live = session.scalar(select(func.count()).select_from(PilotMandate).where(
        PilotMandate.member_id == m.id, PilotMandate.status == "active")) or 0
    terms = _terms_in(body)
    if body.item_id is not None:
        it = session.get(PilotItem, body.item_id)
        if it is None or it.status in ("removed", "under_review") and it.seller_id != m.id:
            raise HTTPException(404, "item not found")
        if it.status in ("sold", "removed", "under_review"):
            raise HTTPException(409, f"item is {it.status}")
        side = "sell" if it.seller_id == m.id else "buy"
        if side == "sell":
            low = body.lowest_price if body.lowest_price is not None else it.floor_price
            if low is None:
                raise HTTPException(422, "lowest_price is needed: the least your user accepts (ask them)")
            if low > it.price:
                raise HTTPException(422, f"lowest_price is above the listed price ({it.price} {it.currency})")
            md = PilotMandate(member_id=m.id, side="sell", item_id=it.id, currency=it.currency, limit_price=low,
                              start_price=it.price, terms=terms or None)
        else:
            if body.highest_price is None:
                raise HTTPException(422, "highest_price is needed: the most your user pays (ask them)")
            md = PilotMandate(member_id=m.id, side="buy", item_id=it.id, currency=it.currency,
                              limit_price=body.highest_price, terms=terms or None)
        replaced = price_ranges.range_for(session, m.id, it.id, side)
    else:
        w = session.get(PilotWant, body.want_id)
        if w is None or w.buyer_id != m.id:
            raise HTTPException(404, "want not found")
        if w.status != "open":
            raise HTTPException(409, f"want is {w.status}")
        high = body.highest_price if body.highest_price is not None else w.max_price
        if high is None:
            raise HTTPException(422, "highest_price is needed: the most your user pays (ask them)")
        md = PilotMandate(member_id=m.id, side="buy", want_id=w.id, currency=w.currency, limit_price=high,
                          terms=terms or None)
        replaced = session.scalar(select(PilotMandate).where(
            PilotMandate.member_id == m.id, PilotMandate.want_id == w.id, PilotMandate.status == "active").limit(1))
    if replaced is not None:
        price_ranges.end(replaced, "replaced")
    elif live >= price_ranges.MAX_RANGES:
        raise HTTPException(409, f"at most {price_ranges.MAX_RANGES} saved ranges; remove some first")
    session.add(md)
    session.flush()
    audit(session, "pilot", m.id, "pilot.range_saved", md.id, side=md.side, item=md.item_id, want=md.want_id)
    return _with_checks({"saved": True, "range": price_ranges.view(session, md), "private": price_ranges.PRIVATE,
                         "how_it_works": HOW, "say_to_your_user": price_ranges.SAY_TO_USER,
            "next_step": ("Tell your user in their language, in plain words like say_to_your_user (not \"saved "
                          "privately\"), that the range is for them only and never shown to anyone else, and "
                          "that you (not ONAA) will answer offers within it when you are active, at their hourly "
                          "check and while they chat with you; under their deal rules you ask before confirming a "
                          "price unless they let you confirm up to a limit (update_deal_rules).")}, m)


@router.get("/ranges")
def overview(m: Member, session: Db):
    act = price_ranges.active(session, m)
    return {"active": act, "summary": f"{len(act)} saved range(s).", "private": price_ranges.PRIVATE,
            "how_it_works": HOW}


@router.delete("/ranges/{range_id}")
def remove(range_id: str, m: Member, session: Db):
    md = session.get(PilotMandate, range_id)
    if md is None or md.member_id != m.id:
        raise HTTPException(404, "range not found")
    price_ranges.end(md, "removed")
    return {"removed": True, "range": price_ranges.view(session, md)}
