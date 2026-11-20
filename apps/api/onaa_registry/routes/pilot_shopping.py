"""Shopping runs: one buyer's AI negotiating with several sellers at once (founder decisions 2026-11-20).

A run holds what the member asked their own AI for ("10 folding chairs, at most $10 each with shipping"): a target
quantity, an optional private per-unit limit for the whole run (shipping included), and whether buying fewer than
the target is fine. Offers made inside a run may be for some units of a listing. The server keeps three promises:

1. At most MAX_PARALLEL open offers per run (founder: 5 sellers at once).
2. Units on open offers plus units already bought never exceed the target, so several sellers accepting at the same
   moment cannot make the member buy more than they asked for, and no seller sees an accepted deal taken back.
3. When the target is filled, the run's other open offers are withdrawn and their sellers are told, without prices.

ONAA still never picks, offers, counters or accepts anything itself (DP-PILOT-NO-SERVER-NEGOTIATION-01): the
member's AI does, inside their deal rules. The run's per-unit limit only bounds what that AI may confirm alone.
Rule 11 (founder): another member's price or offer is never used to bargain, not even a real one.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import PilotItem, PilotMember, PilotOffer, PilotShopping, utcnow
from .pilot import Db, Member, _clean, _split

router = APIRouter(prefix="/v1/market", tags=["pilot"], include_in_schema=False)

MAX_PARALLEL = 5  # open offers per run (founder 2026-11-20: "동시 협상이 5곳 까지")
ASK_AGAIN_DAYS = 3  # founder 2026-11-20: ask again when the target is not filled after 3 days
MAX_OPEN_RUNS = 10
LIVE_DEAL = ("arranging", "arranged", "done")

RUN_STEP = (
    "Search with search_items (sort=total, or unit_total for several units), compare the listings for your user in one "
    "short table, then make offers with make_offer(item_id, amount, shopping_id, units, includes_shipping) to up to "
    f"{MAX_PARALLEL} sellers at once. Open offers never add up to more than units_needed, so you cannot buy too many; "
    "when the target is filled the other open offers are withdrawn for you. Never tell a seller another seller's "
    "price or offer, not even a real one. Do not announce that you compare several sellers; if a seller asks, say "
    "truthfully that you do, without prices.")


class ShoppingIn(BaseModel):
    title: str = Field(min_length=2, max_length=120, description="what your user wants, e.g. 'folding chairs'")
    currency: str = Field(min_length=3, max_length=3)
    target_quantity: int = Field(default=1, ge=1, le=1000)
    unit_limit: int | None = Field(
        default=None, ge=0, le=1_000_000_000,
        description="highest total per unit, shipping included, your AI may agree alone; leave out to ask each price")
    partial_ok: bool | None = Field(default=None, description="may it buy fewer than the target")

    @field_validator("currency")
    @classmethod
    def _cur(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("currency must be a 3-letter code")
        return v.upper()


class ShoppingPatch(BaseModel):
    target_quantity: int | None = Field(default=None, ge=1, le=1000)
    unit_limit: int | None = Field(default=None, ge=0, le=1_000_000_000)
    clear_unit_limit: bool = False
    partial_ok: bool | None = None
    status: Literal["ended"] | None = None


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return t.replace(tzinfo=dt.UTC) if t is not None and t.tzinfo is None else t


def units_of(o: PilotOffer, it: PilotItem | None) -> int:
    """Units an offer is for: its units, else the listing's whole quantity (1 when not stated)."""
    if o.units:
        return o.units
    return (it.quantity if it is not None and it.quantity else 1)


def bought(session: Session, run: PilotShopping) -> list[PilotOffer]:
    return list(session.scalars(select(PilotOffer).where(
        PilotOffer.shopping_id == run.id, PilotOffer.status == "accepted",
        PilotOffer.deal_state.in_(LIVE_DEAL))))


def open_offers(session: Session, run: PilotShopping) -> list[PilotOffer]:
    return list(session.scalars(select(PilotOffer).where(PilotOffer.shopping_id == run.id,
                                                         PilotOffer.status == "open")))


def _units(session: Session, offers: list[PilotOffer]) -> int:
    return sum(units_of(o, session.get(PilotItem, o.item_id)) for o in offers)


def check_room(session: Session, run: PilotShopping, units: int) -> None:
    """Raise 409 when a new offer for `units` would break promise 1 or 2."""
    if run.status != "open":
        raise HTTPException(409, f"this shopping run is {run.status}")
    opened = open_offers(session, run)
    if len(opened) >= MAX_PARALLEL:
        raise HTTPException(409, f"at most {MAX_PARALLEL} open offers in one shopping run: wait for an answer, or "
                                 "withdraw one first")
    needed = run.target_quantity - _units(session, bought(session, run)) - _units(session, opened)
    if units > needed:
        raise HTTPException(409, f"that would go over the target: {max(needed, 0)} more unit(s) can be on offer now "
                                 f"({run.target_quantity} wanted). Offer for fewer units (units=...), or wait for "
                                 "an open offer to be answered")


def range_limit(run: PilotShopping | None, units: int, it: PilotItem, includes_shipping: bool | None
                ) -> dict[str, Any] | None:
    """The run's per-unit limit as a limit on this offer's amount, for the member's deal rules only (the AI may
    confirm alone inside it). None (ask) when there is no limit, another currency, or shipping that is not in the
    amount and not known."""
    if run is None or run.unit_limit is None or run.currency != it.currency:
        return None
    cap = run.unit_limit * units
    if "shipping" in _split(it.trade_methods) and not includes_shipping:
        if it.shipping_cost is None:
            return None
        cap -= it.shipping_cost
    return {"amount": max(cap, 0), "currency": run.currency}


def guard_accept(session: Session, o: PilotOffer, it: PilotItem) -> None:
    """Before an accept reserves anything: lock the shopping run row (FOR UPDATE on PostgreSQL) and refuse when the
    run is no longer open or this deal would take it over its target. Two sellers accepting in the same second are
    then served one after the other, and the late one gets a clear answer instead of a deal (review 2026-11-20)."""
    if not o.shopping_id:
        return
    run = session.scalars(select(PilotShopping).where(PilotShopping.id == o.shopping_id).with_for_update()).first()
    if run is None:
        return
    if run.status != "open" or \
            _units(session, bought(session, run)) + units_of(o, it) > run.target_quantity:
        raise HTTPException(409, "bought_elsewhere: the buyer already has enough from other sellers, so this offer "
                                 "can no longer be accepted")


def after_accept(session: Session, o: PilotOffer, emit) -> None:
    """Promise 3: once the run's target is filled, withdraw its other open offers (their sellers are told, no
    prices) and mark the run filled. `emit(session, offer, to_member, action)` sends the usual offer event."""
    if not o.shopping_id:
        return
    run = session.get(PilotShopping, o.shopping_id)
    if run is None or run.status != "open":
        return
    session.flush()  # the accept above is not flushed yet; bought() must see it
    if _units(session, bought(session, run)) < run.target_quantity:
        return
    run.status, run.updated_at = "filled", utcnow()
    for other in open_offers(session, run):
        other.status, other.updated_at = "withdrawn", utcnow()
        other.history = [*other.history, {"by": "buyer", "action": "bought_elsewhere", "amount": None,
                                          "message": None, "at": utcnow().isoformat()}]
        emit(session, other, other.seller_id, "bought_elsewhere")


def view(session: Session, run: PilotShopping) -> dict[str, Any]:
    got, opened = bought(session, run), open_offers(session, run)
    n_got, n_open = _units(session, got), _units(session, opened)
    out: dict[str, Any] = {
        "id": run.id, "title": run.title, "currency": run.currency, "status": run.status,
        "target_quantity": run.target_quantity, "units_bought": n_got, "units_on_open_offers": n_open,
        "units_needed": max(run.target_quantity - n_got - n_open, 0), "unit_limit": run.unit_limit,
        "partial_ok": run.partial_ok, "max_parallel_offers": MAX_PARALLEL,
        "deals": [{"offer_id": o.id, "item_id": o.item_id, "units": units_of(o, session.get(PilotItem, o.item_id)),
                   "amount": o.amount, "includes_shipping": o.includes_shipping, "deal_state": o.deal_state}
                  for o in got],
        "open_offers": [{"offer_id": o.id, "item_id": o.item_id,
                         "units": units_of(o, session.get(PilotItem, o.item_id)), "amount": o.amount,
                         "your_turn": o.turn == "buyer"} for o in opened],
        "created_at": run.created_at.isoformat()}
    if run.unit_limit is not None:
        out["unit_limit_note"] = ("Private: only your user and you see it. You may agree alone when the total per "
                                  "unit, shipping included, is at or under it; otherwise ask your user.")
    if run.status == "open":
        ask_at = _aware(run.ask_again_at)
        if ask_at is not None and ask_at <= utcnow() and n_got < run.target_quantity:
            out["ask_your_user"] = (f"Only {n_got} of {run.target_quantity} found so far. Keep looking, buy what we "
                                    "have, or stop?")
            out["next_step"] = ("Ask your user ask_your_user in bold. Keep looking: shopping_action(extend). Stop: "
                                "shopping_action(end).")
        elif run.partial_ok is None and run.target_quantity > 1:
            out["next_step"] = ("Ask your user once, in bold: **If I can't find all of them, may I buy fewer?** and "
                                "save it with shopping_action(partial_ok=...). " + RUN_STEP)
        else:
            out["next_step"] = RUN_STEP
    elif run.status == "filled":
        out["next_step"] = ("Done: tell your user what was bought (units, seller, amount in bold, how many deals) and "
                            "carry on with each deal in my_deals.")
    return out


@router.post("/shopping", status_code=201)
def start_shopping(body: ShoppingIn, m: Member, session: Db):
    live = session.scalar(select(func.count()).select_from(PilotShopping).where(
        PilotShopping.member_id == m.id, PilotShopping.status == "open")) or 0
    if live >= MAX_OPEN_RUNS:
        raise HTTPException(409, f"at most {MAX_OPEN_RUNS} open shopping runs; end one first")
    run = PilotShopping(member_id=m.id, title=_clean(body.title) or "shopping", currency=body.currency,
                        target_quantity=body.target_quantity, unit_limit=body.unit_limit, partial_ok=body.partial_ok,
                        ask_again_at=utcnow() + dt.timedelta(days=ASK_AGAIN_DAYS))
    session.add(run)
    session.flush()
    out = view(session, run)
    if body.unit_limit is None:
        out["limit_question"] = ("Ask your user in bold: **May I agree alone up to a total per unit (shipping "
                                 "included)? If so, how much?** Save it with shopping_action(unit_limit=...).")
    return out


def _mine(session: Session, m: PilotMember, run_id: str) -> PilotShopping:
    run = session.get(PilotShopping, run_id)
    if run is None or run.member_id != m.id:
        raise HTTPException(404, "shopping run not found")
    return run


@router.get("/shopping")
def my_shopping(m: Member, session: Db, state: Literal["open", "all"] = "open"):
    stmt = select(PilotShopping).where(PilotShopping.member_id == m.id)
    if state == "open":
        stmt = stmt.where(PilotShopping.status == "open")
    rows = session.scalars(stmt.order_by(PilotShopping.created_at.desc()).limit(30)).all()
    return {"shopping": [view(session, r) for r in rows]}


@router.get("/shopping/{run_id}")
def get_shopping(run_id: str, m: Member, session: Db):
    return view(session, _mine(session, m, run_id))


@router.patch("/shopping/{run_id}")
def update_shopping(run_id: str, body: ShoppingPatch, m: Member, session: Db):
    run = _mine(session, m, run_id)
    if run.status != "open":
        raise HTTPException(409, f"this shopping run is {run.status}")
    if body.target_quantity is not None:
        if body.target_quantity < _units(session, bought(session, run)) + _units(session, open_offers(session, run)):
            raise HTTPException(409, "the target cannot go below what is bought or on open offers; withdraw an "
                                     "offer first")
        run.target_quantity = body.target_quantity
    if body.clear_unit_limit:
        run.unit_limit = None
    elif body.unit_limit is not None:
        run.unit_limit = body.unit_limit
    if body.partial_ok is not None:
        run.partial_ok = body.partial_ok
    if body.status == "ended":
        run.status = "ended"
        from .pilot import _offer_event

        for o in open_offers(session, run):
            o.status, o.updated_at = "withdrawn", utcnow()
            o.history = [*o.history, {"by": "buyer", "action": "withdraw", "amount": None, "message": None,
                                      "at": utcnow().isoformat()}]
            _offer_event(session, o, o.seller_id, "withdraw")
    run.updated_at = utcnow()
    return view(session, run)


@router.post("/shopping/{run_id}/extend")
def extend_shopping(run_id: str, m: Member, session: Db):
    run = _mine(session, m, run_id)
    if run.status != "open":
        raise HTTPException(409, f"this shopping run is {run.status}")
    run.ask_again_at, run.updated_at = utcnow() + dt.timedelta(days=ASK_AGAIN_DAYS), utcnow()
    return view(session, run)
