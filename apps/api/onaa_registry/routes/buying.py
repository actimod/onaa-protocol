"""Buying questions for AI buying agents, answered from ONAA's checkout checker observations (see ..buying)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from .. import buying
from ..db import get_session

router = APIRouter(prefix="/v1/buying", tags=["buying"])

Country = Annotated[str | None, Query(max_length=2, description="ISO 3166-1 country to ship to, e.g. KR")]
Agent = Annotated[str | None, Query(max_length=60, description="your agent or platform, e.g. gemini, chatgpt, claude")]
Payment = Annotated[list[str] | None, Query(description="payment methods you or your buyer can use: shop_pay, card, "
                                                        "google_pay (comma-separated or repeated)")]
PayAlone = Annotated[bool, Query(description="only stores where the agent can pay without the buyer each time "
                                             "(observed: after a one-time Shop Pay link)")]


def _split(values: list[str] | None) -> list[str]:
    return [p.strip() for v in values or [] for p in v.split(",") if p.strip()][:10]


@router.get("/stores", summary="Stores an agent can buy from under your conditions (ship-to, payment, pay alone)")
def stores(request: Request, session: Session = Depends(get_session), country: Country = None, agent: Agent = None,
           payment: Payment = None, pay_alone: PayAlone = False,
           q: Annotated[str | None, Query(max_length=100, description="words in the store name or description; "
                                                                      "product search stays with each store")] = None,
           include: Annotated[Literal["buyable", "possible", "all"], Query(
               description="buyable = yes answers only; possible (default) adds 'maybe' (e.g. delivery untested); "
                           "all adds no/unknown with reasons")] = "possible",
           limit: Annotated[int, Query(ge=1, le=100)] = 20, offset: Annotated[int, Query(ge=0, le=10_000)] = 0):
    from .stores import count_search

    result = buying.find_stores(session, country=country, agent=agent, payment=_split(payment), pay_alone=pay_alone,
                                q=q, include=include, limit=limit, offset=offset)
    if offset == 0:  # count searches, not the pages of one search
        count_search(request, "find_stores", {"country": country, "agent": agent, "payment": _split(payment),
                                              "pays_alone": True if pay_alone else None,
                                              "q": "given" if (q or "").strip() else None, "include": include},
                     matched=result.get("total"))
    return result


@router.get("/check", summary="Can I buy at these stores, and how? (ids, domains or product URLs, up to 25)")
def check(request: Request,
          store: Annotated[list[str], Query(description="svc_ id, store domain or any URL on the store; repeat or "
                                                        "comma-separate, e.g. the shops in Shop MCP results")],
          session: Session = Depends(get_session), country: Country = None, agent: Agent = None,
          payment: Payment = None, pay_alone: PayAlone = False):
    keys = [k[:300] for k in _split_many(store)]
    if not keys:
        raise HTTPException(422, "store is required")
    if len(keys) > buying.MAX_STORES_PER_CHECK:
        raise HTTPException(422, f"at most {buying.MAX_STORES_PER_CHECK} stores per call")
    from .stores import run_check  # adds a live /.well-known/ucp look-up for stores ONAA has not listed

    return run_check(request, session, keys, country=country, agent=agent, payment=_split(payment),
                     pay_alone=pay_alone)


def _split_many(values: list[str]) -> list[str]:
    return [p.strip() for v in values for p in v.split(",") if p.strip()]
