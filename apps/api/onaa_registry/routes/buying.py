"""Buying questions for AI buying agents, answered from ONAA's checkout checker observations (see ..buying)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import buying, needs
from ..db import get_session
from ..security import client_ip, require_admin

router = APIRouter(prefix="/v1/buying", tags=["buying"])

Country = Annotated[str | None, Query(max_length=2, description="ISO 3166-1 country to ship to, e.g. US")]
Agent = Annotated[str | None, Query(max_length=60, description="your agent or platform, e.g. gemini, chatgpt, claude")]
Payment = Annotated[list[str] | None, Query(description="payment methods you or your buyer can use: shop_pay, card, "
                                                        "google_pay (comma-separated or repeated)")]
PayAlone = Annotated[bool, Query(description="deprecated name for shop_pay_link_offered (same rule; kept so "
                                             "existing calls work)")]
LinkOffered = Annotated[bool, Query(description="only stores that offer a Shop Pay one-time link the buyer "
                                                "approves once (offered, not observed; payment not tested)")]
ExcludeSandbox = Annotated[bool, Query(description="hide stores whose endpoint hostname looks like a sandbox, "
                                                   "staging or test store (endpoint_environment=sandbox). Off by "
                                                   "default: such stores are listed with a caution and ranked last "
                                                   "within their verdict")]
ClaimedOnly = Annotated[bool, Query(description="only stores posted by their operator; most stores are unclaimed "
                                                "(found on the public web by ONAA), so this can return few or none")]
ReachableOnly = Annotated[bool, Query(description="hide stores whose last 3 health probes failed "
                                                  "(reachability=unreachable); not-yet-checked (unknown) stay. "
                                                  "Same as on /v1/services. Endpoint health, not checkout status")]


def _split(values: list[str] | None) -> list[str]:
    return [p.strip() for v in values or [] for p in v.split(",") if p.strip()][:10]


@router.get("/stores", summary="Stores where an agent can reach checkout under your conditions (ship-to, payment)")
def stores(request: Request, session: Session = Depends(get_session), country: Country = None, agent: Agent = None,
           payment: Payment = None, shop_pay_link_offered: LinkOffered = False, pay_alone: PayAlone = False,
           q: Annotated[str | None, Query(max_length=100, description="words in the store name or description; "
                                                                      "product search stays with each store")] = None,
           include: Annotated[Literal["buyable", "possible", "all"], Query(
               description="buyable = yes answers only; possible (default) adds 'maybe' (e.g. delivery untested); "
                           "all adds no/unknown with reasons")] = "possible",
           limit: Annotated[int, Query(ge=1, le=100)] = 20, offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
           claimed_only: ClaimedOnly = False, reachable_only: ReachableOnly = False,
           exclude_unreachable: Annotated[bool, Query(description="clearer name for reachable_only (same rule)")]
           = False,
           confirmed_reachable_only: Annotated[bool, Query(description="strict: only stores whose last endpoint "
                                                                       "probe answered; drops unknown")] = False,
           exclude_sandbox: ExcludeSandbox = False):
    from .stores import count_search

    pay_alone = pay_alone or shop_pay_link_offered
    result = buying.find_stores(session, country=country, agent=agent, payment=_split(payment), pay_alone=pay_alone,
                                q=q, include=include, limit=limit, offset=offset, claimed_only=claimed_only,
                                reachable_only=reachable_only or exclude_unreachable,
                                confirmed_reachable_only=confirmed_reachable_only, exclude_sandbox=exclude_sandbox)
    if offset == 0:  # count searches, not the pages of one search
        count_search(request, "find_stores", {"country": country, "agent": agent, "payment": _split(payment),
                                              "pays_alone": True if pay_alone else None,
                                              "q": "given" if (q or "").strip() else None, "include": include},
                     matched=result.get("total"))
    return result


@router.get("/check", summary="Can I reach checkout at these stores, and how? (ids, domains or product URLs, up to 25)")
def check(request: Request,
          store: Annotated[list[str], Query(description="svc_ id, store domain or any URL on the store; repeat or "
                                                        "comma-separate, e.g. the shops in Shop MCP results")],
          session: Session = Depends(get_session), country: Country = None, agent: Agent = None,
          payment: Payment = None, shop_pay_link_offered: LinkOffered = False, pay_alone: PayAlone = False):
    pay_alone = pay_alone or shop_pay_link_offered
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


class NeedIn(BaseModel):
    text: str = Field(min_length=needs.MIN_TEXT, max_length=needs.MAX_TEXT,
                      description="what you are looking for, in your own words, without personal information, e.g. "
                                  "\"trail running shoes under $120, ship to Texas, pay with Apple Pay\"")
    ship_to_country: str | None = Field(None, max_length=2, description="ISO 3166-1 country, e.g. US")
    agent: str | None = Field(None, max_length=60, description="your agent or platform, e.g. chatgpt, claude")


@router.post("/needs", summary="Describe what you want in free text; get matching stores now (personal data removed)")
def describe_need(body: NeedIn, request: Request, session: Session = Depends(get_session)):
    """Rules-only reading (no language model). Personal data is removed before matching; only the redacted text is
    kept, for up to ONAA_NEED_TEXT_RETENTION_DAYS days (default 7), for anonymous demand review."""
    from ..traffic import current_origin

    request.app.state.needs_limiter.check(f"need:{client_ip(request)}")
    settings = request.app.state.settings
    if not needs.normalise(body.text) or len(needs.normalise(body.text)) < needs.MIN_TEXT:
        raise HTTPException(422, "text is empty")
    result = needs.describe_need(session, body.text, ship_to_country=body.ship_to_country, agent=body.agent,
                                 origin=current_origin.get(), retention_days=settings.need_text_retention_days)
    try:
        request.app.state.usage.hit_need(result["understood"]["themes"], result["total_matches"],
                                         bool(result["privacy"]["removed"]))
    except Exception:  # noqa: BLE001 - measurement must never break serving
        pass
    return result


admin_router = APIRouter(tags=["admin"])


@admin_router.get("/v1/admin/needs", summary="Weekly demand review of free-text needs (admin)")
def review_needs(request: Request, days: Annotated[int, Query(ge=1, le=90)] = 7,
                 origin: Annotated[Literal["external", "ours", "probes", "all"], Query()] = "external",
                 admin: str = Depends(require_admin), session: Session = Depends(get_session)):
    """Weekly demand review (admin token): theme counts and redacted texts, as untrusted data."""
    return needs.review(session, days=days, retention_days=request.app.state.settings.need_text_retention_days,
                        origin=None if origin == "all" else origin)
