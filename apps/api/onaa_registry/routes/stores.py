"""Store data for buying agents: filtered list, one store, bulk JSON/CSV feeds and crawlable store pages."""

from __future__ import annotations

import html
import zlib
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy.orm import Session

from ..buying import MAX_STORES_PER_CHECK
from ..db import get_session
from ..landing import CSS
from ..security import client_ip
from ..stores import (
    FEED_NOTE,
    PAGE_SIZE,
    TESTED_COUNTRIES,
    check_with_discovery,
    csv_lines,
    derived,
    find_store,
    snapshot,
    store_record,
)

router = APIRouter(tags=["stores"])
CACHE = "public, max-age=900"


def _base(request: Request) -> str:
    return request.app.state.settings.public_base_url.rstrip("/")


def _csv_param(values: list[str] | None, upper: bool = False) -> list[str]:
    out = []
    for v in values or []:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part.upper() if upper else part.lower())
    return out


def gzip_response(request: Request, gz: bytes, media_type: str, headers: dict[str, str]) -> Response:
    """Send stored gzip bytes as-is to clients that accept gzip, else decompress while streaming."""
    headers = {**headers, "Vary": "Accept-Encoding"}
    if "gzip" in request.headers.get("accept-encoding", "").lower():
        return Response(gz, media_type=media_type, headers={**headers, "Content-Encoding": "gzip"})

    def chunks():
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        for i in range(0, len(gz), 1 << 16):
            yield d.decompress(gz[i:i + (1 << 16)])
        yield d.flush()

    return StreamingResponse(chunks(), media_type=media_type, headers=headers)


def _feed_response(request: Request, session: Session) -> Response:
    snap = snapshot(session, _base(request))
    headers = {"ETag": snap.etag, "Cache-Control": CACHE}
    if request.headers.get("if-none-match") == snap.etag:
        return Response(status_code=304, headers=headers)
    return gzip_response(request, snap.feed_gz, "application/json", headers)


@router.get("/stores.json", summary="All stores AI buying agents can buy from, with checkout requirements (one file)")
def stores_feed(request: Request, session: Session = Depends(get_session)):
    """The full store feed: every listed store with ONAA's last checkout probe (protocol, payment handlers,
    whether an agent can pay alone, buyer info required, tested shipping countries) and links. Supports
    If-None-Match. Same document as /v1/stores.json."""
    return _feed_response(request, session)


@router.get("/v1/stores.json", include_in_schema=False)
def stores_feed_v1(request: Request, session: Session = Depends(get_session)):
    return _feed_response(request, session)


@router.get("/stores.csv", summary="All stores as CSV (one row per store)")
def stores_csv(request: Request, session: Session = Depends(get_session)):
    snap = snapshot(session, _base(request))
    return gzip_response(request, derived(snap, "csv", csv_lines), "text/csv; charset=utf-8",
                         {"Cache-Control": CACHE, "Content-Disposition": 'inline; filename="onaa-stores.csv"'})


@router.get("/v1/stores", summary="Find stores an AI agent can buy from (filter by shipping country, pay-alone, ...)")
def list_stores(
    request: Request,
    ships_to: Annotated[list[str] | None, Query(description="ISO country where ONAA's test checkout (one test "
                                                            "item, public test address, cancelled before payment) "
                                                            "offered a delivery option. Observed, not a guarantee "
                                                            "for your items or address. Tested: "
                                                            + ", ".join(TESTED_COUNTRIES))] = None,
    store_ships_to: Annotated[list[str] | None, Query(
        description="ISO country the store's own published shipping list includes (worldwide counts; "
                    "store-published, not tested by ONAA). Works for any country")] = None,
    pays_alone: Annotated[bool | None, Query(description="true: an agent can pay alone after the buyer approves "
                                                         "a one-time link (Shop Pay identity linking)")] = None,
    checkout: Annotated[list[str] | None, Query(description="last probe status: checkout_ready, "
                                                            "buyer_step_required, auth_required, no_checkout, "
                                                            "failed, not_checked_yet")] = None,
    protocol: Annotated[list[str] | None, Query(description="ucp, shop-mcp")] = None,
    payment_handler: Annotated[list[str] | None, Query(description="e.g. shop_pay, shopify.card, gpay")] = None,
    currency: Annotated[list[str] | None, Query(description="currency seen at checkout, ISO 4217")] = None,
    q: Annotated[str | None, Query(max_length=200, description="store name or domain contains")] = None,
    claimed_only: Annotated[bool, Query(description="only stores posted by their operator; most are unclaimed "
                                                    "(found on the public web by ONAA)")] = False,
    reachable_only: Annotated[bool, Query(description="hide stores whose last 3 health probes failed "
                                                      "(reachability=unreachable); not-yet-checked (unknown) stay. "
                                                      "Same as on /v1/services. Endpoint health, not checkout "
                                                      "status")] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    session: Session = Depends(get_session),
):
    """Stores ONAA lists, filtered on ONAA's last checkout probe. ONAA has no product data: to find a product,
    use the store's own catalog search (its MCP endpoint) or Shop MCP, then check the store here or with
    /v1/stores/check. For the whole list in one request use /stores.json."""
    ships = _csv_param(ships_to, upper=True)
    store_ships = set(_csv_param(store_ships_to, upper=True))
    statuses = _csv_param(checkout)
    protos = _csv_param(protocol)
    handlers = _csv_param(payment_handler)
    currencies = _csv_param(currency, upper=True)
    terms = [t for t in (q or "").lower().split() if t][:8]
    snap = snapshot(session, _base(request))
    want_ships, want_handlers, want_currencies = set(ships), set(handlers), set(currencies)
    matched = []
    for row in snap.rows:
        if want_ships and not want_ships & row.ships_to:
            continue
        if store_ships and not (row.published_worldwide or store_ships <= row.published_to):
            continue
        if pays_alone is not None and bool(row.pays_alone) != pays_alone:
            continue
        if statuses and row.status not in statuses:
            continue
        if protos and not any(row.protocol.startswith("ucp-mcp" if p == "ucp" else p) for p in protos):
            continue
        if want_handlers and not want_handlers & row.handlers:
            continue
        if want_currencies and not want_currencies & row.currencies:
            continue
        if terms and not all(t in row.hay for t in terms):
            continue
        if (claimed_only and not row.claimed) or (reachable_only and not row.reachable):
            continue
        matched.append(row)
    if offset == 0:  # count searches, not the pages of one search
        count_search(request, "list", {"country": ships, "pays_alone": pays_alone, "checkout": statuses,
                                       "protocol": protos, "payment": handlers, "currency": currencies,
                                       "q": "given" if terms else None}, matched=len(matched))
    items = list(snap.records(matched[offset:offset + limit]))
    untested = sorted(set(ships) - set(TESTED_COUNTRIES))
    out = {"total": len(matched), "limit": limit, "offset": offset, "items": items,
           "note": FEED_NOTE}
    if untested:
        out["untested_countries"] = untested
        out["untested_note"] = (f"ONAA's checker tests delivery to {', '.join(TESTED_COUNTRIES)} only, so no store "
                                f"is shown as shipping to {', '.join(untested)}. Use store_ships_to= for the "
                                "store's own published shipping list, and check delivery at the store's checkout.")
    return JSONResponse(out, headers={"Cache-Control": "public, max-age=300"})


def count_search(request: Request, door: str, conditions: dict, matched: int | None = None) -> None:
    """Anonymous count of the filter values of one search (fixed vocabulary, external only); never breaks serving."""
    try:
        request.app.state.usage.hit_search(door, conditions, matched)
    except Exception:  # noqa: BLE001 - measurement must never break serving
        pass


def run_check(request: Request, session: Session, keys: list[str], *, country: str | None, agent: str | None,
              payment: list[str], pay_alone: bool) -> dict:
    """Shared by /v1/stores/check and /v1/buying/check."""
    keys = [k.strip()[:300] for k in keys if k and k.strip()]
    if not keys:
        raise HTTPException(422, "give at least one store: svc_ id, domain or any URL on the store")
    if len(keys) > MAX_STORES_PER_CHECK:
        raise HTTPException(422, f"at most {MAX_STORES_PER_CHECK} stores per call")
    state, settings = request.app.state, request.app.state.settings
    count_search(request, "check", {"country": country, "agent": agent, "payment": payment,
                                    "pays_alone": True if pay_alone else None})
    ip = client_ip(request)

    def allowed() -> bool:
        if settings.store_probe_per_ip_per_hour <= 0:
            return False
        try:
            state.store_probe_limiter.check(ip)
            return True
        except HTTPException:
            return False

    return check_with_discovery(session, state.fetcher, keys, usage=state.usage, probe_allowed=allowed,
                                autodiscover=settings.store_autodiscovery_enabled, country=country, agent=agent,
                                payment=payment, pay_alone=pay_alone)


def _split(values: list[str] | None) -> list[str]:
    return [p.strip() for v in values or [] for p in v.split(",") if p.strip()]


@router.get("/v1/stores/check", summary="Can an AI agent buy here? Any product URL, store domain or svc_ id")
def check_get(
    request: Request,
    url: Annotated[list[str] | None, Query(description="product or store URL, domain or svc_ id; repeat or "
                                                       "comma-separate (max 25), e.g. the shops in Shop MCP "
                                                       "results")] = None,
    store: Annotated[list[str] | None, Query(include_in_schema=False)] = None,
    country: Annotated[str | None, Query(max_length=2, description="ship-to country, ISO 3166-1")] = None,
    agent: Annotated[str | None, Query(max_length=60, description="your agent platform, e.g. gemini")] = None,
    payment: Annotated[list[str] | None, Query(description="payment methods you can use: shop_pay, card, "
                                                           "google_pay")] = None,
    pay_alone: bool = False,
    session: Session = Depends(get_session),
):
    """Answers per store: verdict (yes, yes_buyer_finishes, maybe, no, unknown), reasons, cautions and how to
    buy. A store ONAA has not listed is looked up live at its /.well-known/ucp (robots.txt honoured); if it
    publishes a UCP shopping endpoint, ONAA adds it (links only) and answers from its declared protocol."""
    return run_check(request, session, _split(url) + _split(store), country=country, agent=agent,
                     payment=_split(payment), pay_alone=pay_alone)


@router.post("/v1/stores/check", summary="Same as GET /v1/stores/check, with a JSON body")
def check_post(
    request: Request,
    body: Annotated[dict, Body(examples=[{"stores": ["https://example-shop.com/products/x", "svc_..."],
                                          "country": "US", "pay_alone": True}])],
    session: Session = Depends(get_session),
):
    stores = body.get("stores") or body.get("urls") or []
    if not isinstance(stores, list) or not all(isinstance(x, str) for x in stores):
        raise HTTPException(422, "stores must be a list of strings")
    payment = body.get("payment") or []
    if not isinstance(payment, list) or not all(isinstance(x, str) for x in payment):
        raise HTTPException(422, "payment must be a list of strings")
    country, agent = body.get("country"), body.get("agent")
    if country is not None and (not isinstance(country, str) or len(country) != 2):
        raise HTTPException(422, "country must be ISO 3166-1 alpha-2")
    if agent is not None and (not isinstance(agent, str) or len(agent) > 60):
        raise HTTPException(422, "agent must be a short string")
    return run_check(request, session, stores, country=country, agent=agent, payment=payment[:10],
                     pay_alone=bool(body.get("pay_alone")))


@router.get("/v1/stores/{store}", summary="One store by listing id or domain, with how to buy there")
def get_store(store: str, request: Request,
              country: Annotated[str | None, Query(min_length=2, max_length=2)] = None,
              session: Session = Depends(get_session)):
    listing = find_store(session, store)
    if listing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"store not listed; ask {_base(request)}/v1/stores/check?url={store[:100]}")
    return JSONResponse(store_record(listing, _base(request), country=country.upper() if country else None),
                        headers={"Cache-Control": "public, max-age=300"})


# ---------- crawlable HTML ----------
def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _page(title: str, desc: str, body: str, alt_json: str) -> str:
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_e(title)}</title><meta name="description" content="{_e(desc)}">'
            '<meta name="color-scheme" content="light dark">'
            f'<link rel="alternate" type="application/json" href="{_e(alt_json)}">'
            f'<style>{CSS}</style></head><body><header><div class="wrap bar"><a class="logo" href="/">ONAA '
            '<span>Open Network for AI Agents</span></a><nav><a href="/stores">Stores</a>'
            '<a href="/llms.txt">For agents</a></nav></div></header><main class="wrap">'
            f'{body}</main><footer><div class="wrap"><p>{_e(FEED_NOTE)}</p>'
            '<p><a href="/opt-out">Listed without asking? Remove it.</a></p></div></footer></body></html>')


STATUS_TEXT = {
    "checkout_ready": "Checkout tested: an outside agent reached a checkout that asks for payment (payment not tested)",
    "buyer_step_required": "An outside agent built a checkout; the buyer must finish a step",
    "auth_required": "Partner or approved agents only",
    "no_checkout": "No agent checkout found",
    "failed": "Last check failed",
    "not_checked_yet": "Not checked yet",
}


@router.get("/stores", response_class=HTMLResponse, include_in_schema=False)
def stores_index(request: Request, page: Annotated[int, Query(ge=1, le=10_000)] = 1,
                 session: Session = Depends(get_session)):
    base = _base(request)
    snap = snapshot(session, base)
    pages = max(1, -(-snap.count // PAGE_SIZE))
    if page > pages:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such page")
    rows = []
    for it in snap.records(snap.rows[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]):
        cp = it["checkout_probe"]
        key = it["domain"] or it["id"]
        pay = " · Shop Pay one-time link offered (payment not tested)" if cp["agent_can_pay_alone"] else ""
        ships = ", ".join(it["shipping"]["ships_to"])
        rows.append(f'<div class="item"><h3><a href="/stores/{_e(key)}">{_e(it["name"])}</a></h3>'
                    f'<p>{_e(STATUS_TEXT.get(cp["status"], cp["status"]))}{_e(pay)}'
                    + (f' · ships to {_e(ships)}' if ships else "") + "</p></div>")
    nav = " ".join(([f'<a href="/stores?page={page - 1}" rel="prev">previous</a>'] if page > 1 else [])
                   + [f"page {page} of {pages}"]
                   + ([f'<a href="/stores?page={page + 1}" rel="next">next</a>'] if page < pages else []))
    body = (f'<section class="hero"><h1>{snap.count} stores probed for AI agent checkout</h1>'
            '<p>ONAA probes each store as an outside agent, up to a created checkout that is then cancelled; '
            'payment is never tested. Agents: page through '
            f'<code>GET {_e(base)}/v1/stores?ships_to=US&amp;pays_alone=true&amp;limit=100</code>, or get '
            f'everything at once from <a href="{_e(base)}/stores.json">/stores.json</a>.</p></section>'
            f'<p class="list-sub">{nav}</p>' + "".join(rows) + f'<p class="list-sub">{nav}</p>')
    return HTMLResponse(_page(f"{snap.count} stores probed for AI agent checkout | ONAA",
                              "Stores and marketplaces with an agent checkout, tested by ONAA.", body,
                              f"{base}/stores.json"), headers={"Cache-Control": CACHE})


def _published_text(pub) -> str:
    if not isinstance(pub, dict):
        return "unknown"
    if pub["ships_worldwide"]:
        return "worldwide (store's own shipping list)"
    return f'{len(pub["countries"])} countries: ' + ", ".join(pub["countries"][:40]) + (
        " ..." if len(pub["countries"]) > 40 else "")


@router.get("/stores/{store}", response_class=HTMLResponse, include_in_schema=False)
def store_page(store: str, request: Request, session: Session = Depends(get_session)):
    base = _base(request)
    listing = find_store(session, store)
    if listing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "store not listed")
    it = store_record(listing, base)
    cp, sh = it["checkout_probe"], it["shipping"]
    verdict = it.get("agent_purchase") or {}
    steps = verdict.get("how_to_buy") or []
    facts = [
        ("Last checked", cp["checked_at"] or "not yet"),
        ("Result", STATUS_TEXT.get(cp["status"], cp["status"])),
        ("Protocol", cp["protocol"] or "unknown"),
        ("Agent can pay alone (not tested)",
         {True: "Shop Pay one-time link offered; ONAA never pays, so whether the agent can then pay alone is "
                "not verified", False: "no", None: "unknown"}[cp["agent_can_pay_alone"]]),
        ("Payment tested", "no: ONAA's checker always stops before payment"),
        ("Payment options at checkout", ", ".join(cp["payment_handlers"]) or "none seen"),
        ("Buyer must provide", ", ".join(cp["buyer_info_required"]) or "nothing reported"),
        ("Ships to (tested by ONAA)", ", ".join(sh["ships_to"]) or "none of the tested countries confirmed"),
        ("No delivery to (tested by ONAA)", ", ".join(sh["no_shipping_to"]) or "-"),
        ("Ships to (store-published, not tested)", _published_text(sh["store_published"])),
        ("Agent shopping endpoint", it["endpoints"]["mcp"] or "not public"),
    ]
    table = "".join(f'<li><strong>{_e(k)}:</strong> {_e(v)}</li>' for k, v in facts)
    how = "".join(f"<li>{_e(step)}</li>" for step in steps)
    store_link = (f'<a href="{_e(it["store_url"])}" rel="nofollow noopener ugc">{_e(it["store_url"])}</a>'
                  if it["store_url"] else "")
    body = (f'<section class="hero"><h1>Can an AI agent buy from {_e(it["name"])}?</h1>'
            f'<p>{_e(verdict.get("summary") or STATUS_TEXT.get(cp["status"], ""))}</p>'
            f'<p>{store_link}</p></section>'
            f'<div class="item"><ul>{table}</ul></div>'
            + (f'<h2 class="list-h">How an agent buys here</h2><ol>{how}</ol>' if how else "")
            + f'<p class="list-sub">Machine-readable: <a href="{_e(it["links"]["json"])}">JSON</a> · '
              f'<a href="{_e(it["links"]["history"])}">check history</a></p>')
    return HTMLResponse(_page(f"Can an AI agent buy from {it['name']}? | ONAA",
                              f"Tested agent checkout for {it['name']}: {STATUS_TEXT.get(cp['status'], '')}.",
                              body, it["links"]["json"]), headers={"Cache-Control": CACHE})
