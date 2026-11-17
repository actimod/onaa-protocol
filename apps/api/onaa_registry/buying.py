"""Buying questions over the checkout checker's observations ("can I buy here?", "how do I buy here?").

Built only on what `scripts/check_agent_checkout.py` records in `listings.agent_checkout` (see
schemas.AgentCheckoutRequirements): protocol, payment handlers offered at checkout, buyer information the checkout
asked for, tested delivery countries and currencies, whether a Shop Pay one-time link is offered (payment not
tested), and which agents a store appears to accept. Nothing here probes a store, holds product data or pays:
answers are derived from the last observation and say when it was made. Product search stays with each store's
own catalog tool (or Shopify's Shop MCP).

Every answer is an observation by ONAA's checker, not a verification, endorsement or guarantee; the store's own
terms apply. Answers distinguish "not tested" from "no".
"""

from __future__ import annotations

import datetime as dt
import functools
import gc
import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from .checkout_checker import SHIP_TEST
from .logic import PAYMENT_EVIDENCE, PUBLIC_STATUSES, aware
from .models import Listing, ListingFacet, utcnow

Verdict = Literal["yes", "yes_buyer_finishes", "maybe", "no", "unknown"]
# ONAA's checker always stops before payment. Every answer and store record says so in fields, so "yes" is never
# read as a tested purchase: yes = an agent checkout path was observed (payment not tested).
# Founder decision 2026-11-16: checkout_path_observed leads every answer; verdict "yes" keeps working for 90 days and
# is then renamed (VERDICT_YES_RENAME_ON). Clients should read checkout_path_observed, not verdict == "yes".
VERDICT_YES_RENAME_ON = "2027-02-14"
CHECKOUT_PATH_VERDICTS = ("yes", "yes_buyer_finishes")
CHECKOUT_REACHED_STATUSES = ("checkout_ready", "buyer_step_required")
VERDICT_NOTE = ("checkout_path_observed = ONAA's last probe reached the store's checkout (payment not tested); it is "
                "the same whatever conditions you pass. eligible_for_request = the store also meets your conditions "
                "(country, payment, pay_alone, agent); eligibility_reasons says why not. verdict yes = checkout "
                "path observed and eligible; yes_buyer_finishes = an agent can build the order, the buyer finishes it. "
                f"verdict value yes is deprecated and will be renamed on {VERDICT_YES_RENAME_ON}; read "
                "checkout_path_observed and eligible_for_request instead. ONAA never pays, so no payment outcome "
                "is verified.")
VERDICT_RANK = {"yes": 0, "yes_buyer_finishes": 1, "maybe": 2, "unknown": 3, "no": 4}
STALE_AFTER = dt.timedelta(days=14)
TESTED_COUNTRIES = tuple(SHIP_TEST)
MAX_STORES_PER_CHECK = 25
NOTE = ("Derived from ONAA's last checkout probe, which stops before payment and places no order. An observation, "
        "not a verification, endorsement or guarantee; the store's own terms, prices and policies apply. "
        "Search products with the store's own catalog tool (or Shopify's Shop MCP); ONAA holds no product data.")

# Payment method words an agent may use -> handler ids the checker records at checkout.
PAYMENT_ALIASES = {
    "shop_pay": "shop_pay", "shoppay": "shop_pay", "shop": "shop_pay",
    "card": "shopify.card", "credit_card": "shopify.card", "debit_card": "shopify.card", "shopify.card": "shopify.card",
    "visa": "shopify.card", "mastercard": "shopify.card", "amex": "shopify.card",
    "gpay": "gpay", "google_pay": "gpay", "googlepay": "gpay", "com.google.pay": "gpay",
}
HANDLER_TEXT = {
    "shop_pay": "Shop Pay: on the first purchase the buyer approves once at the store's continue_url and can link "
                "Shop Pay to the agent (identity linking); whether the agent can then pay without a person is not "
                "tested",
    "shopify.card": "card: the buyer enters card details on the store's checkout page (continue_url) for each "
                    "purchase",
    "gpay": "Google Pay: the buyer approves in Google Pay",
}
BUYER_INFO_TEXT = {
    "buyer_identity_contact_method_required": "buyer email or phone number",
    "delivery_address_required": "delivery address",
    "extension_interaction_required": "a step the buyer completes on the store's own page (continue_url)",
    "payment_method_required": "a payment method",
    "buyer_identity_required": "buyer identity (name, email)",
}
# Per-store check record (trust signal): how often ONAA's checker has probed the store and how often it reached
# checkout. Kept inside agent_checkout as {"total", "reached", "first", "recent": [[YYYY-MM-DD, status], ...]} with
# dates only and the newest RECENT_CHECKS kept, so the in-memory store cache stays small (strings are interned).
RECENT_CHECKS = 5
CHECK_RECORD_NOTE = ("ONAA's own checkout probes of this store (each stops before payment). checkout_reached_rate = "
                     "share of all probes that reached checkout; always read it with checks_total: "
                     "insufficient_history = true means fewer than 3 probes, too few for the rate to mean much. "
                     "recent_checks = newest first, by day. A record of observations, not a verification or "
                     "guarantee.")
MIN_CHECKS_FOR_RATE = 3
# Endpoint environment from the endpoint's own hostname only. ONAA cannot confirm that an endpoint is production,
# so the answer is "sandbox" when the name says so and "unknown" otherwise.
_SANDBOX_WORDS = ("sandbox", "staging", "stage", "test", "testing", "dev", "preview", "demo")
_SANDBOX_HOST = re.compile(rf"(?:^|[.-])(?:{'|'.join(_SANDBOX_WORDS)})(?:[.-]|$)", re.I)


@functools.lru_cache(maxsize=65536)
def endpoint_environment(url: str | None) -> str:
    host = urlsplit(url or "").hostname or ""
    return "sandbox" if host and _SANDBOX_HOST.search(host) else "unknown"


def next_check_history(prev: dict | None, status: str, at: dt.datetime) -> dict:
    """The stored check record after one more probe with result `status` at `at`."""
    prev = prev or {}
    day = aware(at).date().isoformat()
    recent = [[day, status]] + [list(x) for x in prev.get("recent") or [] if isinstance(x, list | tuple)]
    return {"total": int(prev.get("total") or 0) + 1,
            "reached": int(prev.get("reached") or 0) + (status in CHECKOUT_REACHED_STATUSES),
            "first": prev.get("first") or day, "recent": recent[:RECENT_CHECKS]}


def check_record(ac: dict | None) -> dict[str, Any]:
    """Public trust signal from the stored check record; falls back to the last probe alone."""
    ac = ac or {}
    hist = ac.get("check_history")
    if not hist and ac.get("status"):
        day = (ac.get("checked_at") or "")[:10] or None
        hist = {"total": 1, "reached": int(ac["status"] in CHECKOUT_REACHED_STATUSES), "first": day,
                "recent": [[day, ac["status"]]]}
    if not hist:
        return {"checks_total": 0, "checkout_reached_count": 0, "checkout_reached_rate": None,
                "insufficient_history": True, "recent_checks": [],
                "first_checked_on": None, "last_checked_at": None, "note": CHECK_RECORD_NOTE}
    total, reached = int(hist.get("total") or 0), int(hist.get("reached") or 0)
    recent = [{"on": d, "status": st} for d, st in hist.get("recent") or []]
    return {"checks_total": total, "checkout_reached_count": reached,
            "checkout_reached_rate": round(reached / total, 2) if total else None,
            "insufficient_history": total < MIN_CHECKS_FOR_RATE,
            "recent_checks": recent,
            "recent_consistent": len(recent) > 1 and len({r["status"] for r in recent}) == 1,
            "first_checked_on": hist.get("first"), "last_checked_at": ac.get("checked_at"),
            "note": CHECK_RECORD_NOTE}


AGENT_WORDS = {  # words in accepted_agents_hint -> agent names that match it
    "google": ("gemini", "google", "ai mode", "ai-mode", "bard", "project mariner", "mariner"),
}


def _country(c: str | None) -> str | None:
    c = (c or "").strip().upper()
    if c == "UK":
        c = "GB"
    return c if len(c) == 2 and c.isalpha() else None


def normalise_payment(methods: list[str] | None) -> list[str]:
    out = []
    for m in methods or []:
        k = re.sub(r"[\s-]+", "_", m.strip().lower())
        out.append(PAYMENT_ALIASES.get(k, k[:40]))
    return sorted(set(out))


def store_key(value: str) -> str:
    """'https://www.Shop.example/products/x' -> 'shop.example'; also accepts a bare domain."""
    v = value.strip().lower()
    host = urlsplit(v if "//" in v else "//" + v).hostname or ""
    return host.removeprefix("www.")


def _info_text(code: str) -> str | None:
    if code.startswith("delivery_no_delivery_available"):
        return None  # a shipping result, reported under ships_to
    return BUYER_INFO_TEXT.get(code, code.replace("_", " "))


def _agent_accepted(hint: str | None, agent: str | None) -> bool | None:
    if not agent:
        return None
    a = agent.strip().lower()
    h = (hint or "").lower()
    for word, names in AGENT_WORDS.items():
        if word in h and any(n in a for n in names):
            return True
    return False


def _protocol_text(req: dict) -> str:
    proto = req.get("protocol") or "ucp-mcp"
    if proto.startswith("shop-mcp"):
        return ("Shopify Shop MCP (one endpoint for many Shopify stores; pass the store's domain as `shop` in "
                "search_catalog and create_checkout)")
    ver = f" version {req['protocol_version']}" if req.get("protocol_version") else ""
    return f"Universal Commerce Protocol over MCP (ucp-mcp{ver}) at store.endpoint_url"


def how_to_buy(ac: dict | None, *, country: str | None = None) -> dict[str, Any]:
    """Steps an outside agent follows at this store, from the last observation. Never includes payment data."""
    ac = ac or {}
    req = ac.get("requirements") or {}
    status = ac.get("status")
    handlers = req.get("payment_handlers") or []
    info = [t for t in (_info_text(c) for c in req.get("buyer_info_required") or []) if t]
    cc = country or req.get("tested_country") or "US"
    steps: list[str] = []
    if status in (None, "failed"):
        steps.append("ONAA could not complete a checkout probe here; the steps below follow the store's declared "
                     "protocol and are untested.")
    if status == "auth_required":
        steps.append("This endpoint refused an anonymous agent. Only " + (req.get("accepted_agents_hint")
                     or "authenticated or partner agents") + " can reach checkout here; others cannot.")
    if status == "no_checkout":
        steps.append("The probe found no usable catalog search or checkout tool; an agent cannot buy here today.")
    steps.append("Connect: " + _protocol_text(req) + ".")
    if req.get("agent_profile_required"):
        steps.append('Identify your agent: send the header UCP-Agent: profile="<https URL of your UCP agent '
                     'profile>" (and the same profile in the tool call meta "ucp-agent").')
    seen = [c for c in (req.get("currencies_seen") or []) if isinstance(c, str)]
    asked = req.get("currency") if cc == req.get("tested_country") else None
    # Only suggest the currency the probe asked for when the store's test checkout actually returned it (a store can
    # answer a USD request in EUR, e.g. beurbanrunning.com on 2026-11-15).
    use = asked if asked and (not seen or asked in seen) else None
    steps.append(f'Find the product: call search_catalog with your query and context {{"address_country": "{cc}"'
                 + (f', "currency": "{use}"' if use else "") + "}.")
    if asked and seen and asked not in seen:
        steps.append(f"Currency: ONAA's test checkout asked for {asked} and the store answered in "
                     f"{', '.join(seen)}. Show the buyer the currency and total from the store's own quote.")
    steps.append("Create a checkout: create_checkout with the variant id and quantity and the same context. The "
                 "response shows the total, delivery options and any messages.")
    if info:
        steps.append("Before checkout completes, have from the buyer: " + "; ".join(info) + ".")
    if handlers:
        steps.append("Payment offered at checkout: " + "; ".join(HANDLER_TEXT.get(h, h) for h in handlers) + ".")
    elif status in ("checkout_ready", "buyer_step_required"):
        steps.append("No agent payment handler was offered: the buyer pays on the store's own checkout page "
                     "(continue_url in the checkout response).")
    if req.get("buyer_confirmation_required") or status == "buyer_step_required":
        steps.append("The checkout returned requires_escalation: hand the buyer the continue_url to confirm and pay.")
    steps.append("Pay only with the buyer's authorisation, under the store's terms. ONAA is not a party to the "
                 "purchase, holds no funds and cannot pay for you.")
    return {"steps": steps, "before_checkout": info, "payment_options": handlers,
            "pay_alone": req.get("autonomous_payment"), "protocol": req.get("protocol"),
            "agent_profile_required": req.get("agent_profile_required"),
            "agent_auth_required": req.get("agent_auth_required")}


def shipping_view(req: dict) -> dict[str, Any]:
    """Tested and store-published shipping, kept apart. Tested = ONAA's own test checkout (verified).

    Probes before 2026-11-16 sent no address, so the store answered "no delivery available" everywhere; those
    "no delivery" results are not evidence and are shown as unconfirmed instead."""
    ships = list(req.get("ships_to") or [])
    no_ship = list(req.get("no_shipping_to") or [])
    unconfirmed: list[str] = []
    if req.get("delivery_test") != "address" and "delivery_address_required" in (req.get("buyer_info_required")
                                                                                  or []):
        unconfirmed, no_ship = no_ship, []
    worldwide = req.get("published_ships_worldwide")
    published = list(req.get("published_ships_to") or [])
    return {"ships_to": ships, "no_shipping_to": no_ship, "unconfirmed": unconfirmed,
            "published_worldwide": worldwide, "published_ships_to": published,
            "published_known": worldwide is True or bool(published),
            "published_source": req.get("published_ships_source"),
            "quotes": req.get("shipping_quotes") or {}}


def published_ships(view: dict, cc: str) -> bool | None:
    """Does the store's own published list include `cc`? None when the store published none."""
    if not view["published_known"]:
        return None
    return view["published_worldwide"] is True or cc in view["published_ships_to"]


def assess(listing: Listing, *, country: str | None = None, agent: str | None = None,
           payment: list[str] | None = None, pay_alone: bool = False,
           now: dt.datetime | None = None, steps: bool = True) -> dict[str, Any]:
    """Answer "can this agent reach checkout here (shipping to `country`, paying with `payment`)?" from the probe.
    steps=False leaves how_to_buy out (find_stores ranks thousands of stores and fills it for its page only)."""
    ac = listing.agent_checkout or {}
    req = ac.get("requirements") or {}
    status = ac.get("status")
    cc = _country(country)
    pay = normalise_payment(payment)
    handlers = req.get("payment_handlers") or []
    reasons: list[str] = []      # why the answer is not a yes
    cautions: list[str] = []     # yes, but
    verdict: Verdict

    if status is None:
        verdict = "unknown"
        reasons.append("not checked by ONAA yet")
    elif status == "failed":
        verdict = "unknown"
        reasons.append("ONAA's last checkout probe failed (network or protocol error)")
    elif status == "no_checkout":
        verdict = "no"
        reasons.append("no usable catalog search or checkout tool for outside agents")
    elif status == "auth_required":
        ok = _agent_accepted(req.get("accepted_agents_hint"), agent)
        verdict = "maybe" if ok else "no"
        reasons.append("the store refuses anonymous agents: " + (req.get("accepted_agents_hint")
                                                               or "authenticated or partner agents only"))
        if ok:
            cautions.append("your agent appears to match the agents this store serves; it must authenticate "
                            "through that agent platform (untested by ONAA)")
        elif not agent:
            reasons.append("pass `agent` (e.g. gemini, chatgpt, claude) to check whether your agent is one of them")
    else:
        verdict = "yes" if status == "checkout_ready" else "yes_buyer_finishes"
        if status == "buyer_step_required":
            cautions.append("the buyer finishes the purchase (confirms and/or pays) at the store's continue_url")

    view = shipping_view(req)
    ships: bool | None = None
    published: bool | None = None
    if cc:
        published = published_ships(view, cc)
        if cc in view["no_shipping_to"]:
            ships = False
        elif cc in view["ships_to"]:
            ships = True
        if ships is False and verdict != "no":
            verdict = "no"
            reasons.append(f"a test checkout to {cc} reported no delivery")
        elif ships is None and published is False and verdict != "no":
            verdict = "no"
            reasons.append(f"{cc} is not in the shipping countries the store publishes (store-published list, "
                           "not tested by ONAA)")
        elif ships is None and verdict in ("yes", "yes_buyer_finishes"):
            verdict = "maybe"
            if published:
                reasons.append(f"the store publishes {cc} as a shipping destination, but ONAA has not confirmed "
                               "delivery there with a test checkout; check delivery options in the checkout")
            else:
                reasons.append(f"delivery to {cc} was not tested (tested: "
                               f"{', '.join(TESTED_COUNTRIES)}; check delivery options in the checkout)"
                               if cc not in TESTED_COUNTRIES else
                               f"delivery to {cc} was not confirmed by the last probe; check delivery options in "
                               "the checkout")

    pay_ok: bool | None = None
    if pay and handlers:
        pay_ok = bool(set(pay) & set(handlers))
        if not pay_ok and verdict != "no":
            verdict = "no"
            reasons.append("none of your payment methods was offered at checkout (offered: "
                           + ", ".join(handlers) + ")")
    elif pay and not handlers and verdict in ("yes", "yes_buyer_finishes"):
        cautions.append("no agent payment handler was offered; the buyer pays on the store's page")

    alone = req.get("autonomous_payment")
    if pay_alone and verdict != "no":
        if alone != "after_one_time_link":
            verdict = "no"
            reasons.append("no Shop Pay one-time link offered: the buyer pays each purchase")
        elif pay and "shop_pay" not in pay:
            verdict = "no"
            reasons.append("the one-time link needs Shop Pay, which is not among your payment methods")
        else:
            cautions.append("a Shop Pay one-time link is offered: the buyer must approve it once, and payment "
                            "after that was not tested")

    checked = ac.get("checked_at")
    when = now or utcnow()
    try:
        checked_dt = dt.datetime.fromisoformat(checked) if checked else None
    except ValueError:
        checked_dt = None
    if checked_dt is not None and aware(when) - aware(checked_dt) > STALE_AFTER:
        cautions.append(f"last checked {checked_dt.date().isoformat()}, more than 14 days ago")
    if verdict in ("yes", "yes_buyer_finishes", "maybe") and listing.reachability == "unreachable":
        cautions.append("ONAA's recent health probes could not reach the endpoint")
    environment = endpoint_environment(listing.endpoint_url)
    record = check_record(ac)
    if environment == "sandbox":
        cautions.append("the endpoint hostname looks like a sandbox or test store: orders there may not be real; "
                        "confirm the store's production endpoint before involving a buyer")
    if record["insufficient_history"] and record["checks_total"]:
        n = record["checks_total"]
        cautions.append(f"ONAA has probed this store only {n} time{'s' if n != 1 else ''}: too few to rely on "
                        "the result; re-check at the store")

    return {
        # The probe's observation never depends on the caller's conditions; eligibility does.
        "checkout_path_observed": status in CHECKOUT_REACHED_STATUSES,
        "eligible_for_request": verdict in CHECKOUT_PATH_VERDICTS,
        "eligibility_reasons": reasons,
        "store": {"id": listing.id, "name": listing.display_name, "endpoint_url": listing.endpoint_url,
                  "manifest_url": listing.source_url or listing.documentation_url},
        "verdict": verdict,
        "reasons": reasons,
        "cautions": cautions,
        "checkout_status": status,
        "ships_to_country": ships,
        "store_publishes_country": published,
        "country": cc,
        "payment_match": pay_ok,
        # What the store's manifest declares vs what ONAA's test checkout actually offered: they can differ.
        "declared_payment_handlers": req.get("manifest_payment_handlers") or [],
        "observed_checkout_payment_options": req.get("payment_handlers") or [],
        "endpoint_environment": environment,
        "pay_alone": alone,  # legacy name; read shop_pay_link_offered
        "shop_pay_link_offered": {"after_one_time_link": True, "none_observed": False}.get(alone),
        "ships_to": view["ships_to"],
        "no_shipping_to": view["no_shipping_to"],
        "shipping_quote": view["quotes"].get(cc) if cc else None,
        "currencies_seen": req.get("currencies_seen") or ([req["currency"]] if req.get("currency") else []),
        # What the store's test checkout actually returned (may differ from what the probe asked for).
        "observed_checkout_currency": (req.get("currencies_seen") or [None])[0],
        "accepted_agents": req.get("accepted_agents_hint") or ("any agent that sends a UCP agent profile"
                                                              if status in ("checkout_ready", "buyer_step_required")
                                                              else None),
        "how_to_buy": how_to_buy(ac, country=cc) if steps else None,
        "last_checked_at": checked,
        "check_record": record,
        **PAYMENT_EVIDENCE,
    }


@dataclass(frozen=True, slots=True)
class StoreView:
    """The columns `assess` reads, without the ORM object and its facets (tens of thousands of stores)."""
    id: str
    display_name: str | None
    description: str | None
    endpoint_url: str | None
    source_url: str | None
    documentation_url: str | None
    agent_checkout: dict | None
    reachability: str | None
    operator_id: str | None
    lifecycle_status: str | None

    @property
    def claimed(self) -> bool:
        """Posted by its operator (not only found on the public web by ONAA)."""
        return self.operator_id is not None and self.lifecycle_status != "discovered"


_VIEW_COLUMNS = (Listing.id, Listing.display_name, Listing.description, Listing.endpoint_url, Listing.source_url,
                 Listing.documentation_url, Listing.agent_checkout, Listing.reachability, Listing.operator_id,
                 Listing.lifecycle_status)
# Probe results that can lead to a yes or maybe; every other status always answers no or unknown.
POSSIBLE_STATUSES = ("checkout_ready", "buyer_step_required", "auth_required")


def _store_query():
    return select(*_VIEW_COLUMNS).where(Listing.service_type == "marketplace",
                                        Listing.lifecycle_status.in_(PUBLIC_STATUSES))


def _stores(session: Session, statuses: tuple[str, ...] | None = None) -> list[StoreView]:
    q = _store_query()
    if statuses is not None:
        q = q.where(Listing.id.in_(select(ListingFacet.listing_id).where(
            ListingFacet.kind == "agent_checkout", ListingFacet.value.in_(statuses))))
    rows = session.execute(q.order_by(Listing.id).execution_options(yield_per=500))  # compact while reading
    return [StoreView(*row[:6], _compact(row[6]), *row[7:]) for row in rows]


def _compact(value: Any) -> Any:
    """The probe JSON with every string interned. Each store repeats the same short strings (country codes in
    published_ships_to, handler and status names), so ~16k decoded probe records took ~290 MB as separate
    objects and ~60 MB interned; two copies during a cache refresh ran the 512 MB machine out of memory."""
    if isinstance(value, str):
        return sys.intern(value)
    if isinstance(value, list):
        return [_compact(v) for v in value]
    if isinstance(value, dict):
        return {sys.intern(k): _compact(v) for k, v in value.items()}
    return value


# find_stores reads every candidate store (thousands of rows with their probe JSON) and ranks them per request.
# On the small production machine that took 10-40 s per call, so the candidate list is kept in memory for
# BUYING_CACHE_SECONDS and refreshed in the background while the previous list keeps being served. Probe results
# change at most every few minutes (the checker), so answers stay as fresh as the store feed. 0 = no cache (tests).
BUYING_CACHE_SECONDS = float(os.environ.get("ONAA_BUYING_CACHE_SECONDS", "0"))
# Refreshes read only the stores changed since the last read (by updated_at; see stores._build for why), with a
# full read once per FULL_RELOAD_SECONDS. Value: (loaded_at, stores, watermark, full_at).
FULL_RELOAD_SECONDS = float(os.environ.get("ONAA_STORE_FULL_REBUILD_SECONDS", "86400"))
_cache: dict[tuple[str, ...] | None, tuple] = {}
_cache_lock = threading.Lock()
_refreshing: set[tuple[str, ...] | None] = set()
COLD_WAIT_SECONDS = float(os.environ.get("ONAA_STORE_COLD_WAIT_SECONDS", "25"))
log = logging.getLogger("onaa.buying")
# One heavy read at a time: the store snapshot build (stores._build) and this list's loads each read every store
# with its probe JSON. Run together on the 512 MB, one shared CPU machine they starved each other and the request
# threads, so after a restart neither finished and /v1/stores answered 503 for good (production outage 2026-11-16).
HEAVY_BUILD_LOCK = threading.Lock()


def _cached_stores(session: Session, statuses: tuple[str, ...] | None) -> list[StoreView]:
    return _cached_stores_as_of(session, statuses)[0]


def _cached_stores_as_of(session: Session, statuses: tuple[str, ...] | None) -> tuple[list[StoreView], str]:
    """The store list and when it was read (UTC). Totals and reachability_counts in one answer come from one list,
    so they always reconcile; two answers with different `list_as_of` may differ as new probes come in."""
    if BUYING_CACHE_SECONDS <= 0 or statuses is None:
        return _stores(session, statuses), _now_iso()
    hit = _cache.get(statuses)
    if hit is not None:
        if time.monotonic() - hit[0] >= BUYING_CACHE_SECONDS:
            _refresh_in_background(session, statuses)
        return hit[1], hit[4]  # fresh, or stale while a refresh runs
    # Cold: one request builds, concurrent ones wait for it instead of building again, but not forever (see
    # stores.snapshot): they give back their pool connection and get a 503 if the list is not ready in time.
    session.close()
    if not _cache_lock.acquire(timeout=COLD_WAIT_SECONDS):
        from fastapi import HTTPException, status

        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "the store list is being loaded; retry shortly",
                            headers={"Retry-After": "30"})
    try:
        hit = _cache.get(statuses)
        if hit is None:
            hit = _cache[statuses] = _load(session, statuses, None)
    finally:
        _cache_lock.release()
    return hit[1], hit[4]


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _watermark(session: Session):
    return session.scalar(select(func.max(Listing.updated_at)).where(Listing.service_type == "marketplace"))


def _load(session: Session, statuses: tuple[str, ...] | None, prev: tuple | None) -> tuple:
    with HEAVY_BUILD_LOCK:
        out = _load_unlocked(session, statuses, prev)
    gc.collect()  # hand the build's temporaries back before the next one starts
    return out


def _load_unlocked(session: Session, statuses: tuple[str, ...] | None, prev: tuple | None) -> tuple:
    now = time.monotonic()
    watermark = _watermark(session)
    if prev is None or prev[2] is None or watermark is None or now - prev[3] >= FULL_RELOAD_SECONDS:
        return (now, _stores(session, statuses), watermark, now, _now_iso())
    rows = session.execute(select(*_VIEW_COLUMNS).where(
        Listing.service_type == "marketplace", Listing.updated_at >= prev[2]))
    by_id = {v.id: v for v in prev[1]}
    for row in rows:
        view = StoreView(*row[:6], _compact(row[6]), *row[7:])
        by_id.pop(view.id, None)
        if view.lifecycle_status in PUBLIC_STATUSES and (
                statuses is None or (view.agent_checkout or {}).get("status") in statuses):
            by_id[view.id] = view
    return (now, sorted(by_id.values(), key=lambda v: v.id), watermark, prev[3], _now_iso())


def _refresh_in_background(session: Session, statuses: tuple[str, ...] | None) -> None:
    with _cache_lock:
        if statuses in _refreshing:
            return
        _refreshing.add(statuses)
    bind = session.get_bind()

    def run() -> None:
        try:
            with Session(bind=bind) as s:
                _cache[statuses] = _load(s, statuses, _cache.get(statuses))
        except Exception:  # noqa: BLE001 - keep serving the previous list
            log.warning("buying store list refresh failed", exc_info=True)
        finally:
            with _cache_lock:
                _refreshing.discard(statuses)

    threading.Thread(target=run, name="onaa-buying-cache", daemon=True).start()


def warm_cache(sessionmaker, after: threading.Thread | None = None) -> None:
    """Load the default candidate list at startup (see BUYING_CACHE_SECONDS), after `after` (the store snapshot
    warm-up) has finished, so the two full reads never run at the same time."""
    if BUYING_CACHE_SECONDS <= 0:
        return

    def run() -> None:
        if after is not None:
            after.join()
        # Load at startup, then refresh on a timer: refreshing only when a request arrives served the first
        # caller after a quiet spell a list up to 40 min old (live audit 2026-11-17, 8th).
        while True:
            try:
                with sessionmaker() as s:
                    hit = _cache.get(POSSIBLE_STATUSES)
                    if hit is None:
                        _cached_stores(s, POSSIBLE_STATUSES)
                    elif time.monotonic() - hit[0] >= BUYING_CACHE_SECONDS:
                        _cache[POSSIBLE_STATUSES] = _load(s, POSSIBLE_STATUSES, hit)
            except Exception:  # noqa: BLE001
                log.warning("buying store list refresh failed", exc_info=True)
            time.sleep(max(BUYING_CACHE_SECONDS / 2, 30))

    threading.Thread(target=run, name="onaa-buying-warm", daemon=True).start()


def reset_cache() -> None:
    _cache.clear()
    _ranks.clear()


def _lookup(session: Session, key: str) -> StoreView | None:
    """One store by listing id, domain or any URL on it, matched in SQL (see `store_key`)."""
    if key.startswith("svc_"):
        row = session.execute(_store_query().where(Listing.id == key)).first()
        return StoreView(*row) if row is not None else None
    k = store_key(key)
    if not k:
        return None
    urls = [f"{scheme}://{host}{path}" for scheme in ("https", "http") for host in (k, "www." + k)
            for path in ("/.well-known/ucp", "/")]
    cond = or_(Listing.documentation_url.in_(urls), Listing.source_url.in_(urls),
               func.lower(Listing.display_name).in_([k, "www." + k]),
               *[Listing.endpoint_url.like(f"{scheme}://{host}/%") for scheme in ("https", "http")
                 for host in (k, "www." + k)],
               *[col.like(f"{scheme}://{host}/%") for col in (Listing.documentation_url, Listing.source_url)
                 for scheme in ("https", "http") for host in (k, "www." + k)])
    rows = session.execute(_store_query().where(cond).order_by(Listing.id).limit(20)).all()
    # Same rule as before: the store whose name or URLs normalise to exactly this key.
    for row in rows:
        view = StoreView(*row)
        names = {store_key(view.display_name or ""), store_key(view.endpoint_url or ""),
                 store_key(view.source_url or ""), store_key(view.documentation_url or "")}
        if k in names:
            return view
    return None


def _shop_mcp(session: Session) -> StoreView | None:
    """The Shop MCP channel listing: narrowed in SQL on the probe text, confirmed on the parsed probe."""
    q = _store_query().where(cast(Listing.agent_checkout, String).like("%shop-mcp%"))
    for row in session.execute(q.order_by(Listing.id).limit(50)).all():
        view = StoreView(*row)
        if ((view.agent_checkout or {}).get("requirements") or {}).get("protocol", "").startswith("shop-mcp"):
            return view
    return None


def _matches_text(listing: Listing, q: str | None) -> bool:
    if not q:
        return True
    hay = " ".join(filter(None, [listing.display_name, listing.description, listing.endpoint_url])).lower()
    return all(w in hay for w in q.lower().split())


def find_stores(session: Session, *, country: str | None = None, agent: str | None = None,
                payment: list[str] | None = None, pay_alone: bool = False, q: str | None = None,
                include: Literal["buyable", "possible", "all"] = "possible", limit: int = 20,
                offset: int = 0, claimed_only: bool = False, reachable_only: bool = False,
                confirmed_reachable_only: bool = False, exclude_sandbox: bool = False) -> dict[str, Any]:
    """Stores matching the buyer's conditions, best answers first.

    include=all = the ranked candidate list (stores whose probe got far enough to answer, cached in memory) followed
    by every other store in store id order. That rest (stores never probed, or whose probe failed) is counted in SQL
    and only the rows on the requested page are read: reading all ~32k stores with their probe JSON per call took
    5-7 s and enough memory to slow the whole 1 GB machine (live re-verification 2026-11-17, 7th).
    exclude_sandbox drops stores whose endpoint hostname looks like a sandbox or test store."""
    wanted = {"buyable": ("yes", "yes_buyer_finishes"), "possible": ("yes", "yes_buyer_finishes", "maybe"),
              "all": tuple(VERDICT_RANK)}[include]
    stores, list_as_of = _cached_stores_as_of(session, POSSIBLE_STATUSES)
    kw = {"country": country, "agent": agent, "payment": payment, "pay_alone": pay_alone}
    pairs = [(s, verdict) for s, verdict, sandbox in _ranked(stores, kw)
             if verdict in wanted and _matches_text(s, q) and (not claimed_only or s.claimed)
             and (not reachable_only or s.reachability != "unreachable")
             and (not confirmed_reachable_only or s.reachability == "reachable")
             and not (exclude_sandbox and sandbox)]
    from .stores import reachability_counts  # stores imports this module

    counts = reachability_counts(s.reachability or "unknown" for s, _ in pairs)
    page = [assess(s, **kw) for s, _ in pairs[offset:offset + limit]]
    total = len(pairs)
    if include == "all":
        rest = _rest_conditions(q, claimed_only, reachable_only, confirmed_reachable_only, exclude_sandbox)
        for state, n in session.execute(select(Listing.reachability, func.count()).where(*rest)
                                        .group_by(Listing.reachability)).all():
            key = state if state in counts else "unknown"
            counts[key] += n
            total += n
        want = offset + limit - len(pairs)
        if want > 0:
            skip = max(0, offset - len(pairs))
            rows = session.execute(_store_query().where(*rest).order_by(Listing.id).offset(skip)
                                   .limit(min(want, limit))).all()
            page += [assess(StoreView(*row[:6], _compact(row[6]), *row[7:]), **kw) for row in rows]
    return {"total": total, "offset": offset, "items": page,
            "reachability_counts": counts,
            "list_as_of": list_as_of,
            "conditions": {"country": _country(country), "agent": agent, "payment": normalise_payment(payment),
                           "pay_alone": pay_alone, "shop_pay_link_offered": pay_alone, "query": q,
                           "include": include, "claimed_only": claimed_only, "reachable_only": reachable_only,
                           "confirmed_reachable_only": confirmed_reachable_only, "exclude_sandbox": exclude_sandbox},
            "tested_countries": list(TESTED_COUNTRIES), "note": NOTE, "verdict_note": VERDICT_NOTE}


# Ranked candidate lists per buyer condition set (country, agent, payment, pay_alone) for the current store list.
# Ranking assesses every candidate (~20k) and took about 1 s of CPU per call on the production machine, so nine
# concurrent calls took 8-11 s each (live audit 2026-11-17, 8th). A ranking is computed once per condition set and
# store list; concurrent callers with the same conditions wait for that one computation. Each entry holds only
# (store, verdict, sandbox) tuples, about 2 MB.
RANK_CACHE_SIZE = 24
_ranks: dict[tuple, tuple[list, list]] = {}
_rank_locks: dict[tuple, threading.Lock] = {}
_ranks_guard = threading.Lock()


def _ranked(stores: list[StoreView], kw: dict) -> list[tuple[StoreView, str, bool]]:
    key = (_country(kw["country"]), (kw["agent"] or "").lower() or None,
           tuple(normalise_payment(kw["payment"])), bool(kw["pay_alone"]))
    hit = _ranks.get(key)
    if hit is not None and hit[0] is stores:
        return hit[1]
    with _ranks_guard:
        lock = _rank_locks.setdefault(key, threading.Lock())
    with lock:
        hit = _ranks.get(key)
        if hit is not None and hit[0] is stores:
            return hit[1]
        scored = [(s, assess(s, steps=False, **kw)) for s in stores]
        scored.sort(key=lambda p: (VERDICT_RANK[p[1]["verdict"]], p[1]["endpoint_environment"] == "sandbox",
                                   p[1]["pay_alone"] != "after_one_time_link",
                                   p[1]["ships_to_country"] is not True, (p[0].display_name or "").lower()))
        ranked = [(s, r["verdict"], r["endpoint_environment"] == "sandbox") for s, r in scored]
        with _ranks_guard:
            for k in [k for k, v in _ranks.items() if v[0] is not stores]:
                del _ranks[k]  # rankings of an older store list would keep that whole list in memory
            if key not in _ranks and len(_ranks) >= RANK_CACHE_SIZE:
                _ranks.pop(next(iter(_ranks)))
            _ranks[key] = (stores, ranked)
    return ranked


def _rest_conditions(q: str | None, claimed_only: bool, reachable_only: bool, confirmed: bool,
                     exclude_sandbox: bool = False) -> list:
    """SQL for the stores outside the candidate list, with the same filters find_stores applies in memory."""
    out = [Listing.service_type == "marketplace", Listing.lifecycle_status.in_(PUBLIC_STATUSES),
           ~Listing.id.in_(select(ListingFacet.listing_id).where(
               ListingFacet.kind == "agent_checkout", ListingFacet.value.in_(POSSIBLE_STATUSES)))]
    for word in (q or "").lower().split():
        like = f"%{word}%"
        out.append(or_(func.lower(Listing.display_name).like(like), func.lower(Listing.description).like(like),
                       func.lower(Listing.endpoint_url).like(like)))
    if claimed_only:
        out.append(and_(Listing.operator_id.is_not(None), Listing.lifecycle_status != "discovered"))
    if reachable_only:
        out.append(Listing.reachability != "unreachable")
    if confirmed:
        out.append(Listing.reachability == "reachable")
    if exclude_sandbox:  # the SQL side of endpoint_environment's _SANDBOX_HOST: a sandbox word between . - or ://
        url = func.lower(func.coalesce(Listing.endpoint_url, ""))
        out.extend(~url.like(f"%{a}{w}{b}%") for w in _SANDBOX_WORDS for a in ("://", ".", "-") for b in (".", "-"))
    return out


def check_stores(session: Session, stores: list[str], *, country: str | None = None, agent: str | None = None,
                 payment: list[str] | None = None, pay_alone: bool = False) -> dict[str, Any]:
    """Answer for each given store id, domain or URL (e.g. the shops in Shop MCP product results)."""
    shop_mcp: StoreView | None = None
    shop_mcp_looked = False
    items = []
    for key in stores[:MAX_STORES_PER_CHECK]:
        listing = _lookup(session, key)
        if listing is not None:
            items.append({"query": key, "found": True,
                          **assess(listing, country=country, agent=agent, payment=payment, pay_alone=pay_alone)})
            continue
        miss: dict[str, Any] = {"query": key, "found": False, "verdict": "unknown",
                                "reasons": ["ONAA has not checked this store"]}
        if not shop_mcp_looked:
            shop_mcp, shop_mcp_looked = _shop_mcp(session), True
        if shop_mcp is not None:
            miss["reasons"].append("if it is a Shopify store, Shopify's Shop MCP may reach it: see `via_shop_mcp` "
                                   "(that probe was made on another store, so it is only indicative)")
            miss["via_shop_mcp"] = assess(shop_mcp, country=country, agent=agent, payment=payment,
                                          pay_alone=pay_alone)
        items.append(miss)
    return {"items": items, "conditions": {"country": _country(country), "agent": agent,
                                           "payment": normalise_payment(payment), "pay_alone": pay_alone},
            "note": NOTE, "verdict_note": VERDICT_NOTE}
