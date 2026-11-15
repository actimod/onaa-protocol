"""Check whether an outside agent can search each buying channel and reach checkout, and record "how to buy here".

For every `service_type=marketplace` listing with an MCP endpoint, as an anonymous agent identified by ONAA's
UCP profile: list tools -> search the catalog -> create a one-item checkout -> cancel it when the store offers a
cancel tool. It NEVER completes a checkout, creates a spend request or sends payment data: those tool names are
refused in code. No order is placed and nothing is charged. One store at a time, with a pause between stores.

What is recorded per store (via the admin API, with --apply): status (checkout_ready, buyer_step_required,
auth_required, no_checkout, failed), the steps that worked, and purchase requirements observed: protocol and
version, whether an agent profile or authentication is required, payment handler ids offered, buyer information
the checkout asked for, whether the buyer must confirm, and the tested country and currency. Product data seen
during the probe is not stored. Store responses are untrusted data: only those fields are read.

    python scripts/check_agent_checkout.py --registry-url https://api.onaa.net            # dry run, prints JSON
    ONAA_ADMIN_TOKEN=... python scripts/check_agent_checkout.py --registry-url ... --apply

Running it against the public registry, and scheduling it, need the founder's approval.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

import httpx

from onaa_registry.netsafety import UnsafeURLError, resolve_public, system_resolver, validate_public_url

FORBIDDEN_TOOLS = frozenset({"complete_checkout", "create_spend_request", "complete_spend_request",
                             "update_spend_request"})
NEW_PROTOCOL = "2026-07-28"
SEARCH_QUERIES = ("gift", "t-shirt", "socks", "book", "mug")
SHIP_TEST = {"US": "USD", "GB": "GBP", "DE": "EUR", "JP": "JPY", "KR": "KRW",
             "CA": "CAD", "AU": "AUD", "FR": "EUR", "SG": "SGD", "IN": "INR"}
# A delivery test needs an address: without one a store answers "no delivery available" for every country (the
# 2026-11 false "ships nowhere" results). These are public landmarks, never a person's address; the recipient
# name is the checker itself. The checkout is cancelled and never paid, so nothing is ever sent there.
TEST_DESTINATIONS = {
    "US": ("350 Fifth Avenue", "New York", "NY", "10118"),               # Empire State Building
    "GB": ("30 St Mary Axe", "London", "", "EC3A 8BF"),                   # 30 St Mary Axe
    "DE": ("Alexanderplatz 1", "Berlin", "", "10178"),
    "JP": ("2-8-1 Nishi-Shinjuku", "Shinjuku-ku", "Tokyo", "163-8001"),  # Tokyo Metropolitan Government
    "KR": ("110 Sejong-daero", "Jung-gu", "Seoul", "04524"),              # Seoul City Hall
    "CA": ("290 Bremner Blvd", "Toronto", "ON", "M5V 3L9"),               # CN Tower
    "AU": ("Bennelong Point", "Sydney", "NSW", "2000"),                   # Sydney Opera House
    "FR": ("5 Avenue Anatole France", "Paris", "", "75007"),              # Eiffel Tower
    "SG": ("10 Bayfront Avenue", "Singapore", "", "018956"),              # Marina Bay Sands
    "IN": ("Apollo Bandar, Colaba", "Mumbai", "MH", "400001"),            # Gateway of India
}
NO_DELIVERY = "delivery_no_delivery_available"
ADDRESS_REQUIRED = "delivery_address_required"
MAX_PUBLISHED_COUNTRIES = 260
MAX_BODY = 2 * 1024 * 1024
CLIENT_INFO = {"name": "onaa-checkout-checker", "version": "0.1"}


class ProbeError(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class McpClient:
    """Minimal MCP client for both header styles: classic JSON-RPC, and the 2026-07-28 per-request metadata."""

    def __init__(self, endpoint: str, http: httpx.Client, profile_url: str | None,
                 resolver: Callable[[str], list[str]] | None = system_resolver):
        host = validate_public_url(endpoint)
        if resolver is not None:
            resolve_public(host, resolver)
        self.endpoint, self.http, self.profile_url = endpoint, http, profile_url
        self.new_style = False
        self.calls = 0

    def _headers(self, method: str, name: str | None) -> dict[str, str]:
        h = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        if self.profile_url:
            h["UCP-Agent"] = f'profile="{self.profile_url}"'
        if self.new_style:
            h["MCP-Protocol-Version"] = NEW_PROTOCOL
            h["Mcp-Method"] = method
            if name:
                h["Mcp-Name"] = name
        return h

    def _post(self, method: str, params: dict, name: str | None) -> dict:
        if self.new_style:
            params = {**params, "_meta": {"io.modelcontextprotocol/clientInfo": CLIENT_INFO,
                                          "io.modelcontextprotocol/protocolVersion": NEW_PROTOCOL,
                                          "io.modelcontextprotocol/clientCapabilities": {}}}
        body = {"jsonrpc": "2.0", "id": self.calls + 1, "method": method, "params": params}
        self.calls += 1
        r = self.http.post(self.endpoint, json=body, headers=self._headers(method, name))
        raw = r.content[:MAX_BODY]
        text = raw.decode("utf-8", "replace")
        if "text/event-stream" in (r.headers.get("content-type") or ""):
            data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
            text = data[-1] if data else ""
        try:
            doc = json.loads(text)
        except ValueError as exc:
            if r.status_code in (401, 403):
                raise ProbeError("auth_required", f"HTTP {r.status_code}") from exc
            raise ProbeError("failed", f"HTTP {r.status_code}, not JSON") from exc
        if not isinstance(doc, dict):
            raise ProbeError("failed", "unexpected JSON-RPC response")
        return doc

    def request(self, method: str, params: dict | None = None, name: str | None = None) -> dict:
        if method == "tools/call" and name in FORBIDDEN_TOOLS:
            raise RuntimeError(f"refusing to call {name}: the checker never pays or places orders")
        doc = self._post(method, params or {}, name)
        err = doc.get("error")
        if err and not self.new_style and err.get("code") in (-32022, -32020, -32602):
            self.new_style = True
            doc = self._post(method, params or {}, name)
            err = doc.get("error")
        if err:
            code, msg = err.get("code"), str(err.get("message", ""))[:200]
            data = err.get("data") if isinstance(err.get("data"), dict) else {}
            if code in (-32000, -32001) and data.get("code") in ("unauthenticated", "unauthorized", "forbidden") \
                    or "unauthor" in msg.lower():
                raise ProbeError("auth_required", msg)
            raise ProbeError("failed", f"{code} {msg} {str(data.get('code', ''))[:60]}".strip())
        return doc.get("result") or {}

    def call_tool(self, name: str, arguments: dict) -> dict:
        res = self.request("tools/call", {"name": name, "arguments": arguments}, name)
        sc = res.get("structuredContent")
        if not isinstance(sc, dict):
            content = res.get("content") or []
            text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
            try:
                sc = json.loads(text)
            except ValueError:
                sc = {}
        if res.get("isError") and not sc.get("status"):
            raise ProbeError("failed", f"{name} returned an error")
        return sc if isinstance(sc, dict) else {}


def _first_offer(result: dict) -> tuple[str, str | None, str | None] | None:
    """(variant id, seller domain, protocol version) of the first available, priced variant."""
    for p in result.get("products") or []:
        if not isinstance(p, dict):
            continue
        for v in p.get("variants") or []:
            if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                continue
            if (v.get("availability") or {}).get("available") is False:
                continue
            seller = v.get("seller") if isinstance(v.get("seller"), dict) else {}
            return v["id"], seller.get("domain"), (result.get("ucp") or {}).get("version")
    return None


def _handlers(checkout: dict) -> list[str]:
    ph = (checkout.get("ucp") or {}).get("payment_handlers") or {}
    ids = set()
    if isinstance(ph, dict):
        for items in ph.values():
            for h in items if isinstance(items, list) else []:
                if isinstance(h, dict) and isinstance(h.get("id"), str):
                    ids.add(h["id"].lower()[:60])
    return sorted(ids)[:16]


def _message_codes(checkout: dict) -> list[str]:
    codes = set()
    for m in checkout.get("messages") or []:
        if isinstance(m, dict) and m.get("type") == "error" and isinstance(m.get("code"), str):
            codes.add(m["code"].lower()[:80])
    return sorted(codes)[:16]


def destination(country: str) -> dict[str, Any] | None:
    """UCP fulfillment input with the public test address for `country`, or None when there is none."""
    addr = TEST_DESTINATIONS.get(country)
    if not addr:
        return None
    street, locality, region, postal = addr
    dest = {"id": f"onaa-test-{country.lower()}", "first_name": "ONAA", "last_name": "Checker",
            "street_address": street, "address_locality": locality, "postal_code": postal,
            "address_country": country}
    if region:
        dest["address_region"] = region
    return {"methods": [{"type": "shipping", "destinations": [dest]}]}


def _amount(totals: Any) -> int | None:
    if not isinstance(totals, list):
        return None
    by_type = {t.get("type"): t.get("amount") for t in totals if isinstance(t, dict)}
    for key in ("total", "fulfillment", "subtotal"):
        if isinstance(by_type.get(key), int) and not isinstance(by_type.get(key), bool):
            return by_type[key]
    return None


def _options(checkout: dict) -> list[dict]:
    ful = checkout.get("fulfillment")
    out = []
    for m in (ful.get("methods") or []) if isinstance(ful, dict) else []:
        if not isinstance(m, dict) or m.get("type", "shipping") != "shipping":
            continue
        for g in m.get("groups") or []:
            for o in (g.get("options") or []) if isinstance(g, dict) else []:
                if isinstance(o, dict):
                    out.append(o)
    return out


def delivery(checkout: dict) -> tuple[bool | None, dict | None]:
    """(ships, cheapest shipping quote) from one test checkout. None = the checkout did not say.

    Shipping options returned for the test address -> ships, with the cheapest option's cost (minor units of the
    checkout currency) and delivery window. "No delivery available" -> does not ship, unless the store also asked
    for an address: then it never looked at one, and the answer says nothing about the country."""
    codes = _message_codes(checkout)
    opts = _options(checkout)
    if opts:
        priced = [(a, o) for o in opts if (a := _amount(o.get("totals"))) is not None]
        quote: dict[str, Any] = {"options": min(len(opts), 50)}
        if priced:
            amount, best = min(priced, key=lambda x: x[0])
            quote["cheapest_amount"] = amount
            cur = checkout.get("currency")
            if isinstance(cur, str) and len(cur) == 3 and cur.isalpha():
                quote["currency"] = cur.upper()
            for key, out in (("earliest_fulfillment_time", "earliest"), ("latest_fulfillment_time", "latest")):
                if isinstance(best.get(key), str):
                    quote[out] = best[key][:32]
        return True, quote
    if any(c.startswith(NO_DELIVERY) for c in codes):
        return (None, None) if ADDRESS_REQUIRED in codes else (False, None)
    if ADDRESS_REQUIRED in codes:
        return None, None
    return True, None


def published_shipping(http: httpx.Client, manifest_url: str | None) -> dict[str, Any]:
    """The countries the store itself publishes as shipping destinations (Shopify /meta.json), best effort.

    Store-published, not tested by ONAA: kept apart from ships_to. "*" is Shopify's rest-of-world zone, i.e. the
    store ships everywhere, so the country list is then dropped."""
    if not manifest_url or not manifest_url.endswith("/.well-known/ucp"):
        return {}
    url = manifest_url[: -len("/.well-known/ucp")] + "/meta.json"
    try:
        validate_public_url(url)
        r = http.get(url)
        doc = json.loads(r.content[:MAX_BODY]) if r.status_code == 200 else None
    except (httpx.HTTPError, UnsafeURLError, ValueError):
        return {}
    raw = doc.get("ships_to_countries") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        return {}
    worldwide = "*" in raw
    codes = sorted({c.upper() for c in raw if isinstance(c, str) and len(c) == 2 and c.isalpha()})
    return {"published_ships_worldwide": worldwide,
            "published_ships_to": [] if worldwide else codes[:MAX_PUBLISHED_COUNTRIES],
            "published_ships_source": url[:300]}


def _autonomy(handlers: list[str]) -> str:
    if "shop_pay" in handlers:
        return "after_one_time_link"
    return "none_observed" if handlers else "not_offered"


def manifest_hints(http: httpx.Client, manifest_url: str | None) -> dict[str, Any]:
    """Payment handler namespaces from the store's public UCP manifest (best effort, untrusted)."""
    if not manifest_url or not manifest_url.endswith("/.well-known/ucp"):
        return {}
    try:
        host = validate_public_url(manifest_url)
        r = http.get(manifest_url)
        loc = r.headers.get("location", "")
        # One redirect is followed only to the same site with or without "www." (e.g. ikea.com -> www.ikea.com).
        if r.status_code in (301, 302, 307, 308) and loc.endswith("/.well-known/ucp"):
            to = validate_public_url(loc)
            if to.removeprefix("www.") == host.removeprefix("www."):
                r = http.get(loc)
        doc = json.loads(r.content[:MAX_BODY]) if r.status_code == 200 else {}
    except (httpx.HTTPError, UnsafeURLError, ValueError):
        return {}
    ph = (doc.get("ucp") or {}).get("payment_handlers") if isinstance(doc, dict) else None
    names = sorted(str(k).lower()[:60] for k in ph)[:16] if isinstance(ph, dict) else []
    return {"manifest_payment_handlers": names} if names else {}


def accepted_agents_hint(req: dict) -> str | None:
    names = req.get("manifest_payment_handlers", [])
    if "com.google.pay" in names and not any(n.startswith("dev.shopify") for n in names):
        return "Google agents (Gemini, AI Mode) via Google Pay, inferred from the manifest; anonymous agents refused"
    return "authenticated or partner agents only; anonymous agents refused"


def probe_channel(client: McpClient, *, shop_mcp: bool, country: str, currency: str,
                  pause: Callable[[float], None] = time.sleep, ship_test: dict[str, str] | None = None,
                  hints: dict[str, Any] | None = None) -> dict[str, Any]:
    steps: list[str] = []
    req: dict[str, Any] = {"protocol": "shop-mcp" if shop_mcp else "ucp-mcp", "tested_country": country,
                           "currency": currency, "agent_profile_required": None if shop_mcp else True,
                           **(hints or {})}
    meta = {} if shop_mcp else {"meta": {"ucp-agent": {"profile": client.profile_url}}}
    try:
        tools = {t.get("name") for t in client.request("tools/list").get("tools", []) if isinstance(t, dict)}
        steps.append("tools_list")
        req["agent_auth_required"] = False
        if client.new_style:
            req["protocol"] += f"/mcp-{NEW_PROTOCOL}"
        if "search_catalog" not in tools or "create_checkout" not in tools:
            return {"status": "no_checkout", "steps": steps, "detail": "no catalog search or checkout tool",
                    "requirements": req}
        offer = None
        for q in SEARCH_QUERIES:
            res = client.call_tool("search_catalog", {**meta, "catalog": {
                "query": q, "context": {"address_country": country, "currency": currency}}})
            offer = _first_offer(res)
            if offer:
                break
            pause(1.0)
        steps.append("search")
        if not offer:
            return {"status": "no_checkout", "steps": steps, "detail": "search returned nothing purchasable",
                    "requirements": req}
        variant, seller, version = offer
        req["protocol_version"] = (version or "")[:20] or None
        def checkout_input(cc: str, cur: str) -> dict[str, Any]:
            body: dict[str, Any] = {"line_items": [{"item": {"id": variant}, "quantity": 1}],
                                    "context": {"address_country": cc, "currency": cur}}
            if (ful := destination(cc)) is not None:
                body["fulfillment"] = ful
            return body

        args: dict[str, Any] = {**meta, "checkout": checkout_input(country, currency)}
        if shop_mcp:
            if not seller:
                return {"status": "no_checkout", "steps": steps, "detail": "offer had no seller domain",
                        "requirements": req}
            args["shop"] = seller
        checkout = client.call_tool("create_checkout", args)
        if not checkout.get("id"):
            return {"status": "failed", "steps": steps, "detail": "create_checkout returned no checkout id",
                    "requirements": req}
        steps.append("checkout")
        state = str(checkout.get("status", ""))
        req["payment_handlers"] = _handlers(checkout)
        req["buyer_info_required"] = _message_codes(checkout)
        req["buyer_confirmation_required"] = state == "requires_escalation" or None
        req["autonomous_payment"] = _autonomy(req["payment_handlers"])

        def cancel(chk: dict) -> bool:
            if "cancel_checkout" not in tools or not chk.get("id"):
                return False
            try:
                cargs = {**meta, "id": chk["id"]}
                if shop_mcp:
                    cargs["shop"] = seller
                client.call_tool("cancel_checkout", cargs)
                return True
            except ProbeError:
                return False  # checkouts also expire on their own; no order exists either way

        if cancel(checkout):
            steps.append("cancel")
        ships, no_ship, currencies = set(), set(), {str(checkout.get("currency", ""))[:3].upper()} - {""}
        quotes: dict[str, dict] = {}

        def record(cc: str, chk: dict) -> None:
            ok, quote = delivery(chk)
            if ok is True:
                ships.add(cc)
            elif ok is False:
                no_ship.add(cc)
            if quote and "cheapest_amount" in quote:
                quotes[cc] = quote

        record(country, checkout)
        for cc, cur in (ship_test or {}).items():
            if cc == country:
                continue
            pause(1.0)
            try:
                other = client.call_tool("create_checkout", {**args, "checkout": checkout_input(cc, cur)})
            except ProbeError:
                continue
            if not other.get("id"):
                continue
            record(cc, other)
            if isinstance(other.get("currency"), str):
                currencies.add(other["currency"][:3].upper())
            cancel(other)
        req["ships_to"], req["no_shipping_to"] = sorted(ships), sorted(no_ship)
        req["delivery_test"] = "address"
        req["shipping_quotes"] = dict(sorted(quotes.items()))
        req["currencies_seen"] = sorted(c for c in currencies if len(c) == 3 and c.isalpha())
        status = "buyer_step_required" if state == "requires_escalation" else "checkout_ready"
        return {"status": status, "steps": steps, "detail": f"checkout status {state[:40] or 'unknown'}",
                "requirements": req}
    except ProbeError as exc:
        if exc.status == "auth_required":
            req["agent_auth_required"] = True
            req["accepted_agents_hint"] = accepted_agents_hint(req)
        return {"status": exc.status, "steps": steps, "detail": exc.detail[:500], "requirements": req}
    except (httpx.HTTPError, UnsafeURLError) as exc:
        return {"status": "failed", "steps": steps, "detail": type(exc).__name__, "requirements": req}


def clean(obs: dict) -> dict:
    req = {k: v for k, v in obs.get("requirements", {}).items() if v not in (None, [], "", {})}
    out = {k: v for k, v in obs.items() if k != "requirements" and v not in (None, [], "")}
    if req:
        out["requirements"] = req
    return out


def marketplace_listings(http: httpx.Client, registry: str) -> list[dict]:
    items, offset = [], 0
    while True:
        page = http.get(f"{registry}/v1/services", params={"service_type": "marketplace", "limit": 100,
                                                           "offset": offset}).json()
        items += page.get("items", [])
        offset += 100
        if offset >= page.get("total", 0):
            return items


def check_order(listing: dict) -> tuple:
    """Never-checked stores first, then the oldest check."""
    checked = (listing.get("agent_checkout") or {}).get("checked_at")
    return (checked is not None, checked or "", listing.get("id", ""))


def check_one(http: httpx.Client, listing: dict, profile: str, args) -> dict:
    shop_mcp = (httpx.URL(listing["endpoint_url"]).host or "") == "mcp.shop.com"
    try:
        client = McpClient(listing["endpoint_url"], http, None if shop_mcp else profile)
        countries = [c.strip().upper() for c in args.ship_countries.split(",") if c.strip()]
        ship_test = {c: SHIP_TEST.get(c, args.currency) for c in countries}
        hints = {**manifest_hints(http, listing.get("documentation_url")),
                 **published_shipping(http, listing.get("documentation_url"))}
        obs = probe_channel(client, shop_mcp=shop_mcp, country=args.country, currency=args.currency,
                            ship_test=ship_test, hints=hints)
    except UnsafeURLError as exc:
        obs = {"status": "failed", "steps": [], "detail": f"unsafe endpoint: {exc}"[:500]}
    except Exception as exc:  # noqa: BLE001 - one broken store must not stop the run
        obs = {"status": "failed", "steps": [], "detail": type(exc).__name__}
    return clean(obs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--registry-url", default="https://api.onaa.net")
    ap.add_argument("--profile-url", default=None,
                    help="UCP agent profile (default: <registry>/agent/ucp-profile.json)")
    ap.add_argument("--country", default="US")
    ap.add_argument("--currency", default="USD")
    ap.add_argument("--delay", type=float, default=3.0, help="seconds between stores")
    ap.add_argument("--ship-countries", default=",".join(SHIP_TEST),
                    help="countries to test delivery for (one extra checkout each, cancelled); empty to skip")
    ap.add_argument("--only", action="append", default=[], help="listing id(s) to check")
    ap.add_argument("--apply", action="store_true", help="record results through the admin API")
    ap.add_argument("--workers", type=int, default=1,
                    help="stores checked in parallel (each store is still probed one call at a time)")
    ap.add_argument("--max-minutes", type=float, default=0,
                    help="stop starting new stores after this long (0 = no limit); never-checked and oldest "
                         "checks go first, so repeated runs rotate through every store")
    args = ap.parse_args(argv)

    registry = args.registry_url.rstrip("/")
    profile = args.profile_url or f"{registry}/agent/ucp-profile.json"
    token = os.environ.get("ONAA_ADMIN_TOKEN", "")
    if args.apply and not token:
        raise SystemExit("ONAA_ADMIN_TOKEN is required with --apply")
    run_id = uuid.uuid4().hex[:8]
    summary: dict[str, int] = {}
    with httpx.Client(timeout=20.0, follow_redirects=False,
                      headers={"user-agent": f"ONAA-Checkout-Checker/0.1 (+{registry}/opt-out; run {run_id})"}) as http:
        listings = [x for x in marketplace_listings(http, registry)
                    if x.get("endpoint_url") and (not args.only or x["id"] in args.only)]
        listings.sort(key=check_order)
        started = time.monotonic()
        deadline = started + args.max_minutes * 60 if args.max_minutes > 0 else None
        lock = threading.Lock()
        queue = list(reversed(listings))

        def next_listing() -> dict | None:
            with lock:
                if not queue or (deadline is not None and time.monotonic() > deadline):
                    return None
                return queue.pop()

        def worker(first: bool) -> None:
            while (listing := next_listing()) is not None:
                if not first:
                    time.sleep(args.delay)
                first = False
                obs = check_one(http, listing, profile, args)
                with lock:
                    summary[obs["status"]] = summary.get(obs["status"], 0) + 1
                    print(json.dumps({"id": listing["id"], "name": listing["display_name"], **obs},
                                     ensure_ascii=False), flush=True)
                if args.apply:
                    r = http.post(f"{registry}/v1/admin/listings/{listing['id']}/agent-checkout", json=obs,
                                  headers={"Authorization": f"Bearer {token}"})
                    if r.status_code != 200:
                        print(f"record failed for {listing['id']}: HTTP {r.status_code}", file=sys.stderr)

        threads = [threading.Thread(target=worker, args=(i == 0,)) for i in range(max(1, min(args.workers, 8)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if queue:
            print(f"time budget reached: {len(queue)} stores left for the next run", file=sys.stderr)
    print(json.dumps({"checked": sum(summary.values()), "by_status": summary}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
