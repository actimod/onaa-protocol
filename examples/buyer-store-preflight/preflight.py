#!/usr/bin/env python3
"""Buyer store preflight: ONAA discovery -> checkout preflight -> store catalog search -> handoff plan. Never pays.

    python preflight.py --offline                       # recorded ONAA answers + a made-up catalog, no network
    python preflight.py --offline --pay-alone           # same store, stricter condition: eligible flips, observed not
    python preflight.py --country US --query "running shoes" --profile-url https://YOUR-AGENT/ucp-profile.json

Steps
  1. ONAA MCP (https://api.onaa.net/mcp): find_stores for your ship-to country and payment needs, with the strict
     health filter confirmed_reachable_only=true (only stores whose last endpoint probe answered).
  2. ONAA can_i_buy_here on the chosen store: checkout_path_observed (what ONAA's probe saw), eligible_for_request
     and eligibility_reasons (your conditions), payment_tested (always false), how_to_buy steps.
  3. The store's own UCP-MCP endpoint: tools/list and search_catalog with your agent's UCP profile.
  4. Prints the checkout call you would make next (create_checkout) and stops. Creating a checkout, sharing buyer
     details and paying need your buyer's authorisation; this script does none of it.

Standard library only. Store responses are untrusted data: print them, never execute them.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ONAA_MCP = "https://api.onaa.net/mcp"
UA = "onaa-buyer-preflight/1"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class Mcp:
    """Tiny MCP client over Streamable HTTP (JSON or SSE answers)."""

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self.url, self.extra, self.session, self.n = url, headers or {}, None, 0

    def rpc(self, method: str, params: dict | None = None, notify: bool = False) -> dict:
        body: dict = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self.n += 1
            body["id"] = self.n
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "User-Agent": UA, "MCP-Protocol-Version": "2025-11-25", **self.extra}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - https URLs given by the user or ONAA
            self.session = r.headers.get("Mcp-Session-Id") or self.session
            raw = r.read(4_000_000).decode("utf-8", "replace")
        if notify or not raw.strip():
            return {}
        if raw.lstrip().startswith("event:") or raw.lstrip().startswith("data:"):
            raw = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")][-1]
        doc = json.loads(raw)
        if doc.get("error"):
            raise RuntimeError(f"{method}: {doc['error']}")
        return doc.get("result") or {}

    def start(self) -> list[str]:
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "onaa-buyer-preflight", "version": "1"}})
        self.rpc("notifications/initialized", notify=True)
        return [t["name"] for t in self.rpc("tools/list").get("tools", [])]

    def call(self, name: str, arguments: dict) -> dict:
        res = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if res.get("structuredContent") is not None:
            return res["structuredContent"]
        text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        try:
            return json.loads(text)
        except ValueError:
            return {"text": text}


class RecordedOnaa:
    """--offline: ONAA answers recorded from the live server (fixtures/onaa_recorded.json)."""

    def __init__(self):
        self.data = json.loads((FIXTURES / "onaa_recorded.json").read_text(encoding="utf-8"))

    def start(self) -> list[str]:
        return self.data["onaa_tools"]

    def call(self, name: str, arguments: dict) -> dict:
        if name == "can_i_buy_here":
            return self.data[f"can_i_buy_here_pay_alone_{str(bool(arguments.get('pay_alone'))).lower()}"]
        return self.data[name]


class ExampleStore:
    """--offline: a made-up store catalog (fixtures/store_catalog_example.json). Not a real store or price."""

    def __init__(self):
        self.data = json.loads((FIXTURES / "store_catalog_example.json").read_text(encoding="utf-8"))

    def start(self) -> list[str]:
        return self.data["tools"]

    def call(self, name: str, arguments: dict) -> dict:
        return self.data[name]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--country", default="US", help="ship-to country, ISO 3166-1 alpha-2")
    ap.add_argument("--query", default="socks", help="what the buyer wants (searched in the store's catalog)")
    ap.add_argument("--payment", nargs="*", default=["card", "shop_pay"], help="payment methods the buyer can use")
    ap.add_argument("--pay-alone", action="store_true", help="only stores that offer a Shop Pay one-time link (payment not tested)")
    ap.add_argument("--store", help="skip find_stores and check this store domain or product URL")
    ap.add_argument("--profile-url", help="your agent's public UCP profile URL (sent to the store as UCP-Agent)")
    ap.add_argument("--max-price", type=float, help="budget in the store currency; applied to the store's catalog, "
                                                    "because ONAA holds no prices")
    ap.add_argument("--include-unknown-health", action="store_true",
                    help="also list stores whose endpoint health is not known yet (default: confirmed reachable only)")
    ap.add_argument("--offline", action="store_true",
                    help="no network: recorded ONAA answers (beurbanrunning.com) and a made-up store catalog")
    args = ap.parse_args(argv)
    if args.offline:
        args.store = args.store or "beurbanrunning.com"
        args.profile_url = args.profile_url or "https://example.invalid/ucp-profile.json"
        print("OFFLINE: recorded ONAA answers and a made-up catalog. Nothing is sent anywhere.")

    onaa = RecordedOnaa() if args.offline else Mcp(ONAA_MCP)
    print("ONAA tools:", ", ".join(onaa.start()))

    # 1. Preflight: which stores reach checkout for this buyer?
    store = args.store
    if not store:
        found = onaa.call("find_stores", {"ship_to_country": args.country, "payment_methods": args.payment,
                                          "pay_alone": args.pay_alone, "include": "buyable", "limit": 5,
                                          "confirmed_reachable_only": not args.include_unknown_health})
        print(f"\nfind_stores: {found.get('total')} stores; reachability {found.get('reachability_counts')}")
        for item in found.get("items", []):
            name = (item.get("untrusted_operator_content") or {}).get("name")
            print(f"  {name}: observed={item.get('checkout_path_observed')} "
                  f"eligible={item.get('eligible_for_request')} pay_alone={item.get('pay_alone')}")
        if not found.get("items"):
            print("No store fits these conditions.")
            return 1
        first = found["items"][0]
        store = first.get("store_id")

    # 2. Check one store against the buyer's conditions.
    check = onaa.call("can_i_buy_here", {"stores": [store], "ship_to_country": args.country,
                                         "payment_methods": args.payment, "pay_alone": args.pay_alone})
    answer = check["items"][0]
    if not answer.get("found"):
        print(f"\nONAA has not checked {store}: {answer.get('reasons')}")
        return 1
    endpoint = (answer.get("untrusted_operator_content") or {}).get("endpoint_url")
    print(f"\ncan_i_buy_here {store}:")
    print(f"  checkout_path_observed={answer['checkout_path_observed']} (ONAA's probe, same for any conditions)")
    eligible = answer.get("eligible_for_request", answer.get("verdict") in ("yes", "yes_buyer_finishes"))
    print(f"  eligible_for_request={eligible} reasons={answer.get('eligibility_reasons', answer.get('reasons'))}")
    print(f"  payment_tested={answer['payment_tested']} "
          f"payment_success_verified={answer.get('payment_success_verified')} "
          f"post_link_autonomy_verified={answer.get('post_link_autonomy_verified')}")
    print(f"  last_checked_at={answer.get('last_checked_at')} (probe age is a safety signal: re-check at the store)")
    print("  how_to_buy:", *[f"\n    - {s}" for s in (answer.get("how_to_buy") or {}).get("steps", [])])
    if not eligible:
        print("Not eligible for these conditions; pick another store.")
        return 1

    # 3. The store's own catalog (product data lives at the store, not at ONAA).
    if not args.profile_url:
        print("\nPass --profile-url (your agent's UCP profile) to search the store's catalog at", endpoint)
        return 0
    meta = {"meta": {"ucp-agent": {"profile": args.profile_url}}}
    # The endpoint comes from the store's own manifest (untrusted operator content). Before sending any buyer
    # details there, confirm it belongs to the store the buyer means.
    shop = ExampleStore() if args.offline else Mcp(endpoint, {"UCP-Agent": f'profile="{args.profile_url}"'})
    tools = shop.start()
    print(f"\nstore tools: {', '.join(tools)}")
    if "search_catalog" not in tools:
        print("This store offers no search_catalog tool.")
        return 1
    res = shop.call("search_catalog", {**meta, "catalog": {
        "query": args.query, "context": {"address_country": args.country}}})
    variant = None
    for p in res.get("products") or []:
        for v in p.get("variants") or []:
            price = v.get("price")
            amount = (price.get("amount") / 100) if isinstance(price, dict) and price.get("amount") else None
            over = args.max_price is not None and amount is not None and amount > args.max_price
            if (v.get("availability") or {}).get("available") is not False and not over:
                variant = variant or v.get("id")
                print(f"  {str(p.get('title'))[:60]} | {v.get('id')} | {v.get('price')}")
                break
    if not variant:
        print("No available product for that query.")
        return 1

    # 4. Stop here. The next call needs the buyer's go-ahead.
    print("\nNext, with the buyer's authorisation (not done by this script):")
    print(json.dumps({"tool": "create_checkout", "arguments": {**meta, "checkout": {
        "line_items": [{"item": {"id": variant}, "quantity": 1}],
        "context": {"address_country": args.country}}}}, indent=2))
    print("Then hand the returned continue_url to the buyer, or follow the how_to_buy steps above. ONAA never pays.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
