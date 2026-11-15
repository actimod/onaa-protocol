"""check_agent_checkout: stops before payment, classifies outcomes, never calls purchase tools. No network."""

from __future__ import annotations

import json

import httpx
import pytest

from onaa_registry import checkout_checker as mod

TOOLS = [{"name": n} for n in ("search_catalog", "create_checkout", "cancel_checkout", "complete_checkout")]
PRODUCTS = {"ucp": {"version": "2026-08-25"}, "products": [{"variants": [
    {"id": "gid://v/1", "availability": {"available": False}},
    {"id": "gid://v/2", "availability": {"available": True}, "seller": {"domain": "s.example"}}]}]}
CHECKOUT = {"id": "chk_1", "status": "requires_escalation",
            "ucp": {"payment_handlers": {"dev.shopify.card": [{"id": "shopify.card"}], "x": [{"id": "shop_pay"}]}},
            "messages": [{"type": "error", "code": "delivery_address_required"},
                         {"type": "info", "code": "ignored"}]}


def server(calls, *, tools_error=None):
    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((body["method"], body["params"].get("name"), body["params"].get("arguments"),
                      dict(request.headers)))
        if body["method"] == "tools/list":
            if tools_error:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": tools_error})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": TOOLS}})
        name = body["params"]["name"]
        out = {"search_catalog": PRODUCTS, "create_checkout": CHECKOUT, "cancel_checkout": {"status": "canceled"}}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                         "result": {"structuredContent": out[name]}})
    return httpx.Client(transport=httpx.MockTransport(handle))


def test_probe_reaches_checkout_records_requirements_and_cancels():
    calls = []
    http = server(calls)
    c = mod.McpClient("https://shop.example/api/ucp/mcp", http, "https://reg.example/agent/ucp-profile.json",
                      resolver=None)
    obs = mod.clean(mod.probe_channel(c, shop_mcp=False, country="US", currency="USD", pause=lambda s: None))
    assert obs["status"] == "buyer_step_required"
    assert obs["steps"] == ["tools_list", "search", "checkout", "cancel"]
    req = obs["requirements"]
    assert req["payment_handlers"] == ["shop_pay", "shopify.card"]
    assert req["buyer_info_required"] == ["delivery_address_required"]
    assert req["buyer_confirmation_required"] is True and req["agent_auth_required"] is False
    names = [n for _, n, _, _ in calls if n]
    assert "complete_checkout" not in names
    create = next(a for _, n, a, _ in calls if n == "create_checkout")
    assert create["checkout"]["line_items"] == [{"item": {"id": "gid://v/2"}, "quantity": 1}]
    assert all(h.get("ucp-agent") == 'profile="https://reg.example/agent/ucp-profile.json"' for *_, h in calls)


def test_auth_required_and_forbidden_tools():
    calls = []
    http = server(calls, tools_error={"code": -32000, "message": "Unauthorized", "data": {"code": "unauthenticated"}})
    c = mod.McpClient("https://ikea.example/mcp", http, "https://reg.example/p.json", resolver=None)
    obs = mod.probe_channel(c, shop_mcp=False, country="US", currency="USD", pause=lambda s: None)
    assert obs["status"] == "auth_required" and obs["requirements"]["agent_auth_required"] is True
    for name in mod.FORBIDDEN_TOOLS:
        with pytest.raises(RuntimeError):
            c.call_tool(name, {})


def test_unsafe_endpoint_refused():
    with pytest.raises(mod.UnsafeURLError):
        mod.McpClient("http://10.0.0.1/mcp", httpx.Client(), None, resolver=None)


def test_shipping_countries_currency_and_autonomy():
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body["params"].get("name"))
        if body["method"] == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}})
        name = body["params"]["name"]
        if name == "create_checkout":
            cc = body["params"]["arguments"]["checkout"]["context"]["address_country"]
            chk = {**CHECKOUT, "currency": {"US": "USD", "JP": "JPY"}.get(cc, "EUR"),
                   "messages": [] if cc in ("US", "JP") else [{"type": "error",
                                                               "code": "delivery_no_delivery_available"}]}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": chk}})
        out = PRODUCTS if name == "search_catalog" else {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": out}})

    c = mod.McpClient("https://shop.example/mcp", httpx.Client(transport=httpx.MockTransport(handle)),
                      "https://reg.example/p.json", resolver=None)
    obs = mod.clean(mod.probe_channel(c, shop_mcp=False, country="US", currency="USD", pause=lambda s: None,
                                      ship_test={"US": "USD", "DE": "EUR", "JP": "JPY"}))
    req = obs["requirements"]
    assert req["ships_to"] == ["JP", "US"] and req["no_shipping_to"] == ["DE"]
    assert req["currencies_seen"] == ["EUR", "JPY", "USD"]
    assert req["autonomous_payment"] == "after_one_time_link"
    assert calls.count("create_checkout") == 3 and calls.count("cancel_checkout") == 3
    assert "complete_checkout" not in calls


def test_partner_hint_from_manifest():
    req = {"manifest_payment_handlers": ["com.google.pay"]}
    assert "Google" in mod.accepted_agents_hint(req)
    assert mod.accepted_agents_hint({}).startswith("authenticated")


def test_manifest_hint_follows_www_redirect_only():
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.host == "ikea.example":
            return httpx.Response(301, headers={"location": "https://www.ikea.example/.well-known/ucp"})
        if request.url.host == "www.ikea.example":
            return httpx.Response(200, json={"ucp": {"payment_handlers": {"com.google.pay": []}}})
        return httpx.Response(301, headers={"location": "https://evil.example/.well-known/ucp"})
    http = httpx.Client(transport=httpx.MockTransport(handle))
    assert mod.manifest_hints(http, "https://ikea.example/.well-known/ucp") == {
        "manifest_payment_handlers": ["com.google.pay"]}
    assert mod.manifest_hints(http, "https://other.example/.well-known/ucp") == {}


def test_check_order_never_checked_then_oldest():
    rows = [{"id": "svc_b", "agent_checkout": {"checked_at": "2026-11-14T10:00:00+00:00"}},
            {"id": "svc_c"},
            {"id": "svc_a", "agent_checkout": {"checked_at": "2026-11-01T10:00:00+00:00"}}]
    assert [r["id"] for r in sorted(rows, key=mod.check_order)] == ["svc_c", "svc_a", "svc_b"]


FULFILLMENT_KR = {"methods": [{"type": "shipping", "groups": [{"id": "g1", "options": [
    {"id": "exp", "title": "Express", "totals": [{"type": "total", "amount": 45000}],
     "earliest_fulfillment_time": "2026-11-20T00:00:00Z", "latest_fulfillment_time": "2026-11-22T00:00:00Z"},
    {"id": "std", "title": "Standard", "totals": [{"type": "total", "amount": 18000}],
     "earliest_fulfillment_time": "2026-11-25T00:00:00Z", "latest_fulfillment_time": "2026-12-02T00:00:00Z"}]}]}]}


def test_delivery_without_address_is_not_a_no():
    # The store never looked at an address: "no delivery available" says nothing about the country.
    no_addr = {"messages": [{"type": "error", "code": "delivery_address_required"},
                            {"type": "error", "code": "delivery_no_delivery_available"}]}
    assert mod.delivery(no_addr) == (None, None)
    assert mod.delivery({"messages": [{"type": "error", "code": "delivery_no_delivery_available"}]}) == (False, None)
    ok, quote = mod.delivery({"currency": "KRW", "fulfillment": FULFILLMENT_KR, "messages": []})
    assert ok is True
    assert quote == {"options": 2, "cheapest_amount": 18000, "currency": "KRW",
                     "earliest": "2026-11-25T00:00:00Z", "latest": "2026-12-02T00:00:00Z"}


def test_probe_sends_public_test_address_and_records_quotes():
    sent = {}

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}})
        name = body["params"]["name"]
        out: dict = PRODUCTS if name == "search_catalog" else {}
        if name == "create_checkout":
            chk_in = body["params"]["arguments"]["checkout"]
            cc = chk_in["context"]["address_country"]
            sent[cc] = chk_in.get("fulfillment")
            if cc == "KR":
                out = {**CHECKOUT, "currency": "KRW", "fulfillment": FULFILLMENT_KR, "messages": []}
            elif cc == "IN":  # address given, store still has no option: a real "no delivery"
                out = {**CHECKOUT, "messages": [{"type": "error", "code": "delivery_no_delivery_available"}]}
            else:  # store ignored the address (no fulfillment negotiated): unknown, never "no"
                out = {**CHECKOUT, "messages": [{"type": "error", "code": "delivery_address_required"},
                                                {"type": "error", "code": "delivery_no_delivery_available"}]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": out}})

    c = mod.McpClient("https://shop.example/mcp", httpx.Client(transport=httpx.MockTransport(handle)),
                      "https://reg.example/p.json", resolver=None)
    obs = mod.clean(mod.probe_channel(c, shop_mcp=False, country="US", currency="USD", pause=lambda s: None,
                                      ship_test=mod.SHIP_TEST))
    req = obs["requirements"]
    assert len(mod.SHIP_TEST) == 10 and set(sent) == set(mod.SHIP_TEST)
    dest = sent["KR"]["methods"][0]["destinations"][0]
    assert dest["address_country"] == "KR" and dest["postal_code"] == "04524" and dest["first_name"] == "ONAA"
    assert req["ships_to"] == ["KR"] and req["no_shipping_to"] == ["IN"]
    assert req["delivery_test"] == "address"
    assert req["shipping_quotes"]["KR"]["cheapest_amount"] == 18000
    from onaa_registry.schemas import AgentCheckoutObservation
    AgentCheckoutObservation(**obs)  # the admin/loop schema accepts it


def test_published_shipping_from_meta_json():
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/meta.json"
        host = request.url.host
        if host == "world.example":
            return httpx.Response(200, json={"ships_to_countries": ["*", "KR", "US"]})
        if host == "few.example":
            return httpx.Response(200, json={"ships_to_countries": ["us", "CA", "bad1", 3]})
        return httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handle))
    w = mod.published_shipping(http, "https://world.example/.well-known/ucp")
    assert w == {"published_ships_worldwide": True, "published_ships_to": [],
                 "published_ships_source": "https://world.example/meta.json"}
    f = mod.published_shipping(http, "https://few.example/.well-known/ucp")
    assert f["published_ships_worldwide"] is False and f["published_ships_to"] == ["CA", "US"]
    assert mod.published_shipping(http, "https://none.example/.well-known/ucp") == {}
    assert mod.published_shipping(http, "https://mcp.shop.com/docs") == {}
