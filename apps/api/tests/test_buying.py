"""Buying questions: answers derived from recorded checkout probes, with "not tested" kept apart from "no"."""

from __future__ import annotations

import datetime as dt

from conftest import admin_headers

from onaa_registry import buying
from onaa_registry.models import Listing


def _store(client, domain, status, requirements=None, endpoint=None):
    svc = {"display_name": domain, "service_type": "marketplace",
           "endpoint_url": endpoint or f"https://{domain.split('.')[0]}-shop.myshopify.com/api/ucp/mcp",
           "documentation_url": f"https://{domain}/.well-known/ucp",
           "source_url": f"https://{domain}/.well-known/ucp"}
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=svc)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    body = {"status": status, "steps": ["tools_list", "search", "checkout", "cancel"]}
    if requirements:
        body["requirements"] = requirements
    r = client.post(f"/v1/admin/listings/{sid}/agent-checkout", headers=admin_headers(), json=body)
    assert r.status_code == 200, r.text
    return sid


SHOP_PAY = {"protocol": "ucp-mcp", "protocol_version": "2026-08-25", "agent_profile_required": True,
            "agent_auth_required": False, "payment_handlers": ["shop_pay", "shopify.card"],
            "buyer_info_required": ["buyer_identity_contact_method_required", "delivery_address_required"],
            "buyer_confirmation_required": True, "tested_country": "US", "currency": "USD",
            "ships_to": ["KR", "US"], "no_shipping_to": ["DE"], "delivery_test": "address",
            "autonomous_payment": "after_one_time_link"}
CARD_ONLY = {**SHOP_PAY, "payment_handlers": ["shopify.card"], "autonomous_payment": "none_observed",
             "ships_to": ["KR", "US", "DE"], "no_shipping_to": []}
GOOGLE_ONLY = {"protocol": "ucp-mcp", "agent_profile_required": True, "agent_auth_required": True,
               "manifest_payment_handlers": ["com.google.pay"],
               "accepted_agents_hint": "Google agents (Gemini, AI Mode) via Google Pay, inferred from the manifest; "
                                       "anonymous agents refused"}


def _seed(client):
    return {"shoes": _store(client, "shoes.example.com", "buyer_step_required", SHOP_PAY),
            "cards": _store(client, "cards.example.com", "checkout_ready", CARD_ONLY),
            "google": _store(client, "google-only.example.com", "auth_required", GOOGLE_ONLY),
            "none": _store(client, "nothing.example.com", "no_checkout")}


def test_find_stores_ship_to_korea_and_pay_alone(client):
    ids = _seed(client)
    page = client.get("/v1/buying/stores", params={"country": "kr", "pay_alone": "true"}).json()
    assert [i["store"]["id"] for i in page["items"]] == [ids["shoes"]]
    item = page["items"][0]
    assert item["verdict"] == "yes_buyer_finishes" and item["ships_to_country"] is True
    assert item["pay_alone"] == "after_one_time_link"
    assert "delivery address" in item["how_to_buy"]["before_checkout"]
    assert page["conditions"]["country"] == "KR" and "not a verification" in page["note"]
    # Without pay_alone the card-only store qualifies too, and ranks first (checkout_ready).
    page = client.get("/v1/buying/stores", params={"country": "KR"}).json()
    assert [i["store"]["id"] for i in page["items"]] == [ids["cards"], ids["shoes"]]
    # Germany: shoes reported no delivery; it drops out of the default list but shows with reasons in include=all.
    page = client.get("/v1/buying/stores", params={"country": "DE", "include": "all"}).json()
    by_id = {i["store"]["id"]: i for i in page["items"]}
    assert by_id[ids["shoes"]]["verdict"] == "no"
    assert any("no delivery" in r for r in by_id[ids["shoes"]]["reasons"])
    assert by_id[ids["none"]]["verdict"] == "no" and by_id[ids["google"]]["verdict"] == "no"


def test_untested_country_is_maybe_not_no(client):
    ids = _seed(client)
    page = client.get("/v1/buying/stores", params={"country": "FR"}).json()
    assert {i["store"]["id"] for i in page["items"]} == {ids["shoes"], ids["cards"]}
    assert all(i["verdict"] == "maybe" and i["ships_to_country"] is None for i in page["items"])
    assert client.get("/v1/buying/stores", params={"country": "FR", "include": "buyable"}).json()["total"] == 0


def test_check_by_domain_url_and_agent(client):
    ids = _seed(client)
    r = client.get("/v1/buying/check", params=[
        ("store", "https://www.shoes.example.com/products/runner?variant=1"), ("store", "google-only.example.com"),
        ("store", "unknown.example.org"), ("store", ids["cards"]), ("country", "KR"), ("agent", "Gemini"),
        ("payment", "google_pay")])
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert [i["found"] for i in items] == [True, True, False, True]
    shoes, google, unknown, cards = items
    assert shoes["store"]["id"] == ids["shoes"] and shoes["verdict"] == "no"  # google pay not offered there
    assert any("payment methods" in x for x in shoes["reasons"])
    assert google["verdict"] == "maybe" and "Google agents" in google["accepted_agents"]
    assert unknown["verdict"] == "unknown" and "not checked" in unknown["reasons"][0]
    assert cards["verdict"] == "no"
    claude = client.get("/v1/buying/check", params={"store": "google-only.example.com", "agent": "claude"}).json()
    assert claude["items"][0]["verdict"] == "no"


def test_check_by_myshopify_endpoint_and_card(client):
    ids = _seed(client)
    out = client.get("/v1/buying/check", params={"store": "shoes-shop.myshopify.com", "payment": "card,shop_pay",
                                                  "country": "US"}).json()["items"][0]
    assert out["store"]["id"] == ids["shoes"] and out["verdict"] == "yes_buyer_finishes"
    assert out["payment_match"] is True
    steps = " ".join(out["how_to_buy"]["steps"])
    assert "UCP-Agent" in steps and "search_catalog" in steps and "continue_url" in steps
    assert "ONAA is not a party" in steps


def test_check_limits(client):
    assert client.get("/v1/buying/check").status_code == 422
    many = ",".join(f"s{i}.example.com" for i in range(26))
    assert client.get("/v1/buying/check", params={"store": many}).status_code == 422


def test_shop_mcp_fallback_for_unchecked_shopify_store(client):
    _store(client, "shop.app", "buyer_step_required",
           {**SHOP_PAY, "protocol": "shop-mcp/mcp-2026-07-28", "agent_profile_required": None, "ships_to": []},
           endpoint="https://mcp.shop.com/")
    item = client.get("/v1/buying/check", params={"store": "brand-new.example.com"}).json()["items"][0]
    assert item["found"] is False and item["via_shop_mcp"]["checkout_status"] == "buyer_step_required"
    assert "Shop MCP" in " ".join(item["via_shop_mcp"]["how_to_buy"]["steps"])


def test_stale_and_never_checked():
    listing = Listing(id="svc_x", display_name="old.example.com", service_type="marketplace",
                      reachability="unknown",
                      agent_checkout={"status": "checkout_ready", "checked_at": "2026-01-01T00:00:00+00:00",
                                      "requirements": {}})
    out = buying.assess(listing, now=dt.datetime(2026, 3, 1, tzinfo=dt.UTC))
    assert out["verdict"] == "yes" and any("14 days" in c for c in out["cautions"])
    fresh = Listing(id="svc_y", display_name="new.example.com", service_type="marketplace", reachability="unknown")
    assert buying.assess(fresh)["verdict"] == "unknown"
    assert buying.store_key("HTTPS://WWW.A.Example/x") == "a.example"
    assert buying.normalise_payment(["Google Pay", "credit-card", "Shop Pay"]) == ["gpay", "shop_pay",
                                                                                    "shopify.card"]


def test_find_stores_candidate_cache_serves_stale_then_refreshes(client, monkeypatch):
    """Production keeps the candidate list in memory; a new probe result shows up after the next refresh."""
    import time

    monkeypatch.setattr(buying, "BUYING_CACHE_SECONDS", 3600)
    buying.reset_cache()
    try:
        _seed(client)
        before = client.get("/v1/buying/stores", params={"include": "possible"}).json()["total"]
        _store(client, "cachetest.example.com", "checkout_ready", CARD_ONLY)
        assert client.get("/v1/buying/stores", params={"include": "possible"}).json()["total"] == before  # cached
        key = buying.POSSIBLE_STATUSES
        stale_at = buying._cache[key][0] - 7200
        buying._cache[key] = (stale_at, buying._cache[key][1])  # expire it
        client.get("/v1/buying/stores", params={"include": "possible"})  # stale served, refresh started
        for _ in range(200):  # wait for the background rebuild itself, not a proxy for it
            if buying._cache[key][0] > stale_at and key not in buying._refreshing:
                break
            time.sleep(0.05)
        assert client.get("/v1/buying/stores", params={"include": "possible"}).json()["total"] == before + 1
    finally:
        buying.reset_cache()


def test_candidate_probe_json_is_interned():
    """The cached candidate list keeps one copy of each repeated string (country codes, handler names)."""
    a = buying._compact({"requirements": {"published_ships_to": ["U" + "S", "CA"]}})
    b = buying._compact({"requirements": {"published_ships_to": ["".join(["U", "S"]), "CA"]}})
    assert a == b and a["requirements"]["published_ships_to"][0] is b["requirements"]["published_ships_to"][0]


def test_find_stores_trust_filters(client):
    """claimed_only and reachable_only mean the same on find_stores, /v1/buying/stores and /v1/stores."""
    _seed(client)
    for path in ("/v1/buying/stores", "/v1/stores"):
        everything = client.get(path).json()["total"]
        assert everything > 0
        # Every seeded store was found on the web (unclaimed) and never health-checked.
        assert client.get(path, params={"claimed_only": "true"}).json()["total"] == 0
        assert client.get(path, params={"reachable_only": "true"}).json()["total"] == 0
    item = client.get("/v1/stores").json()["items"][0]
    assert item["trust"]["claimed"] is False and item["trust"]["reachability"] == "unknown"
