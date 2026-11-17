"""Buying questions: answers derived from recorded checkout probes, with "not tested" kept apart from "no"."""

from __future__ import annotations

import datetime as dt
import re

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
        buying._cache[key] = (stale_at, *buying._cache[key][1:])  # expire it (incremental refresh follows)
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
        # Every seeded store was found on the web (unclaimed).
        assert client.get(path, params={"claimed_only": "true"}).json()["total"] == 0
        # reachable_only hides only "unreachable" (same as /v1/services); unknown stays.
        assert client.get(path, params={"reachable_only": "true"}).json()["total"] == everything
    item = client.get("/v1/stores").json()["items"][0]
    # The checkout probe reached the endpoint, so it counts as reachable (endpoint health from the checker).
    assert item["trust"]["claimed"] is False and item["trust"]["reachability"] == "reachable"


def test_services_agent_checkout_carries_payment_flags(client):
    """/v1/services shows the same 'payment never tested' facts as /v1/stores and find_stores."""
    sid = _store(client, "flags.example.com", "checkout_ready", CARD_ONLY)
    ac = client.get(f"/v1/services/{sid}").json()["agent_checkout"]
    assert ac["status"] == "checkout_ready"
    assert ac["payment_tested"] is False and ac["payment_success_verified"] is False
    assert ac["post_link_autonomy_verified"] is False
    hit = next(i for i in client.get("/v1/services", params={"q": "flags"}).json()["items"] if i["id"] == sid)
    assert hit["agent_checkout"]["payment_tested"] is False


def test_exclude_unreachable_alias_and_reachability_counts(client):
    """exclude_unreachable is the same rule as reachable_only; answers count reachable/unknown/unreachable.
    The 1-2 failures stay reachable, 3 make it unreachable, recovery rule is covered in test_health.py."""
    from onaa_registry.models import utcnow

    ids = _seed(client)
    with client.app.state.sessionmaker() as s:
        s.get(Listing, ids["cards"]).reachability = "unreachable"
        s.get(Listing, ids["shoes"]).reachability = "reachable"
        for key in ("cards", "shoes"):
            s.get(Listing, ids[key]).updated_at = utcnow()
        s.commit()
    buying.reset_cache()
    for path in ("/v1/buying/stores", "/v1/stores"):
        page = client.get(path, params={"include": "all"} if "buying" in path else {}).json()
        counts = page["reachability_counts"]
        # Every probed store answered (reachable) except the one marked unreachable.
        assert counts["unreachable"] == 1 and counts["reachable"] == page["total"] - 1
        assert sum(counts.values()) == page["total"]
        for flag in ("reachable_only", "exclude_unreachable"):
            params = {flag: "true", **({"include": "all"} if "buying" in path else {})}
            filtered = client.get(path, params=params).json()
            assert filtered["total"] == page["total"] - 1 and filtered["reachability_counts"]["unreachable"] == 0
            assert ids["cards"] not in [(i.get("store") or i).get("id") for i in filtered["items"]]


def test_checkout_path_observed_leads_every_answer(client):
    """Founder decision 2026-11-16: checkout_path_observed first; verdict yes deprecated with a rename date."""
    ids = _seed(client)
    page = client.get("/v1/buying/stores", params={"include": "all"}).json()
    by_id = {i["store"]["id"]: i for i in page["items"]}
    assert next(iter(by_id[ids["cards"]])) == "checkout_path_observed"
    assert by_id[ids["cards"]]["checkout_path_observed"] is True and by_id[ids["cards"]]["verdict"] == "yes"
    assert by_id[ids["none"]]["checkout_path_observed"] is False
    assert buying.VERDICT_YES_RENAME_ON in page["verdict_note"]
    rec = client.get("/v1/stores/cards.example.com").json()
    assert rec["agent_purchase"]["checkout_path_observed"] is True


def test_observation_does_not_change_with_caller_conditions(client):
    """BeUrbanRunning case: card-only store, checkout_ready. pay_alone=true makes it ineligible, but the
    observation (checkout reached) stays true; only eligible_for_request and its reasons change."""
    _store(client, "beurban.example.com", "checkout_ready", CARD_ONLY)
    answers = {}
    for flag in ("false", "true"):
        r = client.get("/v1/buying/check", params={"store": "beurban.example.com", "country": "US",
                                                   "payment": "card,shop_pay", "pay_alone": flag})
        answers[flag] = r.json()["items"][0]
    loose, strict = answers["false"], answers["true"]
    assert loose["checkout_path_observed"] is True and strict["checkout_path_observed"] is True
    assert loose["checkout_status"] == strict["checkout_status"] == "checkout_ready"
    assert loose["eligible_for_request"] is True and loose["eligibility_reasons"] == []
    assert strict["eligible_for_request"] is False and strict["verdict"] == "no"
    assert any("one-time link" in r for r in strict["eligibility_reasons"])



def test_checker_records_endpoint_health_and_strict_filter(client):
    """Developer evaluation 2026-11-16: every store was 'unknown' because discovered stores were never
    health-probed. The checkout probe now records endpoint health; confirmed_reachable_only keeps only stores
    whose last probe answered; three failed probes make a store unreachable."""
    ok = _store(client, "answered.example.com", "checkout_ready", CARD_ONLY)
    bad = _store(client, "broken.example.com", "failed")
    with client.app.state.sessionmaker() as s:
        assert s.get(Listing, ok).reachability == "reachable" and s.get(Listing, ok).last_check_result == "ok"
        assert s.get(Listing, bad).reachability == "unknown" and s.get(Listing, bad).consecutive_check_failures == 1
    for _ in range(2):
        client.post(f"/v1/admin/listings/{bad}/agent-checkout", headers=admin_headers(), json={"status": "failed"})
    with client.app.state.sessionmaker() as s:
        assert s.get(Listing, bad).reachability == "unreachable"
    buying.reset_cache()
    for path in ("/v1/buying/stores", "/v1/stores"):
        params = {"include": "all"} if "buying" in path else {}
        strict = client.get(path, params={**params, "confirmed_reachable_only": "true"}).json()
        ids = [(i.get("store") or i).get("id") for i in strict["items"]]
        assert ok in ids and bad not in ids
        assert set(k for k, v in strict["reachability_counts"].items() if v) == {"reachable"}


def test_strict_and_relaxed_counts_reconcile_within_one_list(client):
    """Live re-verification 2026-11-17 (5th): strict 18,809 vs relaxed 18,841, both all 'reachable'. The two
    calls read different store lists (new probes landed in between). Each answer now says which list it read
    (list_as_of), and within one list strict = relaxed's reachable count."""
    _store(client, "answered.example.com", "checkout_ready", CARD_ONLY)
    _store(client, "unprobed.example.com", "buyer_step_required", CARD_ONLY)
    buying.reset_cache()
    with client.app.state.sessionmaker() as s:
        relaxed = buying.find_stores(s, include="all")
        strict = buying.find_stores(s, include="all", confirmed_reachable_only=True)
    assert relaxed["total"] == sum(relaxed["reachability_counts"].values())
    assert strict["total"] == relaxed["reachability_counts"]["reachable"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", relaxed["list_as_of"])


def test_how_to_buy_uses_the_currency_the_store_actually_returned():
    # The probe asked for USD; the store's test checkout answered in EUR (beurbanrunning.com, 2026-11-15).
    req = {"tested_country": "US", "currency": "USD", "currencies_seen": ["EUR"], "agent_profile_required": True}
    ac = {"status": "checkout_ready", "protocol": "ucp-mcp", "requirements": req}
    steps = " ".join(buying.how_to_buy(ac, country="US")["steps"])
    assert '"currency": "USD"' not in steps
    assert "asked for USD and the store answered in EUR" in steps
    usd = {**ac, "requirements": {**req, "currencies_seen": ["USD"]}}
    same = " ".join(buying.how_to_buy(usd, country="US")["steps"])
    assert '"currency": "USD"' in same and "answered in" not in same


def test_check_record_counts_probes_and_shows_recent_checks(client):
    sid = _store(client, "record.example.com", "buyer_step_required", SHOP_PAY)
    path = f"/v1/admin/listings/{sid}/agent-checkout"
    for status in ("failed", "checkout_ready"):
        r = client.post(path, headers=admin_headers(), json={"status": status, "requirements": SHOP_PAY})
        assert r.status_code == 200, r.text
    item = client.get("/v1/buying/check", params={"store": "record.example.com"}).json()["items"][0]
    rec = item["check_record"]
    assert rec["checks_total"] == 3 and rec["checkout_reached_count"] == 2
    assert rec["checkout_reached_rate"] == 0.67
    assert [c["status"] for c in rec["recent_checks"]] == ["checkout_ready", "failed", "buyer_step_required"]
    assert rec["first_checked_on"] == rec["recent_checks"][-1]["on"] and rec["last_checked_at"]
    assert rec["recent_consistent"] is False and "not a verification" in rec["note"]
    assert rec["insufficient_history"] is False
    store = client.get("/v1/stores/record.example.com").json()
    assert store["trust"]["check_record"]["checks_total"] == 3


def test_check_record_rebuilt_from_audit_for_older_probes(client):
    sid = _store(client, "older.example.com", "checkout_ready", CARD_ONLY)
    with client.app.state.sessionmaker() as s:
        listing = s.get(Listing, sid)
        listing.agent_checkout = {k: v for k, v in listing.agent_checkout.items() if k != "check_history"}
        s.commit()
    # Before the next probe, the answer falls back to the last probe alone.
    rec = client.get("/v1/buying/check", params={"store": sid}).json()["items"][0]["check_record"]
    assert rec["checks_total"] == 1 and rec["checkout_reached_rate"] == 1.0
    assert rec["insufficient_history"] is True  # a rate of 1.0 from one probe means little
    r = client.post(f"/v1/admin/listings/{sid}/agent-checkout", headers=admin_headers(),
                    json={"status": "no_checkout"})
    assert r.status_code == 200, r.text
    rec = client.get("/v1/buying/check", params={"store": sid}).json()["items"][0]["check_record"]
    assert rec["checks_total"] == 2 and rec["checkout_reached_count"] == 1


def test_next_check_history_keeps_newest_five():
    hist = None
    for i in range(7):
        hist = buying.next_check_history(hist, "checkout_ready" if i % 2 else "failed",
                                         dt.datetime(2026, 11, 1 + i, tzinfo=dt.UTC))
    assert hist["total"] == 7 and hist["reached"] == 3 and hist["first"] == "2026-11-01"
    assert [d for d, _ in hist["recent"]] == ["2026-11-07", "2026-11-06", "2026-11-05", "2026-11-04", "2026-11-03"]
    assert buying.check_record({})["checks_total"] == 0


def test_declared_vs_observed_payment_and_endpoint_environment(client):
    """6th re-verification 2026-11-17: a manifest declared handlers the test checkout did not offer, and the
    endpoint was a sandbox host. Both are now shown apart, and the environment is labelled."""
    req = {**CARD_ONLY, "manifest_payment_handlers": ["com.google.pay", "dev.shopify.shop_pay"]}
    _store(client, "sandboxed.example.com", "checkout_ready", req,
           endpoint="https://sandboxed-sandbox.myshopify.com/api/ucp/mcp")
    _store(client, "plain.example.com", "checkout_ready", CARD_ONLY)
    sb, plain = (client.get("/v1/buying/check", params={"store": d}).json()["items"][0]
                 for d in ("sandboxed.example.com", "plain.example.com"))
    assert sb["declared_payment_handlers"] == ["com.google.pay", "dev.shopify.shop_pay"]
    assert sb["observed_checkout_payment_options"] == ["shopify.card"]
    assert sb["endpoint_environment"] == "sandbox" and plain["endpoint_environment"] == "unknown"
    assert buying.endpoint_environment("https://staging.shop.example.com/mcp") == "sandbox"


def test_sandbox_and_single_probe_are_cautioned(client):
    """7th live re-verification: a sandbox endpoint probed once came back verdict yes with no cautions."""
    _store(client, "sbx.example.com", "checkout_ready", CARD_ONLY,
           endpoint="https://sbx-sandbox.myshopify.com/api/ucp/mcp")
    item = client.get("/v1/buying/check", params={"store": "sbx.example.com"}).json()["items"][0]
    text = " ".join(item["cautions"])
    assert "sandbox" in text and "only 1 time" in text
    _store(client, "prod.example.com", "checkout_ready", CARD_ONLY)
    ranked = [i["store_id"] if "store_id" in i else i["store"]["name"]
              for i in client.get("/v1/buying/stores", params={"country": "US", "exclude_sandbox": "false"}).json()[
                  "items"]]
    assert ranked.index("prod.example.com") < ranked.index("sbx.example.com")


def test_include_all_appends_unprobed_stores_counted_in_sql(client, monkeypatch):
    """7th live re-verification 2026-11-17: include=all read every store with its probe JSON per call (5-7 s, and
    memory enough to slow the 1 GB machine). The candidate list stays cached; the other stores are counted in SQL
    and only the rows on the page are read."""
    monkeypatch.setattr(buying, "BUYING_CACHE_SECONDS", 3600)
    buying.reset_cache()
    try:
        _store(client, "ready.example.com", "checkout_ready", CARD_ONLY)
        _store(client, "broken.example.com", "failed")
        _store(client, "nocheckout.example.com", "no_checkout")
        reads = []
        real = buying._stores
        monkeypatch.setattr(buying, "_stores", lambda s, st=None: reads.append(st) or real(s, st))
        everything = client.get("/v1/buying/stores", params={"include": "all", "limit": 2}).json()
        assert reads == [buying.POSSIBLE_STATUSES]  # never the whole table
        assert everything["total"] == 3 == sum(everything["reachability_counts"].values())
        names = [i["store"]["name"] for i in everything["items"]]
        assert names[0] == "ready.example.com" and len(names) == 2
        assert all(i["how_to_buy"] is not None for i in everything["items"])
        page2 = client.get("/v1/buying/stores", params={"include": "all", "limit": 2, "offset": 2}).json()
        assert len(page2["items"]) == 1 and page2["items"][0]["store"]["name"] not in names
        strict = client.get("/v1/buying/stores", params={"include": "all", "confirmed_reachable_only": "true"}).json()
        assert strict["total"] == everything["reachability_counts"]["reachable"]
        texty = client.get("/v1/buying/stores", params={"include": "all", "q": "nocheckout"}).json()
        assert [i["store"]["name"] for i in texty["items"]] == ["nocheckout.example.com"]
    finally:
        buying.reset_cache()


def test_shop_pay_link_offered_is_the_literal_name_for_pay_alone(client):
    """8th live audit 2026-11-17: pay_alone read like a capability. shop_pay_link_offered names what ONAA saw;
    pay_alone stays as a deprecated alias with the same result."""
    ids = _seed(client)
    new = client.get("/v1/buying/stores", params={"country": "KR", "shop_pay_link_offered": "true"}).json()
    old = client.get("/v1/buying/stores", params={"country": "KR", "pay_alone": "true"}).json()
    assert [i["store"]["id"] for i in new["items"]] == [i["store"]["id"] for i in old["items"]] == [ids["shoes"]]
    item = new["items"][0]
    assert item["shop_pay_link_offered"] is True and item["pay_alone"] == "after_one_time_link"
    assert new["conditions"]["shop_pay_link_offered"] is True
    assert not any("works" in c for c in item["cautions"])
    cards = client.get("/v1/buying/check", params={"store": "cards.example.com"}).json()["items"][0]
    assert cards["shop_pay_link_offered"] is False
    check = client.get("/v1/buying/check", params={"store": "cards.example.com", "country": "KR",
                                                   "shop_pay_link_offered": "true"}).json()["items"][0]
    assert check["verdict"] == "no"


def test_sandbox_endpoints_are_left_out_by_default(client):
    """8th live audit: sandbox endpoints could be eligible with no way to drop them. exclude_sandbox drops them
    (in the ranked list and in the include=all rest), on by default since the founder's decision of 2026-11-17;
    exclude_sandbox=false lists them."""
    _store(client, "prod.example.com", "checkout_ready", CARD_ONLY)
    _store(client, "sbx.example.com", "checkout_ready", CARD_ONLY, endpoint="https://sbx-sandbox.myshopify.com/api")
    _store(client, "dead.example.com", "failed", endpoint="https://shop.test.example.org/api")
    names = lambda body: {i["store"]["name"] for i in body["items"]}  # noqa: E731
    shown = client.get("/v1/buying/stores", params={"country": "US", "exclude_sandbox": "false"}).json()
    assert names(shown) == {"prod.example.com", "sbx.example.com"}
    assert shown["conditions"]["exclude_sandbox"] is False
    hidden = client.get("/v1/buying/stores", params={"country": "US"}).json()
    assert names(hidden) == {"prod.example.com"} and hidden["total"] == 1
    assert hidden["conditions"]["exclude_sandbox"] is True
    every = client.get("/v1/buying/stores", params={"include": "all"}).json()
    assert names(every) == {"prod.example.com"} and every["total"] == 1
    all_shown = client.get("/v1/buying/stores", params={"include": "all", "exclude_sandbox": "false"}).json()
    assert all_shown["total"] == 3


def test_ranking_is_computed_once_per_condition_set(client, monkeypatch):
    """8th live audit: nine concurrent find_stores calls took 8-11 s each because every call assessed every
    candidate. The ranking is now cached per condition set and store list, and concurrent callers share one."""
    import threading

    monkeypatch.setattr(buying, "BUYING_CACHE_SECONDS", 3600)
    buying.reset_cache()
    try:
        _seed(client)
        calls = []
        real = buying.assess
        monkeypatch.setattr(buying, "assess", lambda *a, **k: calls.append(k.get("steps", True)) or real(*a, **k))
        first = client.get("/v1/buying/stores", params={"country": "KR"}).json()
        ranked = calls.count(False)
        assert ranked == 3  # every candidate once
        results = []
        threads = [threading.Thread(target=lambda: results.append(
            client.get("/v1/buying/stores", params={"country": "KR", "q": "o"}).json())) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert calls.count(False) == ranked  # same conditions: no new ranking
        assert all(r["total"] >= 1 for r in results)
        client.get("/v1/buying/stores", params={"country": "DE"})
        assert calls.count(False) == 2 * ranked  # new conditions: one new ranking
        assert first["list_as_of"]
    finally:
        buying.reset_cache()
