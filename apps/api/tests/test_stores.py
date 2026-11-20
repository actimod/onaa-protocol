"""Store data for buying agents: filters, one store, feeds, store pages, on-demand discovery."""

from __future__ import annotations

import json

from conftest import admin_headers

MANIFEST = {"ucp": {"version": "2026-08-25", "services": {"dev.ucp.shopping": [
    {"transport": "mcp", "endpoint": "https://newshop.myshopify.example/api/ucp/mcp"}]},
    "capabilities": {"dev.ucp.shopping.checkout": [{}], "dev.ucp.shopping.catalog.search": [{}]}}}


def _store(client, domain, status=None, **req):
    svc = {"display_name": domain, "service_type": "marketplace",
           "endpoint_url": f"https://{domain.split('.')[0]}.myshopify.example/api/ucp/mcp",
           "documentation_url": f"https://{domain}/.well-known/ucp",
           "source_url": f"https://{domain}/.well-known/ucp", "capabilities": ["checkout", "cart"]}
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=svc)
    assert r.status_code == 201, r.text
    rec = r.json()
    if status:
        obs = {"status": status, "steps": ["tools_list", "search", "checkout", "cancel"],
               "requirements": {"protocol": "ucp-mcp", "tested_country": "US", "currency": "USD", **req}}
        assert client.post(f"/v1/admin/listings/{rec['id']}/agent-checkout", headers=admin_headers(),
                           json=obs).status_code == 200
    return rec


def _seed(client):
    a = _store(client, "alpha.example", "buyer_step_required", ships_to=["US", "KR"], no_shipping_to=["JP"],
               payment_handlers=["shop_pay", "shopify.card"], autonomous_payment="after_one_time_link")
    b = _store(client, "beta.example", "checkout_ready", ships_to=["US"], no_shipping_to=["KR"],
               payment_handlers=["shopify.card"], autonomous_payment="none_observed")
    c = _store(client, "gamma.example")
    return a, b, c


def test_filters_ships_to_and_pays_alone(client):
    a, b, c = _seed(client)
    got = client.get("/v1/stores", params={"ships_to": "KR", "pays_alone": "true"}).json()
    assert [x["id"] for x in got["items"]] == [a["id"]]
    assert got["items"][0]["checkout_probe"]["agent_can_pay_alone"] is True
    assert got["items"][0]["catalog"]["category"] == "unknown"
    assert client.get("/v1/stores", params={"ships_to": "US"}).json()["total"] == 2
    assert client.get("/v1/stores", params={"checkout": "not_checked_yet"}).json()["items"][0]["id"] == c["id"]
    assert client.get("/v1/stores", params={"payment_handler": "shop_pay"}).json()["total"] == 1
    assert client.get("/v1/stores", params={"protocol": "ucp"}).json()["total"] == 2
    assert client.get("/v1/stores", params={"q": "beta"}).json()["items"][0]["domain"] == "beta.example"
    fr = client.get("/v1/stores", params={"ships_to": "BR"}).json()
    assert fr["total"] == 0 and fr["untested_countries"] == ["BR"]


def test_one_store_by_domain_or_id(client):
    a, _, _ = _seed(client)
    by_domain = client.get("/v1/stores/www.alpha.example").json()
    assert by_domain["id"] == a["id"] and by_domain["store_url"] == "https://alpha.example/"
    assert client.get(f"/v1/stores/{a['id']}").json()["domain"] == "alpha.example"
    assert client.get("/v1/stores/unknown.example").status_code == 404


def test_feeds_and_etag(client):
    _seed(client)
    r = client.get("/stores.json")
    assert r.status_code == 200 and r.headers["etag"]
    body = r.json()
    assert body["count"] == 3 and body["summary"]["agent_can_pay_alone"] == 1
    assert client.get("/stores.json", headers={"If-None-Match": r.headers["etag"]}).status_code == 304
    assert client.get("/v1/stores.json").json()["count"] == 3
    csv_text = client.get("/stores.csv").text
    assert csv_text.splitlines()[0].startswith("id,name,domain") and len(csv_text.splitlines()) == 4
    _store(client, "delta.example")
    assert client.get("/stores.json").json()["count"] == 4  # cache follows changes


def test_store_pages_are_crawlable_and_escaped(client):
    _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    index = client.get("/stores")
    assert index.status_code == 200 and 'href="/stores/alpha.example"' in index.text
    page = client.get("/stores/alpha.example")
    assert page.status_code == 200 and "How alpha.example looks to an AI shopping agent" in page.text
    assert 'type="application/json"' in page.text
    assert client.get("/stores/<script>").status_code == 404


def _manifest_site(fetcher, domain, manifest=MANIFEST):
    fetcher.routes[f"https://{domain}/robots.txt"] = (404, "")
    fetcher.routes[f"https://{domain}/.well-known/ucp"] = (200, json.dumps(manifest))


def test_check_listed_store_by_product_url(client):
    a, _, _ = _seed(client)
    got = client.get("/v1/stores/check", params={"url": "https://www.alpha.example/products/shoe?x=1",
                                                  "country": "KR"}).json()
    item = got["items"][0]
    assert item["found"] is True and item["store"]["id"] == a["id"] and item["verdict"] == "yes_buyer_finishes"
    stats = client.get("/v1/stats/usage").json()
    assert stats["external"]["store_checks"]["listed"] == 1


def test_check_unlisted_store_is_discovered_live(client, fetcher):
    _manifest_site(fetcher, "newshop.example.com")
    r = client.post("/v1/stores/check", json={"stores": ["https://newshop.example.com/products/mug"]})
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["found"] is True and item["newly_discovered"] is True
    assert item["probe"]["outcome"] == "ok_added" and item["verdict"] == "unknown"
    rec = client.get("/v1/stores/newshop.example.com").json()
    assert rec["endpoints"]["mcp"] == "https://newshop.myshopify.example/api/ucp/mcp"
    assert rec["trust"]["registration_status"] == "discovered"
    # Asking again answers from the listing; no second fetch.
    calls = len(fetcher.calls)
    again = client.get("/v1/buying/check", params={"store": "newshop.example.com"}).json()["items"][0]
    assert again["found"] is True and len(fetcher.calls) == calls
    stats = client.get("/v1/stats/usage").json()
    assert stats["external"]["store_checks"]["ok_added"] == 1
    assert stats["external"]["unlisted_stores_asked"] == {"newshop.example.com": 1}


def test_check_unlisted_without_manifest_and_opt_out(client, fetcher):
    item = client.get("/v1/stores/check", params={"url": "nomanifest.example.com"}).json()["items"][0]
    assert item["found"] is False and item["probe"]["outcome"] in ("no_manifest", "robots_or_unreachable")
    # robots.txt disallowing us is honoured
    fetcher.routes["https://blocked.example.com/robots.txt"] = (200, "User-agent: *\nDisallow: /\n")
    fetcher.routes["https://blocked.example.com/.well-known/ucp"] = (200, json.dumps(MANIFEST))
    item = client.get("/v1/stores/check", params={"url": "blocked.example.com"}).json()["items"][0]
    assert item["found"] is False
    assert "https://blocked.example.com/.well-known/ucp" not in fetcher.calls


def test_check_limits(client):
    assert client.get("/v1/stores/check").status_code == 422
    many = ",".join(f"s{i}.example.com" for i in range(26))
    assert client.get("/v1/stores/check", params={"url": many}).status_code == 422
    assert client.post("/v1/stores/check", json={"stores": "x"}).status_code == 422


def test_llms_full_sitemap_and_mcp_card(client):
    _seed(client)
    full = client.get("/llms-full.txt").text
    assert "Buying agents: start here" in full and "- alpha.example | https://alpha.example/" in full
    sm = client.get("/sitemap.xml").text
    assert "/stores/alpha.example</loc>" in sm and "/stores.json</loc>" in sm
    for p in ("/.well-known/mcp.json", "/.well-known/mcp/server-card.json"):
        card = client.get(p).json()
        assert card["remotes"][0]["url"].endswith("/mcp")
    wk = client.get("/.well-known/onaa-registry.json").json()
    assert wk["stores"]["feed_json"].endswith("/stores.json")
    assert client.get("/", headers={"accept": "application/json"}).json()["links"]["stores_feed"].endswith(
        "/stores.json")


def test_snapshot_chunks_pages_gzip_and_stale_serving(client, monkeypatch):
    import gzip
    import time

    from onaa_registry import stores
    from onaa_registry.routes import stores as store_routes

    monkeypatch.setattr(stores, "BUILD_CHUNK", 2)
    monkeypatch.setattr(store_routes, "PAGE_SIZE", 2)
    monkeypatch.setattr(stores, "PAGE_SIZE", 2)
    _seed(client)
    _store(client, "delta.example")
    feed = client.get("/stores.json")
    assert feed.headers["content-encoding"] == "gzip" and feed.json()["count"] == 4
    assert [x["domain"] for x in feed.json()["items"]] == ["alpha.example", "beta.example", "delta.example",
                                                         "gamma.example"]
    raw = client.get("/stores.json", headers={"Accept-Encoding": "identity"})
    assert "content-encoding" not in raw.headers and json.loads(raw.content)["count"] == 4
    assert gzip.decompress(stores._snap.feed_gz) == raw.content
    assert client.get("/v1/stores", params={"limit": 1, "offset": 3}).json()["items"][0]["domain"] == "gamma.example"
    p2 = client.get("/stores", params={"page": 2})
    assert "page 2 of 2" in p2.text and "/stores/delta.example" in p2.text and "/stores/alpha.example" not in p2.text
    assert client.get("/stores", params={"page": 3}).status_code == 404
    assert "/stores?page=2</loc>" in client.get("/sitemap.xml").text

    # Production mode: a stale snapshot is served while a newer one is built in the background.
    monkeypatch.setattr(stores, "FEED_MIN_REFRESH_SECONDS", 3600)
    _store(client, "epsilon.example")
    assert client.get("/stores.json").json()["count"] == 4  # within the refresh window: no DB check
    stores._snap.built_at -= 7200
    assert client.get("/stores.json").json()["count"] == 4  # stale copy served, rebuild started
    for _ in range(100):
        if stores._snap.count == 5:
            break
        time.sleep(0.05)
    assert client.get("/stores.json").json()["count"] == 5


def test_old_no_address_results_unconfirmed_and_store_published_countries(client):
    # Probe from before the address fix: "no delivery" everywhere while the store asked for an address.
    old = _store(client, "old.example", "buyer_step_required", ships_to=[], no_shipping_to=["DE", "KR", "US"],
                 buyer_info_required=["delivery_address_required", "delivery_no_delivery_available"])
    new = _store(client, "new.example", "checkout_ready", ships_to=["KR"], no_shipping_to=["IN"],
                 delivery_test="address", published_ships_to=["CA", "KR"], published_ships_worldwide=False,
                 published_ships_source="https://new.example/meta.json",
                 shipping_quotes={"KR": {"options": 2, "cheapest_amount": 18000, "currency": "KRW"}})
    world = _store(client, "world.example", "checkout_ready", delivery_test="address",
                   published_ships_worldwide=True, published_ships_source="https://world.example/meta.json")
    rec = client.get("/v1/stores/old.example").json()
    assert rec["shipping"]["no_shipping_to"] == [] and rec["shipping"]["unconfirmed_countries"] == ["DE", "KR", "US"]
    assert rec["shipping"]["store_published"] == "unknown"
    kr = client.get("/v1/stores/old.example", params={"country": "KR"}).json()["agent_purchase"]
    assert kr["verdict"] != "no"
    rec = client.get("/v1/stores/new.example", params={"country": "KR"}).json()
    pub = rec["shipping"]["store_published"]
    assert pub["countries"] == ["CA", "KR"] and pub["ships_worldwide"] is False and pub["checked_at"]
    assert rec["shipping"]["quotes"]["KR"]["cheapest_amount"] == 18000
    assert rec["shipping"]["no_shipping_to"] == ["IN"]
    # Brazil: not tested; the store's own list leaves it out -> no; worldwide store -> maybe.
    br = client.get("/v1/stores/new.example", params={"country": "BR"}).json()["agent_purchase"]
    assert br["verdict"] == "no" and any("publishes" in r for r in br["reasons"])
    br = client.get("/v1/stores/world.example", params={"country": "BR"}).json()["agent_purchase"]
    assert br["verdict"] == "maybe" and any("publishes BR" in r for r in br["reasons"])
    got = client.get("/v1/stores", params={"store_ships_to": "CA"}).json()
    assert {x["domain"] for x in got["items"]} == {"new.example", "world.example"}
    assert {old["id"], new["id"], world["id"]}
    page = client.get("/stores/new.example")
    assert page.status_code == 200 and "Store&#x27;s own published list" in page.text


def test_profile_declares_fulfillment(client):
    caps = client.get("/agent/ucp-profile.json").json()["ucp"]["capabilities"]
    assert "dev.ucp.shopping.fulfillment" in caps and "dev.ucp.shopping.checkout" in caps


def test_startup_warm_up_builds_the_snapshot_and_cold_requests_wait_for_it(client, monkeypatch):
    from onaa_registry import stores

    _seed(client)
    stores.reset_snapshot()
    monkeypatch.setattr(stores, "FEED_MIN_REFRESH_SECONDS", 3600)
    builds = []
    real_build = stores._build
    monkeypatch.setattr(stores, "_build", lambda *a, **kw: builds.append(1) or real_build(*a, **kw))
    t = stores.warm_snapshot(client.app.state.sessionmaker, client.app.state.settings.public_base_url.rstrip("/"))
    assert t is not None
    _store(client, "late.example")  # listings change while the warm-up runs (the checker writes all the time)
    t.join(10)
    assert stores._snap is not None and len(builds) == 1
    assert client.get("/stores.json").json()["count"] == stores._snap.count  # served from the warm snapshot
    assert len(builds) <= 2  # at most one background refresh, never a blocking rebuild


def test_snapshot_rows_share_country_sets():
    """~30k stores repeat a few published shipping lists; one shared set per list keeps the snapshot small."""
    from onaa_registry import stores as st

    def rec(i):
        return {"id": f"svc_{i}", "domain": f"s{i}.example", "name": f"S{i}",
                "checkout_probe": {"status": "checkout_ready", "agent_can_pay_alone": False, "protocol": "ucp-mcp",
                                   "payment_handlers": ["shop_pay"]},
                "shipping": {"ships_to": ["US"], "currencies_seen": ["USD"], "test_currency": "USD",
                             "store_published": {"ships_worldwide": False, "countries": ["US", "CA", "DE"]}},
                "trust": {"claimed": False, "reachability": "unknown"}}
    pool = {}
    a, b = st._row(rec(1), pool), st._row(rec(2), pool)
    assert a.published_to is b.published_to and a.handlers is b.handlers and a.ships_to is b.ships_to
    assert a.published_to == frozenset({"US", "CA", "DE"})


def test_record_has_per_country_states_and_stage_denominators(client):
    """Each record says how many countries were tried, when, and gives every tested country an explicit state."""
    _store(client, "new.example", "checkout_ready", ships_to=["KR"], no_shipping_to=["IN"], delivery_test="address",
           shipping_quotes={"KR": {"options": 2, "cheapest_amount": 18000, "currency": "KRW"}})
    _store(client, "old.example", "buyer_step_required", ships_to=[], no_shipping_to=["US"],
           buyer_info_required=["delivery_address_required"])
    sh = client.get("/v1/stores/new.example").json()
    s = sh["shipping"]
    assert s["tested_countries_count"] == 2 and s["tested_at"] and s["delivery_quote_obtained"] is True
    assert s["country_results"]["KR"] == "ships" and s["country_results"]["IN"] == "no_shipping"
    assert s["country_results"]["FR"] == "untested" and len(s["country_results"]) == 10
    assert sh["stages"]["shipping_confirmed"] is True and sh["stages"]["payment_attempted"] is False
    assert "last_health_check_at" in sh["trust"]
    old = client.get("/v1/stores/old.example").json()
    assert old["shipping"]["country_results"]["US"] == "unconfirmed"
    assert old["shipping"]["tested_countries_count"] == 0 and old["shipping"]["delivery_quote_obtained"] is False
    assert old["stages"]["shipping_confirmed"] is False


def test_payment_is_never_claimed_as_tested(client):
    """P1-01: a yes verdict reads as an observed checkout path, and every answer says payment was not tested."""
    _store(client, "ready.example", "checkout_ready", ships_to=["US"], delivery_test="address",
           autonomous_payment="after_one_time_link")
    rec = client.get("/v1/stores/ready.example", params={"country": "US"}).json()
    ap = rec["agent_purchase"]
    assert ap["summary"].startswith("Agent checkout path observed (payment not tested)")
    for block in (ap, rec["checkout_probe"]):
        assert block["payment_tested"] is False and block["payment_success_verified"] is False
        assert block["post_link_autonomy_verified"] is False
    found = client.get("/v1/buying/stores", params={"country": "US"}).json()
    assert "payment not tested" in found["verdict_note"] and found["items"][0]["payment_tested"] is False
    page = client.get("/stores/ready.example").text
    assert "can buy here" not in page and "Payment tested" in page and "payment not tested" in page
    assert "can actually buy" not in client.get("/", headers={"accept": "text/html"}).text


def test_cold_store_request_gives_up_with_503_instead_of_piling_up(client, monkeypatch):
    """While a first build holds the lock (slow DB), requests answer 503 after a bounded wait, not hang forever."""
    from onaa_registry import buying, stores

    _seed(client)
    stores.reset_snapshot()
    buying.reset_cache()
    monkeypatch.setattr(stores, "COLD_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(buying, "COLD_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(buying, "BUYING_CACHE_SECONDS", 300)
    assert stores._build_lock.acquire(timeout=5) and buying._cache_lock.acquire(timeout=5)
    try:
        r = client.get("/v1/stores")
        assert r.status_code == 503 and r.headers["retry-after"] == "30"
        assert client.get("/v1/buying/stores", params={"country": "US"}).status_code == 503
        assert client.get("/v1/health").status_code == 200
    finally:
        stores._build_lock.release()
        buying._cache_lock.release()
    assert client.get("/v1/stores").status_code == 200
    assert client.get("/v1/buying/stores", params={"country": "US"}).status_code == 200


def test_snapshot_refresh_reads_only_changed_stores(client, monkeypatch):
    """Refreshes must not read every store again (that used up the database's monthly network transfer)."""
    from onaa_registry import stores

    _seed(client)
    base = client.app.state.settings.public_base_url.rstrip("/")
    with client.app.state.sessionmaker() as s:
        first = stores._build(s, base, (stores._fingerprint(s), base))
    _store(client, "late.example", "checkout_ready", ships_to=["US"], delivery_test="address")
    read = []
    real = stores._public_rows
    monkeypatch.setattr(stores, "_public_rows", lambda s, b, ids, p: read.append(len(ids)) or real(s, b, ids, p))
    with client.app.state.sessionmaker() as s:
        second = stores._build(s, base, (stores._fingerprint(s), base), prev=first)
    assert len(read) == 1 and read[0] <= 2  # the new store (and any written in the same instant), not all
    assert second.count == first.count + 1 and second.full_at == first.full_at
    assert "late.example" in {r.key for r in second.rows}
    # A store that leaves the public list is dropped; a full read happens when the window has passed.
    with client.app.state.sessionmaker() as s:
        from onaa_registry.models import Listing

        s.query(Listing).filter(Listing.display_name == "late.example").update({"lifecycle_status": "suspended",
                                                                                "updated_at": stores.utcnow()})
        s.commit()
        third = stores._build(s, base, (stores._fingerprint(s), base), prev=second)
    assert third.count == first.count and "late.example" not in {r.key for r in third.rows}
    monkeypatch.setattr(stores, "FULL_REBUILD_SECONDS", 0)
    read.clear()
    with client.app.state.sessionmaker() as s:
        stores._build(s, base, (stores._fingerprint(s), base), prev=third)
    assert read == [first.count]


def test_hide_stores_hides_the_store_directory_everywhere_and_keeps_the_data(client):
    a, _, _ = _seed(client)
    settings = client.app.state.settings
    object.__setattr__(settings, "hide_stores", True)
    try:
        c = client
        for path in ("/stores", "/stores.json", "/stores.csv", "/stores/alpha.example", "/v1/stores",
                     "/v1/stores/alpha.example", "/v1/stores/check?url=alpha.example", "/v1/buying/stores",
                     "/reports", "/reports/1"):
            assert c.get(path).status_code == 404, path
        assert c.get(f"/v1/services/{a['id']}").status_code == 404
        assert c.get("/v1/services", params={"q": "alpha"}).json()["total"] == 0
        home = c.get("/", headers={"Accept": "text/html"}).text
        assert "Where AI agents find each other" in home and "?section=stores" not in home
        assert "/stores" not in c.get("/sitemap.xml").text
        llms = c.get("/llms.txt").text
        assert "/v1/stores" not in llms and "## Register for your operator" in llms
        assert "stores" not in c.get("/.well-known/onaa-registry.json").json()
        assert c.post("/v1/reports", json={}).status_code != 404  # abuse reports are not the store report
    finally:
        object.__setattr__(settings, "hide_stores", False)
    assert client.get("/v1/stores/alpha.example").status_code == 200  # switching it off brings everything back
