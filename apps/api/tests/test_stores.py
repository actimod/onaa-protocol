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
    assert page.status_code == 200 and "Can an AI agent buy from alpha.example?" in page.text
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
    assert page.status_code == 200 and "store-published" in page.text


def test_profile_declares_fulfillment(client):
    caps = client.get("/agent/ucp-profile.json").json()["ucp"]["capabilities"]
    assert "dev.ucp.shopping.fulfillment" in caps and "dev.ucp.shopping.checkout" in caps
