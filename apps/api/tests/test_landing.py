"""Human home page and the machine entry points at /."""

from __future__ import annotations

HTML = {"accept": "text/html,application/xhtml+xml"}


def test_home_says_what_onaa_is_and_how_to_connect(client):
    page = client.get("/", headers=HTML)
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    text = page.text
    assert "A2A address" in text and "/mcp" in text and "claude mcp add --transport http onaa" in text
    assert "never negotiates, sets prices, handles money or ships anything" in text
    assert "/member-terms" in text and "/privacy" in text and "/opt-out" in text
    # nothing from the retired store directory or the old provider board
    for old in ("/stores", "reach checkout", "Payments and services", "/reports", "escrow"):
        assert old not in text, old


def test_root_json_keeps_machine_contract(client):
    data = client.get("/", headers={"accept": "application/json"}).json()
    assert data["name"] == "ONAA (Open Network for AI Agents)" and "A2A address" in data["description"]
    assert data["links"]["mcp"].endswith("/mcp") and "stores_feed" not in data["links"]
    wk = client.get("/.well-known/onaa-registry.json").json()
    assert wk["search"]["agents"].endswith("/v1/agents") and "status" not in wk and "stores" not in wk


def test_every_internal_homepage_link_resolves(client):
    """No link on the homepage (nav, footer, developer list) points at a missing page, e.g. the old /v1 404."""
    import re
    from urllib.parse import urlsplit

    base = client.app.state.settings.public_base_url.rstrip("/")
    page = client.get("/", headers=HTML).text
    hrefs = {h.replace("&amp;", "&") for h in re.findall(r'href="([^"#]+)', page)}
    internal = sorted({h[len(base):] or "/" for h in hrefs if h.startswith(base)}
                      | {h for h in hrefs if h.startswith("/")})
    assert "/v1" in internal and len(internal) > 5
    for path in internal:
        if urlsplit(path).path in ("/mcp", "/.well-known/agent-card.json"):
            continue  # served by the hosted wrapper (apps/mcp-registry), not this app; smoke_readonly.py covers them
        r = client.get(path, headers=HTML)
        assert r.status_code < 400, (path, r.status_code)
    assert client.get("/v1").json()["links"]["openapi"].endswith("/openapi.json")


def test_retired_store_paths_are_gone(client):
    for path in ("/stores", "/stores.json", "/stores.csv", "/v1/stores", "/v1/stores/check?url=x.example",
                 "/v1/buying/stores", "/reports", "/reports/1", "/manage-store", "/agent/ucp-profile.json"):
        assert client.get(path).status_code in (404, 405), path
    assert client.post("/v1/buying/needs", json={"text": "shoes"}).status_code in (404, 405)


def test_policy_pages_ask_caches_to_revalidate(client):
    """Opt-out, privacy and onboarding text must not be served stale by a proxy or crawler cache."""
    for path in ("/opt-out", "/privacy", "/llms.txt", "/v1/terms", "/openapi.json", "/v1"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers.get("cache-control") == "no-cache", path
