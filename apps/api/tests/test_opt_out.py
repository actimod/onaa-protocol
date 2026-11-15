"""Opt-out for discovered entries (DISCOVERY_POLICY section 7): no account, immediate, content erased, no re-import."""

from __future__ import annotations

from conftest import AGENT, admin_headers

SVC = {"display_name": "Example Escrow Co", "service_type": "escrow",
       "documentation_url": "https://docs.escrow.example.net/api", "source_url": "https://docs.escrow.example.net/api",
       "description": "Public escrow API", "regions": ["US"]}
AGT = {"display_name": "Seen agent", "agent_card_url": "https://bot.example.org/.well-known/agent-card.json",
       "source_url": "https://directory.example.org/1", "roles": ["seller_agent"]}


def _import(client):
    s = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=SVC).json()
    a = client.post("/v1/admin/discovered", headers=admin_headers(), json=AGT).json()
    return s, a


def test_host_opt_out_removes_erases_and_blocks_reimport(client):
    s, a = _import(client)
    r = client.post("/v1/discovered/opt-out", json={"url": "https://docs.escrow.example.net/", "reason": "no thanks"})
    assert r.status_code == 200, r.text
    assert r.json()["removed_listing_ids"] == [s["id"]] and r.json()["status"] == "removed"
    assert client.get(f"/v1/services/{s['id']}").status_code == 410
    assert client.get("/v1/services").json()["total"] == 0
    assert client.get(f"/v1/agents/{a['id']}").status_code == 200  # other host untouched
    with client.app.state.sessionmaker() as sess:
        from onaa_registry.models import AuditEvent, Listing

        row = sess.get(Listing, s["id"])
        assert row.display_name == "[removed]" and row.documentation_url is None and row.description is None
        assert row.source_url is None and not row.facets
        assert all("no thanks" not in str(e.detail) for e in sess.query(AuditEvent).all())
    again = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=SVC)
    assert again.status_code == 410 and "opted out" in again.text


def test_url_scope_and_suppression_before_listing(client):
    # Opting out before ever being listed blocks a later import too.
    r = client.post("/v1/discovered/opt-out", json={"url": AGT["agent_card_url"], "scope": "url"})
    assert r.json() == {**r.json(), "status": "suppressed", "removed_listing_ids": []}
    assert client.post("/v1/admin/discovered", headers=admin_headers(), json=AGT).status_code == 410


def test_registered_listings_are_never_affected(client, op):
    _, h = op
    rec = client.post("/v1/agents", headers=h, json=AGENT).json()
    r = client.post("/v1/discovered/opt-out", json={"url": AGENT["agent_card_url"]})
    assert r.json()["removed_listing_ids"] == []
    assert client.get(f"/v1/agents/{rec['id']}").json()["status"] == "registered"


def test_opt_out_validation_and_page(client):
    assert client.post("/v1/discovered/opt-out", json={"url": "http://127.0.0.1/"}).status_code == 422
    assert client.post("/v1/discovered/opt-out", json={"url": "https://x.example.org", "email": "a"}).status_code == 422
    page = client.get("/opt-out")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "/v1/discovered/opt-out" in page.text and "{base}" not in page.text
    wk = client.get("/.well-known/onaa-registry.json").json()
    assert "/v1/discovered/opt-out" in wk["onboarding"]["discovered_opt_out"]
    assert "/v1/discovered/opt-out" in client.get("/llms.txt").text
