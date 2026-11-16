"""Opt-out for discovered entries: hidden at once, erased only after proof of host control, restored after 7 days."""

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


def _prove(fetcher, r):
    fetcher.routes[r["well_known_url"]] = (200, r["token"] + "\n")


def test_host_opt_out_hides_then_erases_after_proof_and_blocks_reimport(client, fetcher):
    s, a = _import(client)
    r = client.post("/v1/discovered/opt-out", json={"url": "https://docs.escrow.example.net/", "reason": "no thanks"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["removed_listing_ids"] == [s["id"]] and body["status"] == "hidden"
    assert body["well_known_url"].startswith("https://docs.escrow.example.net/.well-known/onaa-verification/")
    assert client.get(f"/v1/services/{s['id']}").status_code == 410
    assert client.get("/v1/services").json()["total"] == 0
    assert client.get(f"/v1/agents/{a['id']}").status_code == 200  # other host untouched
    # Hidden, not erased, and no re-import while the request waits.
    with client.app.state.sessionmaker() as sess:
        from onaa_registry.models import Listing
        assert sess.get(Listing, s["id"]).description == "Public escrow API"
    assert client.post("/v1/admin/discovered/services", headers=admin_headers(), json=SVC).status_code == 410
    # Wrong or missing proof is refused.
    confirm = f"/v1/discovered/opt-out/{body['request_id']}/confirm"
    assert body["confirm_url"].endswith(confirm)
    assert client.post(confirm, json={"method": "well_known"}).status_code == 422
    _prove(fetcher, body)
    c = client.post(confirm, json={"method": "well_known"})
    assert c.status_code == 200, c.text
    assert c.json()["removed_listing_ids"] == [s["id"]]
    with client.app.state.sessionmaker() as sess:
        from onaa_registry.models import AuditEvent, Listing

        row = sess.get(Listing, s["id"])
        assert row.display_name == "[removed]" and row.documentation_url is None and row.description is None
        assert row.source_url is None and not row.facets
        assert all("no thanks" not in str(e.detail) for e in sess.query(AuditEvent).all())
        actions = {e.action for e in sess.query(AuditEvent).all()}
        assert {"discovered.opt_out_requested", "discovered.opt_out_confirmed"} <= actions
    again = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=SVC)
    assert again.status_code == 410 and "opted out" in again.text


def test_unproven_opt_out_is_restored_after_seven_days(client):
    import datetime as dt

    from onaa_registry.models import OptOutClaim
    from onaa_registry.routes.optout import expire_opt_outs

    s, _ = _import(client)
    r = client.post("/v1/discovered/opt-out", json={"url": "https://docs.escrow.example.net/"}).json()
    assert client.get(f"/v1/services/{s['id']}").status_code == 410
    with client.app.state.sessionmaker() as sess:
        claim = sess.get(OptOutClaim, r["request_id"])
        claim.expires_at = claim.expires_at - dt.timedelta(days=8)
        sess.commit()
        assert expire_opt_outs(sess) == 1
        sess.commit()
    rec = client.get(f"/v1/services/{s['id']}")
    assert rec.status_code == 200 and rec.json()["status"] == "discovered"
    late = client.post(f"/v1/discovered/opt-out/{r['request_id']}/confirm", json={"method": "well_known"})
    assert late.status_code == 410
    # The block on re-import ends with the request.
    assert client.post("/v1/admin/discovered/services", headers=admin_headers(), json=SVC).status_code != 410


def test_url_scope_before_listing_blocks_import_while_pending(client, fetcher):
    r = client.post("/v1/discovered/opt-out", json={"url": AGT["agent_card_url"], "scope": "url"}).json()
    assert r["status"] == "pending" and r["removed_listing_ids"] == []
    assert client.post("/v1/admin/discovered", headers=admin_headers(), json=AGT).status_code == 410
    _prove(fetcher, r)
    assert client.post(f"/v1/discovered/opt-out/{r['request_id']}/confirm",
                       json={"method": "well_known"}).status_code == 200
    assert client.post("/v1/admin/discovered", headers=admin_headers(), json=AGT).status_code == 410


def test_pending_requests_per_host_are_capped(client):
    for _ in range(3):
        assert client.post("/v1/discovered/opt-out", json={"url": "https://cap.example.org/"}).status_code == 200
    assert client.post("/v1/discovered/opt-out", json={"url": "https://cap.example.org/"}).status_code == 429


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
