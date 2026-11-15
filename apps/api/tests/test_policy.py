"""Policy Service: what the Registry Steward may change alone, what waits for a human, what is refused."""

from __future__ import annotations

from conftest import AGENT, STEWARD, admin_headers

STEWARD_H = {"Authorization": f"Bearer {STEWARD}"}


def _req(client, action, subject=None, params=None, headers=STEWARD_H):
    return client.post("/v1/policy/requests", headers=headers,
                       json={"action": action, "subject_id": subject, "params": params or {}})


def test_steward_token_required_and_admin_token_is_not_a_steward(client):
    assert _req(client, "health.observe", headers={}).status_code == 403
    assert _req(client, "health.observe", headers=admin_headers()).status_code == 403
    assert client.get("/v1/policy/rules").json()["rules"]["listing.suspend"] == "approval"


def test_health_observation_and_incident_lifecycle(client, op):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    for _ in range(3):
        d = _req(client, "health.observe", aid, {"result": "http_5xx", "latency_ms": 12}).json()
        assert d["decision"] == "applied"
    assert d["result"]["reachability"] == "unreachable"
    rec = client.get(f"/v1/agents/{aid}").json()
    assert rec["trust"]["reachability"] == "unreachable" and rec["status"] == "registered"  # signal, not sanction

    opened = _req(client, "incident.open", aid, {"kind": "unreachable", "summary": "endpoint returns 503",
                                                 "detail": {"probe_result": "http_5xx"}}).json()
    inc = opened["result"]["incident"]
    again = _req(client, "incident.open", aid, {"kind": "unreachable", "summary": "x"}).json()
    assert again["result"]["deduplicated"] and again["result"]["incident"]["id"] == inc["id"]
    _req(client, "incident.update", aid, {"incident_id": inc["id"], "note": {"diagnosis": {"cause": "db down"}}})
    listed = client.get("/v1/incidents", params={"listing_id": aid, "state": "open"}).json()["items"]
    assert listed[0]["detail"]["notes"][0]["note"]["diagnosis"]["cause"] == "db down"

    _req(client, "health.observe", aid, {"result": "ok"})
    _req(client, "incident.resolve", aid, {"incident_id": inc["id"], "resolution": "re-verified"})
    done = client.get("/v1/incidents", params={"listing_id": aid}).json()["items"][0]
    assert done["state"] == "resolved" and done["resolved_at"]
    assert client.get(f"/v1/agents/{aid}").json()["trust"]["reachability"] == "reachable"


def test_bad_values_are_rejected(client, op):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    assert _req(client, "health.observe", aid, {"result": "rm -rf"}).status_code == 422
    assert _req(client, "incident.open", aid, {"kind": "sanction", "summary": "x"}).status_code == 422
    assert _req(client, "listing.flag", aid, {"flag": "bad flag!"}).status_code == 422


def test_suspension_waits_for_a_human_and_unknown_actions_are_denied(client, op):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    d = _req(client, "listing.suspend", aid, {"reason": "repeated fraud reports"}).json()
    assert d["decision"] == "pending_approval"
    assert client.get(f"/v1/agents/{aid}").json()["status"] == "registered"  # nothing happened yet
    assert _req(client, "admin.anything", aid).json()["decision"] == "denied"
    assert _req(client, "certification.change", aid).json()["decision"] == "pending_approval"

    pending = client.get("/v1/admin/policy/requests", headers=admin_headers()).json()["items"]
    assert {p["action"] for p in pending} == {"listing.suspend", "certification.change"}
    r = client.post(f"/v1/admin/policy/requests/{d['id']}/decision", headers=admin_headers(),
                    json={"decision": "approve", "reason": "confirmed by founder"})
    assert r.json()["decision"] == "approved"
    assert client.get(f"/v1/agents/{aid}").json()["status"] == "suspended"
    again = client.post(f"/v1/admin/policy/requests/{d['id']}/decision", headers=admin_headers(),
                        json={"decision": "reject", "reason": "x"})
    assert again.status_code == 409


def test_flag_adds_review_hint_only(client, op):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    _req(client, "listing.flag", aid, {"flag": "metadata_errors"})
    rec = client.get(f"/v1/agents/{aid}").json()
    assert "steward:metadata_errors" in rec["trust"]["review_flags"] and rec["status"] == "registered"


def test_publish_self_only_on_registry_host(client):
    base = "http://localhost:8000/steward"
    bad = _req(client, "steward.publish_self", None, {"agent_card_url": "https://evil.example.com/card",
                                                      "endpoint_url": "https://evil.example.com/a2a"})
    assert bad.status_code == 422
    params = {"agent_card_url": f"{base}/.well-known/agent-card.json", "endpoint_url": f"{base}/a2a/v1",
              "display_name": "ONAA Registry Steward", "capabilities": ["registry-steward"],
              "card": {"name": "ONAA Registry Steward", "skills": [{"id": "check_health", "tags": ["health"]}]}}
    first = _req(client, "steward.publish_self", None, params).json()["result"]
    second = _req(client, "steward.publish_self", None, params).json()["result"]
    assert first["created"] and not second["created"] and first["listing_id"] == second["listing_id"]
    rec = client.get(f"/v1/agents/{first['listing_id']}").json()
    assert rec["display_name"] == "ONAA Registry Steward" and rec["trust"]["registration_method"] == "system"
    assert "registry-steward" in rec["capabilities"]
