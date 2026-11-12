"""ENG-011: endpoint health probes and the separate `unreachable` signal."""

from __future__ import annotations

from conftest import AGENT, SERVICE, admin_headers, verify_listing

from onaa_registry.netsafety import FetchError


def test_owner_probe_and_unreachable_after_three_failures(client, op, fetcher):
    _, h = op
    sid = client.post("/v1/services", json=SERVICE, headers=h).json()["id"]
    fetcher.routes[SERVICE["endpoint_url"]] = (200, "{}")
    rec = client.post(f"/v1/services/{sid}/health-check", headers=h).json()
    assert rec["trust"]["reachability"] == "reachable" and rec["trust"]["last_check_result"] == "ok"
    assert rec["last_checked_at"] is not None

    fetcher.routes[SERVICE["endpoint_url"]] = FetchError("timeout")
    for expected in ("reachable", "reachable", "unreachable"):
        rec = client.post(f"/v1/services/{sid}/health-check", headers=h).json()
        assert rec["trust"]["reachability"] == expected
    assert rec["trust"]["last_check_result"] == "timeout"
    # Unreachable is a signal, not a revocation.
    assert rec["status"] == "registered"
    assert client.get("/v1/services").json()["total"] == 1
    assert client.get("/v1/services", params={"reachable_only": True}).json()["total"] == 0

    fetcher.routes[SERVICE["endpoint_url"]] = (503, "down")
    assert client.post(f"/v1/services/{sid}/health-check", headers=h).json()["trust"]["reachability"] == "unreachable"
    fetcher.routes[SERVICE["endpoint_url"]] = (401, "auth required")  # answered -> reachable
    rec = client.post(f"/v1/services/{sid}/health-check", headers=h).json()
    assert rec["trust"]["reachability"] == "reachable"


def test_probe_uses_agent_card_when_no_endpoint(client, op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    client.post(f"/v1/agents/{aid}/health-check", headers=h)
    assert fetcher.calls[-1] == AGENT["agent_card_url"]


def test_verification_records_health_without_blocking(client, op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    fetcher.routes[AGENT["agent_card_url"]] = FetchError("network_error")
    verify_listing(client, fetcher, "agents", aid, h)
    trust = client.get(f"/v1/agents/{aid}/trust").json()
    assert trust["endpoint_control_verified"] is True and trust["last_check_result"] == "network_error"


def test_admin_health_job(client, op, other_op, fetcher):
    _, h = op
    a = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    s = client.post("/v1/services", json=SERVICE, headers=h).json()["id"]
    r = client.post("/v1/admin/jobs/health-checks", headers=admin_headers(), params={"limit": 10})
    assert set(r.json()["checked"]) == {a, s}
    _, h2 = other_op
    assert client.post("/v1/admin/jobs/health-checks", headers=h2).status_code == 403
    assert client.post(f"/v1/agents/{a}/health-check", headers=h2).status_code == 403
