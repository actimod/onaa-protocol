"""Spec section 6: the MVP completion scenario, end to end, with in-process agents and registry.

1 register buyer + seller · 2 steward validates both · 3 steward checks both · 4 seller endpoint fault ·
5 steward detects it · 6 steward asks the seller over A2A · 7 recovery and re-verification ·
8 registry status + incident history updated through the Policy Service · 9 everything logged ·
10 buyer -> seller trade is direct and independent of the steward.
"""

from __future__ import annotations

from conftest import ADMIN, register
from onaa_protocol.a2a import ROLE_USER, data_part, make_message, send_message

from onaa_steward import EXTENSION_URI
from onaa_steward.server import create_app as create_steward_app


def test_mvp_scenario(registry, steward, seller, buyer, net):
    # 1. Buyer and Seller register in the ONAA registry.
    seller_id = register(registry, seller, "seller_agent", ["commerce.rfq.receive", "commerce.quote.issue"])
    buyer_id = register(registry, buyer, "buyer_agent", ["commerce.rfq.send"])

    # 2. The steward validates both registrations (record completeness, live Agent Card, duplicates).
    v_seller, v_buyer = steward.validate(seller_id), steward.validate(buyer_id)
    assert v_seller["ok"] and v_seller["errors"] == 0, v_seller
    assert v_buyer["ok"], v_buyer
    assert {f["code"] for f in v_buyer["findings"]} == {"capability_not_in_card"}  # info only

    # 3. The steward checks both agents (card + A2A JSON-RPC compatibility ping).
    for lid in (seller_id, buyer_id):
        c = steward.check(lid)
        assert c["healthy"] and c["a2a_jsonrpc"] is True and "incident" not in c
        assert registry.get(f"/v1/agents/{lid}").json()["trust"]["reachability"] == "reachable"

    # 4. Fault injected on the seller's test endpoint.
    seller.fault = True

    # 5. The steward detects it (three confirming probes, so a single blip is not an outage).
    c = steward.check(seller_id)
    assert not c["healthy"] and c["result"] == "http_5xx" and c["attempts"] == 3
    incident = c["incident"]
    assert incident["kind"] == "unreachable" and incident["state"] == "open"
    rec = registry.get(f"/v1/agents/{seller_id}").json()
    assert rec["trust"]["reachability"] == "unreachable"
    assert rec["status"] == "registered"  # a health signal, never a sanction

    # 6. The steward asked the seller for failure information over A2A (its declared ops channel).
    assert len(seller.diag_requests) == 1
    assert seller.diag_requests[0]["incident_id"] == incident["id"]
    open_inc = registry.get("/v1/incidents", params={"listing_id": seller_id, "state": "open"}).json()["items"][0]
    diag = open_inc["detail"]["notes"][0]["note"]["diagnosis"]
    assert diag["answered"] and diag["status"] == "down" and diag["cause"] == "inventory database unavailable"
    assert "ignore_previous_instructions" not in str(open_inc)  # unknown reply fields are dropped

    # 7. Recovery; the periodic sweep re-verifies the open incident.
    seller.fault = False
    summary = steward.sweep()
    assert summary["rechecked"] == 1 and summary["resolved"] == 1

    # 8. Registry status and incident history were updated through the policy service.
    rec = registry.get(f"/v1/agents/{seller_id}").json()
    assert rec["trust"]["reachability"] == "reachable" and rec["trust"]["last_check_result"] == "ok"
    history = registry.get("/v1/incidents", params={"listing_id": seller_id}).json()["items"]
    assert len(history) == 1 and history[0]["state"] == "resolved" and history[0]["resolved_at"]
    decisions = registry.get("/v1/admin/policy/requests", params={"decision": "applied", "limit": 200},
                             headers={"Authorization": f"Bearer {ADMIN}"}).json()["items"]
    actions = {d["action"] for d in decisions}
    assert {"health.observe", "incident.open", "incident.update", "incident.resolve"} <= actions
    assert all(d["actor"] == "steward" for d in decisions)

    # 9. Every step is in the steward's activity log.
    events = [e["event"] for e in steward.log.entries(seller_id, 500)]
    for step in ("validate", "probe", "incident.open", "diagnosis", "recheck"):
        assert step in events, step

    # 10. Buyer -> seller trade is direct A2A; the steward and registry are not in the path.
    before = len(net.log)
    with net.client() as buyer_http:
        reply = send_message(buyer_http, f"{seller.base}/a2a/v1",
                             make_message(ROLE_USER, [data_part({"type": "rfq", "sku": "X-1", "qty": 2})]))
    assert reply["parts"][0]["data"]["type"] == "quote"
    assert len(seller.trade_requests) == 1
    assert all(seller.host in url for _m, url in net.log[before:])
    assert not any(e["event"] in ("trade", "rfq") for e in steward.log.entries(None, 2000))


def test_buyer_reports_seller_error_over_a2a(registry, steward, seller, buyer):
    """Spec 2.C example: a buyer reports a seller error to the steward over A2A; the steward verifies, asks the
    seller, records an incident; recovery is re-verified."""
    seller_id = register(registry, seller, "seller_agent", ["commerce.rfq.receive"])
    buyer_id = register(registry, buyer, "buyer_agent", ["commerce.rfq.send"])
    app = create_steward_app(steward, public_url="https://api.example.com/steward",
                             registry_url="https://api.example.com")
    from starlette.testclient import TestClient

    with TestClient(app) as st:
        card = st.get("/.well-known/agent-card.json").json()
        assert card["supportedInterfaces"][0]["url"].endswith("/steward/a2a/v1")
        assert {s["id"] for s in card["skills"]} >= {"report_issue", "check_health", "validate_listing"}
        assert card["capabilities"]["extensions"][0]["uri"] == EXTENSION_URI

        seller.fault = True
        msg = make_message(ROLE_USER, [data_part({"skill": "report_issue", "listing_id": seller_id,
                                                  "symptom": "SendMessage returns HTTP 503 since 14:00 UTC",
                                                  "reporter_listing_id": buyer_id})])
        r = st.post("/a2a/v1", headers={"A2A-Version": "1.0"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}})
        result = r.json()["result"]["message"]["parts"][0]["data"]["result"]
        assert result["healthy"] is False and result["incident"]["kind"] == "unreachable"
        assert result["incident"]["summary"].startswith("reported: SendMessage returns HTTP 503")
        assert len(seller.diag_requests) == 1

        status = st.post("/a2a/v1", headers={"A2A-Version": "1.0"}, json={
            "jsonrpc": "2.0", "id": 2, "method": "SendMessage", "params": {"message": make_message(
                ROLE_USER, [data_part({"skill": "incident_status", "listing_id": seller_id})])}}).json()
        assert status["result"]["message"]["parts"][0]["data"]["result"]["incidents"][0]["state"] == "open"

        seller.fault = False
        assert steward.sweep()["resolved"] == 1

        # Text-only message gets help; bad input gets JSON-RPC errors, not crashes.
        help_ = st.post("/a2a/v1", headers={"A2A-Version": "1.0"}, json={
            "jsonrpc": "2.0", "id": 3, "method": "SendMessage",
            "params": {"message": make_message(ROLE_USER, [{"text": "hi"}])}}).json()
        assert "report_issue" in help_["result"]["message"]["parts"][0]["text"]
        bad = st.post("/a2a/v1", headers={"A2A-Version": "1.0"}, json={
            "jsonrpc": "2.0", "id": 4, "method": "SendMessage", "params": {"message": make_message(
                ROLE_USER, [data_part({"skill": "check_health", "listing_id": "https://evil.example/x"})])}}).json()
        assert bad["error"]["code"] == -32602
        missing = st.post("/a2a/v1", headers={"A2A-Version": "1.0"}, json={
            "jsonrpc": "2.0", "id": 5, "method": "SendMessage", "params": {"message": make_message(
                ROLE_USER, [data_part({"skill": "check_health", "listing_id": "agt_doesnotexist"})])}}).json()
        assert missing["error"]["message"] == "listing not found"
        assert st.post("/a2a/v1", json={"jsonrpc": "2.0", "id": 6, "method": "SendMessage",
                                        "params": {}}).json()["error"]["code"] == -32009
        assert st.get("/v1/activity", params={"listing_id": seller_id}).json()["items"]
