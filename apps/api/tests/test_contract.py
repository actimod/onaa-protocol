"""Contract tests: registry record shape, search filters, lifecycle and trust separation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from conftest import AGENT, SERVICE, admin_headers, verify_listing

REPO = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((REPO / "specs" / "registry-record.draft.schema.json").read_text())


def test_health_and_wellknown(client):
    assert client.get("/v1/health").json()["status"] == "ok"
    wk = client.get("/.well-known/onaa-registry.json").json()
    assert "NOT" not in wk["name"] and "Not relayed" in wk["transactions"]
    assert client.get("/v1/specs/registry-record.schema.json").json() == SCHEMA


def test_packaged_schema_matches_spec():
    packaged = Path(__file__).resolve().parents[1] / "onaa_registry" / "registry-record.schema.json"
    assert json.loads(packaged.read_text()) == SCHEMA


def test_operator_signup_requires_current_terms(client):
    r = client.post("/v1/operators", json={"display_name": "X", "operator_type": "individual",
                                           "accept_terms_version": "old"})
    assert r.status_code == 422


def test_api_key_shown_once_and_hashed(client, op):
    _, headers = op
    assert client.get("/v1/operators/me", headers=headers).status_code == 200
    raw = headers["Authorization"].split()[1]
    with client.app.state.engine.connect() as conn:
        dump = "\n".join(str(r) for r in conn.exec_driver_sql("select * from api_keys"))
    assert raw not in dump


def test_register_agent_returns_valid_registry_record(client, op):
    _, headers = op
    r = client.post("/v1/agents", json=AGENT, headers=headers)
    assert r.status_code == 201, r.text
    rec = r.json()
    jsonschema.validate(rec, SCHEMA)
    assert rec["id"].startswith("agt_")
    assert rec["status"] == "registered"
    assert rec["trust"]["endpoint_control_verified"] is False
    assert rec["trust"]["certifications"] == []
    assert rec["roles"] == ["seller_agent"]
    assert rec["regions"] == ["KR", "US"]


def test_register_service_and_hosting(client, op):
    _, headers = op
    r = client.post("/v1/services", json=SERVICE, headers=headers)
    assert r.status_code == 201, r.text
    rec = r.json()
    jsonschema.validate(rec, SCHEMA)
    assert rec["listing_type"] == "service" and rec["service_type"] == "escrow"
    assert rec["roles"] == ["service_provider"]
    host = dict(SERVICE, service_type="hosting", endpoint_url="https://nodes.host.example.org/api",
                display_name="Example Seller Node Host")
    r = client.post("/v1/services", json=host, headers=headers)
    assert r.json()["listing_type"] == "hosting" and r.json()["roles"] == ["hosting_provider"]


def test_requires_auth_for_writes(client):
    assert client.post("/v1/agents", json=AGENT).status_code == 401
    assert client.post("/v1/agents", json=AGENT, headers={"Authorization": "Bearer onaa_sk_bogus"}).status_code == 401


def test_validation_rejects_bad_tokens(client, op):
    _, headers = op
    for patch in ({"regions": ["usa"]}, {"currencies": ["dollars"]}, {"capabilities": ["Has Space"]},
                  {"roles": ["god_mode"]}, {"unknown_field": 1}):
        assert client.post("/v1/agents", json=dict(AGENT, **patch), headers=headers).status_code == 422, patch


def test_search_filters(client, op, other_op):
    _, h1 = op
    _, h2 = other_op
    client.post("/v1/agents", json=AGENT, headers=h1)
    client.post("/v1/agents", headers=h2, json=dict(
        AGENT, display_name="EU Buyer Bot", roles=["buyer_agent"], regions=["DE"], currencies=["EUR"],
        capabilities=["commerce.rfq.send"], agent_card_url="https://buyer.example.org/.well-known/agent-card.json"))
    client.post("/v1/agents", headers=h2, json=dict(
        AGENT, display_name="Global Seller", regions=["GLOBAL"], currencies=["USD"],
        agent_card_url="https://global.example.org/.well-known/agent-card.json"))

    def names(**params):
        r = client.get("/v1/agents", params=params)
        assert r.status_code == 200
        return sorted(i["display_name"] for i in r.json()["items"])

    assert names() == ["EU Buyer Bot", "Example Parts Seller", "Global Seller"]
    assert names(role="buyer_agent") == ["EU Buyer Bot"]
    assert names(capability="commerce.quote.issue") == ["Example Parts Seller", "Global Seller"]
    assert names(region="KR") == ["Example Parts Seller", "Global Seller"]  # GLOBAL matches any region
    assert names(currency="eur") == ["EU Buyer Bot"]
    assert names(region="de", role="seller_agent") == ["Global Seller"]
    assert names(q="eu buyer") == ["EU Buyer Bot"]
    assert names(q="PARTS") == ["EU Buyer Bot", "Example Parts Seller", "Global Seller"]  # description match
    assert names(protocol="a2a-1.x", currency="KRW") == ["Example Parts Seller"]
    assert names(verified_only=True) == []
    page = client.get("/v1/agents", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3 and len(page["items"]) == 1


def test_service_search_by_type_region_currency(client, op):
    _, headers = op
    client.post("/v1/services", json=SERVICE, headers=headers)
    client.post("/v1/services", headers=headers, json=dict(
        SERVICE, display_name="KR Payments", service_type="payment", regions=["KR"], currencies=["KRW"],
        endpoint_url="https://pay.example.kr/api"))
    r = client.get("/v1/services", params={"type": "escrow", "region": "US", "currency": "USD"}).json()
    assert [i["display_name"] for i in r["items"]] == ["Example Sandbox Escrow"]
    assert client.get("/v1/services", params={"type": "escrow", "region": "KR"}).json()["total"] == 0
    # agents and services are separate namespaces
    assert client.get("/v1/agents").json()["total"] == 0


def test_update_and_delete_by_owner(client, op):
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    r = client.patch(f"/v1/agents/{aid}", json={"regions": ["JP"], "display_name": "Renamed"}, headers=headers)
    assert r.status_code == 200 and r.json()["regions"] == ["JP"] and r.json()["display_name"] == "Renamed"
    # Overlapping update keeps existing values (regression: unique constraint on re-insert).
    r = client.patch(f"/v1/agents/{aid}", json={"regions": ["JP", "KR"], "capabilities": AGENT["capabilities"]},
                     headers=headers)
    assert r.status_code == 200 and r.json()["regions"] == ["JP", "KR"]
    assert client.delete(f"/v1/agents/{aid}", headers=headers).status_code == 204
    assert client.get(f"/v1/agents/{aid}").status_code == 410
    assert client.get("/v1/agents").json()["total"] == 0


def test_domain_verification_lifecycle(client, op, fetcher):
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    res = verify_listing(client, fetcher, "agents", aid, headers)
    assert res["status"] == "verified" and res["listing_status"] == "endpoint_verified"
    rec = client.get(f"/v1/agents/{aid}").json()
    jsonschema.validate(rec, SCHEMA)
    trust = rec["trust"]
    assert trust["endpoint_control_verified"] is True
    # Founder decision 8: endpoint verification never implies identity or certification.
    assert trust["operator_identity_verified"] is False
    assert trust["legal_entity_verified"] is False
    assert trust["certifications"] == []
    assert client.get("/v1/agents", params={"verified_only": True}).json()["total"] == 1
    assert any(c.startswith("https://seller.example.com/.well-known/onaa-verification/") for c in fetcher.calls)


def test_discovered_claim_and_verify(client, op, fetcher):
    _, headers = op
    r = client.post("/v1/admin/discovered", headers=admin_headers(), json={
        "display_name": "Observed Agent", "agent_card_url": "https://observed.example.com/.well-known/agent-card.json",
        "source_url": "https://directory.example.org/listing/1", "roles": ["seller_agent"]})
    assert r.status_code == 201, r.text
    rec = r.json()
    jsonschema.validate(rec, SCHEMA)
    assert rec["status"] == "discovered" and rec["operator_id"] is None
    assert rec["trust"]["claimed"] is False and rec["provenance"]["source_url"]
    assert client.get("/v1/agents", params={"claimed_only": True}).json()["total"] == 0

    r = client.post(f"/v1/agents/{rec['id']}/claim", headers=headers)
    assert r.json()["status"] == "claim_pending"
    res = verify_listing(client, fetcher, "agents", rec["id"], headers)
    assert res["listing_status"] == "endpoint_verified"
    assert client.get(f"/v1/agents/{rec['id']}").json()["trust"]["claimed"] is True


def test_certification_is_separate_and_requires_review(client, op, fetcher):
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    body = {"listing_id": aid, "scheme": "protocol_certified"}
    assert client.post("/v1/certifications/applications", json=body, headers=headers).status_code == 409
    verify_listing(client, fetcher, "agents", aid, headers)
    app_ = client.post("/v1/certifications/applications", json=body, headers=headers).json()
    assert app_["status"] == "submitted"
    # Applying does not certify.
    assert client.get(f"/v1/agents/{aid}").json()["status"] == "endpoint_verified"
    assert client.get(f"/v1/certifications/{app_['id']}", headers=headers).json()["status"] == "submitted"

    # Operators cannot decide their own application.
    r = client.post(f"/v1/admin/certifications/{app_['id']}/decision", headers=headers,
                    json={"decision": "approve", "reason": "self"})
    assert r.status_code == 403
    r = client.post(f"/v1/admin/certifications/{app_['id']}/decision", headers=admin_headers(),
                    json={"decision": "approve", "reason": "Passed protocol test suite draft-0.1", "valid_days": 30})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    rec = client.get(f"/v1/agents/{aid}").json()
    jsonschema.validate(rec, SCHEMA)
    assert rec["status"] == "certified"
    assert [c["scheme"] for c in rec["trust"]["certifications"]] == ["protocol_certified"]
    assert rec["trust"]["operator_identity_verified"] is False
    assert client.get("/v1/agents", params={"certified_only": True}).json()["total"] == 1


def test_reports_anonymous(client, op):
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    r = client.post("/v1/reports", json={"subject_id": aid, "category": "impersonation",
                                         "description": "This is not their endpoint"})
    assert r.status_code == 201 and r.json()["state"] == "received"
    assert client.post("/v1/reports", json={"subject_id": "agt_missing", "category": "spam",
                                            "description": "x"}).status_code == 404


def test_operator_deactivation_delists(client, op):
    _, headers = op
    client.post("/v1/agents", json=AGENT, headers=headers)
    assert client.delete("/v1/operators/me", headers=headers).status_code == 204
    assert client.get("/v1/operators/me", headers=headers).status_code == 401
    assert client.get("/v1/agents").json()["total"] == 0


def test_key_rotation_revokes_old_key(client, op):
    _, headers = op
    new = client.post("/v1/operators/me/keys/rotate", headers=headers).json()["api_key"]
    assert client.get("/v1/operators/me", headers=headers).status_code == 401
    assert client.get("/v1/operators/me", headers={"Authorization": f"Bearer {new}"}).status_code == 200


def _api_signature(spec: dict) -> dict:
    """Structural contract only: stable across FastAPI/Pydantic patch releases that reformat schemas."""
    ops = {}
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            ops[f"{method.upper()} {path}"] = {
                "params": sorted((p["in"], p["name"], p.get("required", False)) for p in op.get("parameters", [])),
                "body": json.dumps(op.get("requestBody", {}).get("content", {}).get("application/json", {})
                                   .get("schema", {}).get("$ref")),
                "responses": sorted(op.get("responses", {})),
                "secured": bool(op.get("security")),
            }
    comps = {name: {"props": sorted(sch.get("properties", {})), "required": sorted(sch.get("required", []))}
             for name, sch in spec.get("components", {}).get("schemas", {}).items()}
    return {"ops": ops, "schemas": comps}


def test_openapi_snapshot_is_current(client):
    committed = REPO / "specs" / "openapi.json"
    current = client.get("/openapi.json").json()
    assert committed.exists(), "run: python scripts/export_openapi.py"
    assert _api_signature(json.loads(committed.read_text())) == _api_signature(current), (
        "specs/openapi.json is stale; run: python scripts/export_openapi.py")
