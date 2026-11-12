"""Agent self-registration: no human signup, proof of endpoint control, agent-scoped key."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json

import pytest
from conftest import AGENT, SERVICE, admin_headers, make_operator, verify_listing
from fastapi.testclient import TestClient
from sqlalchemy import select

from onaa_registry.main import create_app
from onaa_registry.models import AuditEvent, Operator, SelfRegistration

TERMS = "draft-0.2"


def start(client, *, agent=None, service=None, method="well_known"):
    body = {"accept_terms_version": TERMS, "confirm_operator_authority": True, "method": method}
    if agent is not None:
        body["agent"] = agent
    if service is not None:
        body["service"] = service
    return client.post("/v1/self-register", json=body)


def publish_and_complete(client, fetcher, chl):
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"] + "\n")
    return client.post(f"/v1/self-register/{chl['registration_id']}/complete",
                       json={"registration_secret": chl["registration_secret"]})


def self_register(client, fetcher, agent=AGENT):
    r = start(client, agent=agent)
    assert r.status_code == 201, r.text
    r = publish_and_complete(client, fetcher, r.json())
    assert r.status_code == 201, r.text
    return r.json()


def test_agent_registers_itself_end_to_end_without_human_signup(client, fetcher):
    r = start(client, agent=AGENT)
    assert r.status_code == 201, r.text
    chl = r.json()
    assert chl["host"] == "seller.example.com"
    assert chl["challenge_url"] == (
        f"https://seller.example.com/.well-known/onaa-verification/{chl['registration_id']}.txt")
    assert chl["registration_secret"].startswith("onaa_srs_")
    # Nothing is listed before the proof.
    assert client.get("/v1/agents").json()["total"] == 0

    r = publish_and_complete(client, fetcher, chl)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["operator"]["operator_type"] == "agent"
    assert out["operator"]["display_name"] == AGENT["display_name"]
    assert out["api_key"].startswith("onaa_sk_")
    assert fetcher.redirect_flags[-1] is False  # proof fetch never follows redirects
    listing = out["listing"]
    assert listing["status"] == "registered"
    # Signup proof is an anti-abuse gate, not the paid Endpoint Verified tier.
    assert listing["trust"]["endpoint_control_verified"] is False
    assert listing["trust"]["registration_method"] == "agent_self_registration"
    assert listing["trust"]["operator_identity_verified"] is False

    # The agent key works like any operator key: it owns and can edit its listing.
    h = {"Authorization": f"Bearer {out['api_key']}"}
    assert client.get("/v1/operators/me", headers=h).json()["operator_type"] == "agent"
    r = client.patch(f"/v1/agents/{listing['id']}", headers=h, json={"description": "updated by the agent"})
    assert r.status_code == 200, r.text
    assert client.get("/v1/agents", params={"q": "refurbished"}).json()["total"] == 0
    assert client.get(f"/v1/agents/{listing['id']}").json()["description"] == "updated by the agent"

    # Single use.
    r = client.post(f"/v1/self-register/{chl['registration_id']}/complete",
                    json={"registration_secret": chl["registration_secret"]})
    assert r.status_code == 409


def test_service_self_registration(client, fetcher):
    r = start(client, service=SERVICE)
    assert r.status_code == 201, r.text
    chl = r.json()
    assert chl["host"] == "api.escrow.example.net"
    out = publish_and_complete(client, fetcher, chl).json()
    assert out["listing"]["listing_type"] == "service"
    assert out["listing"]["service_type"] == "escrow"
    assert client.get("/v1/services", params={"service_type": "escrow"}).json()["total"] == 1


def test_dns_txt_proof(client, txt):
    chl = start(client, agent=AGENT, method="dns_txt").json()
    assert chl["dns_record_name"] == "_onaa-challenge.seller.example.com"
    url = f"/v1/self-register/{chl['registration_id']}/complete"
    body = {"registration_secret": chl["registration_secret"]}
    r = client.post(url, json=body)
    assert r.status_code == 422 and r.json()["error"] == "txt_record_not_found"
    txt.records[chl["dns_record_name"]] = ["unrelated", chl["token"]]
    assert client.post(url, json=body).status_code == 201


def test_published_token_alone_does_not_hand_out_the_key(client, fetcher):
    """The challenge URL and token are public once published; completion also needs the private secret."""
    chl = start(client, agent=AGENT).json()
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"])
    url = f"/v1/self-register/{chl['registration_id']}/complete"
    for secret in (chl["token"], "onaa_srs_guess", ""):
        r = client.post(url, json={"registration_secret": secret})
        assert r.status_code in (404, 422), r.text
    assert client.post(url, json={"registration_secret": chl["registration_secret"]}).status_code == 201


def test_wrong_token_redirect_and_attempt_cap(client, fetcher):
    chl = start(client, agent=AGENT).json()
    url = f"/v1/self-register/{chl['registration_id']}/complete"
    body = {"registration_secret": chl["registration_secret"]}
    fetcher.routes[chl["challenge_url"]] = (302, "")
    r = client.post(url, json=body)
    assert r.status_code == 422 and r.json()["error"] == "http_302"
    fetcher.routes[chl["challenge_url"]] = (200, "onaa-verify-wrong")
    for _ in range(9):
        r = client.post(url, json=body)
        assert r.status_code == 422 and r.json()["error"] == "token_mismatch"
    assert r.json()["status"] == "failed"
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"])
    assert client.post(url, json=body).status_code == 409
    assert client.get("/v1/agents").json()["total"] == 0


def test_expired_registration(client, fetcher):
    chl = start(client, agent=AGENT).json()
    sm = client.app.state.sessionmaker
    with sm() as s:
        sr = s.get(SelfRegistration, chl["registration_id"])
        sr.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        s.commit()
    assert publish_and_complete(client, fetcher, chl).status_code == 410


def test_input_validation(client):
    r = client.post("/v1/self-register", json={"accept_terms_version": "old", "agent": AGENT})
    assert r.status_code == 422 and "terms" in r.text
    assert start(client).status_code == 422  # neither
    assert start(client, agent=AGENT, service=SERVICE).status_code == 422  # both
    bad = dict(AGENT, agent_card_url="http://127.0.0.1/.well-known/agent-card.json")
    assert start(client, agent=bad).status_code == 422
    other_host = dict(AGENT, endpoint_url="https://elsewhere.example.org/a2a")
    assert start(client, agent=other_host).status_code == 422
    # Fields outside the schema are rejected.
    r = client.post("/v1/self-register", json={"accept_terms_version": TERMS, "confirm_operator_authority": True,
                                               "agent": AGENT, "operator_name": "someone"})
    assert r.status_code == 422


def test_operator_authority_must_be_confirmed(client):
    base = {"accept_terms_version": TERMS, "agent": AGENT}
    assert client.post("/v1/self-register", json=base).status_code == 422  # missing
    r = client.post("/v1/self-register", json=dict(base, confirm_operator_authority=False))
    assert r.status_code == 422 and "confirm_operator_authority" in r.text


def test_terms_endpoint_and_hash_binding(client, fetcher):
    t = client.get("/v1/terms").json()
    assert t["version"] == TERMS and len(t["sha256"]) == 64
    assert hashlib.sha256(t["text"].encode()).hexdigest() == t["sha256"]
    assert "Operator" in t["text"] and "confirm_operator_authority" in t["text"]
    assert t["how_to_accept"] == {"accept_terms_version": TERMS, "accept_terms_sha256": t["sha256"],
                                  "confirm_operator_authority": True}
    md = client.get("/v1/terms.md")
    assert md.text == t["text"] and md.headers["x-onaa-terms-sha256"] == t["sha256"]
    body = {"accept_terms_version": TERMS, "confirm_operator_authority": True, "agent": AGENT}
    r = client.post("/v1/self-register", json=dict(body, accept_terms_sha256="0" * 64))
    assert r.status_code == 422 and "sha256" in r.text
    r = client.post("/v1/self-register", json=dict(body, accept_terms_sha256=t["sha256"]))
    assert r.status_code == 201, r.text


def test_acceptance_evidence_and_private_contact(client, fetcher, settings):
    r = client.post("/v1/self-register", json={"accept_terms_version": TERMS, "confirm_operator_authority": True,
                                               "operator_contact": "ops@seller.example.com", "agent": AGENT})
    assert r.status_code == 201, r.text
    done = publish_and_complete(client, fetcher, r.json()).json()
    assert "ops@seller.example.com" not in json.dumps(done)
    listing_id, op_id = done["listing"]["id"], done["operator"]["id"]
    assert "ops@seller.example.com" not in client.get(f"/v1/agents/{listing_id}").text
    assert any("DELETE" in s for s in done["next_steps"]) and any("/v1/terms" in s for s in done["next_steps"])
    with client.app.state.sessionmaker() as s:
        op = s.get(Operator, op_id)
        assert op.operator_contact == "ops@seller.example.com"
        assert op.terms_version == TERMS and op.terms_acceptance_method == "agent_on_behalf_of_operator"
        assert op.terms_sha256 == client.get("/v1/terms").json()["sha256"] and op.terms_accepted_at is not None
        sr = s.get(SelfRegistration, done["registration_id"])
        assert sr.operator_authority_confirmed is True
        assert "ops@seller.example.com" not in json.dumps([e.detail for e in s.scalars(select(AuditEvent))],
                                                         default=str)


def test_operator_contact_validation(client):
    body = {"accept_terms_version": TERMS, "confirm_operator_authority": True, "agent": AGENT}
    for bad in ("someone", "http://insecure.example.com/contact", "a@b"):
        assert client.post("/v1/self-register", json=dict(body, operator_contact=bad)).status_code == 422, bad
    assert client.post("/v1/self-register",
                       json=dict(body, operator_contact="https://seller.example.com/contact")).status_code == 201


def test_unauthorized_registration_report_category(client, fetcher):
    done = self_register(client, fetcher)
    r = client.post("/v1/reports", json={"subject_id": done["listing"]["id"], "category": "unauthorized_registration",
                                         "description": "We did not authorise this agent to register our host."})
    assert r.status_code == 201 and r.json()["category"] == "unauthorized_registration"


def test_unbundled_terms_version_fails_at_startup(settings, fetcher, txt):
    with pytest.raises(RuntimeError, match="no bundled terms text"):
        create_app(dataclasses.replace(settings, terms_version="draft-9.9"), fetcher, txt)


def test_host_verified_by_another_operator_is_refused(client, fetcher):
    _, h = make_operator(client)
    lid = client.post("/v1/agents", headers=h, json=AGENT).json()["id"]
    verify_listing(client, fetcher, "agents", lid, h)
    r = start(client, agent=dict(AGENT, display_name="Squatter"))
    assert r.status_code == 409


def test_agent_identities_per_host_cap(settings, fetcher, txt):
    s = dataclasses.replace(settings, self_registration_agents_per_host=2)
    with TestClient(create_app(s, fetcher, txt)) as c:
        self_register(c, fetcher)
        self_register(c, fetcher, dict(AGENT, display_name="Second"))
        r = start(c, agent=dict(AGENT, display_name="Third"))
        assert r.status_code == 409 and "self-registered agent identities" in r.text


def test_pending_per_host_and_per_ip_limits(settings, fetcher, txt):
    s = dataclasses.replace(settings, self_registration_pending_per_host=2, self_registration_per_ip_per_hour=3)
    with TestClient(create_app(s, fetcher, txt)) as c:
        first = start(c, agent=AGENT).json()
        assert start(c, agent=AGENT).status_code == 201
        third = start(c, agent=AGENT)
        assert third.status_code == 201  # oldest pending is evicted, the host is never locked out
        fetcher.routes[first["challenge_url"]] = (200, first["token"])
        r = c.post(f"/v1/self-register/{first['registration_id']}/complete",
                   json={"registration_secret": first["registration_secret"]})
        assert r.status_code == 409 and "expired" in r.text
        r = publish_and_complete(c, fetcher, third.json())
        assert r.status_code == 201, r.text
        other = dict(AGENT, agent_card_url="https://other.example.com/.well-known/agent-card.json")
        r = start(c, agent=other)
        assert r.status_code == 429 and r.headers["Retry-After"] == "3600"  # 3 starts per IP per hour


def test_disabled(settings, fetcher, txt):
    s = dataclasses.replace(settings, self_registration_enabled=False)
    with TestClient(create_app(s, fetcher, txt)) as c:
        assert start(c, agent=AGENT).status_code == 404
        assert "disabled" in c.get("/llms.txt").text
        assert c.get("/.well-known/onaa-registry.json").json()["onboarding"]["self_registration_enabled"] is False


def test_discovered_copy_is_retired_on_self_registration(client, fetcher):
    r = client.post("/v1/admin/discovered", headers=admin_headers(), json={
        "display_name": "Seen in the wild", "agent_card_url": AGENT["agent_card_url"],
        "source_url": "https://directory.example.org/agents/1", "roles": ["seller_agent"]})
    assert r.status_code == 201, r.text
    disc = r.json()
    assert disc["trust"]["registration_method"] == "discovery_import"
    out = self_register(client, fetcher)
    assert client.get(f"/v1/agents/{disc['id']}").status_code == 410  # deleted
    ids = [x["id"] for x in client.get("/v1/agents").json()["items"]]
    assert ids == [out["listing"]["id"]]


def test_optional_operator_linkage_and_key_rotation(client, fetcher):
    out = self_register(client, fetcher)
    h = {"Authorization": f"Bearer {out['api_key']}"}
    r = client.patch("/v1/operators/me", headers=h, json={"operator_type": "organization",
                                                          "display_name": "Example Parts Ltd", "country": "KR",
                                                          "website_url": "https://seller.example.com"})
    assert r.status_code == 200, r.text
    assert r.json()["operator_type"] == "organization" and r.json()["identity_verified"] is False
    # Listing still records how it joined.
    rec = client.get(f"/v1/agents/{out['listing']['id']}").json()
    assert rec["trust"]["registration_method"] == "agent_self_registration"
    assert client.patch("/v1/operators/me", headers=h, json={"operator_type": "agent"}).status_code == 422
    new = client.post("/v1/operators/me/keys/rotate", headers=h).json()["api_key"]
    assert client.get("/v1/operators/me", headers=h).status_code == 401
    assert client.get("/v1/operators/me", headers={"Authorization": f"Bearer {new}"}).status_code == 200


def test_operator_account_listing_reports_method(client, op):
    _, h = op
    rec = client.post("/v1/agents", headers=h, json=AGENT).json()
    assert rec["trust"]["registration_method"] == "operator_account"


def test_llms_txt_and_onboarding_block(settings, fetcher, txt):
    s = dataclasses.replace(settings, public_base_url="https://api.onaa.net")
    with TestClient(create_app(s, fetcher, txt)) as c:
        r = c.get("/llms.txt")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
        body = r.text
        assert "Base URL: https://api.onaa.net" in body
        assert "POST https://api.onaa.net/v1/self-register" in body
        assert f'"accept_terms_version": "{TERMS}"' in body
        assert "untrusted data" in body
        wk = c.get("/.well-known/onaa-registry.json").json()
        ob = wk["onboarding"]
        assert ob["terms_version"] == TERMS and ob["self_registration_enabled"] is True
        assert [st["step"] for st in ob["steps"]] == [0, 1, 2, 3]
        assert ob["steps"][0]["call"] == "GET https://api.onaa.net/v1/terms"
        assert ob["steps"][1]["body"]["confirm_operator_authority"] is True
        assert ob["terms_url"] == "https://api.onaa.net/v1/terms" and "operator" in ob["operator_authority"]
        assert '"confirm_operator_authority": true' in body and "Register for your operator" in body
        assert "unauthorized_registration" in body
        assert ob["steps"][1]["call"] == "POST https://api.onaa.net/v1/self-register"
        assert ob["llms_txt"] == "https://api.onaa.net/llms.txt"


def test_operator_account_records_acceptance_evidence(client):
    r = client.post("/v1/operators", json={"display_name": "Acme", "operator_type": "organization",
                                           "accept_terms_version": TERMS, "operator_contact": "legal@acme.example.com"})
    assert r.status_code == 201, r.text
    assert "legal@acme.example.com" not in r.text
    with client.app.state.sessionmaker() as s:
        op = s.get(Operator, r.json()["operator"]["id"])
        assert op.terms_acceptance_method == "operator_account" and op.operator_contact == "legal@acme.example.com"
        assert op.terms_sha256 and op.terms_accepted_at is not None


DISCOVERED_SVC = {"display_name": "Example Escrow Co", "service_type": "escrow",
                  "documentation_url": "https://docs.escrow.example.net/api",
                  "source_url": "https://docs.escrow.example.net/api", "regions": ["US"], "currencies": ["USD"],
                  "capabilities": ["escrow.create"]}


def test_discovered_service_import_without_endpoint(client):
    r = client.post("/v1/admin/discovered/services", json=DISCOVERED_SVC)
    assert r.status_code == 403
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=DISCOVERED_SVC)
    assert r.status_code == 201, r.text
    rec = r.json()
    assert rec["status"] == "discovered" and rec["operator_id"] is None and rec["endpoint_url"] is None
    assert rec["trust"]["claimed"] is False and rec["trust"]["registration_method"] == "discovery_import"
    assert "not registered" in rec["provenance"]["note"]
    page = client.get("/v1/services", params={"service_type": "escrow"}).json()
    assert [x["id"] for x in page["items"]] == [rec["id"]]
    assert client.get("/v1/services", params={"service_type": "escrow", "claimed_only": True}).json()["total"] == 0
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=DISCOVERED_SVC)
    assert r.status_code == 409  # duplicate
    bad = dict(DISCOVERED_SVC, documentation_url="http://10.0.0.1/docs")
    assert client.post("/v1/admin/discovered/services", headers=admin_headers(), json=bad).status_code == 422


def test_self_registered_provider_retires_discovered_service_on_same_host(client, fetcher):
    disc = client.post("/v1/admin/discovered/services", headers=admin_headers(),
                       json=dict(DISCOVERED_SVC, endpoint_url="https://api.escrow.example.net/v1")).json()
    chl = start(client, service=SERVICE).json()
    out = publish_and_complete(client, fetcher, chl).json()
    assert client.get(f"/v1/services/{disc['id']}").status_code == 410
    ids = [x["id"] for x in client.get("/v1/services", params={"service_type": "escrow"}).json()["items"]]
    assert ids == [out["listing"]["id"]]


def test_import_script_dry_run_and_apply(client, tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "import_discovered", Path(__file__).resolve().parents[1] / "scripts" / "import_discovered.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"services": [
        dict(DISCOVERED_SVC, status="discovered", notes="dropped", name=None),
        {"name": "Ship Co", "type": "logistics", "docs_url": "https://docs.ship.example.org",
         "source_url": "https://docs.ship.example.org"},
        {"name": "Broken", "type": "not-a-type", "docs_url": "https://x.example.org", "source_url": "https://x"},
    ]}))
    assert mod.main([str(seed)]) == 1  # one invalid entry; nothing sent
    assert client.get("/v1/services").json()["total"] == 0

    sent = []

    class FakeHttp:
        def __init__(self, **kw):
            assert kw["headers"]["Authorization"] == "Bearer test-admin-token"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def post(self, path, json):
            sent.append(path)
            return client.post(path, json=json, headers=admin_headers())

    monkeypatch.setattr(mod.httpx, "Client", FakeHttp)
    monkeypatch.setenv("ONAA_ADMIN_TOKEN", "test-admin-token")
    assert mod.main([str(seed), "--apply"]) == 1  # still reports the invalid entry
    assert sent == ["/v1/admin/discovered/services"] * 2
    assert client.get("/v1/services").json()["total"] == 2


def test_unresolvable_host_reports_host_not_resolved():
    from onaa_registry.netsafety import SafeFetcher
    from onaa_registry.verification import check_host_proof

    def resolver(host):
        raise OSError("NXDOMAIN")

    err = check_host_proof(SafeFetcher(resolver=resolver), lambda name: [], host="nx.example.com",
                           method="well_known", challenge_id="sreg_x", nonce_hash="0" * 64)
    assert err == "host_not_resolved"
