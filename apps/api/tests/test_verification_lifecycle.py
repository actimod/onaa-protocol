"""ENG-008: verification expiry/re-verification, DNS TXT method, per-operator caps, proxy-aware IPs."""

from __future__ import annotations

import datetime as dt
from dataclasses import replace

from conftest import AGENT, SERVICE, admin_headers, make_operator, verify_listing
from fastapi.testclient import TestClient

from onaa_registry.main import create_app
from onaa_registry.models import Listing
from onaa_registry.verification import DnsLookupError


def _age_verification(client, listing_id, days_ago=1):
    with client.app.state.sessionmaker() as s:
        s.get(Listing, listing_id).endpoint_verified_until = dt.datetime.now(dt.UTC) - dt.timedelta(days=days_ago)
        s.commit()


def test_verification_has_expiry(client, op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    verify_listing(client, fetcher, "agents", aid, h)
    trust = client.get(f"/v1/agents/{aid}/trust").json()
    until = dt.datetime.fromisoformat(trust["endpoint_verified_until"])
    assert dt.timedelta(days=89) < until - dt.datetime.now(dt.UTC) <= dt.timedelta(days=90)
    assert trust["endpoint_verification_method"] == "well_known"


def test_expired_verification_drops_badge_everywhere(client, op, other_op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    verify_listing(client, fetcher, "agents", aid, h)
    _age_verification(client, aid)
    rec = client.get(f"/v1/agents/{aid}").json()
    assert rec["status"] == "registered" and rec["trust"]["endpoint_control_verified"] is False
    assert client.get("/v1/agents", params={"verified_only": True}).json()["total"] == 0
    # Lapsed host is no longer reserved: another operator may register (and would need to verify).
    _, h2 = other_op
    assert client.post("/v1/agents", json=AGENT, headers=h2).status_code == 201


def test_expiry_job_and_reverification(client, op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    verify_listing(client, fetcher, "agents", aid, h)
    _age_verification(client, aid)
    r = client.post("/v1/admin/jobs/expire-verifications", headers=admin_headers())
    assert r.json()["expired"] == [aid]
    with client.app.state.sessionmaker() as s:
        row = s.get(Listing, aid)
        assert row.endpoint_control_verified is False and row.lifecycle_status == "registered"
    verify_listing(client, fetcher, "agents", aid, h)
    assert client.get(f"/v1/agents/{aid}").json()["status"] == "endpoint_verified"


def test_lapsed_verification_hides_certification_until_reverified(client, op, fetcher):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    verify_listing(client, fetcher, "agents", aid, h)
    app_id = client.post("/v1/certifications/applications", headers=h,
                         json={"listing_id": aid, "scheme": "protocol_certified"}).json()["id"]
    client.post(f"/v1/admin/certifications/{app_id}/decision", headers=admin_headers(),
                json={"decision": "approve", "reason": "ok"})
    assert client.get("/v1/agents", params={"certified_only": True}).json()["total"] == 1
    _age_verification(client, aid)
    assert client.get("/v1/agents", params={"certified_only": True}).json()["total"] == 0
    rec = client.get(f"/v1/agents/{aid}").json()
    assert rec["status"] == "registered" and rec["trust"]["certifications"] == []
    client.post("/v1/admin/jobs/expire-verifications", headers=admin_headers())
    verify_listing(client, fetcher, "agents", aid, h)
    assert client.get(f"/v1/agents/{aid}").json()["status"] == "certified"


def test_dns_txt_verification(client, op, txt):
    _, h = op
    sid = client.post("/v1/services", json=SERVICE, headers=h).json()["id"]
    chl = client.post(f"/v1/services/{sid}/verify-domain", json={"method": "dns_txt"}, headers=h).json()
    assert chl["dns_record_name"] == "_onaa-challenge.api.escrow.example.net" and chl["challenge_url"] is None
    body = {"challenge_id": chl["challenge_id"]}
    r = client.post(f"/v1/services/{sid}/verification-complete", json=body, headers=h)
    assert r.status_code == 422 and r.json()["error"] == "txt_record_not_found"
    txt.records[chl["dns_record_name"]] = ["unrelated", "onaa-verify-wrong"]
    r = client.post(f"/v1/services/{sid}/verification-complete", json=body, headers=h)
    assert r.json()["error"] == "token_mismatch"
    txt.records[chl["dns_record_name"]] = DnsLookupError("dns_timeout")
    r = client.post(f"/v1/services/{sid}/verification-complete", json=body, headers=h)
    assert r.json()["error"] == "dns_timeout"
    txt.records[chl["dns_record_name"]] = ["v=spf1 -all", chl["token"]]
    r = client.post(f"/v1/services/{sid}/verification-complete", json=body, headers=h)
    assert r.status_code == 200 and r.json()["endpoint_control_verified"] is True
    assert client.get(f"/v1/services/{sid}/trust").json()["endpoint_verification_method"] == "dns_txt"


def test_challenge_method_validated(client, op):
    _, h = op
    aid = client.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    assert client.post(f"/v1/agents/{aid}/verify-domain", json={"method": "email"}, headers=h).status_code == 422


def test_listing_quota_per_operator(settings, fetcher, txt):
    with TestClient(create_app(replace(settings, max_listings_per_operator=2), fetcher, txt)) as c:
        _, h = make_operator(c)
        codes = [c.post("/v1/agents", headers=h, json=dict(
            AGENT, agent_card_url=f"https://a{i}.example.com/.well-known/agent-card.json")).status_code
            for i in range(3)]
        assert codes == [201, 201, 429]
        # Deleting frees a slot.
        first = c.get("/v1/agents").json()["items"][0]["id"]
        c.delete(f"/v1/agents/{first}", headers=h)
        assert c.post("/v1/agents", json=AGENT, headers=h).status_code == 201


def test_operator_write_limit_independent_of_ip(settings, fetcher, txt):
    with TestClient(create_app(replace(settings, operator_write_limit_per_minute=2), fetcher, txt)) as c:
        _, h = make_operator(c)
        codes = [c.post("/v1/agents", headers=h, json=dict(
            AGENT, agent_card_url=f"https://b{i}.example.com/.well-known/agent-card.json")).status_code
            for i in range(3)]
        assert codes == [201, 201, 429]
        assert c.get("/v1/operators/me", headers=h).status_code == 200  # reads are not limited


def test_trusted_proxy_client_ip(settings, fetcher, txt):
    cfg = replace(settings, write_rate_limit_per_minute=1, trusted_proxy_hops=1)
    with TestClient(create_app(cfg, fetcher, txt)) as c:
        def signup(ip):
            return c.post("/v1/operators", headers={"X-Forwarded-For": f"{ip}"}, json={
                "display_name": "x", "operator_type": "individual", "accept_terms_version": "draft-0.1"}).status_code
        assert signup("198.51.100.1") == 201
        assert signup("198.51.100.2") == 201  # different real client behind the same proxy
        assert signup("198.51.100.1") == 429


def test_name_collision_is_flagged_not_blocked(client, op, other_op, fetcher):
    _, h1 = op
    _, h2 = other_op
    real = client.post("/v1/agents", json=AGENT, headers=h1).json()["id"]
    verify_listing(client, fetcher, "agents", real, h1)
    copy = client.post("/v1/agents", headers=h2, json=dict(
        AGENT, display_name="example parts-seller!",
        agent_card_url="https://lookalike.example.org/.well-known/agent-card.json"))
    assert copy.status_code == 201
    assert copy.json()["trust"]["review_flags"] == ["name_collision_review"]
    assert client.get(f"/v1/agents/{real}").json()["trust"]["review_flags"] == []
