"""CERT-009..011: conformance pre-check in the application flow, unannounced re-checks, card/JWKS change
detection, TEST-ONLY signed attestations, signed status re-issuance and the Merkle transparency log."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace

import pytest
from conftest import AGENT, TRUST, admin_headers, verify_listing
from fastapi.testclient import TestClient
from onaa_protocol import jose, trust
from onaa_protocol import transparency as tl
from onaa_protocol.attestation import verify_attestation
from onaa_protocol.errors import AttestationError

from onaa_registry.main import create_app
from onaa_registry.models import Listing
from onaa_registry.trust_ops import TrustConfigError

CARD_URL = AGENT["agent_card_url"]
JWKS_URL = "https://seller.example.com/.well-known/onaa/jwks.json"


def card(version="1.0.0", jwks_uri=JWKS_URL):
    return json.dumps({"name": "Example Parts Seller", "version": version, "skills": [{"id": "rfq"}],
                       "capabilities": {"extensions": [{"uri": "urn:onaa:a2a-ext:commerce:v0",
                                                        "params": {"jwks_uri": jwks_uri}}]}})


def jwks(x="a"):
    return json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": f"seller-{x}", "x": x * 43}]})


@pytest.fixture
def seller(client, op, fetcher):
    fetcher.routes[CARD_URL] = (200, card())
    fetcher.routes[JWKS_URL] = (200, jwks())
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    verify_listing(client, fetcher, "agents", aid, headers)
    return aid, headers


def certify(client, aid, headers, scheme="protocol_certified"):
    app_ = client.post("/v1/certifications/applications", json={"listing_id": aid, "scheme": scheme},
                       headers=headers).json()
    r = client.post(f"/v1/admin/certifications/{app_['id']}/decision", headers=admin_headers(),
                    json={"decision": "approve", "reviewer": "founder", "reason": "reviewed", "valid_days": 30})
    assert r.status_code == 200, r.text
    return client.get(f"/v1/agents/{aid}").json()["trust"]["certifications"][0]


def issuer(now=None):
    return trust.verify_manifest(TRUST["manifest"], TRUST["root_jwk"], now=now, allow_test_only=True)


def run_monitor(client):
    r = client.post("/v1/admin/jobs/verification-monitor", headers=admin_headers())
    assert r.status_code == 200, r.text
    return r.json()


def make_due(client, aid):
    with client.app.state.sessionmaker() as s:
        s.get(Listing, aid).next_recheck_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
        s.commit()


# ------------------------------------------------------------------ CERT-009 pre-check and application flow


def test_precheck_requires_owned_endpoint_verified_listing(client, op, other_op, fetcher, runner):
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    body = {"listing_id": aid}
    assert client.post("/v1/certifications/precheck", json=body, headers=headers).status_code == 409
    verify_listing(client, fetcher, "agents", aid, headers)
    assert client.post("/v1/certifications/precheck", json=body, headers=other_op[1]).status_code == 403
    r = client.post("/v1/certifications/precheck", json=body, headers=headers)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["verdict"] == "pass" and run["kind"] == "precheck" and run["role"] == "seller_agent"
    assert run["report_sha256"].startswith("sha256:") and "not a certification" in run["note"]
    # Pre-check is evidence only: the listing is not certified.
    assert client.get(f"/v1/agents/{aid}").json()["trust"]["certifications"] == []
    assert runner.calls[-1].card_url == CARD_URL and len(runner.calls[-1].seed) == 16


def test_precheck_rate_limited_per_listing(settings, fetcher, txt, runner):
    with TestClient(create_app(replace(settings, precheck_min_interval_seconds=600), fetcher, txt, runner)) as c:
        from conftest import make_operator
        _, headers = make_operator(c)
        aid = c.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
        verify_listing(c, fetcher, "agents", aid, headers)
        assert c.post("/v1/certifications/precheck", json={"listing_id": aid}, headers=headers).status_code == 201
        assert c.post("/v1/certifications/precheck", json={"listing_id": aid}, headers=headers).status_code == 429


def test_application_files_conformance_run_and_approval_needs_pass_and_reviewer(client, seller, runner):
    aid, headers = seller
    runner.verdicts[CARD_URL] = "fail"
    app_ = client.post("/v1/certifications/applications", json={"listing_id": aid, "scheme": "protocol_certified"},
                       headers=headers).json()
    assert app_["conformance_run"]["verdict"] == "fail"
    assert app_["conformance_run"]["summary"]["failed_tests"] == ["ONAA-C-MUST-001"]
    url = f"/v1/admin/certifications/{app_['id']}/decision"
    r = client.post(url, headers=admin_headers(), json={"decision": "approve", "reviewer": "founder", "reason": "x"})
    assert r.status_code == 409 and "conformance" in r.json()["detail"]
    runner.verdicts[CARD_URL] = "incomplete"  # incomplete never counts as passing
    client.post("/v1/certifications/precheck", json={"listing_id": aid}, headers=headers)
    assert client.post(url, headers=admin_headers(),
                       json={"decision": "approve", "reviewer": "founder", "reason": "x"}).status_code == 409
    runner.verdicts[CARD_URL] = "pass"
    client.post("/v1/certifications/precheck", json={"listing_id": aid}, headers=headers)
    assert client.post(url, headers=admin_headers(), json={"decision": "approve", "reason": "x"}).status_code == 422
    r = client.post(url, headers=admin_headers(), json={"decision": "approve", "reviewer": "founder", "reason": "x"})
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_runner_crash_is_recorded_as_error(client, seller, runner):
    aid, headers = seller
    runner.verdicts[CARD_URL] = "raise"
    run = client.post("/v1/certifications/precheck", json={"listing_id": aid}, headers=headers).json()
    assert run["verdict"] == "error" and run["summary"] == {"error": "RuntimeError"}


# ------------------------------------------------------------------ CERT-011 attestation, status, log


def test_approval_issues_verifiable_test_only_attestation(client, seller):
    aid, headers = seller
    cert = certify(client, aid, headers)
    att = client.get(cert["attestation_url"]).json()
    rec = client.get(cert["status_url"]).json()
    assert att["test_only"] is True and att["subject"]["subject_id"] == aid and att["level"] == "protocol_certified"
    assert att["scope"]["roles"] == ["seller_agent"] and att["scope"]["conformance"]["verdict"] == "pass"
    assert [e["type"] for e in att["evidence"]] == ["conformance_report", "review_record"]
    assert att["status_url"].endswith(cert["status_url"])
    res = verify_attestation(att, issuer_manifest=issuer(), status_record=rec, allow_test_only=True)
    assert res.status == "active"
    # Production verifiers refuse TEST-ONLY material.
    with pytest.raises(AttestationError):
        trust.verify_manifest(TRUST["manifest"], TRUST["root_jwk"])
    # Status records live 7 days and are reused until the re-issue interval passes.
    nu = dt.datetime.fromisoformat(rec["next_update"].replace("Z", "+00:00"))
    sa = dt.datetime.fromisoformat(rec["status_at"].replace("Z", "+00:00"))
    assert nu - sa == dt.timedelta(days=7)
    assert client.get(cert["status_url"]).json() == rec
    # No private key material is ever served.
    for path in ("/.well-known/onaa/issuer-jwks.json", cert["attestation_url"], cert["status_url"],
                 "/v1/transparency/checkpoint"):
        assert '"d"' not in client.get(path).text


def test_transparency_log_inclusion_and_consistency(client, seller, runner):
    aid, headers = seller
    cert = certify(client, aid, headers)
    log_jwk = {k: v for k, v in json.loads(TRUST["log"]).items() if k != "d"}
    log_key = jose.public_key_from_jwk(log_jwk)
    cp1 = client.get("/v1/transparency/checkpoint").json()
    tl.verify_checkpoint(cp1, lambda kid: log_key)
    assert issuer().lookup(tl.TYP_CHECKPOINT)(log_jwk["kid"])
    entries = client.get("/v1/transparency/entries", params={"attestation_id": cert["id"]}).json()["entries"]
    assert [e["entry"]["event"] for e in entries] == ["issue"]
    e = entries[0]
    att = client.get(cert["attestation_url"]).json()
    assert e["entry"]["attestation_sha256"] == tl.attestation_digest(att)
    leaf = tl.leaf_hash(tl.leaf_bytes(e["entry"]))
    assert tl.b64(leaf) == e["leaf_hash"]
    proof = client.get("/v1/transparency/proof/inclusion",
                       params={"index": e["index"], "tree_size": cp1["tree_size"]}).json()
    tl.verify_inclusion(leaf, e["index"], cp1["tree_size"], [tl.unb64(p) for p in proof["proof"]],
                        tl.unb64(cp1["root_hash"]))

    # Suspend via admin; the log grows append-only.
    r = client.post(f"/v1/admin/certifications/issued/{cert['id']}/status", headers=admin_headers(),
                    json={"status": "suspended", "reason": "complaint under review", "reviewer": "founder"})
    assert r.status_code == 200
    cp2 = client.get("/v1/transparency/checkpoint").json()
    assert cp2["tree_size"] == cp1["tree_size"] + 1
    cons = client.get("/v1/transparency/proof/consistency",
                      params={"first": cp1["tree_size"], "second": cp2["tree_size"]}).json()
    tl.verify_consistency(cp1["tree_size"], cp2["tree_size"], [tl.unb64(p) for p in cons["proof"]],
                          tl.unb64(cp1["root_hash"]), tl.unb64(cp2["root_hash"]))
    assert client.get("/v1/transparency/proof/inclusion", params={"index": 0, "tree_size": 99}).status_code == 400


def test_suspend_reinstate_revoke_reissue_status(client, seller):
    aid, headers = seller
    cert = certify(client, aid, headers)
    url = f"/v1/admin/certifications/issued/{cert['id']}/status"
    att = client.get(cert["attestation_url"]).json()
    client.post(url, headers=admin_headers(), json={"status": "suspended", "reason": "check", "reviewer": "a"})
    rec = client.get(cert["status_url"]).json()
    assert rec["status"] == "suspended" and rec["reason"] == "check"
    with pytest.raises(AttestationError) as e:
        verify_attestation(att, issuer_manifest=issuer(), status_record=rec, allow_test_only=True)
    assert e.value.code == "attestation_suspended"
    # Suspended certifications disappear from the public record (fail closed).
    assert client.get(f"/v1/agents/{aid}").json()["trust"]["certifications"] == []
    listed = client.get("/v1/attestations", params={"subject_id": aid}).json()["attestations"]
    assert listed[0]["status"] == "suspended"
    assert client.post(url, headers=admin_headers(),
                       json={"status": "active", "reason": "resolved", "reviewer": "a"}).status_code == 200
    assert client.get(cert["status_url"]).json()["status"] == "active"
    client.post(url, headers=admin_headers(), json={"status": "revoked", "reason": "fraud", "reviewer": "a"})
    assert client.get(cert["status_url"]).json()["status"] == "revoked"
    assert client.post(url, headers=admin_headers(),
                       json={"status": "active", "reason": "oops", "reviewer": "a"}).status_code == 409
    events = [e["entry"]["event"] for e in client.get("/v1/transparency/entries").json()["entries"]]
    assert events == ["issue", "suspend", "reinstate", "revoke"]


# ------------------------------------------------------------------ CERT-009 monitoring


def test_rechecks_are_scheduled_randomly_and_never_published(client, seller):
    aid, headers = seller
    certify(client, aid, headers)
    with client.app.state.sessionmaker() as s:
        nxt = s.get(Listing, aid).next_recheck_at
    delay = (nxt.replace(tzinfo=dt.UTC) if nxt.tzinfo is None else nxt) - dt.datetime.now(dt.UTC)
    assert dt.timedelta(days=6.9) < delay < dt.timedelta(days=30.1)
    assert "next_recheck" not in client.get(f"/v1/agents/{aid}").text


def test_card_change_queues_recheck_and_failure_suspends(client, seller, fetcher, runner):
    aid, headers = seller
    cert = certify(client, aid, headers)
    assert run_monitor(client)["changes"] == {}
    fetcher.routes[CARD_URL] = (200, card(version="2.0.0"))
    runner.verdicts[CARD_URL] = "fail"
    out = run_monitor(client)
    assert out["changes"] == {aid: ["card_changed"]}
    assert out["rechecks"] == {aid: "fail"}  # change queued an immediate re-check in the same job
    rec = client.get(cert["status_url"]).json()
    assert rec["status"] == "suspended" and rec["reason"] == "automated_recheck_failed"
    assert client.get(f"/v1/agents/{aid}").json()["trust"]["certifications"] == []
    runs = client.get(f"/v1/admin/listings/{aid}/verification-runs", headers=admin_headers()).json()
    assert runs["runs"][0]["kind"] == "change_recheck" and "card_changed" in runs["review_flags"]


def test_jwks_change_with_passing_recheck_accepts_new_baseline(client, seller, fetcher, runner):
    aid, headers = seller
    cert = certify(client, aid, headers)
    fetcher.routes[JWKS_URL] = (200, jwks("b"))
    out = run_monitor(client)
    assert out["changes"] == {aid: ["jwks_changed"]} and out["rechecks"] == {aid: "pass"}
    assert client.get(cert["status_url"]).json()["status"] == "active"
    runs = client.get(f"/v1/admin/listings/{aid}/verification-runs", headers=admin_headers()).json()
    assert runs["review_flags"] == []
    assert run_monitor(client)["changes"] == {}  # new JWKS is the baseline now


def test_inconclusive_recheck_does_not_suspend(client, seller, runner):
    aid, headers = seller
    cert = certify(client, aid, headers)
    make_due(client, aid)
    runner.verdicts[CARD_URL] = "incomplete"
    assert run_monitor(client)["rechecks"] == {aid: "incomplete"}
    assert client.get(cert["status_url"]).json()["status"] == "active"
    runs = client.get(f"/v1/admin/listings/{aid}/verification-runs", headers=admin_headers()).json()
    assert "recheck_inconclusive" in runs["review_flags"]


def test_jwks_on_foreign_host_is_not_followed(client, op, fetcher):
    fetcher.routes[CARD_URL] = (200, card(jwks_uri="https://attacker.example.org/jwks.json"))
    _, headers = op
    aid = client.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
    verify_listing(client, fetcher, "agents", aid, headers)
    certify(client, aid, headers)
    run_monitor(client)
    assert not any("attacker" in c for c in fetcher.calls)


def test_vantage_observation_mismatch_flags_cloaking(client, seller):
    aid, headers = seller
    certify(client, aid, headers)
    run_monitor(client)
    r = client.post("/v1/admin/verification/observations", headers=admin_headers(),
                    json={"listing_id": aid, "vantage": "eu-west-probe", "card_sha256": "f" * 64})
    assert r.status_code == 201 and r.json()["mismatch"] == ["card"]
    runs = client.get(f"/v1/admin/listings/{aid}/verification-runs", headers=admin_headers()).json()
    assert "cloaking_suspected" in runs["review_flags"]
    assert client.post("/v1/admin/verification/observations", headers=headers,
                       json={"listing_id": aid, "vantage": "x"}).status_code == 403


def test_expiry_is_logged_and_signed(client, seller):
    aid, headers = seller
    cert = certify(client, aid, headers)
    from onaa_registry.models import Certification
    with client.app.state.sessionmaker() as s:
        s.get(Certification, cert["id"]).expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        s.commit()
    assert run_monitor(client)["expired"] == [cert["id"]]
    assert client.get(cert["status_url"]).json()["status"] == "expired"
    events = [e["entry"]["event"] for e in client.get("/v1/transparency/entries").json()["entries"]]
    assert events == ["issue", "expire"]


# ------------------------------------------------------------------ configuration gates (real issuance stays gated)


def test_non_test_signing_key_is_refused(settings, fetcher, txt):
    real = json.dumps(jose.private_jwk(jose.derive_test_only_key("x"), "prod-att-1"))
    with pytest.raises(TrustConfigError):
        create_app(replace(settings, attestation_signing_jwk=real), fetcher, txt)
    with pytest.raises(TrustConfigError):
        create_app(replace(settings, issuer_manifest=None), fetcher, txt)
    # A key that is not listed for its purpose in the manifest is refused too.
    with pytest.raises(TrustConfigError):
        create_app(replace(settings, attestation_signing_jwk=settings.status_signing_jwk), fetcher, txt)


def test_without_keys_certification_still_works_unsigned(settings, fetcher, txt, runner):
    s = replace(settings, attestation_signing_jwk=None, status_signing_jwk=None, log_signing_jwk=None,
                issuer_manifest=None)
    with TestClient(create_app(s, fetcher, txt, runner)) as c:
        from conftest import make_operator
        _, headers = make_operator(c)
        fetcher.routes[CARD_URL] = (200, card())
        aid = c.post("/v1/agents", json=AGENT, headers=headers).json()["id"]
        verify_listing(c, fetcher, "agents", aid, headers)
        cert = certify(c, aid, headers)
        assert cert["attestation_url"] is None
        assert c.get("/v1/transparency/checkpoint").status_code == 503
        assert c.get("/v1/transparency/entries").json()["tree_size"] == 1
        assert c.get("/.well-known/onaa/issuer-jwks.json").status_code == 404
        assert c.get("/v1/attestations", params={"subject_id": aid}).json()["attestations"] == []
