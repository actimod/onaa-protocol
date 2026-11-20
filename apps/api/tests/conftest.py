from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from onaa_registry.config import Settings
from onaa_registry.main import create_app
from onaa_registry.netsafety import FetchResult, validate_public_url

ADMIN = "test-admin-token"
STEWARD = "test-steward-token"


class FakeFetcher:
    """Deterministic stand-in for the network. Maps URL -> (status, body) or exception."""

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.calls: list[str] = []
        self.redirect_flags: list[bool] = []

    def fetch(self, url: str, *, allow_redirects: bool = True) -> FetchResult:
        validate_public_url(url)  # same static guard as production
        self.calls.append(url)
        self.redirect_flags.append(allow_redirects)
        r = self.routes.get(url)
        if r is None:
            return FetchResult(url, 404, b"not found", "text/plain", 3)
        if isinstance(r, Exception):
            raise r
        status, body = r
        return FetchResult(url, status, body if isinstance(body, bytes) else body.encode(), "text/plain", 3)


@pytest.fixture
def fetcher():
    return FakeFetcher()


TEST_DB = os.environ.get("ONAA_TEST_DATABASE_URL", "sqlite://")


def staging_trust_material() -> dict:
    """TEST-ONLY issuer keys (derived from public labels) and a root-signed manifest, as the dry-run ceremony
    script produces. Never use these outside tests."""
    import json
    from datetime import timedelta

    from onaa_protocol import jose, transparency, trust
    from onaa_protocol.envelope import utcnow

    now = utcnow()
    root = jose.Signer(jose.derive_test_only_key("registry-root"), "test-root-1")
    signers = {p: jose.Signer(jose.derive_test_only_key("registry-" + p), f"test-{p}-1")
               for p in ("attestation", "status", "log")}
    purposes = {"attestation": jose.TYP_ATTESTATION, "status": jose.TYP_ATTESTATION_STATUS,
                "log": transparency.TYP_CHECKPOINT}
    keys = [trust.manifest_key(s.public_jwk(), purposes[p], not_before=now - timedelta(days=1))
            for p, s in signers.items()]
    manifest = trust.sign_manifest(trust.build_manifest(
        "onaa-registry-staging", keys, issued_at=now - timedelta(hours=1), next_update=now + timedelta(days=30)), root)
    return {"root_jwk": root.public_jwk(), "manifest": manifest,
            **{p: json.dumps(jose.private_jwk(s.private_key, s.kid)) for p, s in signers.items()}}


TRUST = staging_trust_material()


class FakeRunner:
    """Stand-in for the live conformance suite. `verdicts` maps card URL -> verdict (default pass)."""

    def __init__(self):
        self.verdicts: dict[str, str] = {}
        self.calls: list = []

    def __call__(self, req):
        self.calls.append(req)
        v = self.verdicts.get(req.card_url, "pass")
        if v == "raise":
            raise RuntimeError("target misbehaved")
        failed = 1 if v == "fail" else 0
        results = [{"id": "ONAA-C-MUST-001", "outcome": "fail" if failed else "pass"}]
        return {"suite_version": "0.5.0", "results": results,
                "summary": {"verdict": v, "must": {"total": 10, "passed": 10 - failed, "failed": failed, "skipped": 0},
                            "should": {"total": 5, "passed": 5, "failed": 0, "skipped": 0}}}


@pytest.fixture
def runner():
    return FakeRunner()


@pytest.fixture
def settings():
    if TEST_DB != "sqlite://":
        # Fresh schema per test on a real server DB (e.g. PostgreSQL in CI).
        from onaa_registry.db import Base, make_engine
        eng = make_engine(TEST_DB)
        Base.metadata.drop_all(eng)
        eng.dispose()
    return Settings(database_url=TEST_DB, auto_create_schema=True, require_verification_entitlement=False,
                    admin_token=ADMIN, steward_token=STEWARD, write_rate_limit_per_minute=0,
                    terms_version="draft-0.2", challenge_ttl_seconds=3600, precheck_min_interval_seconds=0,
                    attestation_signing_jwk=TRUST["attestation"], status_signing_jwk=TRUST["status"],
                    log_signing_jwk=TRUST["log"], issuer_manifest=json.dumps(TRUST["manifest"]),
                    pilot_webhook_worker_seconds=0)


class FakeTxt:
    def __init__(self):
        self.records: dict[str, object] = {}

    def __call__(self, name: str) -> list[str]:
        r = self.records.get(name, [])
        if isinstance(r, Exception):
            raise r
        return list(r)


@pytest.fixture
def txt():
    return FakeTxt()


@pytest.fixture
def client(settings, fetcher, txt, runner):
    with TestClient(create_app(settings, fetcher, txt, runner)) as c:
        yield c


def make_operator(client, name="Acme Seller Ltd"):
    r = client.post("/v1/operators", json={"display_name": name, "operator_type": "organization",
                                           "country": "US", "accept_terms_version": "draft-0.2"})
    assert r.status_code == 201, r.text
    data = r.json()
    return data["operator"]["id"], {"Authorization": f"Bearer {data['api_key']}"}


@pytest.fixture
def op(client):
    return make_operator(client)


@pytest.fixture
def other_op(client):
    return make_operator(client, "Other Operator")


AGENT = {
    "display_name": "Example Parts Seller",
    "description": "Sells refurbished industrial parts",
    "roles": ["seller_agent"],
    "agent_card_url": "https://seller.example.com/.well-known/agent-card.json",
    "supported_protocols": ["a2a-1.x"],
    "capabilities": ["commerce.rfq.receive", "commerce.quote.issue"],
    "regions": ["US", "KR"],
    "currencies": ["USD", "KRW"],
}

SERVICE = {
    "display_name": "Example Sandbox Escrow",
    "service_type": "escrow",
    "endpoint_url": "https://api.escrow.example.net/v1",
    "capabilities": ["escrow.create", "escrow.get_status"],
    "regions": ["US"],
    "currencies": ["USD"],
    "sandbox_available": True,
    "sandbox_url": "https://sandbox.escrow.example.net/v1",
    "supported_interfaces": [{"kind": "openapi", "spec_url": "https://escrow.example.net/openapi.json"}],
    "terms_url": "https://escrow.example.net/terms",
}


def admin_headers():
    return {"Authorization": f"Bearer {ADMIN}"}


def verify_listing(client, fetcher, kind, listing_id, headers):
    r = client.post(f"/v1/{kind}/{listing_id}/verify-domain", headers=headers)
    assert r.status_code == 201, r.text
    chl = r.json()
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"] + "\n")
    r = client.post(f"/v1/{kind}/{listing_id}/verification-complete", headers=headers,
                    json={"challenge_id": chl["challenge_id"]})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(autouse=True)
def _fresh_store_snapshot(monkeypatch):
    """Store snapshots are module-level and rebuilt lazily; each test starts empty and rebuilds on every change."""
    from onaa_registry import stores

    monkeypatch.setattr(stores, "FEED_MIN_REFRESH_SECONDS", 0)
    stores.reset_snapshot()
    yield
    stores.reset_snapshot()


# Details every new pilot listing must state (founder decision 2026-11-18); tests merge them into item bodies.
ITEM_REQUIRED = {"currency": "USD", "region": "Seoul Mapo", "trade_methods": ["in_person"], "payment_methods": ["cash"],
                 "quantity": 1, "condition": "used_good"}
WANT_REQUIRED = {"max_price": 1000, "currency": "USD", "region": "Seoul Mapo",
                 "trade_methods": ["in_person", "shipping"],
                 "payment_methods": ["cash"], "quantity": 1, "conditions": ["new", "like_new", "used_good"]}


@pytest.fixture(autouse=True)
def _reports_count_fully(monkeypatch):
    """Members made in a test are seconds old, so they would count half as reporters (report_rules). Tests of
    report thresholds count them fully; test_review_decisions sets the real age rule where it tests it."""
    from onaa_registry import report_rules

    monkeypatch.setattr(report_rules, "NEW_ACCOUNT_DAYS", 0)


def loosen(c, headers, body: dict) -> dict:
    """Loosen deal rules as the person does: their yes (user_approved) applies auto confirm inside saved ranges
    at once; anything else returns a confirm link the person opens and confirms (deal_rules / rules_confirm).
    Returns the rules view, with done=True once applied."""
    from urllib.parse import urlsplit

    body = {**body, "user_approved": True}
    r = c.patch("/v1/market/rules", headers=headers, json=body).json()
    if not r.get("confirm_url"):
        return r
    path = urlsplit(r["confirm_url"]).path
    assert c.get(path).status_code == 200
    assert c.post(path).status_code == 200
    return c.get("/v1/market/rules", headers=headers).json() | {"done": True}
