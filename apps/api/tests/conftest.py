from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from onaa_registry.config import Settings
from onaa_registry.main import create_app
from onaa_registry.netsafety import FetchResult, validate_public_url

ADMIN = "test-admin-token"


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


@pytest.fixture
def settings():
    if TEST_DB != "sqlite://":
        # Fresh schema per test on a real server DB (e.g. PostgreSQL in CI).
        from onaa_registry.db import Base, make_engine
        eng = make_engine(TEST_DB)
        Base.metadata.drop_all(eng)
        eng.dispose()
    return Settings(database_url=TEST_DB, auto_create_schema=True, require_verification_entitlement=False,
                    admin_token=ADMIN, write_rate_limit_per_minute=0,
                    terms_version="draft-0.2", challenge_ttl_seconds=3600)


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
def client(settings, fetcher, txt):
    with TestClient(create_app(settings, fetcher, txt)) as c:
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
