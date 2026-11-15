from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))

from fakes import FakeAgent, HostRouter, public_resolver  # noqa: E402
from onaa_registry.config import Settings  # noqa: E402
from onaa_registry.main import create_app  # noqa: E402
from onaa_registry.netsafety import FetchResult  # noqa: E402

from onaa_steward.activity import ActivityLog  # noqa: E402
from onaa_steward.diagnostics import Diagnoser  # noqa: E402
from onaa_steward.probe import Prober  # noqa: E402
from onaa_steward.registry_port import RegistryPort  # noqa: E402
from onaa_steward.steward import Steward  # noqa: E402

ADMIN, STEWARD = "admin-test", "steward-test"


class NoNetFetcher:
    def fetch(self, url, *, allow_redirects=True):
        return FetchResult(url, 404, b"", "text/plain", 1)


@pytest.fixture
def registry():
    s = Settings(database_url="sqlite://", auto_create_schema=True, require_verification_entitlement=False,
                 admin_token=ADMIN, steward_token=STEWARD, write_rate_limit_per_minute=0, terms_version="draft-0.2")
    with TestClient(create_app(s, NoNetFetcher())) as c:
        yield c


@pytest.fixture
def seller():
    return FakeAgent("seller.example.com", "Example Parts Seller")


@pytest.fixture
def buyer():
    return FakeAgent("buyer.example.org", "Example Procurement Buyer", ops_channel=False)


@pytest.fixture
def net(seller, buyer):
    return HostRouter({seller.host: seller.app, buyer.host: buyer.app})


@pytest.fixture
def steward(registry, net):
    out = net.client()
    return Steward(RegistryPort(registry, STEWARD), Prober(out, resolver=public_resolver),
                   Diagnoser(out, resolver=public_resolver), ActivityLog(), confirm_delay=0, min_check_interval=0)


def register(registry, agent: FakeAgent, role: str, capabilities: list[str]) -> str:
    r = registry.post("/v1/operators", json={"display_name": f"{agent.name} Ltd", "operator_type": "organization",
                                             "country": "US", "accept_terms_version": "draft-0.2"})
    h = {"Authorization": f"Bearer {r.json()['api_key']}"}
    r = registry.post("/v1/agents", headers=h, json={
        "display_name": agent.name, "description": f"{agent.name} for tests", "roles": [role],
        "agent_card_url": f"{agent.base}/.well-known/agent-card.json", "endpoint_url": f"{agent.base}/a2a/v1",
        "supported_protocols": ["a2a-1.0"], "capabilities": capabilities, "regions": ["GLOBAL"]})
    assert r.status_code == 201, r.text
    return r.json()["id"]
