"""Contract tests: SDK against the real Registry app in-process (no network).

Requires the registry package: pip install -e ../../apps/api -e '.[dev]'
"""

from __future__ import annotations

import pytest

registry = pytest.importorskip("onaa_registry.main")
from fastapi.testclient import TestClient  # noqa: E402
from onaa_registry.config import Settings  # noqa: E402
from onaa_registry.netsafety import FetchResult  # noqa: E402

from onaa import OnaaClient, OnaaError  # noqa: E402

CARD = "https://seller.example.com/.well-known/agent-card.json"


class FakeFetcher:
    def __init__(self):
        self.routes = {}

    def fetch(self, url, *, allow_redirects=True):
        status, body = self.routes.get(url, (404, "missing"))
        return FetchResult(url, status, body.encode(), "text/plain", 1)


@pytest.fixture
def env():
    fetcher, txt = FakeFetcher(), {}
    settings = Settings(database_url="sqlite://", admin_token="adm", write_rate_limit_per_minute=0,
                        operator_write_limit_per_minute=0, auto_create_schema=True,
                        require_verification_entitlement=False)
    app = registry.create_app(settings, fetcher, lambda name: txt.get(name, []))
    with TestClient(app) as http:
        yield OnaaClient("http://testserver", http_client=http), fetcher, txt, http


def _seller(reg: OnaaClient) -> dict:
    reg.create_operator("Acme Parts", "organization", accept_terms_version="draft-0.1", country="US")
    return reg.register_agent(display_name="Acme Parts Seller", roles=["seller_agent"], agent_card_url=CARD,
                              capabilities=["commerce.quote.issue"], regions=["US"], currencies=["USD"],
                              supported_protocols=["a2a-1.x"])


def test_register_search_verify_flow(env):
    reg, fetcher, _, _ = env
    assert reg.health()["status"] == "ok"
    agent = _seller(reg)
    assert agent["status"] == "registered" and reg.api_key.startswith("onaa_sk_")

    page = reg.search_agents(role="seller_agent", capability="commerce.quote.issue", region="US")
    assert page.total == 1 and page.items[0]["id"] == agent["id"]
    assert reg.search_agents(verified_only=True).total == 0

    chl = reg.start_verification("agents", agent["id"])
    with pytest.raises(OnaaError) as ei:
        reg.complete_verification("agents", agent["id"], chl["challenge_id"])
    assert ei.value.status_code == 422 and ei.value.body["error"] == "http_404"
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"])
    assert reg.complete_verification("agents", agent["id"], chl["challenge_id"])["endpoint_control_verified"]
    assert reg.trust("agents", agent["id"])["endpoint_control_verified"] is True
    assert reg.search_agents(verified_only=True).total == 1


def test_dns_txt_and_services(env):
    reg, _, txt, _ = env
    reg.create_operator("Escrow Co", "organization", accept_terms_version="draft-0.1")
    svc = reg.register_service(display_name="Sandbox Escrow", service_type="escrow",
                               endpoint_url="https://api.escrow.example.net/v1", regions=["US"], currencies=["USD"],
                               sandbox_available=True)
    chl = reg.start_verification("services", svc["id"], method="dns_txt")
    txt[chl["dns_record_name"]] = [chl["token"]]
    reg.complete_verification("services", svc["id"], chl["challenge_id"])
    found = reg.search_services(type="escrow", region="US", currency="USD", verified_only=True)
    assert [s["id"] for s in found.items] == [svc["id"]]


def test_update_delete_and_errors(env):
    reg, _, _, http = env
    agent = _seller(reg)
    assert reg.update("agents", agent["id"], regions=["US", "KR"])["regions"] == ["KR", "US"]
    other = OnaaClient("http://testserver", http_client=http)
    other.create_operator("Other", "individual", accept_terms_version="draft-0.1")
    with pytest.raises(OnaaError) as ei:
        other.delete("agents", agent["id"])
    assert ei.value.status_code == 403
    reg.delete("agents", agent["id"])
    with pytest.raises(OnaaError) as ei:
        reg.get("agents", agent["id"])
    assert ei.value.status_code == 410


def test_iter_search_paginates(env):
    reg, _, _, _ = env
    reg.create_operator("Many", "organization", accept_terms_version="draft-0.1")
    for i in range(5):
        reg.register_agent(display_name=f"Agent {i}", roles=["buyer_agent"],
                           agent_card_url=f"https://a{i}.example.com/.well-known/agent-card.json")
    assert len(list(reg.iter_search("agents", page_size=2))) == 5
    assert len(list(reg.iter_search("agents", page_size=2, max_items=3))) == 3


def test_certification_and_report(env):
    reg, fetcher, _, _ = env
    agent = _seller(reg)
    chl = reg.start_verification("agents", agent["id"])
    fetcher.routes[chl["challenge_url"]] = (200, chl["token"])
    reg.complete_verification("agents", agent["id"], chl["challenge_id"])
    app_ = reg.apply_certification(agent["id"], "protocol_certified")
    assert reg.get_certification_application(app_["id"])["status"] == "submitted"
    anon = OnaaClient("http://testserver", http_client=env[3])
    assert anon.report(agent["id"], "spam", "test report")["state"] == "received"


def test_agent_self_registers_in_one_call(env):
    reg, fetcher, txt, _ = env
    assert reg.api_key is None
    published = []

    def publish(chl):
        published.append(chl)
        fetcher.routes[chl["challenge_url"]] = (200, chl["token"])

    out = reg.self_register({"display_name": "Self Seller", "roles": ["seller_agent"], "agent_card_url": CARD,
                             "capabilities": ["commerce.quote.issue"]}, publish)
    assert published and out["operator"]["operator_type"] == "agent"
    assert reg.api_key == out["api_key"]
    assert out["listing"]["trust"]["registration_method"] == "agent_self_registration"
    assert out["listing"]["trust"]["endpoint_control_verified"] is False
    assert reg.me()["operator_type"] == "agent"
    assert reg.update_profile(operator_type="organization", display_name="Self Seller Ltd")["operator_type"] == \
        "organization"


def test_self_register_retries_then_fails(env):
    reg, _, txt, _ = env
    with pytest.raises(OnaaError) as ei:
        reg.self_register({"display_name": "X", "roles": ["seller_agent"], "agent_card_url": CARD},
                          lambda chl: None, method="dns_txt", attempts=2, retry_delay=0)
    assert ei.value.status_code == 422 and ei.value.body["error"] == "txt_record_not_found"
    assert reg.api_key is None
