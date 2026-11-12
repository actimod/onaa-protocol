"""Registry adapter: request shape against the stub, plus an optional contract run against the
real ONAA Registry API (``onaa_registry`` from apps/api), skipped when it is not installed."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import pytest

from onaa_demo.a2a import AGENT_CARD_PATH
from onaa_demo.buyer import BuyerAgent, BuyerNode
from onaa_demo.demo import bind_ephemeral, serve
from onaa_demo.mock_escrow import MockEscrow
from onaa_demo.registry_client import RegistryClient, RegistryError
from onaa_demo.registry_stub import RegistryStub, sample_record
from onaa_demo.seller import SellerAgent


def test_adapter_query_params_and_page_shape(strict_mode):
    seen = []

    def handler(req):
        seen.append(req.url)
        return httpx.Response(200, json={"items": [{"id": "agt_1", "listing_type": "agent", "status": "registered",
                                                    "trust": {}}, {"junk": True}], "total": 2, "limit": 20,
                                         "offset": 0})

    c = RegistryClient("https://registry.example.com", client=httpx.Client(transport=httpx.MockTransport(handler)),
                       resolver=lambda h, p: ["93.184.215.14"])
    items = c.search_agents(role="seller_agent", capability="widgets.sell", region="US", currency="USD")
    assert [i["id"] for i in items] == ["agt_1"]                       # malformed record dropped
    c.search_services(service_type="escrow", region="US", currency="USD")
    assert seen[0].path == "/v1/agents"
    assert dict(seen[0].params) == {"role": "seller_agent", "capability": "widgets.sell", "region": "US",
                                    "currency": "USD", "limit": "20"}
    assert seen[1].path == "/v1/services" and seen[1].params["type"] == "escrow"


def test_adapter_rejects_bad_shapes(strict_mode):
    def handler(req):
        return httpx.Response(200, json=[{"id": "x"}])                # bare list is not a SearchPage
    c = RegistryClient("https://registry.example.com", client=httpx.Client(transport=httpx.MockTransport(handler)),
                       resolver=lambda h, p: ["93.184.215.14"])
    with pytest.raises(RegistryError):
        c.search_agents()
    with pytest.raises(Exception, match="https|plain http|loopback"):
        RegistryClient("http://registry.example.com", resolver=lambda h, p: ["93.184.215.14"])


def test_stub_filters_like_registry_api():
    stub = RegistryStub([
        sample_record(id_="agt_a", listing_type="agent", display_name="A", roles=["seller_agent"],
                      agent_card_url="https://a.example.com" + AGENT_CARD_PATH, endpoint_url=None,
                      capabilities=["widgets.sell"], regions=["DE"], currencies=["EUR"]),
        sample_record(id_="svc_e", listing_type="service", service_type="escrow", display_name="E",
                      roles=["service_provider"], agent_card_url=None, endpoint_url="https://e.example.com/",
                      capabilities=[], regions=["GLOBAL"], currencies=["USD"]),
    ])
    from starlette.testclient import TestClient
    with TestClient(stub.app) as c:
        assert c.get("/v1/agents", params={"region": "us"}).json()["total"] == 0
        page = c.get("/v1/agents", params={"region": "DE", "currency": "eur", "role": "seller_agent"}).json()
        assert set(page) == {"items", "total", "limit", "offset"} and page["total"] == 1
        assert c.get("/v1/services", params={"type": "escrow", "region": "US"}).json()["total"] == 1  # GLOBAL
        assert c.get("/v1/agents", params={"type": "escrow"}).json()["total"] == 1   # type ignored for agents
        assert c.post("/v1/relay", json={"x": 1}).status_code == 404
    assert stub.request_log[-1]["method"] == "POST"


# ------------------------------------------------------------ optional: real apps/api

class _RouteToLocal(httpx.BaseTransport):
    """Test-only: map public demo hostnames to local servers (no DNS, no internet)."""

    def __init__(self, routes: dict[str, str]):
        self.routes = routes
        self.inner = httpx.HTTPTransport()

    def handle_request(self, request):
        target = self.routes.get(request.url.host)
        if target:
            t = urlsplit(target)
            request.url = request.url.copy_with(scheme=t.scheme, host=t.hostname, port=t.port)
        return self.inner.handle_request(request)


def test_contract_against_real_registry_api(strict_mode):
    pytest.importorskip("onaa_registry", reason="apps/api (onaa_registry) not installed")
    from onaa_registry.config import Settings
    from onaa_registry.main import create_app

    b_host, s_host, e_host = "buyer.demo.example.com", "seller.demo.example.com", "escrow.demo.example.com"
    b_sock, b_local = bind_ephemeral()
    s_sock, s_local = bind_ephemeral()
    e_sock, e_local = bind_ephemeral()
    r_sock, r_local = bind_ephemeral()
    # Every agent fetches counterparty cards/JWKS under the strict (non-demo) SSRF policy: https + public IP
    # via an injected resolver, routed to local servers by a test-only transport.
    routes = {b_host: b_local, s_host: s_local, e_host: e_local}
    agent_http = httpx.Client(transport=_RouteToLocal(routes), timeout=10)
    strict = {"http_client": agent_http, "allow_localhost": False, "resolver": lambda h, p: ["93.184.215.14"]}
    buyer_node = BuyerNode(f"https://{b_host}", **strict)
    seller = SellerAgent(f"https://{s_host}", **strict)
    escrow = MockEscrow(f"https://{e_host}", **strict)
    settings = Settings(database_url="sqlite://", admin_token=None, write_rate_limit_per_minute=0,
                        terms_version="draft-0.2", challenge_ttl_seconds=3600)
    handles = [serve(buyer_node.app(), b_sock, b_local), serve(seller.app(), s_sock, s_local),
               serve(escrow.app(), e_sock, e_local),
               serve(create_app(settings), r_sock, r_local)]
    try:
        with httpx.Client(timeout=10) as admin:
            op = admin.post(r_local + "/v1/operators", json={
                "display_name": "Demo Sample Operator", "operator_type": "organization", "country": "US",
                "accept_terms_version": "draft-0.2"})
            assert op.status_code == 201, op.text
            auth = {"Authorization": "Bearer " + op.json()["api_key"]}   # in-memory only, never logged
            r = admin.post(r_local + "/v1/agents", headers=auth, json={
                "display_name": "ONAA Sample Seller Agent", "roles": ["seller_agent"],
                "agent_card_url": f"https://{s_host}{AGENT_CARD_PATH}", "endpoint_url": f"https://{s_host}/a2a/v1",
                "capabilities": ["widgets.sell"], "regions": ["US"], "currencies": ["USD"],
                "supported_protocols": ["a2a"]})
            assert r.status_code == 201, r.text
            r = admin.post(r_local + "/v1/services", headers=auth, json={
                "display_name": "ONAA MOCK Escrow (no real funds)", "service_type": "escrow",
                "endpoint_url": f"https://{e_host}/a2a/v1", "agent_card_url": f"https://{e_host}{AGENT_CARD_PATH}",
                "sandbox_available": True, "supported_interfaces": [{"kind": "a2a", "url": f"https://{e_host}/a2a/v1"}],
                "capabilities": ["escrow.mock"], "regions": ["GLOBAL"], "currencies": ["USD"]})
            assert r.status_code == 201, r.text

        with httpx.Client(timeout=10) as reg_http:
            registry = RegistryClient(r_local, client=reg_http, allow_localhost=True)
            buyer = BuyerAgent(registry, buyer_node, **strict)
            result = buyer.run()
        assert result.seller_record["trust"]["registration_status"] == "registered"
        assert result.escrow_ack["body"]["mock"] is True
        assert result.order_confirm["type"] == "ORDER_CONFIRM"
        assert len(seller.request_log) == 2 and len(escrow.request_log) == 2
    finally:
        for h in handles:
            h.stop()
        agent_http.close()
