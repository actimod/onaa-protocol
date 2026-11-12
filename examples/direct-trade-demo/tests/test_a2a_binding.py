"""A2A 1.0 JSON-RPC subset: method names, headers, error codes, Agent Card shape."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from onaa_demo import a2a
from onaa_demo.commerce import EXTENSION_URI, new_envelope
from onaa_demo.seller import SellerAgent

BASE = "http://127.0.0.1:9"


@pytest.fixture
def seller_client():
    seller = SellerAgent(BASE)
    with TestClient(seller.app(), base_url=BASE) as c:
        yield c


def _rfq_msg(**overrides):
    env = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 2}], "currency": "USD"},
                       sender={"agent_id": "t-buyer"})
    msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], extensions=[EXTENSION_URI])
    msg.update(overrides)
    return msg


def _rpc(method="SendMessage", message=None):
    return {"jsonrpc": "2.0", "id": "1", "method": method, "params": {"message": message or _rfq_msg()}}


HDRS = {"A2A-Version": "1.0", "A2A-Extensions": EXTENSION_URI}


def test_agent_card_well_known_and_required_fields(seller_client):
    r = seller_client.get("/.well-known/agent-card.json")
    assert r.status_code == 200
    card = a2a.validate_agent_card(r.json())
    for key in ("name", "description", "supportedInterfaces", "version", "capabilities",
                "defaultInputModes", "defaultOutputModes", "skills"):
        assert key in card
    iface = card["supportedInterfaces"][0]
    assert iface == {"url": BASE + "/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    assert EXTENSION_URI in a2a.card_extension_uris(card)
    assert "kind" not in str(card.keys())


def test_send_message_returns_result_message(seller_client):
    r = seller_client.post("/a2a/v1", json=_rpc(), headers=HDRS)
    body = r.json()
    assert "error" not in body, body
    msg = body["result"]["message"]
    assert msg["role"] == "ROLE_AGENT"
    assert msg["parts"][0]["mediaType"] == "application/json"
    assert msg["parts"][0]["data"]["type"] == "QUOTE"
    assert "kind" not in msg["parts"][0]
    assert r.headers["A2A-Extensions"] == EXTENSION_URI


def test_legacy_0_3_method_name_is_not_found(seller_client):
    r = seller_client.post("/a2a/v1", json=_rpc(method="message/send"), headers=HDRS)
    assert r.json()["error"]["code"] == a2a.METHOD_NOT_FOUND


def test_missing_version_header_means_0_3_and_is_rejected(seller_client):
    r = seller_client.post("/a2a/v1", json=_rpc(), headers={"A2A-Extensions": EXTENSION_URI})
    assert r.json()["error"]["code"] == a2a.VERSION_NOT_SUPPORTED == -32009


def test_required_extension_must_be_declared(seller_client):
    r = seller_client.post("/a2a/v1", json=_rpc(), headers={"A2A-Version": "1.0"})
    err = r.json()["error"]
    assert err["code"] == a2a.EXTENSION_SUPPORT_REQUIRED == -32008
    assert err["data"]["required"] == [EXTENSION_URI]


@pytest.mark.parametrize("bad", [
    {"role": "user"},                                   # 0.3-style lowercase role
    {"parts": [{"kind": "data", "data": {}}]},          # removed kind discriminator
    {"parts": [{"text": "a", "data": {}}]},             # more than one content field
    {"parts": []},
])
def test_invalid_message_shapes(seller_client, bad):
    r = seller_client.post("/a2a/v1", json=_rpc(message=_rfq_msg(**bad)), headers=HDRS)
    assert r.json()["error"]["code"] == a2a.INVALID_PARAMS


def test_parse_error(seller_client):
    r = seller_client.post("/a2a/v1", content=b"{not json", headers=HDRS)
    assert r.json()["error"]["code"] == a2a.PARSE_ERROR


def test_card_validation_rejects_missing_interface():
    card = SellerAgent(BASE).card
    bad = {k: v for k, v in card.items() if k != "supportedInterfaces"}
    with pytest.raises(a2a.AgentCardError):
        a2a.validate_agent_card(bad)
    grpc_only = dict(card, supportedInterfaces=[{"url": "x", "protocolBinding": "GRPC", "protocolVersion": "1.0"}])
    with pytest.raises(a2a.AgentCardError):
        a2a.select_jsonrpc_interface(grpc_only)
