"""ONAA Hosting (pilot): hosted A2A addresses for pilot members, inbound and outbound, over ONAA Protocol v0.1."""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta

import httpx
import pytest
from conftest import ADMIN, ITEM_REQUIRED
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from onaa_protocol import (
    EXTENSION_URI,
    Signer,
    StaticKeyResolver,
    check_envelope,
    extract_envelope,
    new_envelope,
)
from onaa_protocol import a2a as pa2a

from onaa_registry import hosting
from onaa_registry.main import create_app

A = {"Authorization": f"Bearer {ADMIN}"}
DOMAIN = "agents.test"
BUYER_CARD = "https://buyer.example/.well-known/agent-card.json"
SELLER_CARD = "https://seller.example/.well-known/agent-card.json"


class Peer:
    """An external ONAA v0.1 agent (not hosted by ONAA)."""

    def __init__(self, card_url: str, agent_id: str):
        self.signer = Signer(Ed25519PrivateKey.generate(), agent_id + "-k1")
        self.me = {"agent_id": agent_id, "agent_card_url": card_url}

    def jwks(self):
        return {"keys": [self.signer.public_jwk()]}


@pytest.fixture
def env(settings, fetcher, txt, runner):
    s = dataclasses.replace(settings, pilot_enabled=True, hosting_domain=DOMAIN, hosting_scheme="http",
                            hosted_agent_secret="test-only-hosted-agent-secret-0123456789")
    buyer, seller = Peer(BUYER_CARD, "ext-buyer"), Peer(SELLER_CARD, "ext-seller")
    with TestClient(create_app(s, fetcher, txt, runner)) as c:
        state = c.app.state
        state.hosting = hosting.Runtime(
            s, state.sessionmaker, http=httpx.Client(transport=httpx.MockTransport(fake_seller(seller, s))),
            resolver=lambda host, port: ["93.184.216.34"],
            remote_keys=StaticKeyResolver({BUYER_CARD: buyer.jwks(), SELLER_CARD: seller.jwks()}))
        yield c, buyer, seller


def member(c, nick, contact, a2a=True):
    r = c.post("/v1/admin/market/members", headers=A,
               json={"nickname": nick, "contact": contact, "region": "Seoul Mapo", "a2a_enabled": a2a})
    assert r.status_code == 201, r.text
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    return h, c.get("/v1/market/agent", headers=h).json()


def host_of(agent):
    return agent["address"].split("://", 1)[1]


def send(c, agent, env_):
    msg = pa2a.make_message(pa2a.ROLE_USER, [pa2a.data_part(env_)], context_id=env_["id"], extensions=[EXTENSION_URI])
    r = c.post("/a2a/v1", headers={"Host": host_of(agent), "A2A-Version": "1.0", "A2A-Extensions": EXTENSION_URI},
               json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}})
    assert r.status_code == 200, r.text
    return extract_envelope(r.json()["result"]["message"])


def fake_seller(peer: Peer, settings):
    """An external seller agent behind httpx.MockTransport: card + RFQ -> QUOTE + ORDER_PROPOSE -> ORDER_CONFIRM."""
    from onaa_protocol import TradeLedger, build_extension_params, extension_declaration, order_terms_hash

    hosted_keys = hosting.HostedKeys(settings, None)
    ledgers: dict[str, TradeLedger] = {}
    card = {"name": "ext seller", "description": "x", "version": "1", "skills": [],
            "supportedInterfaces": [{"url": "https://seller.example/a2a/v1", "protocolBinding": "JSONRPC",
                                     "protocolVersion": "1.0"}],
            "capabilities": {"extensions": [extension_declaration(build_extension_params(
                roles=["seller_agent"], jwks_uri="https://seller.example/.well-known/onaa/jwks.json"))]},
            "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json"]}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/.well-known/agent-card.json":
            return httpx.Response(200, json=card)
        body = json.loads(request.content)
        env_ = extract_envelope(body["params"]["message"])
        check_envelope(env_, hosted_keys, expected_recipient=peer.me)
        if env_["type"] == "RFQ":
            led = ledgers.setdefault(env_["id"], TradeLedger())
            led.apply(env_)
            price = 900 if env_["body"].get("max_total_minor", 1000) >= 900 else 1000
            out = new_envelope("QUOTE", {
                "rfq_id": env_["id"], "seller_agent_id": peer.me["agent_id"],
                "buyer_agent_id": env_["sender"]["agent_id"],
                "currency": "USD", "total_minor": price,
                "line_items": [{"sku": "w", "quantity": 1, "unit_price_minor": price, "line_total_minor": price}]},
                sender=peer.me, recipient=env_["sender"], in_reply_to=env_["id"], signer=peer.signer)
        else:
            led = ledgers[env_["body"]["rfq_id"]]
            out = new_envelope("ORDER_CONFIRM", {
                "order_id": env_["id"], "order_terms_hash": order_terms_hash(env_["body"]),
                "quote_id": env_["body"]["quote_id"], "state": "CONFIRMED"},
                sender=peer.me, recipient=env_["sender"], in_reply_to=env_["id"], signer=peer.signer,
                ttl=timedelta(hours=1))
        led.apply(env_)
        led.apply(out)
        msg = pa2a.make_message(pa2a.ROLE_AGENT, [pa2a.data_part(out)], extensions=[EXTENSION_URI])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"message": msg}})
    return handler


def test_card_jwks_catalog_and_registry_listing(env):
    c, _, _ = env
    h, agent = member(c, "jun", "kakao:jun")
    assert agent["terms"]["url"].endswith("/member-terms") and agent["terms"]["version"]  # always the terms link
    c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED,
        "title": "iPad Air 4", "price": 350000, "floor_price": 300000,
                                               "currency": "KRW"})
    card = c.get("/.well-known/agent-card.json", headers={"Host": host_of(agent)})
    assert card.status_code == 200
    card = card.json()
    assert card["supportedInterfaces"][0]["url"] == agent["address"] + "/a2a/v1"
    assert "ONAA Hosting" in card["provider"]["organization"]
    jwks = c.get("/.well-known/onaa/jwks.json", headers={"Host": host_of(agent)}).json()
    assert jwks["keys"][0]["kid"].endswith("-k1") and "d" not in jwks["keys"][0]
    cat = c.get("/.well-known/onaa/catalog.json", headers={"Host": host_of(agent)}).json()
    assert cat["items"][0]["unit_price_minor"] == 350000 and "floor" not in json.dumps(cat)
    assert "contact" not in json.dumps(cat) and "kakao" not in json.dumps(card)
    # listed in the directory as a registered (not discovered) agent, found by buyers
    found = c.get("/v1/agents", params={"q": "iPad", "role": "seller_agent"}).json()["items"]
    rec = next(r for r in found if r["agent_card_url"] == agent["agent_card_url"])
    assert rec["trust"]["registration_method"] == "onaa_hosting" and rec["trust"]["level"] == "operator_registered"
    # unknown or disabled member hosts answer 404; the registry API is not served there
    assert c.get("/.well-known/agent-card.json", headers={"Host": f"pm-{'0' * 24}.{DOMAIN}"}).status_code == 404
    assert c.get("/v1/agents", headers={"Host": host_of(agent)}).status_code == 404
    c.patch("/v1/market/agent", headers=h, json={"a2a_enabled": False})
    assert c.get("/.well-known/agent-card.json", headers={"Host": host_of(agent)}).status_code == 404
    assert all(r["agent_card_url"] != agent["agent_card_url"]
               for r in c.get("/v1/agents", params={"q": "iPad"}).json()["items"])


def test_external_buyer_gets_the_listed_price_and_the_member_approves(env):
    c, buyer, _ = env
    h, agent = member(c, "jun", "kakao:jun")
    it = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED, "title": "iPad Air 4", "price": 350000,
                                                     "floor_price": 300000, "currency": "KRW"}).json()
    seller = {"agent_id": agent["agent_id"], "agent_card_url": agent["agent_card_url"]}
    rfq = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "KRW",
                               "max_total_minor": 280000}, sender=buyer.me, recipient=seller, signer=buyer.signer)
    out = send(c, agent, rfq)
    assert out["type"] == "REJECT" and out["body"]["code"] == "over_budget"  # ONAA never lowers the price

    rfq = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "KRW",
                               "max_total_minor": 350000}, sender=buyer.me, recipient=seller, signer=buyer.signer)
    quote = send(c, agent, rfq)
    assert quote["type"] == "QUOTE" and quote["body"]["total_minor"] == 350000, quote["body"]
    keys = StaticKeyResolver({agent["agent_card_url"]: c.get("/.well-known/onaa/jwks.json",
                                                             headers={"Host": host_of(agent)}).json()})
    check_envelope(quote, keys, expected_recipient=buyer.me)  # signed by the member's hosted key
    qb = quote["body"]
    def propose():
        return new_envelope("ORDER_PROPOSE", {
            "quote_id": quote["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
            "rfq_id": rfq["id"], "buyer_agent_id": buyer.me["agent_id"], "seller_agent_id": qb["seller_agent_id"],
            "currency": "KRW", "total_minor": 350000}, sender=buyer.me, recipient=quote["sender"],
            signer=buyer.signer)

    # The member confirms orders personally: first a retryable REJECT, nothing reserved, the order waits.
    pending = send(c, agent, propose())
    assert pending["type"] == "REJECT" and pending["body"] == {
        "code": "awaiting_seller_approval", "retryable": True, "message": pending["body"]["message"]}
    assert c.get(f"/v1/market/items/{it['id']}", headers=h).json()["status"] == "available"
    inbox = c.get("/v1/market/agent/inbox", headers=h).json()
    deal = inbox["deals"][0]
    assert deal["state"] == "order_pending" and deal["pending_order"]["total"] == 350000
    assert send(c, agent, propose())["body"]["code"] == "awaiting_seller_approval"  # retry before approval
    assert c.post(f"/v1/market/agent/deals/{deal['deal_id']}/approve", headers=h,
                  json={"user_approved": True}).json()["state"] == "approved"
    order = propose()
    confirm = send(c, agent, order)
    assert confirm["type"] == "ORDER_CONFIRM", confirm
    check_envelope(confirm, keys, expected_recipient=buyer.me)
    assert c.get(f"/v1/market/items/{it['id']}", headers=h).json()["status"] == "reserved"
    inbox = c.get("/v1/market/agent/inbox", headers=h).json()
    assert inbox["unread"] == 1 and inbox["deals"][0]["state"] == "confirmed" and inbox["deals"][0]["total"] == 350000
    detail = c.get(f"/v1/market/agent/deals/{inbox['deals'][0]['deal_id']}", headers=h).json()
    assert [m["type"] for m in detail["messages"]] == ["RFQ", "QUOTE", "REJECT", "REJECT", "ORDER_PROPOSE",
                                                       "ORDER_CONFIRM"]
    # a second buyer order on the same reserved item is refused
    rfq2 = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "KRW"},
                        sender=buyer.me, recipient=seller, signer=buyer.signer)
    assert send(c, agent, rfq2)["body"]["code"] == "unknown_sku"
    # cancel from the buyer frees the item again
    cancel = new_envelope("ORDER_CANCEL", {"order_id": order["id"], "reason_code": "buyer_request"},
                          sender=buyer.me, recipient=seller,
                          signer=buyer.signer)
    st = send(c, agent, cancel)
    assert st["type"] == "ORDER_STATUS" and st["body"]["state"] == "CANCELLED"
    assert c.get(f"/v1/market/items/{it['id']}", headers=h).json()["status"] == "available"


def test_inbound_refuses_bad_messages(env):
    c, buyer, _ = env
    h, agent = member(c, "jun", "kakao:jun")
    it = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED,
        "title": "Keyboard", "price": 50000, "currency": "KRW"}).json()
    other = {"agent_id": "x", "agent_card_url": "https://other.example/.well-known/agent-card.json"}
    rfq = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "KRW"},
                       sender=buyer.me, recipient=other, signer=buyer.signer)
    assert send(c, agent, rfq)["body"]["code"] == "recipient_mismatch"
    me = {"agent_id": agent["agent_id"], "agent_card_url": agent["agent_card_url"]}
    forged = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "KRW"},
                          sender=buyer.me, recipient=me, signer=Signer(Ed25519PrivateKey.generate(), "ext-buyer-k1"))
    assert send(c, agent, forged)["type"] == "REJECT"
    rfq = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "USD"},
                       sender=buyer.me, recipient=me, signer=buyer.signer)
    assert send(c, agent, rfq)["body"]["code"] == "unsupported_currency"
    r = c.post("/a2a/v1", headers={"Host": host_of(agent), "A2A-Version": "1.0"},
               json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {}}})
    assert r.json()["error"]["code"] == pa2a.EXTENSION_SUPPORT_REQUIRED


def test_members_cannot_send_quote_requests_or_orders(env):
    """Founder 2026-11-19: the old outbound quote path is gone. ONAA sends no RFQ or order for a member; member
    listings are bought with offers, and the member's agent only answers buyers that write to it."""
    c, _, _ = env
    hb, _ = member(c, "buyer", "kakao:buyer1")
    q = {"agent_card_url": SELLER_CARD, "items": [{"sku": "w", "quantity": 1}], "currency": "USD", "max_total": 9}
    assert c.post("/v1/market/agent/quotes", headers=hb, json=q).status_code in (404, 405)
    assert c.get("/v1/market/agent/catalog", headers=hb, params={"agent_card_url": SELLER_CARD}).status_code == 404
    assert c.post("/v1/market/agent/deals/x/accept", headers=hb).status_code in (404, 405)


def test_hosting_off_without_domain(settings, fetcher, txt, runner):
    s = dataclasses.replace(settings, pilot_enabled=True)
    with TestClient(create_app(s, fetcher, txt, runner)) as c:
        h, _ = (lambda r: ({"Authorization": f"Bearer {r['token']}"}, r))(c.post(
            "/v1/admin/market/members", headers=A, json={"nickname": "a", "contact": "b"}).json())
        assert c.get("/v1/market/agent", headers=h).status_code == 404


def test_seller_declines_and_usd_minor_units(env):
    c, buyer, _ = env
    h, agent = member(c, "ann", "signal:ann")
    it = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED,
        "title": "Film camera", "price": 120, "floor_price": 100}).json()
    assert it["currency"] == "USD"
    me = {"agent_id": agent["agent_id"], "agent_card_url": agent["agent_card_url"]}
    rfq = new_envelope("RFQ", {"items": [{"sku": it["id"], "quantity": 1}], "currency": "USD",
                               "max_total_minor": 12000}, sender=buyer.me, recipient=me, signer=buyer.signer)
    quote = send(c, agent, rfq)
    assert quote["body"]["total_minor"] == 12000  # cents
    qb = quote["body"]
    order = new_envelope("ORDER_PROPOSE", {
        "quote_id": quote["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
        "rfq_id": rfq["id"], "buyer_agent_id": buyer.me["agent_id"], "seller_agent_id": qb["seller_agent_id"],
        "currency": "USD", "total_minor": 12000}, sender=buyer.me, recipient=quote["sender"], signer=buyer.signer)
    assert send(c, agent, order)["body"]["code"] == "awaiting_seller_approval"
    deal = c.get("/v1/market/agent/inbox", headers=h).json()["deals"][0]
    assert deal["pending_order"]["total"] == 120.0
    assert c.post(f"/v1/market/agent/deals/{deal['deal_id']}/decline", headers=h).json()["state"] == "declined"
    again = new_envelope("ORDER_PROPOSE", order["body"], sender=buyer.me, recipient=quote["sender"],
                         signer=buyer.signer)
    out = send(c, agent, again)
    assert out["type"] == "ORDER_REJECT" and out["body"]["code"] == "declined_by_seller"
    assert c.post(f"/v1/market/agent/deals/{deal['deal_id']}/approve", headers=h,
                  json={"user_approved": True}).status_code == 409
