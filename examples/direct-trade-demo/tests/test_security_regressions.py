"""Regression tests for the security review of the demo agents (ONAA Protocol v0.1.1 errata).

Each test replays one reviewed attack (PoC1-PoC9 plus the low findings) against the SAMPLE agents and
asserts that it no longer works. Library-level attacks are in
packages/onaa-protocol/tests/test_security_errata.py.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from onaa_protocol import EXTENSION_URI, Signer, StaticKeyResolver, new_envelope, public_message
from onaa_protocol.conformance import run_live
from onaa_protocol.envelope import extract_envelope, parse_ts, utcnow
from starlette.testclient import TestClient

import onaa_demo.a2a as demo_a2a
import onaa_demo.seller as seller_mod
from onaa_demo import a2a
from onaa_demo.buyer import BuyerAgent, BuyerNode
from onaa_demo.demo import bind_ephemeral, serve
from onaa_demo.mock_escrow import MockEscrow
from onaa_demo.registry_client import RegistryClient
from onaa_demo.seller import SellerAgent

CARD = a2a.AGENT_CARD_PATH


def _send_http(http: httpx.Client, base_url: str, env: dict) -> dict:
    msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], extensions=[EXTENSION_URI])
    return extract_envelope(a2a.send_message(http, base_url + "/a2a/v1", msg, extensions=[EXTENSION_URI]))


def _send(agent, env: dict) -> dict:
    return extract_envelope(agent.handle(a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)])))


def _trade(net, http):
    return BuyerAgent(RegistryClient(net.registry_url, client=http), net.buyer, http_client=http).run()


@pytest.fixture
def parties():
    buyer, seller, escrow = BuyerNode("http://127.0.0.1:7"), SellerAgent("http://127.0.0.1:8"), MockEscrow(
        "http://127.0.0.1:9")
    keys = StaticKeyResolver({n.sender["agent_card_url"]: n.jwks() for n in (buyer, seller, escrow)})
    for n in (buyer, seller, escrow):
        n.keys = keys
    return buyer, seller, escrow


# ------------------------------------------------------------------ PoC1 (H1) spoofed ORDER_STATUS


def test_poc1_unsigned_order_status_cannot_cancel_a_confirmed_order(network):
    with httpx.Client(timeout=10) as http:
        res = _trade(network, http)
        oid = res.order["id"]
        ledger = network.seller.ledgers[res.rfq["id"]]
        spoof = new_envelope("ORDER_STATUS", {"order_id": oid, "state": "CANCELLED"},
                             sender=res.handoff_request["sender"])
        reply = _send_http(http, network.seller.base_url, spoof)
    assert (reply["type"], reply["body"]["code"]) == ("REJECT", "signer_mismatch")
    assert ledger.orders[oid].state == "CONFIRMED"


# ------------------------------------------------------------------ PoC2 (M1) backdated order


def test_poc2_backdated_order_cannot_accept_an_expired_quote(network, monkeypatch):
    monkeypatch.setattr(seller_mod.SellerAgent._env, "__defaults__", (timedelta(seconds=2), True))
    b = network.buyer
    with httpx.Client(timeout=10) as http:
        t0 = utcnow()
        rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                           sender=b.sender, recipient=network.seller.sender)
        q = _send_http(http, network.seller.base_url, rfq)
        time.sleep(3)
        assert utcnow() >= parse_ts(q["expires_at"], "expires_at")
        qb = q["body"]
        body = {"quote_id": q["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
                "rfq_id": rfq["id"], "buyer_agent_id": b.agent_id, "seller_agent_id": qb["seller_agent_id"],
                "currency": "USD", "total_minor": qb["total_minor"]}
        back = new_envelope("ORDER_PROPOSE", body, sender=b.sender, recipient=q["sender"], signer=b.signer, now=t0,
                            ttl=timedelta(hours=1))
        r = _send_http(http, network.seller.base_url, back)
    assert (r["type"], r["body"]["code"]) == ("REJECT", "quote_expired")


# ------------------------------------------------------------------ PoC4 (H3) slow-drip key fetch


class _Drip(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            for _ in range(12):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(1)
            self.wfile.write(b"{}")
        except OSError:
            pass


def test_poc4_slow_drip_signer_card_does_not_freeze_the_agent(network):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Drip)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    evil_card = f"http://127.0.0.1:{srv.server_address[1]}{CARD}"
    network.seller.keys.fetch_deadline = 2.0
    env = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                       sender={"agent_id": "evil", "agent_card_url": evil_card}, recipient=network.seller.sender,
                       signer=Signer(Ed25519PrivateKey.generate(), "k1"))
    out: dict = {}

    def attack():
        with httpx.Client(timeout=60) as c:
            t = time.monotonic()
            out["reply"] = _send_http(c, network.seller.base_url, env)
            out["secs"] = time.monotonic() - t
    th = threading.Thread(target=attack)
    try:
        th.start()
        time.sleep(0.5)
        t = time.monotonic()
        httpx.get(network.seller.base_url + CARD, timeout=10)
        unrelated = time.monotonic() - t
        th.join(30)
    finally:
        srv.shutdown()
    assert unrelated < 1.0, unrelated                      # event loop not blocked by the key fetch
    assert out["secs"] < 5.0, out                           # total deadline, not per-read timeout
    assert out["reply"]["body"]["code"] == "jwks_unavailable"


# ------------------------------------------------------------------ PoC5 (M4) DNS oracle


def test_poc5_reject_does_not_leak_internal_dns():
    internal = {"db.corp.internal": ["10.20.30.40"], "metadata.google.internal": ["169.254.169.254"]}
    seller = SellerAgent("https://seller.example.com", allow_localhost=False, resolver=lambda h, p: internal[h])
    for host in internal:
        env = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                           sender={"agent_id": "x", "agent_card_url": f"https://{host}{CARD}"},
                           recipient=seller.sender, signer=Signer(Ed25519PrivateKey.generate(), "k"))
        body = _send(seller, env)["body"]
        assert body == {"code": "jwks_unavailable", "message": public_message("jwks_unavailable")}
        assert host not in json.dumps(body) and internal[host][0] not in json.dumps(body)


# ------------------------------------------------------------------ PoC6 (M2, L1) cross-recipient replay


def test_poc6_signed_handoff_cannot_be_replayed_to_another_provider(network):
    sock, url = bind_ephemeral()
    other = MockEscrow(url, agent_id="other-escrow")
    h = serve(other.app(), sock, url)
    try:
        with httpx.Client(timeout=10) as http:
            res = _trade(network, http)
            req = res.handoff_request
            reply = _send_http(http, url, req)
            assert (reply["type"], reply["body"]["code"]) == ("REJECT", "recipient_mismatch")
            assert other.handoffs == {}
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            m = copy.deepcopy(req)
            s = m["signature"]["signature"]
            m["signature"]["signature"] = s[:-1] + alphabet[alphabet.index(s[-1]) ^ 1]
            reply = _send_http(http, network.escrow.base_url, m)  # right recipient, malleated signature
            assert (reply["type"], reply["body"]["code"]) == ("REJECT", "signature_invalid")
    finally:
        h.stop()


# ------------------------------------------------------------------ PoC7 (H4) reused RFQ id


def test_poc7_reused_rfq_id_cannot_wipe_the_deal(network):
    with httpx.Client(timeout=10) as http:
        res = _trade(network, http)
        ctx = json.loads(network.escrow.request_log[0]["body"])["params"]["message"]["contextId"]
        assert ctx == res.rfq["id"]
        evil = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                            sender={"agent_id": "evil", "agent_card_url": "https://evil.example/.well-known/agent-card.json"},
                            id_=ctx)
        r = _send_http(http, network.seller.base_url, evil)
        assert (r["type"], r["body"]["code"]) == ("REJECT", "not_a_party")
        led = network.seller.ledgers[ctx]
        assert led.buyer_id == network.buyer.agent_id and res.order["id"] in led.orders
        cancel = new_envelope("ORDER_CANCEL", {"order_id": res.order["id"], "reason_code": "buyer_request"},
                              sender=network.buyer.sender, recipient=network.seller.sender,
                              signer=network.buyer.signer)
        r = _send_http(http, network.seller.base_url, cancel)
    assert (r["type"], r["body"]["state"]) == ("ORDER_STATUS", "CANCELLED")


def test_reused_rfq_id_by_the_bound_buyer_requires_a_signature(parties):
    buyer, seller, _ = parties
    rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                       sender=buyer.sender, recipient=seller.sender)
    assert _send(seller, rfq)["type"] == "QUOTE"
    again = new_envelope("RFQ", rfq["body"], sender=buyer.sender, recipient=seller.sender, id_=rfq["id"])
    assert _send(seller, again)["body"]["code"] == "signer_mismatch"
    signed = new_envelope("RFQ", rfq["body"], sender=buyer.sender, recipient=seller.sender, id_=rfq["id"],
                          signer=buyer.signer)
    q2 = _send(seller, signed)
    assert q2["type"] == "QUOTE" and q2["body"]["revision"] == 2   # a revision in the same deal, not a reset


# ------------------------------------------------------------------ PoC9 (M5) request body and log


def test_poc9_oversized_bodies_are_refused_before_buffering_and_not_logged(parties):
    _, seller, _ = parties
    client = TestClient(seller.app())
    r = client.post("/a2a/v1", content=b"x" * (2 * 1024 * 1024))
    assert r.json()["error"]["message"] == "request too large"

    def chunks():
        for _ in range(64):
            yield b"x" * 16384
    r = client.post("/a2a/v1", content=chunks())  # chunked: no Content-Length
    assert r.json()["error"]["message"] == "request too large"
    assert sum(len(e["body"]) for e in seller.request_log) == 0
    assert all(e["truncated"] for e in seller.request_log)


def test_request_log_is_bounded(parties, monkeypatch):
    _, seller, _ = parties
    monkeypatch.setattr(demo_a2a, "MAX_REQUEST_LOG", 10)
    client = TestClient(seller.app())
    for _ in range(25):
        client.post("/a2a/v1", content=b"{}")
    assert len(seller.request_log) == 10


@pytest.mark.parametrize("raw", [b"[" * 200_000 + b"]" * 200_000, b'{"jsonrpc":"2.0","jsonrpc":"2.0"}',
                                 b"[" * 80 + b"]" * 80])
def test_hostile_json_is_a_parse_error_not_a_crash(parties, raw):
    _, seller, _ = parties
    r = TestClient(seller.app()).post("/a2a/v1", content=raw[: demo_a2a.MAX_BODY_BYTES])
    assert r.status_code == 200 and r.json()["error"]["code"] in (a2a.PARSE_ERROR, a2a.INVALID_REQUEST)


# ------------------------------------------------------------------ M5 bounded state


def test_seller_deals_are_bounded(parties, monkeypatch):
    buyer, seller, _ = parties
    monkeypatch.setattr(seller_mod, "MAX_LEDGERS", 2)
    ids = []
    for i in range(3):
        rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                           sender={"agent_id": f"b{i}", "agent_card_url": "https://t-buyer.example/.well-known/agent-card.json"},
                           recipient=seller.sender)
        ids.append(rfq["id"])
        assert _send(seller, rfq)["type"] == "QUOTE"
    assert list(seller.ledgers) == ids[1:]          # the oldest quote-only deal was evicted
    for led in seller.ledgers.values():
        led.orders["pinned"] = None                 # every remaining deal has an order: nothing to evict
    rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                       sender={"agent_id": "b9", "agent_card_url": "https://t-buyer.example/.well-known/agent-card.json"},
                       recipient=seller.sender)
    assert _send(seller, rfq)["body"]["code"] == "rate_limited"


def test_mock_escrow_handoffs_are_bounded(parties, monkeypatch):
    import onaa_demo.mock_escrow as escrow_mod

    buyer, _, escrow = parties
    monkeypatch.setattr(escrow_mod, "MAX_HANDOFFS", 0)
    req = new_envelope("SERVICE_HANDOFF_REQUEST", {
        "service_type": "escrow", "mode": "mock", "order_id": "o-1",
        "parties": {"buyer_agent_id": buyer.agent_id, "seller_agent_id": "s"}, "currency": "USD",
        "amount_minor": 1}, sender=buyer.sender, recipient=escrow.sender, signer=buyer.signer)
    assert _send(escrow, req)["body"]["code"] == "rate_limited"


# ------------------------------------------------------------------ L8 atomic replay reservation


def test_l8_concurrent_identical_requests_get_one_reply(parties, monkeypatch):
    buyer, seller, _ = parties
    orig = seller._on_rfq

    def slow(env):
        time.sleep(0.3)
        return orig(env)
    monkeypatch.setattr(seller, "_on_rfq", slow)
    rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                       sender=buyer.sender, recipient=seller.sender)
    replies: list = []
    threads = [threading.Thread(target=lambda: replies.append(_send(seller, copy.deepcopy(rfq))))
               for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [r["type"] for r in replies] == ["QUOTE"] * 3
    assert len({r["id"] for r in replies}) == 1 and len(seller.ledgers) == 1


# ------------------------------------------------------------------ L7 rendering untrusted text


def test_l7_buyer_transcript_escapes_control_characters(network):
    network.stub.records[0]["display_name"] = "Seller\x1b[2J\u202eevil\r\nRESULT: OK"
    with httpx.Client(timeout=10) as http:
        res = _trade(network, http)
    text = "\n".join(res.transcript)
    assert "\x1b" not in text and "\u202e" not in text and "\r" not in text
    assert "Seller\\x1b[2J\\u202eevil\\x0d\\x0aRESULT: OK" in text  # shown escaped, on one line


# ------------------------------------------------------------------ the live suite catches regressions


def test_live_suite_detects_missing_recipient_check(network, monkeypatch):
    from onaa_protocol import check_envelope

    import onaa_demo.node as node_mod

    monkeypatch.setattr(node_mod, "check_envelope",
                        lambda env, keys, *, expected_recipient=None, **kw: check_envelope(env, keys, **kw))
    fails = _fails(run_live(network.escrow.base_url + CARD, "service_provider", allow_loopback=True))
    assert "ONAA-C-MUST-078" in fails, fails


def test_live_suite_detects_pre_errata_status_handling(network, monkeypatch):
    """Emulates the v0.1 ledger: unsigned envelopes bind first-seen, unsigned ORDER_STATUS changes state."""
    from onaa_protocol import state

    def old_bind(self, env):
        s = env["sender"]
        url = s.get("agent_card_url")
        if url and self.cards.setdefault(s["agent_id"], url) != url:
            raise state.SignatureError("signer_mismatch", "sender changed agent_card_url within the deal")
    monkeypatch.setattr(state.TradeLedger, "_bind", old_bind)
    monkeypatch.setattr(state, "is_legacy", lambda env: True)
    fails = _fails(run_live(network.seller.base_url + CARD, "seller_agent", allow_loopback=True))
    assert "ONAA-C-MUST-077" in fails, fails


def _fails(report: dict) -> dict:
    return {r["id"]: r["detail"] for r in report["results"] if r["outcome"] == "fail"}
