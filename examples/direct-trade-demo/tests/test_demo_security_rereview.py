"""Regression tests for the v0.1.2 security errata against the SAMPLE agents (security re-review of v0.1.1).

Each test replays one re-review finding (N1-N3, L-b, L-c, L-d, conformance trigger, new conformance tests)
and asserts that the attack no longer works. Library-level tests are in
packages/onaa-protocol/tests/test_security_rereview.py.
"""

from __future__ import annotations

import json
import threading
import time
import tracemalloc
import uuid
from datetime import timedelta

import httpx
import pytest
from onaa_protocol import EXTENSION_URI, StaticKeyResolver, check_envelope, new_envelope
from onaa_protocol.conformance import run_live
from onaa_protocol.envelope import LEGACY_SPEC_VERSION, extract_envelope, format_ts, utcnow
from onaa_protocol.trigger import build_trigger
from starlette.testclient import TestClient

import onaa_demo.mock_escrow as escrow_mod
import onaa_demo.seller as seller_mod
from onaa_demo import a2a
from onaa_demo.buyer import BuyerAgent, BuyerNode
from onaa_demo.mock_escrow import MockEscrow
from onaa_demo.registry_client import RegistryClient, RegistryError
from onaa_demo.seller import SellerAgent

CARD = a2a.AGENT_CARD_PATH
SYBIL_CARD = "https://sybil.example/.well-known/agent-card.json"
BUYER_CARD = "https://buyer.example/.well-known/agent-card.json"
ATTACKER, VICTIM = "ip:198.51.100.9", "ip:203.0.113.5"


def _msg(env: dict) -> dict:
    return a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], extensions=[EXTENSION_URI])


def _send(agent, env: dict, source: str | None = None) -> dict:
    return extract_envelope(agent.handle(_msg(env), source))


def _rfq(seller, agent_id: str, card: str = SYBIL_CARD, ttl: timedelta = timedelta(minutes=30)) -> dict:
    return new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                        sender={"agent_id": agent_id, "agent_card_url": card}, recipient=seller.sender, ttl=ttl)


@pytest.fixture
def parties():
    buyer, seller, escrow = BuyerNode("http://127.0.0.1:7"), SellerAgent("http://127.0.0.1:8"), MockEscrow(
        "http://127.0.0.1:9")
    keys = StaticKeyResolver({n.sender["agent_card_url"]: n.jwks() for n in (buyer, seller, escrow)})
    for n in (buyer, seller, escrow):
        n.keys = keys
    return buyer, seller, escrow


# ------------------------------------------------------------------ N2 replay store / deals / escrow / notifications


def test_n2_poc_r3_long_lived_unsigned_rfq_is_refused(parties):
    _, seller, _ = parties
    r = _send(seller, _rfq(seller, "x", ttl=timedelta(hours=24)), ATTACKER)
    assert (r["type"], r["body"]["code"]) == ("REJECT", "invalid_envelope")
    assert len(seller.guard) == 0 and len(seller.ledgers) == 0


def test_n2_poc_r3_replay_store_flood_locks_out_only_the_flooding_source(parties):
    _, seller, _ = parties
    seller.guard.max_per_source = 20                       # default max_entries // 10; scaled for runtime
    codes = [_send(seller, _rfq(seller, f"sybil-{uuid.uuid4()}"), ATTACKER) for _ in range(25)]
    assert [c["type"] for c in codes[:20]] == ["QUOTE"] * 20
    rejected = codes[20:]
    assert all((r["type"], r["body"]["code"], r["body"].get("retryable")) == ("REJECT", "rate_limited", True)
               for r in rejected)
    assert _send(seller, _rfq(seller, "legit-buyer", BUYER_CARD), VICTIM)["type"] == "QUOTE"


def test_n2_poc_r4_sybil_rfqs_cannot_evict_another_sources_pending_quote(parties, monkeypatch):
    buyer, seller, _ = parties
    monkeypatch.setattr(seller_mod, "MAX_LEDGERS", 10)
    rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                       sender=buyer.sender, recipient=seller.sender)
    quote = _send(seller, rfq, VICTIM)
    for i in range(40):
        assert _send(seller, _rfq(seller, f"sybil-{i}"), f"ip:198.51.100.{i % 4}")["type"] == "QUOTE"
    assert rfq["id"] in seller.ledgers and len(seller.ledgers) == 10
    qb = quote["body"]
    order = new_envelope("ORDER_PROPOSE", {
        "quote_id": quote["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
        "rfq_id": rfq["id"], "buyer_agent_id": buyer.agent_id, "seller_agent_id": qb["seller_agent_id"],
        "currency": "USD", "total_minor": qb["total_minor"]}, sender=buyer.sender, recipient=quote["sender"],
        signer=buyer.signer)
    assert _send(seller, order, VICTIM)["type"] == "ORDER_CONFIRM"


def test_n2_one_source_only_recycles_its_own_pending_quotes(parties, monkeypatch):
    _, seller, _ = parties
    monkeypatch.setattr(seller_mod, "MAX_QUOTE_ONLY_PER_SOURCE", 3)
    victim = _rfq(seller, "legit", BUYER_CARD)
    _send(seller, victim, VICTIM)
    for i in range(10):
        _send(seller, _rfq(seller, f"sybil-{i}"), ATTACKER)
    assert victim["id"] in seller.ledgers and len(seller.ledgers) == 4


def test_n2_deals_with_orders_are_never_evicted(parties, monkeypatch):
    _, seller, _ = parties
    monkeypatch.setattr(seller_mod, "MAX_LEDGERS", 2)
    for i in range(2):
        _send(seller, _rfq(seller, f"b{i}"), f"ip:192.0.2.{i}")
    for led in seller.ledgers.values():
        led.orders["pinned"] = None
    assert _send(seller, _rfq(seller, "b9"), ATTACKER)["body"]["code"] == "rate_limited"


def _legacy_handoff(escrow, i: int) -> dict:
    return new_envelope("ESCROW_HANDOFF_REQUEST", {
        "quote_id": str(uuid.uuid4()), "buyer_agent_id": "b", "seller_agent_id": "s", "currency": "USD",
        "amount_minor": 1, "quote_expires_at": format_ts(utcnow() + timedelta(hours=1))},
        sender={"agent_id": f"sybil-{i}"}, recipient=escrow.sender, spec_version=LEGACY_SPEC_VERSION)


def test_n2_poc_r3_mock_escrow_quota_is_per_source_and_handoffs_expire(parties, monkeypatch):
    _, _, escrow = parties
    monkeypatch.setattr(escrow_mod, "MAX_HANDOFFS_PER_SOURCE", 5)
    for i in range(5):
        assert _send(escrow, _legacy_handoff(escrow, i), ATTACKER)["type"] == "ESCROW_HANDOFF_ACK"
    assert _send(escrow, _legacy_handoff(escrow, 99), ATTACKER)["body"]["code"] == "rate_limited"
    assert _send(escrow, _legacy_handoff(escrow, 100), VICTIM)["type"] == "ESCROW_HANDOFF_ACK"
    for h in escrow.handoffs.values():                     # HANDOFF_TTL elapsed
        h["expires"] = utcnow() - timedelta(seconds=1)
    assert _send(escrow, _legacy_handoff(escrow, 101), ATTACKER)["type"] == "ESCROW_HANDOFF_ACK"
    assert len(escrow.handoffs) == 1 and escrow._per_source == {ATTACKER: 1}


def test_n2_poc_r4_buyer_notifications_are_small_bounded_summaries(parties):
    buyer, _, _ = parties
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        for i in range(300):
            env = new_envelope("ORDER_STATUS", {"order_id": str(uuid.uuid4()), "state": "DELIVERED",
                                                "pad": "x" * 100_000},
                               sender={"agent_id": f"sybil-{i}"}, recipient=buyer.sender, ttl=timedelta(minutes=1))
            assert _send(buyer, env, ATTACKER)["type"] == "RECEIPT"
        retained = tracemalloc.get_traced_memory()[0] - base
    finally:
        tracemalloc.stop()
    assert len(buyer.notifications) == 256 and "pad" not in json.dumps(list(buyer.notifications))
    assert retained < 5_000_000                            # was ~26 MB for 256 padded envelopes


# ------------------------------------------------------------------ N1 demo seller lists its accepted provider


def test_n1_demo_seller_quote_lists_the_accepted_provider(network):
    with httpx.Client(timeout=10) as http:
        res = BuyerAgent(RegistryClient(network.registry_url, client=http), network.buyer, http_client=http).run()
    settlement = res.quote["body"]["settlement"]
    assert settlement["accepted_provider_card_urls"] == [network.escrow.base_url + CARD]
    assert res.handoff_request["recipient"]["agent_card_url"] in settlement["accepted_provider_card_urls"]


# ------------------------------------------------------------------ N3 bounded handler executor


def test_n3_handlers_run_on_a_bounded_limiter_and_the_card_stays_responsive():
    active, peak, lock = [0], [0], threading.Lock()

    def handler(message, source):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.3)
        with lock:
            active[0] -= 1
        return a2a.make_message(a2a.ROLE_AGENT, [a2a.data_part({"spec": "x"})])

    app = a2a.create_agent_app({"name": "t"}, handler, pass_source=True, max_handler_threads=2)
    body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": {"message": a2a.make_message(a2a.ROLE_USER, [a2a.data_part({"x": 1})])}}
    with TestClient(app) as client:
        threads = [threading.Thread(target=client.post, args=("/a2a/v1",),
                                    kwargs={"json": body, "headers": {"A2A-Version": "1.0"}}) for _ in range(6)]
        for t in threads:
            t.start()
        time.sleep(0.1)
        t0 = time.monotonic()
        assert client.get(CARD).status_code == 200 and time.monotonic() - t0 < 0.2
        for t in threads:
            t.join()
    assert peak[0] == 2


def test_n3_client_source_groups_ipv6_by_64():
    assert a2a.client_source("2001:db8:1:2::5") == a2a.client_source("2001:db8:1:2:ffff::1") == "ip6:2001:db8:1:2::/64"
    assert a2a.client_source("::ffff:198.51.100.7") == "ip:198.51.100.7"
    assert a2a.client_source(None) is None


# ------------------------------------------------------------------ L-b, L-c, L-d


def test_lb_order_id_cannot_be_reused_across_deals(parties):
    buyer, seller, _ = parties

    def order_for(rfq_id: str, oid: str) -> dict:
        rfq = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                           sender=buyer.sender, recipient=seller.sender, id_=rfq_id)
        q = _send(seller, rfq)
        qb = q["body"]
        return new_envelope("ORDER_PROPOSE", {
            "quote_id": q["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
            "rfq_id": rfq_id, "buyer_agent_id": buyer.agent_id, "seller_agent_id": qb["seller_agent_id"],
            "currency": "USD", "total_minor": qb["total_minor"]}, sender=buyer.sender, recipient=q["sender"],
            signer=buyer.signer, id_=oid)
    oid = str(uuid.uuid4())
    assert _send(seller, order_for(str(uuid.uuid4()), oid))["type"] == "ORDER_CONFIRM"
    second_rfq = str(uuid.uuid4())
    r = _send(seller, order_for(second_rfq, oid))
    assert (r["type"], r["body"]["code"]) == ("REJECT", "replay")
    assert seller.order_index[oid] != second_rfq and not seller.ledgers[second_rfq].orders


@pytest.mark.parametrize("body", [b'{"items":[],"items":[]}', b"[" * 5000 + b"]" * 5000, b"x" * 2_000_000])
def test_lc_registry_client_parses_strictly_with_a_size_cap(body):
    http = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=body, headers={"content-type": "application/json"})))
    reg = RegistryClient("https://registry.example.com", client=http, resolver=lambda h, p: ["93.184.215.14"])
    with pytest.raises(RegistryError):
        reg.search_agents(role="seller_agent")


def test_lc_registry_client_default_client_pins_addresses():
    reg = RegistryClient("https://registry.example.com", resolver=lambda h, p: ["93.184.215.14"])
    from onaa_protocol.safe_fetch import PinnedTransport
    assert isinstance(reg._client._transport, PinnedTransport)


class _Boom(BaseException):
    pass


def test_ld_reservation_is_released_on_base_exceptions(parties, monkeypatch):
    _, seller, _ = parties

    def boom(env, source=None):
        raise _Boom()
    monkeypatch.setattr(seller, "dispatch_from", boom)
    rfq = _rfq(seller, "b1", BUYER_CARD)
    with pytest.raises(_Boom):
        _send(seller, rfq)
    assert len(seller.guard) == 0                          # the retry is not stuck behind a dead reservation


# ------------------------------------------------------------------ conformance trigger allowlist (spec 12.1.5)


def test_trigger_from_a_sender_outside_the_allowlist_is_refused_without_a_key_fetch(allow_localhost):
    harness = "https://harness.example/.well-known/agent-card.json"
    buyer = BuyerNode("http://127.0.0.1:7", conformance_trigger=True, trigger_allowed_senders=[harness])
    fetched: list = []
    buyer.keys = type("K", (), {"resolve": lambda self, s, k: fetched.append(s) or (_ for _ in ()).throw(
        AssertionError("no key fetch expected"))})()
    seller, escrow = SellerAgent("http://127.0.0.1:8"), MockEscrow("http://127.0.0.1:9")
    trig = build_trigger(sender={"agent_id": "h", "agent_card_url": "https://evil.example/.well-known/agent-card.json"},
                         recipient=buyer.sender, seller=seller.sender, provider=escrow.sender,
                         rfq={"items": [{"sku": "widget-std", "quantity": 1}], "currency": "USD"},
                         signer=seller.signer)
    out = extract_envelope(buyer.handle(_msg(trig)))
    assert (out["type"], out["body"]["code"]) == ("REJECT", "not_a_party") and fetched == []


# ------------------------------------------------------------------ new live conformance tests catch old sellers


def test_live_suite_catches_a_seller_accepting_rfqs_without_a_card(network, monkeypatch):
    import onaa_demo.node as node_mod

    def lax(env, keys, **kw):
        if isinstance(env, dict) and env.get("type") == "RFQ" and not env.get("sender", {}).get("agent_card_url"):
            env["sender"]["agent_card_url"] = BUYER_CARD
            try:
                return check_envelope(env, keys, **kw)
            finally:
                env["sender"].pop("agent_card_url")
        return check_envelope(env, keys, **kw)
    monkeypatch.setattr(node_mod, "check_envelope", lax)
    report = run_live(network.seller.base_url + CARD, "seller_agent", allow_loopback=True)
    fails = {r["id"] for r in report["results"] if r["outcome"] == "fail"}
    assert "ONAA-C-MUST-092" in fails


def test_live_suite_catches_unsigned_same_state_status(network, monkeypatch):
    from onaa_protocol import state

    orig = state.TradeLedger._bind

    def lax_bind(self, env):
        if env["type"] == "ORDER_STATUS" and "signature" not in env:
            return None
        return orig(self, env)
    monkeypatch.setattr(state.TradeLedger, "_bind", lax_bind)
    report = run_live(network.seller.base_url + CARD, "seller_agent", allow_loopback=True)
    fails = {r["id"] for r in report["results"] if r["outcome"] == "fail"}
    assert "ONAA-C-MUST-093" in fails and "ONAA-C-MUST-077" not in fails
