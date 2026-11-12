"""Buyer client-side conformance via the opt-in conformance trade trigger (spec section 12.1).

The SAMPLE buyer passes with the trigger enabled, ignores triggers when it is not enabled, and deliberately
broken buyers are caught by the new ONAA-C-MUST-080..091 tests. Loopback demo flag only; mock trades only.
"""

from __future__ import annotations

import re

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from onaa_protocol import Signer, check_recipient, state, validate_envelope
from onaa_protocol import a2a as proto_a2a
from onaa_protocol.conformance import run_live
from onaa_protocol.envelope import EXTENSION_URI, extract_envelope
from onaa_protocol.trigger import build_trigger

import onaa_demo.a2a as demo_a2a
import onaa_demo.buyer as buyer_mod
from onaa_demo.a2a import AGENT_CARD_PATH

TRIGGER_IDS = {f"ONAA-C-MUST-0{n}" for n in range(80, 92)}


def _report(net):
    return run_live(net.buyer.base_url + AGENT_CARD_PATH, "buyer_agent", allow_loopback=True)


def _fails(report):
    return {r["id"]: r["detail"] for r in report["results"] if r["outcome"] not in ("pass", "n/a")}


def test_opted_in_buyer_passes_every_trigger_test(trigger_network):
    report = _report(trigger_network)
    res = {r["id"]: r["outcome"] for r in report["results"]}
    assert {i: res[i] for i in TRIGGER_IDS} == dict.fromkeys(TRIGGER_IDS, "pass"), _fails(report)
    assert report["summary"]["verdict"] == "pass", _fails(report)
    assert trigger_network.buyer.params["conformance"]["trade_trigger"]["modes"] == ["mock"]


def test_trigger_is_off_by_default(network):
    """Without the operator opt-in the buyer declares nothing and refuses a (validly signed) trigger."""
    buyer = network.buyer
    assert "conformance" not in buyer.params
    signer = Signer(Ed25519PrivateKey.generate(), "harness")
    trig = build_trigger(sender={"agent_id": "h", "agent_card_url": "https://harness.invalid" + AGENT_CARD_PATH},
                         recipient=buyer.sender, seller={"agent_id": "s", "agent_card_url": network.seller.sender[
                             "agent_card_url"]}, provider={"agent_id": "p", "agent_card_url": network.escrow.sender[
                                 "agent_card_url"]}, rfq={"items": [{"sku": "widget-std", "quantity": 1}],
                                                          "currency": "USD"}, signer=signer)
    msg = proto_a2a.make_message(proto_a2a.ROLE_USER, [proto_a2a.data_part(trig)], extensions=[EXTENSION_URI])
    with httpx.Client(timeout=10) as http:
        reply = proto_a2a.send_message(http, buyer.base_url + "/a2a/v1", msg, extensions=[EXTENSION_URI])
    env = extract_envelope(reply)
    assert env["type"] == "REJECT" and env["body"]["code"] == "invalid_envelope"
    assert network.seller.request_log == [] and network.escrow.request_log == []


def _skip_checks_for(type_, *, verify_signature=False):
    """A broken check_envelope that skips verification for one reply type (the rest stays strict)."""
    real = buyer_mod.check_envelope

    def broken(env, keys, *, expected_recipient=None, **kw):
        if env.get("type") != type_:
            return real(env, keys, expected_recipient=expected_recipient, **kw)
        if verify_signature:  # schema/semantics and recipient checked, signature never verified
            validate_envelope(env, **kw)
            check_recipient(env, expected_recipient)
        return env
    return broken


def _fetch_free_text_urls(monkeypatch):
    real = buyer_mod.BuyerAgent._apply

    def apply(self, env):
        if env["type"] == "QUOTE":
            for line in env["body"]["line_items"]:
                for url in re.findall(r"https?://\S+", line.get("description", "")):
                    try:
                        httpx.get(url, timeout=2.0)  # broken: acts on untrusted free text
                    except httpx.HTTPError:
                        pass
        return real(self, env)
    monkeypatch.setattr(buyer_mod.BuyerAgent, "_apply", apply)


def _no_recipient_on_orders(monkeypatch):
    real = buyer_mod.new_envelope

    def build(type_, body, **kw):
        if type_ == "ORDER_PROPOSE":
            kw["recipient"] = None  # broken: signed request not bound to its recipient
        return real(type_, body, **kw)
    monkeypatch.setattr(buyer_mod, "new_envelope", build)


def _fixed_nonce(monkeypatch):
    real = buyer_mod.new_envelope
    monkeypatch.setattr(buyer_mod, "new_envelope", lambda t, b, **kw: real(t, b, nonce="N" * 24, **kw))


def _no_extension_header(monkeypatch):
    real = demo_a2a.send_message
    monkeypatch.setattr(demo_a2a, "send_message", lambda http, url, msg, **kw: real(http, url, msg))


def _trust_any_ack(monkeypatch):
    real = state.TradeLedger._on_service_handoff_ack

    def trusting(self, env, b, now):  # broken: believes whoever answers instead of the named provider
        req = self.pending_handoffs.get(env.get("in_reply_to", ""))
        if req is not None:
            env = dict(env, sender=dict(env["sender"], agent_card_url=req["recipient"]["agent_card_url"]))
        return real(self, env, b, now)
    monkeypatch.setattr(state.TradeLedger, "_on_service_handoff_ack", trusting)
    monkeypatch.setattr(buyer_mod.BuyerAgent, "_check_reply_sender", staticmethod(lambda out, url: None))


def _retyped_quote_without_state_machine(monkeypatch):
    real = buyer_mod.new_envelope

    def build(type_, body, **kw):
        if type_ == "ORDER_PROPOSE":
            body = dict(body, total_minor=body["total_minor"] - 1, buyer_authority={
                "max_total_minor": body["total_minor"] - 1, "human_approval": "not_required"})  # re-typed copy
        return real(type_, body, **kw)
    monkeypatch.setattr(buyer_mod, "new_envelope", build)
    monkeypatch.setattr(buyer_mod.BuyerAgent, "_apply", lambda self, env: None)


@pytest.mark.parametrize("breakage,expected,exact", [
    pytest.param(lambda mp, net: mp.setattr(buyer_mod, "check_trigger", lambda t, keys, **kw: t),
                 {"ONAA-C-MUST-081"}, True, id="trigger-without-checks"),
    pytest.param(lambda mp, net: mp.setattr(buyer_mod, "check_counterparty", lambda params, t: None),
                 {"ONAA-C-MUST-081"}, True, id="counterparty-marker-ignored"),
    pytest.param(lambda mp, net: _no_recipient_on_orders(mp), {"ONAA-C-MUST-082"}, True,
                 id="signed-order-without-recipient"),
    pytest.param(lambda mp, net: _fixed_nonce(mp), {"ONAA-C-MUST-083"}, True, id="reused-nonce"),
    pytest.param(lambda mp, net: _no_extension_header(mp), {"ONAA-C-MUST-084"}, True, id="no-a2a-extensions"),
    pytest.param(lambda mp, net: mp.setattr(buyer_mod, "check_envelope", _skip_checks_for("QUOTE")),
                 {"ONAA-C-MUST-086"}, True, id="quote-not-verified"),
    pytest.param(lambda mp, net: mp.setattr(buyer_mod, "check_envelope",
                                            _skip_checks_for("ORDER_CONFIRM", verify_signature=True)),
                 {"ONAA-C-MUST-087"}, True, id="confirm-signature-not-verified"),
    pytest.param(lambda mp, net: _trust_any_ack(mp), {"ONAA-C-MUST-089"}, True, id="ack-from-anyone"),
    pytest.param(lambda mp, net: mp.setattr(net.buyer, "remember_deal", lambda ledger: None),
                 {"ONAA-C-MUST-090"}, True, id="notifications-without-deal-state"),
    pytest.param(lambda mp, net: _fetch_free_text_urls(mp), {"ONAA-C-MUST-091"}, True, id="acts-on-free-text"),
    pytest.param(lambda mp, net: _retyped_quote_without_state_machine(mp),
                 {"ONAA-C-MUST-085", "ONAA-C-MUST-087", "ONAA-C-MUST-088"}, False, id="retyped-quote-no-ledger"),
])
def test_broken_buyers_are_caught(trigger_network, monkeypatch, breakage, expected, exact):
    breakage(monkeypatch, trigger_network)
    report = _report(trigger_network)
    fails = _fails(report)
    if exact:
        assert set(fails) == expected, fails
    else:
        assert expected <= set(fails), fails
    assert report["summary"]["verdict"] == "fail"
