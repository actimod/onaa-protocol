"""Conformance trade trigger (spec section 12.1): opt-in, signed, recipient-bound, mock-only, single-use."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onaa_protocol import ProtocolError, Signer, StaticKeyResolver, new_envelope, schemas
from onaa_protocol.conformance import TESTS, for_role
from onaa_protocol.envelope import utcnow
from onaa_protocol.jose import TYP_ENVELOPE, sign_detached
from onaa_protocol.trigger import (
    TriggerGuard,
    build_trigger,
    check_counterparty,
    check_trigger,
    counterparty_marker,
    declared_trigger,
    find_trigger,
    sign_trigger,
    trigger_declaration,
    trigger_result,
)

HARNESS = {"agent_id": "harness", "agent_card_url": "https://harness.example/.well-known/agent-card.json"}
BUYER = {"agent_id": "buyer", "agent_card_url": "https://buyer.example/.well-known/agent-card.json"}
SELLER = {"agent_id": "seller", "agent_card_url": "https://seller.example/.well-known/agent-card.json"}
PROVIDER = {"agent_id": "provider", "agent_card_url": "https://provider.example/.well-known/agent-card.json"}
RFQ = {"items": [{"sku": "sample", "quantity": 2}], "currency": "USD"}
SIGNER = Signer(Ed25519PrivateKey.generate(), "harness-test")
KEYS = StaticKeyResolver({HARNESS["agent_card_url"]: {"keys": [SIGNER.public_jwk()]}})


def _trigger(**kw):
    args = {"sender": HARNESS, "recipient": BUYER, "seller": SELLER, "provider": PROVIDER, "rfq": RFQ,
            "signer": SIGNER}
    args.update(kw)
    return build_trigger(**args)


def _code(trigger, **kw):
    with pytest.raises(ProtocolError) as exc:
        check_trigger(trigger, KEYS, expected_recipient=BUYER, **kw)
    return exc.value.code


def test_valid_trigger_verifies():
    trig = _trigger()
    assert check_trigger(trig, KEYS, expected_recipient=BUYER) is trig
    assert schemas.errors("conformance-trigger", trig) == []


def _resigned(mutate):
    trig = _trigger()
    mutate(trig)
    return sign_trigger(trig, SIGNER)


@pytest.mark.parametrize("make,code", [
    (lambda: _trigger(signer=None), "signature_missing"),
    (lambda: _trigger(signer=Signer(Ed25519PrivateKey.generate(), SIGNER.kid)), "signature_invalid"),
    (lambda: _trigger(signer=Signer(Ed25519PrivateKey.generate(), "unknown-kid")), "key_not_found"),
    (lambda: _trigger(recipient=SELLER), "recipient_mismatch"),
    (lambda: _trigger(now=utcnow() - timedelta(minutes=20), ttl=timedelta(minutes=10)), "expired"),
    (lambda: _trigger(ttl=timedelta(minutes=11)), "invalid_envelope"),
    (lambda: _trigger(now=utcnow() + timedelta(minutes=6)), "invalid_envelope"),
    (lambda: _trigger(mode="live"), "live_mode_not_supported"),
    (lambda: _trigger(mode="sandbox"), "invalid_envelope"),
    (lambda: _trigger(test_only=False), "invalid_envelope"),
    (lambda: _trigger(seller=PROVIDER), "invalid_envelope"),
    (lambda: _trigger(seller=BUYER), "invalid_envelope"),
    (lambda: _resigned(lambda t: t.update(x_extra=1)), "invalid_envelope"),
    (lambda: _resigned(lambda t: t["provider"].update(card_number="4111")), "invalid_envelope"),
    (lambda: dict(_trigger(), type="RFQ"), "invalid_envelope"),
])
def test_invalid_triggers_are_refused(make, code):
    assert _code(make()) == code


def test_tampered_trigger_fails_signature():
    trig = _trigger()
    trig["rfq"]["items"][0]["quantity"] = 3
    assert _code(trig) == "signature_invalid"


def test_envelope_and_trigger_signatures_are_not_interchangeable():
    trig = _trigger(signer=None)
    trig["signature"] = sign_detached({k: v for k, v in trig.items() if k != "signature"}, SIGNER, TYP_ENVELOPE)
    assert _code(trig) == "signature_header_invalid"


def test_find_trigger():
    trig, env = _trigger(), new_envelope("RECEIPT", {"received_id": "x", "received_type": "PING"},
                                         sender=HARNESS, in_reply_to="x")
    part = {"data": trig, "mediaType": "application/json"}
    assert find_trigger({"parts": [part]}) is trig
    assert find_trigger({"parts": [{"data": env}]}) is None
    for parts in ([part, {"data": env}], [part, part]):
        with pytest.raises(ProtocolError) as exc:
            find_trigger({"parts": parts})
        assert exc.value.code == "invalid_envelope"


def test_counterparty_marker_binds_to_the_trigger_sender():
    trig = _trigger()
    check_counterparty({"conformance": {"harness_counterparty": counterparty_marker(HARNESS["agent_card_url"])}},
                       trig)
    for params in ({}, {"conformance": {"harness_counterparty": counterparty_marker(SELLER["agent_card_url"])}},
                   {"conformance": {"harness_counterparty": {"test_only": False,
                                                             "trigger_sender": HARNESS["agent_card_url"]}}}):
        with pytest.raises(ProtocolError) as exc:
            check_counterparty(params, trig)
        assert exc.value.code == "not_a_party"


def test_guard_is_single_use_and_one_at_a_time():
    guard, trig = TriggerGuard(), _trigger()
    guard.reserve(trig)
    with pytest.raises(ProtocolError, match="another") as exc:
        guard.reserve(_trigger())
    assert exc.value.code == "rate_limited"
    guard.finish()
    for replay in (copy.deepcopy(trig), dict(_trigger(), id=trig["id"]), dict(_trigger(), nonce=trig["nonce"])):
        with pytest.raises(ProtocolError) as exc:
            guard.reserve(replay)
        assert exc.value.code == "replay"
    guard.reserve(_trigger())
    guard.finish()
    small = TriggerGuard(max_entries=2)
    small.reserve(_trigger())
    small.finish()
    with pytest.raises(ProtocolError) as exc:
        small.reserve(_trigger())
    assert exc.value.code == "rate_limited"


def test_declaration_and_result_shapes():
    base = {"onaa_protocol": "0.1", "spec": "onaa.commerce/v0", "spec_versions": ["0.2.0"], "roles": ["buyer_agent"],
            "message_types": ["ORDER_STATUS"], "jwks_uri": "https://buyer.example/.well-known/onaa/jwks.json"}
    assert declared_trigger(base) is None
    on = dict(base, conformance={"trade_trigger": trigger_declaration()})
    assert declared_trigger(on) == trigger_declaration()
    assert schemas.errors("agent-card-extension-params", on) == []
    live = dict(base, conformance={"trade_trigger": {"version": "0.1", "modes": ["live"]}})
    assert schemas.errors("agent-card-extension-params", live)
    assert declared_trigger(dict(base, conformance={"trade_trigger": {"version": "9"}})) is None
    res = trigger_result(_trigger(), "stopped", code="invalid_body", stopped_on="QUOTE")
    assert schemas.errors("conformance-trigger", res, "#/$defs/result") == []
    with pytest.raises(ValueError):
        trigger_result(_trigger(), "maybe")


def test_trigger_tests_are_buyer_only_must_and_new():
    ids = {f"ONAA-C-MUST-0{n}" for n in range(80, 92)}
    assert ids <= set(TESTS)
    assert all(TESTS[i].roles == ("buyer_agent",) and TESTS[i].level == "MUST" for i in ids)
    assert ids <= {t.id for t in for_role("buyer_agent")}
