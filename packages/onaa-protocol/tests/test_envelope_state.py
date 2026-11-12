"""Envelope validation, signing policy, replay guard and the trade state machines."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from onaa_protocol import (
    ProtocolError,
    ReplayGuard,
    SignatureError,
    StaticKeyResolver,
    TradeLedger,
    check_envelope,
    check_transition,
    extract_envelope,
    new_envelope,
    reject,
    terms_hash,
    validate_envelope,
)
from onaa_protocol.envelope import MUST_SIGN, REPLY_TYPES, TYPES
from onaa_protocol.vectors import T0, party, signer, transcript

AT = T0 + timedelta(minutes=2)


@pytest.fixture
def tr():
    return {m["envelope"]["type"]: m["envelope"] for m in transcript()["messages"]}


@pytest.fixture
def keys():
    t = transcript()
    return StaticKeyResolver({p["agent_card_url"]: p["jwks"] for p in t["parties"].values()})


def test_reply_table_and_signing_policy_are_consistent():
    assert set(REPLY_TYPES) <= set(TYPES)
    assert all(set(v) <= set(TYPES) for v in REPLY_TYPES.values())
    assert {"ORDER_PROPOSE", "ORDER_CONFIRM", "ORDER_CANCEL", "DISPUTE_OPEN", "SERVICE_HANDOFF_REQUEST",
            "SERVICE_HANDOFF_ACK"} <= MUST_SIGN


def test_transcript_verifies(tr, keys):
    for env in tr.values():
        check_envelope(env, keys, now=AT)


def test_signature_covers_every_member(tr, keys):
    order = copy.deepcopy(tr["ORDER_PROPOSE"])
    order["recipient"]["agent_id"] = "someone-else"
    validate_envelope(order, now=AT)               # still structurally valid ...
    with pytest.raises(SignatureError) as e:       # ... but no longer verifies
        check_envelope(order, keys, now=AT)
    assert e.value.code == "signature_invalid"


def test_signed_by_wrong_party_key(tr, keys):
    order = copy.deepcopy(tr["ORDER_PROPOSE"])
    order.pop("signature")
    order["sender"] = party("seller") | {"agent_id": order["sender"]["agent_id"]}
    from onaa_protocol import sign_envelope
    sign_envelope(order, signer("buyer"))          # buyer key, but seller card -> kid not in seller JWKS
    with pytest.raises(SignatureError) as e:
        check_envelope(order, keys, now=AT)
    assert e.value.code == "key_not_found"


def test_pinned_agent_id_mismatch(tr):
    t = transcript()
    keys = StaticKeyResolver({p["agent_card_url"]: p["jwks"] for p in t["parties"].values()},
                             pins={"sample-buyer-agent": "https://other.example.com/.well-known/agent-card.json"})
    with pytest.raises(SignatureError) as e:
        check_envelope(tr["ORDER_PROPOSE"], keys, now=AT)
    assert e.value.code == "signer_mismatch"


def test_check_envelope_requires_keys_for_signed(tr):
    with pytest.raises(SignatureError):
        check_envelope(tr["ORDER_PROPOSE"], None, now=AT)
    check_envelope(tr["RFQ"], None, now=AT)        # unsigned RFQ is fine


def test_terms_hash_detects_quote_change(tr):
    q = copy.deepcopy(tr["QUOTE"])
    q.pop("signature")
    q["body"]["delivery_terms"] = "EXW"
    with pytest.raises(ProtocolError) as e:
        validate_envelope(q, now=AT)
    assert e.value.code == "invalid_body"
    q["body"]["terms_hash"] = terms_hash(q["body"])
    validate_envelope(q, now=AT)


def test_new_envelope_refuses_aliases_and_bad_ttl():
    with pytest.raises(ProtocolError):
        new_envelope("ESCROW_HANDOFF_REQUEST", {}, sender={"agent_id": "x"})
    with pytest.raises(ProtocolError):
        new_envelope("RFQ", {}, sender={"agent_id": "x"}, ttl=timedelta(hours=25))
    with pytest.raises(ProtocolError):
        new_envelope("ORDER_PROPOSE", {}, sender={"agent_id": "x"}, signer=signer("buyer"))  # no card url


def test_expected_types_and_tax_arithmetic(tr):
    with pytest.raises(ProtocolError) as e:
        validate_envelope(tr["RFQ"], now=AT, expected_types=("ORDER_PROPOSE",))
    assert e.value.code == "unexpected_type"
    q = new_envelope("QUOTE", {"rfq_id": "r", "seller_agent_id": "s", "currency": "EUR", "tax_policy": "added",
                               "tax_minor": 190, "shipping_minor": 500,
                               "line_items": [{"sku": "a", "quantity": 2, "unit_price_minor": 500,
                                               "line_total_minor": 1000}], "total_minor": 1690},
                     sender={"agent_id": "s"}, in_reply_to="r", now=T0)
    validate_envelope(q, now=AT)


def test_replay_guard():
    g = ReplayGuard()
    env = new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"},
                       sender={"agent_id": "b"}, now=T0)
    assert g.check(env, now=AT) is None
    g.remember(env, {"cached": 1})
    assert g.check(copy.deepcopy(env), now=AT) == {"cached": 1}
    changed = copy.deepcopy(env)
    changed["body"]["items"][0]["quantity"] = 2
    with pytest.raises(ProtocolError, match="idempotency_conflict"):
        g.check(changed, now=AT)
    replay = dict(copy.deepcopy(env), idempotency_key="another-key-0123456789")
    with pytest.raises(ProtocolError, match="replay"):
        g.check(replay, now=AT)
    assert g.check(replay, now=T0 + timedelta(hours=1)) is None      # records expire with the envelope


def test_extract_and_reject():
    env = new_envelope("RFQ", {"items": [{"sku": "a", "quantity": 1}], "currency": "USD"}, sender={"agent_id": "b"})
    with pytest.raises(ProtocolError):
        extract_envelope({"parts": [{"data": env}, {"data": env}]})
    r = reject({"id": "x" * 500}, {"agent_id": "s"}, "invalid_envelope", "m")
    assert "in_reply_to" not in r and r["body"] == {"code": "invalid_envelope", "message": "m"}
    validate_envelope(r)


# ------------------------------------------------------------------ state machines


def test_transition_tables():
    check_transition("order", "PROPOSED", "CONFIRMED")
    check_transition("order", "CONFIRMED", "CONFIRMED")          # repeated status is a no-op
    for bad in [("PROPOSED", "SECURED"), ("COMPLETED", "DISPUTED"), ("CANCELLED", "CONFIRMED")]:
        with pytest.raises(ProtocolError, match="invalid_transition"):
            check_transition("order", *bad)
    with pytest.raises(ProtocolError):
        check_transition("handoff", "CREATED", "RELEASED")


def _ledger(tr, upto):
    led = TradeLedger()
    for t in ("RFQ", "QUOTE", "ORDER_PROPOSE", "ORDER_CONFIRM", "SERVICE_HANDOFF_REQUEST", "SERVICE_HANDOFF_ACK"):
        if t == upto:
            return led
        led.apply(tr[t], now=AT)
    return led


def test_ledger_full_flow(tr):
    led = _ledger(tr, None)
    led.apply(tr["SERVICE_STATUS"], now=AT)
    assert led.quote_state == "ACCEPTED"
    assert next(iter(led.orders.values())).state == "CONFIRMED"
    assert next(iter(led.handoffs.values())).state == "CREATED"


@pytest.mark.parametrize("mutate,code", [
    (lambda b: b.update(quote_terms_hash="sha256:" + "0" * 64), "terms_mismatch"),
    (lambda b: b.update(total_minor=1), "amount_mismatch"),
    (lambda b: b.update(quote_id="nope"), "unknown_quote"),
    (lambda b: b.update(quote_revision=2), "terms_mismatch"),
])
def test_ledger_rejects_bad_order(tr, mutate, code):
    led = _ledger(tr, "ORDER_PROPOSE")
    order = copy.deepcopy(tr["ORDER_PROPOSE"])
    mutate(order["body"])
    with pytest.raises(ProtocolError) as e:
        led.apply(order, now=AT)
    assert e.value.code == code


def test_ledger_quote_expiry_and_supersede(tr):
    led = _ledger(tr, "ORDER_PROPOSE")
    with pytest.raises(ProtocolError, match="quote_expired"):
        led.apply(tr["ORDER_PROPOSE"], now=T0 + timedelta(hours=1))
    q2 = copy.deepcopy(tr["QUOTE"])
    q2["id"] = "quote-rev-2"
    q2["body"]["revision"] = 2
    led.apply(q2, now=AT)
    with pytest.raises(ProtocolError, match="quote_superseded"):
        led.apply(tr["ORDER_PROPOSE"], now=AT)
    with pytest.raises(ProtocolError, match="quote_superseded"):
        led.apply(dict(q2, id="quote-rev-1-again", body=dict(q2["body"], revision=1)), now=AT)


def test_ledger_party_and_card_binding(tr):
    led = _ledger(tr, "ORDER_CONFIRM")
    fake = copy.deepcopy(tr["ORDER_CONFIRM"])
    fake["sender"] = {"agent_id": "intruder", "agent_card_url": "https://x.example.com/.well-known/agent-card.json"}
    with pytest.raises(ProtocolError, match="not_a_party"):
        led.apply(fake, now=AT)
    moved = copy.deepcopy(tr["ORDER_CONFIRM"])
    moved["sender"]["agent_card_url"] = "https://moved.example.com/.well-known/agent-card.json"
    with pytest.raises(SignatureError, match="signer_mismatch"):
        led.apply(moved, now=AT)


def test_ledger_secured_needs_provider_confirmation(tr):
    led = _ledger(tr, None)
    order_id = tr["ORDER_PROPOSE"]["id"]
    pay = new_envelope("ORDER_STATUS", {"order_id": order_id, "state": "PAYMENT_PENDING"},
                       sender=party("buyer"), signer=signer("buyer"), now=T0)
    led.apply(pay, now=AT)
    secured = new_envelope("ORDER_STATUS", {"order_id": order_id, "state": "SECURED",
                                            "handoff_reference": "MOCK-ESC-0000000000000001"},
                           sender=party("buyer"), signer=signer("buyer"), now=T0)
    with pytest.raises(ProtocolError, match="invalid_transition"):
        led.apply(secured, now=AT)                              # mock handoff is never SECURED


def test_ledger_cancel_and_dispute(tr):
    led = _ledger(tr, "SERVICE_HANDOFF_REQUEST")
    order_id = tr["ORDER_PROPOSE"]["id"]
    dispute = new_envelope("DISPUTE_OPEN", {"order_id": order_id, "reason_code": "other",
                                            "dispute_provider": {"agent_id": "d"}},
                           sender=party("buyer"), signer=signer("buyer"), now=T0)
    with pytest.raises(ProtocolError, match="invalid_transition"):
        led.apply(dispute, now=AT)                              # nothing to dispute before SECURED/fulfilment
    cancel = new_envelope("ORDER_CANCEL", {"order_id": order_id, "reason_code": "buyer_request"},
                          sender=party("buyer"), signer=signer("buyer"), now=T0)
    led.apply(cancel, now=AT)
    assert led.orders[order_id].state == "CANCELLED"
    with pytest.raises(ProtocolError, match="invalid_transition"):
        led.apply(cancel | {"id": "cancel-2"}, now=AT)
