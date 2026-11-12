"""onaa.commerce/v0 envelope: validation, expiry, idempotency, replay, JSON Schema agreement."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from onaa_demo import a2a
from onaa_demo.commerce import (
    EnvelopeError,
    ReplayGuard,
    extract_envelope,
    new_envelope,
    validate_envelope,
)
from onaa_demo.mock_escrow import MockEscrow
from onaa_demo.seller import SellerAgent

T0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
BUYER = {"agent_id": "t-buyer"}


def rfq(**kw):
    body = kw.pop("body", {"items": [{"sku": "widget-std", "quantity": 3}], "currency": "USD"})
    return new_envelope("RFQ", body, sender=BUYER, now=kw.pop("now", T0), **kw)


def test_valid_rfq():
    env = rfq()
    assert validate_envelope(env, now=T0 + timedelta(minutes=1)) is env
    assert env["spec"] == "onaa.commerce/v0" and env["spec_version"] == "0.1.0"


def test_expired():
    env = rfq(ttl=timedelta(minutes=1))
    with pytest.raises(EnvelopeError) as e:
        validate_envelope(env, now=T0 + timedelta(minutes=2))
    assert e.value.code == "expired"


def test_future_created_at_rejected():
    env = rfq(now=T0 + timedelta(hours=1))
    with pytest.raises(EnvelopeError):
        validate_envelope(env, now=T0)


@pytest.mark.parametrize("mutate,code", [
    (lambda e: e.update(spec="onaa.commerce/v1"), "unsupported_spec"),
    (lambda e: e.update(spec_version="1.0.0"), "unsupported_spec"),
    (lambda e: e.update(idempotency_key="short"), "invalid_envelope"),
    (lambda e: e.update(nonce="abc"), "invalid_envelope"),
    (lambda e: e["body"].update(currency="usd"), "invalid_body"),
    (lambda e: e["body"]["items"][0].update(quantity=0), "invalid_body"),
    (lambda e: e["body"]["items"][0].update(quantity=True), "invalid_body"),
    (lambda e: e["body"].update(max_total_minor=12.5), "invalid_body"),
])
def test_invalid(mutate, code):
    env = rfq()
    mutate(env)
    with pytest.raises(EnvelopeError) as e:
        validate_envelope(env, now=T0)
    assert e.value.code == code


def test_ttl_bounds():
    with pytest.raises(EnvelopeError):
        rfq(ttl=timedelta(hours=25))


def test_replay_guard_idempotent_conflict_and_replay():
    g = ReplayGuard()
    env = rfq()
    assert g.check(env, now=T0) is None
    g.remember(env, {"cached": 1})
    assert g.check(copy.deepcopy(env), now=T0) == {"cached": 1}          # safe retry
    changed = copy.deepcopy(env)
    changed["body"]["items"][0]["quantity"] = 99
    with pytest.raises(EnvelopeError) as e:
        g.check(changed, now=T0)
    assert e.value.code == "idempotency_conflict"
    replay = copy.deepcopy(env)
    replay["idempotency_key"] = "another-key-0123456789"
    with pytest.raises(EnvelopeError) as e:
        g.check(replay, now=T0)
    assert e.value.code == "replay"
    # entries expire with the envelope
    assert g.check(replay, now=T0 + timedelta(hours=1)) is None


def _send(agent, env):
    msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)])
    return extract_envelope(agent.handle(msg))


def test_seller_retry_returns_same_quote_and_conflict_rejected():
    seller = SellerAgent("http://127.0.0.1:9")
    env = new_envelope("RFQ", {"items": [{"sku": "widget-pro", "quantity": 2}], "currency": "EUR"}, sender=BUYER)
    q1 = _send(seller, env)
    q2 = _send(seller, copy.deepcopy(env))
    assert q1["type"] == "QUOTE" and q1 == q2
    assert q1["body"]["total_minor"] == 2 * 4599
    env2 = copy.deepcopy(env)
    env2["body"]["items"][0]["quantity"] = 3
    r = _send(seller, env2)
    assert r["type"] == "REJECT" and r["body"]["code"] == "idempotency_conflict"


def test_seller_business_rejects():
    seller = SellerAgent("http://127.0.0.1:9")
    for body, code in [
        ({"items": [{"sku": "nope", "quantity": 1}], "currency": "USD"}, "unknown_sku"),
        ({"items": [{"sku": "widget-std", "quantity": 1}], "currency": "JPY"}, "unsupported_currency"),
        ({"items": [{"sku": "widget-std", "quantity": 10}], "currency": "USD", "max_total_minor": 100}, "over_budget"),
    ]:
        r = _send(seller, new_envelope("RFQ", body, sender=BUYER))
        assert (r["type"], r["body"]["code"]) == ("REJECT", code)


def test_mock_escrow_rejects_expired_quote_and_is_labelled():
    escrow = MockEscrow("http://127.0.0.1:9")
    body = {"quote_id": "q1", "seller_agent_id": "s", "buyer_agent_id": "b", "currency": "USD",
            "amount_minor": 5000, "quote_expires_at": "2020-01-01T00:00:00Z"}
    r = _send(escrow, new_envelope("ESCROW_HANDOFF_REQUEST", body, sender=BUYER))
    assert r["body"]["code"] == "quote_expired"
    ok_body = dict(body, quote_expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat())
    req = new_envelope("ESCROW_HANDOFF_REQUEST", ok_body, sender=BUYER)
    ack = _send(escrow, req)
    assert ack["type"] == "ESCROW_HANDOFF_ACK"
    assert ack["body"]["mock"] is True and ack["body"]["funds_held_minor"] == 0
    assert ack["body"]["escrow_reference"].startswith("MOCK-ESC-")
    assert "NO REAL FUNDS" in ack["body"]["label"]
    assert _send(escrow, copy.deepcopy(req)) == ack                       # idempotent


def test_ack_without_mock_flag_is_invalid():
    env = new_envelope("ESCROW_HANDOFF_ACK", {"escrow_reference": "x", "state": "s", "funds_held_minor": 0},
                       sender=BUYER, in_reply_to="r")
    with pytest.raises(EnvelopeError):
        validate_envelope(env)


def test_extract_requires_exactly_one_envelope():
    env = rfq()
    with pytest.raises(EnvelopeError):
        extract_envelope({"parts": [{"text": "hello"}]})
    with pytest.raises(EnvelopeError):
        extract_envelope({"parts": [a2a.data_part(env), a2a.data_part(env)]})


def test_generated_envelopes_match_json_schema(envelope_validator):
    seller = SellerAgent("http://127.0.0.1:9")
    escrow = MockEscrow("http://127.0.0.1:9")
    r = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 4}], "currency": "USD",
                             "delivery_region": "US"}, sender=BUYER)
    q = _send(seller, r)
    h = new_envelope("ESCROW_HANDOFF_REQUEST", {
        "quote_id": q["id"], "quote_expires_at": q["expires_at"], "seller_agent_id": "s",
        "buyer_agent_id": "b", "currency": "USD", "amount_minor": q["body"]["total_minor"]}, sender=BUYER)
    ack = _send(escrow, h)
    rej = _send(seller, new_envelope("RFQ", {"items": [{"sku": "nope", "quantity": 1}], "currency": "USD"},
                                     sender=BUYER))
    for env in (r, q, h, ack, rej):
        errors = list(envelope_validator.iter_errors(env))
        assert not errors, (env["type"], [e.message for e in errors])
    bad = dict(ack, body={k: v for k, v in ack["body"].items() if k != "mock"})
    assert list(envelope_validator.iter_errors(bad))
    assert list(envelope_validator.iter_errors(dict(r, extra_field=1)))
