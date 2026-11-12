"""ONAA Protocol v0.1 envelopes as used by the demo agents: validation, signing, idempotency, replay,
legacy v0 compatibility and JSON Schema agreement. Envelope logic itself lives in onaa_protocol."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest
from onaa_protocol import StaticKeyResolver, new_envelope, order_terms_hash
from onaa_protocol.envelope import LEGACY_SPEC_VERSION

from onaa_demo import a2a
from onaa_demo.buyer import BuyerNode
from onaa_demo.commerce import EnvelopeError, ReplayGuard, extract_envelope, validate_envelope
from onaa_demo.mock_escrow import MockEscrow
from onaa_demo.seller import SellerAgent

T0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
BASE = "http://127.0.0.1:9"


@pytest.fixture
def parties():
    """Buyer/seller/escrow nodes whose key resolvers know each other (no network)."""
    buyer = BuyerNode("http://127.0.0.1:7")
    seller = SellerAgent("http://127.0.0.1:8")
    escrow = MockEscrow(BASE)
    keys = StaticKeyResolver({n.sender["agent_card_url"]: n.jwks() for n in (buyer, seller, escrow)})
    for n in (buyer, seller, escrow):
        n.keys = keys
    return buyer, seller, escrow, keys


def rfq(sender=None, **kw):
    body = kw.pop("body", {"items": [{"sku": "widget-std", "quantity": 3}], "currency": "USD"})
    return new_envelope("RFQ", body, sender=sender or {"agent_id": "t-buyer"}, now=kw.pop("now", T0), **kw)


def _send(agent, env):
    msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)])
    return extract_envelope(agent.handle(msg))


def test_valid_rfq_is_v0_1():
    env = rfq()
    assert validate_envelope(env, now=T0 + timedelta(minutes=1)) is env
    assert env["spec"] == "onaa.commerce/v0" and env["spec_version"] == "0.2.0"


def test_expired_and_future():
    with pytest.raises(EnvelopeError) as e:
        validate_envelope(rfq(ttl=timedelta(minutes=1)), now=T0 + timedelta(minutes=2))
    assert e.value.code == "expired"
    with pytest.raises(EnvelopeError):
        validate_envelope(rfq(now=T0 + timedelta(hours=1)), now=T0)


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


def test_replay_guard_idempotent_conflict_and_replay():
    g = ReplayGuard()
    env = rfq()
    assert g.check(env, now=T0) is None
    g.remember(env, {"cached": 1})
    assert g.check(copy.deepcopy(env), now=T0) == {"cached": 1}
    changed = copy.deepcopy(env)
    changed["body"]["items"][0]["quantity"] = 99
    with pytest.raises(EnvelopeError, match="idempotency_conflict"):
        g.check(changed, now=T0)
    with pytest.raises(EnvelopeError, match="replay"):
        g.check(dict(copy.deepcopy(env), idempotency_key="another-key-0123456789"), now=T0)


def test_seller_quote_is_signed_and_retry_safe(parties):
    buyer, seller, _, keys = parties
    env = new_envelope("RFQ", {"items": [{"sku": "widget-pro", "quantity": 2}], "currency": "EUR"},
                       sender=buyer.sender)
    q1 = _send(seller, env)
    assert q1["type"] == "QUOTE" and q1 == _send(seller, copy.deepcopy(env))
    assert q1["body"]["total_minor"] == 2 * 4599 and q1["body"]["revision"] == 1
    assert "signature" in q1
    env2 = copy.deepcopy(env)
    env2["body"]["items"][0]["quantity"] = 3
    r = _send(seller, env2)
    assert r["type"] == "REJECT" and r["body"]["code"] == "idempotency_conflict"


def test_seller_business_rejects(parties):
    _, seller, _, _ = parties
    for body, code in [
        ({"items": [{"sku": "nope", "quantity": 1}], "currency": "USD"}, "unknown_sku"),
        ({"items": [{"sku": "widget-std", "quantity": 1}], "currency": "JPY"}, "unsupported_currency"),
        ({"items": [{"sku": "widget-std", "quantity": 10}], "currency": "USD", "max_total_minor": 100}, "over_budget"),
    ]:
        r = _send(seller, new_envelope("RFQ", body, sender={"agent_id": "t-buyer"}))
        assert (r["type"], r["body"]["code"]) == ("REJECT", code)


def _order(buyer, quote, **override):
    qb = quote["body"]
    body = {"quote_id": quote["id"], "quote_revision": qb["revision"], "quote_terms_hash": qb["terms_hash"],
            "rfq_id": qb["rfq_id"], "buyer_agent_id": buyer.agent_id, "seller_agent_id": qb["seller_agent_id"],
            "currency": qb["currency"], "total_minor": qb["total_minor"]}
    body.update(override)
    return new_envelope("ORDER_PROPOSE", body, sender=buyer.sender, recipient=quote["sender"], signer=buyer.signer)


def test_order_flow_signed_and_bound(parties):
    buyer, seller, _, keys = parties
    quote = _send(seller, new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 2}], "currency": "USD"},
                                       sender=buyer.sender))
    bad = _send(seller, _order(buyer, quote, quote_terms_hash="sha256:" + "0" * 64))
    assert bad["body"]["code"] == "terms_mismatch"
    unsigned = _order(buyer, quote)
    unsigned.pop("signature")
    assert _send(seller, unsigned)["body"]["code"] == "signature_missing"
    order = _order(buyer, quote)
    confirm = _send(seller, order)
    assert confirm["type"] == "ORDER_CONFIRM" and "signature" in confirm
    assert confirm["body"]["order_terms_hash"] == order_terms_hash(order["body"])
    again = _order(buyer, quote)
    assert _send(seller, again)["body"]["code"] == "invalid_transition"      # quote already accepted
    cancel = new_envelope("ORDER_CANCEL", {"order_id": order["id"], "reason_code": "buyer_request"},
                          sender=buyer.sender, recipient=seller.sender, signer=buyer.signer)
    status = _send(seller, cancel)
    assert (status["type"], status["body"]["state"]) == ("ORDER_STATUS", "CANCELLED")


def _handoff(buyer, escrow, **override):
    body = {"service_type": "escrow", "mode": "mock", "order_id": "o-1",
            "parties": {"buyer_agent_id": buyer.agent_id, "seller_agent_id": "s"}, "currency": "USD",
            "amount_minor": 5000, "quote_expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat()}
    body.update(override)
    return new_envelope("SERVICE_HANDOFF_REQUEST", body, sender=buyer.sender, recipient=escrow.sender,
                        signer=buyer.signer)


def test_mock_escrow_handoff_is_mock_signed_and_idempotent(parties):
    buyer, _, escrow, _ = parties
    req = _handoff(buyer, escrow)
    ack = _send(escrow, req)
    assert ack["type"] == "SERVICE_HANDOFF_ACK" and "signature" in ack
    b = ack["body"]
    assert b["mock"] is True and b["mode"] == "mock" and b["funds_held_minor"] == 0
    assert b["provider_confirmed"] is False and b["state"] == "CREATED"
    assert b["handoff_reference"].startswith("MOCK-ESC-") and "NO REAL FUNDS" in b["label"]
    assert _send(escrow, copy.deepcopy(req)) == ack
    status = _send(escrow, new_envelope("SERVICE_STATUS_QUERY", {"handoff_reference": b["handoff_reference"]},
                                        sender=buyer.sender))
    assert status["type"] == "SERVICE_STATUS" and status["body"]["state"] != "SECURED"


@pytest.mark.parametrize("override,code", [
    ({"quote_expires_at": "2020-01-01T00:00:00Z"}, "quote_expired"),
    ({"mode": "live"}, "live_mode_not_supported"),
    ({"mode": "sandbox"}, "unsupported_mode"),
    ({"service_type": "insurance"}, "unsupported_service_type"),
])
def test_mock_escrow_rejects(parties, override, code):
    buyer, _, escrow, _ = parties
    r = _send(escrow, _handoff(buyer, escrow, **override))
    assert (r["type"], r["body"]["code"]) == ("REJECT", code)


def test_legacy_v0_escrow_alias_still_accepted(parties, v0_validator):
    _, _, escrow, _ = parties
    body = {"quote_id": "q1", "seller_agent_id": "s", "buyer_agent_id": "b", "currency": "USD",
            "amount_minor": 5000, "quote_expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat()}
    req = new_envelope("ESCROW_HANDOFF_REQUEST", body, sender={"agent_id": "legacy-buyer"},
                       spec_version=LEGACY_SPEC_VERSION)
    ack = _send(escrow, req)
    assert ack["type"] == "ESCROW_HANDOFF_ACK" and ack["spec_version"] == LEGACY_SPEC_VERSION
    assert ack["body"]["mock"] is True and ack["body"]["funds_held_minor"] == 0
    for env in (req, ack):                       # still valid under the superseded v0 schema
        assert not list(v0_validator.iter_errors(env))


def test_extract_requires_exactly_one_envelope():
    env = rfq()
    with pytest.raises(EnvelopeError):
        extract_envelope({"parts": [{"text": "hello"}]})
    with pytest.raises(EnvelopeError):
        extract_envelope({"parts": [a2a.data_part(env), a2a.data_part(env)]})


def test_generated_envelopes_match_json_schema(parties, envelope_validator):
    buyer, seller, escrow, _ = parties
    r = new_envelope("RFQ", {"items": [{"sku": "widget-std", "quantity": 4}], "currency": "USD",
                             "delivery_region": "US"}, sender=buyer.sender)
    q = _send(seller, r)
    o = _order(buyer, q)
    c = _send(seller, o)
    h = _handoff(buyer, escrow, order_id=o["id"], amount_minor=q["body"]["total_minor"])
    ack = _send(escrow, h)
    rej = _send(seller, new_envelope("RFQ", {"items": [{"sku": "nope", "quantity": 1}], "currency": "USD"},
                                     sender=buyer.sender))
    for env in (r, q, o, c, h, ack, rej):
        errors = list(envelope_validator.iter_errors(env))
        assert not errors, (env["type"], [e.message for e in errors])
    bad = dict(ack, body={k: v for k, v in ack["body"].items() if k != "mock"})
    assert list(envelope_validator.iter_errors(bad))
    assert list(envelope_validator.iter_errors(dict(r, extra_field=1)))
