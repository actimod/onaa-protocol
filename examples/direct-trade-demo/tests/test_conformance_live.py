"""The SAMPLE seller and MOCK escrow pass the ONAA Protocol v0.1 live conformance suite for their roles,
and the suite catches deliberately broken agents. Runs on ephemeral loopback ports (demo flag only)."""

from __future__ import annotations

import json

import pytest
from onaa_protocol.conformance import run_live, run_registry_live
from onaa_protocol.conformance.cli import main as conformance_cli

from onaa_demo.a2a import AGENT_CARD_PATH


def _fails(report):
    """Tests that did not pass and are applicable (n/a is not a failure)."""
    return {r["id"]: r["detail"] for r in report["results"] if r["outcome"] not in ("pass", "n/a")}


@pytest.mark.parametrize("node,role", [("seller", "seller_agent"), ("escrow", "service_provider"),
                                       ("buyer", "buyer_agent")])
def test_reference_agents_pass(trigger_network, node, role):
    """The buyer runs with its conformance trade trigger enabled, so its client-side tests apply."""
    url = getattr(trigger_network, node).base_url + AGENT_CARD_PATH
    report = run_live(url, role, allow_loopback=True)
    assert report["summary"]["verdict"] == "pass", _fails(report)
    assert report["summary"]["must"]["failed"] == report["summary"]["must"]["skipped"] == 0


def test_registry_stub_passes_and_is_not_a_relay(network):
    report = run_registry_live(network.registry_url, allow_loopback=True)
    assert report["summary"]["verdict"] == "pass", _fails(report)


def test_cli_writes_json_report(network, tmp_path):
    out = tmp_path / "report.json"
    code = conformance_cli(["--agent-card-url", network.seller.base_url + AGENT_CARD_PATH, "--role", "seller",
                            "--allow-loopback", "--out", str(out)])
    report = json.loads(out.read_text())
    assert code == 0 and report["role"] == "seller_agent" and report["mode"] == "live"
    assert {r["id"] for r in report["results"]} >= {"ONAA-C-MUST-001", "ONAA-C-MUST-021", "ONAA-C-SHOULD-001"}


def test_without_loopback_flag_nothing_is_contacted(network, monkeypatch):
    monkeypatch.delenv("ONAA_DEMO_ALLOW_LOCALHOST", raising=False)
    report = run_live(network.seller.base_url + AGENT_CARD_PATH, "seller_agent")
    assert report["results"][0]["outcome"] == "fail" and report["summary"]["verdict"] == "fail"
    assert network.seller.request_log == []


def test_seller_that_skips_signature_checks_fails(network, monkeypatch):
    from onaa_protocol import check_recipient, validate_envelope

    import onaa_demo.node as node_mod

    def no_verify(env, keys, *, expected_recipient=None, **kw):  # broken: never verifies signatures
        validate_envelope(env, **kw)
        if expected_recipient is not None:
            check_recipient(env, expected_recipient)
        return env
    monkeypatch.setattr(node_mod, "check_envelope", no_verify)
    report = run_live(network.seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True)
    fails = _fails(report)
    # forged, wrong-typ, alg none/HS256, embedded-jwk, revoked and unknown-kid signatures are all accepted;
    # everything else (presence of signatures, card binding, state machines) still passes
    assert set(fails) == {"ONAA-C-MUST-015", "ONAA-C-MUST-016", "ONAA-C-MUST-017", "ONAA-C-MUST-018",
                          "ONAA-C-MUST-019", "ONAA-C-MUST-050", "ONAA-C-MUST-075"}, fails
    assert report["summary"]["verdict"] == "fail"


def test_unsigned_confirm_and_quote_fail(network, monkeypatch):
    seller = network.seller
    orig_rfq, orig_order = seller._on_rfq, seller._on_order_propose

    def strip(env):
        env.pop("signature", None)
        return env
    monkeypatch.setattr(seller, "_on_rfq", lambda e: strip(orig_rfq(e)))
    monkeypatch.setattr(seller, "_on_order_propose", lambda e: strip(orig_order(e)))
    report = run_live(seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True)
    fails = _fails(report)
    assert "ONAA-C-SHOULD-001" in fails and "ONAA-C-MUST-021" in fails
    assert report["summary"]["verdict"] == "fail"


def test_escrow_claiming_secured_in_mock_fails(network, monkeypatch):
    escrow = network.escrow
    orig = escrow._on_service_handoff_request

    def lie(env):
        ack = orig(env)
        ack.pop("signature")
        ack["body"].update(state="SECURED", provider_confirmed=True)
        from onaa_protocol import sign_envelope
        return sign_envelope(ack, escrow.signer)
    monkeypatch.setattr(escrow, "_on_service_handoff_request", lie)
    report = run_live(escrow.base_url + AGENT_CARD_PATH, "service_provider", allow_loopback=True)
    assert "ONAA-C-MUST-030" in _fails(report)
    assert report["summary"]["verdict"] == "fail"


def test_seller_without_order_checks_fails(network, monkeypatch):
    """A seller that confirms every signed ORDER_PROPOSE without checking it against the QUOTE."""
    from onaa_protocol import new_envelope, order_terms_hash

    seller = network.seller

    def confirm_anything(order):
        return new_envelope("ORDER_CONFIRM", {
            "order_id": order["id"], "order_terms_hash": order_terms_hash(order["body"]),
            "quote_id": order["body"]["quote_id"], "state": "CONFIRMED"}, sender=seller.sender,
            recipient=order["sender"], in_reply_to=order["id"], signer=seller.signer)
    monkeypatch.setattr(seller, "_on_order_propose", confirm_anything)
    fails = _fails(run_live(seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert {"ONAA-C-MUST-022", "ONAA-C-MUST-023", "ONAA-C-MUST-024", "ONAA-C-MUST-025",
            "ONAA-C-MUST-071"} <= set(fails), fails


def test_seller_accepting_any_order_status_fails(network, monkeypatch):
    """A seller that believes a counterparty's SECURED claim and skips the ORDER state machine."""
    seller = network.seller
    monkeypatch.setattr(seller, "_on_order_status", seller._receipt)
    fails = _fails(run_live(seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert {"ONAA-C-MUST-028", "ONAA-C-MUST-029"} <= set(fails), fails


def test_reject_echoing_untrusted_input_fails(network, monkeypatch):
    import json

    import onaa_demo.node as node_mod

    seller = network.seller
    real_reject = node_mod.reject

    def echoing_reject(env, sender, code, message="", **kw):  # broken: quotes the request in REJECT.message
        body = env.get("body") if isinstance(env, dict) else None
        return real_reject(env, sender, code, "refused: " + json.dumps(body)[:300], **kw)
    monkeypatch.setattr(node_mod, "reject", echoing_reject)
    fails = _fails(run_live(seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert "ONAA-C-MUST-058" in fails, fails


def test_seller_answering_legacy_rfq_at_0_2_fails(network, monkeypatch):
    import onaa_demo.seller as seller_mod

    monkeypatch.setattr(seller_mod, "is_legacy", lambda env: False)
    fails = _fails(run_live(network.seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert set(fails) == {"ONAA-C-MUST-072"}, fails


def test_buyer_without_replay_protection_fails(network, monkeypatch):
    monkeypatch.setattr(network.buyer.guard, "reserve", lambda env, now=None, **kw: None)
    report = run_live(network.buyer.base_url + AGENT_CARD_PATH, "buyer_agent", allow_loopback=True)
    assert set(_fails(report)) == {"ONAA-C-MUST-065"}, _fails(report)
    assert report["summary"]["verdict"] == "fail"


def test_escrow_disclosing_status_to_anyone_fails(network, monkeypatch):
    escrow = network.escrow
    orig = escrow._on_service_status_query

    def leak(env):
        h = escrow.handoffs.get(env["body"]["handoff_reference"])
        if h is not None:
            h["parties"].add(env["sender"]["agent_id"])
        return orig(env)
    monkeypatch.setattr(escrow, "_on_service_status_query", leak)
    report = run_live(escrow.base_url + AGENT_CARD_PATH, "service_provider", allow_loopback=True)
    failed = {r["id"] for r in report["results"] if r["outcome"] == "fail"}
    assert failed == {"ONAA-C-SHOULD-015"}, _fails(report)
    assert report["summary"]["verdict"] == "pass"          # 8/9 SHOULD still >= 80%


def test_buyer_without_inbound_endpoint_types_is_not_applicable(network, monkeypatch):
    """SendMessage is SHOULD for buyers: with no declared inbound request types the buyer tests are n/a."""
    buyer = network.buyer
    monkeypatch.setitem(buyer.params, "message_types", ["RECEIPT"])
    report = run_live(buyer.base_url + AGENT_CARD_PATH, "buyer_agent", allow_loopback=True)
    na = {r["id"] for r in report["results"] if r["outcome"] == "n/a"}
    assert {"ONAA-C-MUST-060", "ONAA-C-MUST-062", "ONAA-C-MUST-065"} <= na, na
    assert {f"ONAA-C-MUST-0{n}" for n in range(80, 92)} <= na, na  # trigger not enabled: client tests n/a
    assert report["summary"]["verdict"] == "pass", _fails(report)


def test_agent_verifying_only_must_sign_types_fails(network, monkeypatch):
    """Section 9.2: an invalid optional signature (here on an RFQ) is still a failure."""
    from onaa_protocol import MUST_SIGN, check_envelope, check_recipient, validate_envelope

    import onaa_demo.node as node_mod

    def must_sign_only(env, keys, *, expected_recipient=None, **kw):
        if env.get("type") in MUST_SIGN:
            return check_envelope(env, keys, expected_recipient=expected_recipient, **kw)
        validate_envelope(env, **kw)
        if expected_recipient is not None:
            check_recipient(env, expected_recipient)
        return env
    monkeypatch.setattr(node_mod, "check_envelope", must_sign_only)
    fails = _fails(run_live(network.seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert set(fails) == {"ONAA-C-MUST-075"}, fails


def test_seller_fetching_tracking_url_fails(network, monkeypatch):
    import httpx

    seller = network.seller
    orig = seller._on_order_status

    def fetch_then_handle(env):
        url = env["body"].get("fulfillment", {}).get("tracking_url")
        if url:
            httpx.get(url, timeout=2.0)          # broken: dereferences untrusted URLs
        return orig(env)
    monkeypatch.setattr(seller, "_on_order_status", fetch_then_handle)
    fails = _fails(run_live(seller.base_url + AGENT_CARD_PATH, "seller_agent", allow_loopback=True))
    assert set(fails) == {"ONAA-C-MUST-073"}, fails
