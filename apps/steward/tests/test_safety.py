"""Steward guardrails: SSRF-safe probing, untrusted diagnostics channels, no direct power."""

from __future__ import annotations

from conftest import register
from fakes import FakeAgent

from onaa_steward.diagnostics import diagnostics_url, parse_reply
from onaa_steward.probe import Prober
from onaa_steward.validator import check_duplicates


def test_private_address_is_never_probed(net):
    prober = Prober(net.client(), resolver=lambda h, p: ["10.0.0.5"])
    res = prober.probe({"listing_type": "agent", "agent_card_url": "https://seller.example.com/.well-known/a.json"})
    assert res.result == "blocked_unsafe_url" and net.log == []


def test_plain_http_is_refused(net):
    res = Prober(net.client(), resolver=lambda h, p: ["93.184.215.14"]).probe(
        {"listing_type": "service", "endpoint_url": "http://seller.example.com/x"})
    assert res.result == "blocked_unsafe_url" and net.log == []


def test_off_host_diagnostics_channel_is_ignored():
    agent = FakeAgent("seller.example.com", "S")
    card = agent.card()
    card["capabilities"]["extensions"][0]["params"]["diagnostics_interface"] = "https://attacker.example.net/x"
    assert diagnostics_url(card, "seller.example.com") == "https://seller.example.com/a2a/v1"


def test_reply_fields_are_bounded_and_typed():
    out = parse_reply({"parts": [{"data": {"type": "onaa.steward.diagnostic_response/v1", "status": "pwned",
                                           "cause": "x" * 5000, "expected_recovery": 5}}]})
    assert out["status"] == "unknown" and len(out["cause"]) == 500 and out["expected_recovery"] is None


def test_suspension_is_only_a_request(registry, steward, seller):
    sid = register(registry, seller, "seller_agent", ["commerce.rfq.receive"])
    d = steward.escalate("listing.suspend", sid, "repeated fraud reports", {"reports": 3})
    assert d["decision"] == "pending_approval"
    assert registry.get(f"/v1/agents/{sid}").json()["status"] == "registered"
    assert steward.registry.request("listing.delete_everything", sid)["decision"] == "denied"


def test_validation_flags_unbacked_protocol_and_duplicates(registry, steward, seller):
    sid = register(registry, seller, "seller_agent", ["commerce.rfq.receive"])
    seller_card = seller.card()
    seller_card["supportedInterfaces"][0]["protocolVersion"] = "0.3"
    seller.card = lambda: seller_card
    rep = steward.validate(sid)
    codes = {f["code"] for f in rep["findings"]}
    assert not rep["ok"] and {"no_a2a_1x_interface", "protocol_claim_unbacked"} <= codes
    assert "steward:metadata_errors" in registry.get(f"/v1/agents/{sid}").json()["trust"]["review_flags"]
    rec = {"id": "a", "display_name": "Shop", "endpoint_url": "https://x.example.com/a2a"}
    dup = check_duplicates(rec, [{"id": "b", "display_name": "Other", "endpoint_url": "https://x.example.com/a2a"},
                                 {"id": "c", "display_name": "SHOP!", "endpoint_url": "https://y.example.com/"}])
    assert [f.code for f in dup] == ["duplicate_endpoint", "possible_name_conflict"]


def test_single_failed_sweep_probe_does_not_open_incident(registry, steward, seller):
    sid = register(registry, seller, "seller_agent", ["commerce.rfq.receive"])
    seller.fault = True
    steward.sweep()
    assert registry.get("/v1/incidents", params={"listing_id": sid}).json()["items"] == []
    steward.sweep()
    steward.sweep()  # third consecutive failure: registry marks unreachable -> incident
    assert registry.get("/v1/incidents", params={"listing_id": sid}).json()["items"][0]["kind"] == "unreachable"
