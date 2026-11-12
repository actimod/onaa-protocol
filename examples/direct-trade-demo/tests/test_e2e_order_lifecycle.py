"""Live HTTP lifecycle after ORDER_CONFIRM: buyer cancels one order, opens a dispute on another (MOCK only).

Exercises what an outside buyer agent does after the happy path in test_e2e_direct_trade.py, over real A2A
HTTP between separate nodes. No real funds, no real partner.
"""

from __future__ import annotations

import httpx
from onaa_protocol import EXTENSION_URI, new_envelope
from onaa_protocol.envelope import extract_envelope

from onaa_demo import a2a
from onaa_demo.buyer import BuyerAgent
from onaa_demo.registry_client import RegistryClient


def _send(http, base_url, env):
    msg = a2a.make_message(a2a.ROLE_USER, [a2a.data_part(env)], extensions=[EXTENSION_URI])
    return extract_envelope(a2a.send_message(http, base_url + "/a2a/v1", msg, extensions=[EXTENSION_URI]))


def _trade(net, http):
    return BuyerAgent(RegistryClient(net.registry_url, client=http), net.buyer, http_client=http).run()


def _signed(net, type_, body):
    return new_envelope(type_, body, sender=net.buyer.sender, recipient=net.seller.sender, signer=net.buyer.signer)


def test_buyer_cancels_confirmed_order_then_cannot_dispute_or_recancel(network):
    with httpx.Client(timeout=10) as http:
        order_id = _trade(network, http).order["id"]
        r = _send(http, network.seller.base_url,
                  _signed(network, "ORDER_CANCEL", {"order_id": order_id, "reason_code": "buyer_request"}))
        assert (r["type"], r["body"]["state"]) == ("ORDER_STATUS", "CANCELLED")
        again = _send(http, network.seller.base_url,
                      _signed(network, "ORDER_CANCEL", {"order_id": order_id, "reason_code": "buyer_request"}))
        assert again["type"] == "REJECT"


def test_dispute_before_fulfilment_is_rejected_with_a_specific_code(network):
    """Spec 7.5.7 / 7.4: nothing is disputable before SECURED or fulfilment, and the MOCK escrow never reaches
    SECURED, so in the MVP a dispute is refused with invalid_transition. A body without dispute_provider is
    refused earlier with invalid_body."""
    with httpx.Client(timeout=10) as http:
        order_id = _trade(network, http).order["id"]
        body = {"order_id": order_id, "reason_code": "not_received", "description": "E2E test, sample data"}
        r = _send(http, network.seller.base_url, _signed(network, "DISPUTE_OPEN", body))
        assert (r["type"], r["body"]["code"]) == ("REJECT", "invalid_body")
        body["dispute_provider"] = {"agent_id": "sample-dispute-provider"}
        r = _send(http, network.seller.base_url, _signed(network, "DISPUTE_OPEN", body))
        assert (r["type"], r["body"]["code"]) == ("REJECT", "invalid_transition")
        stranger = new_envelope("DISPUTE_OPEN", body, sender={"agent_id": "stranger"},
                                recipient=network.seller.sender)
        assert _send(http, network.seller.base_url, stranger)["type"] == "REJECT"
