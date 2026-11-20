"""The pilot's external auto buyer (examples/pilot-auto-buyer) haggles with a member's hosted agent end to end."""

from __future__ import annotations

import dataclasses
import importlib.util
import sys
from pathlib import Path

from conftest import ADMIN, ITEM_REQUIRED
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from onaa_protocol import Signer, StaticKeyResolver

from onaa_registry import hosting
from onaa_registry.main import create_app

SCRIPT = Path(__file__).resolve().parents[3] / "examples" / "pilot-auto-buyer" / "auto_buyer.py"
spec = importlib.util.spec_from_file_location("auto_buyer", SCRIPT)
auto_buyer = importlib.util.module_from_spec(spec)
sys.modules["auto_buyer"] = auto_buyer  # dataclasses look their module up
spec.loader.exec_module(auto_buyer)

A = {"Authorization": f"Bearer {ADMIN}"}
CARD = "https://auto-buyer.example/.well-known/agent-card.json"


def test_auto_buyer_haggles_and_orders(settings, fetcher, txt, runner):
    s = dataclasses.replace(settings, pilot_enabled=True, hosting_domain="agents.test", hosting_scheme="http",
                            hosted_agent_secret="test-only-hosted-agent-secret-0123456789")
    buyer = auto_buyer.Buyer("onaa-pilot-auto-buyer", CARD, Signer(Ed25519PrivateKey.generate(), "ab-k1"))
    with TestClient(create_app(s, fetcher, txt, runner)) as c:
        c.app.state.hosting = hosting.Runtime(
            s, c.app.state.sessionmaker,
            remote_keys=StaticKeyResolver({CARD: {"keys": [buyer.signer.public_jwk()]}}))
        tok = c.post("/v1/admin/market/members", headers=A, json={
            "nickname": "jun", "contact": "kakao:jun", "a2a_enabled": True}).json()["token"]
        h = {"Authorization": f"Bearer {tok}"}
        it = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED, "title": "Mechanical keyboard", "price": 50,
                                                         "floor_price": 44}).json()
        result = auto_buyer.run(c, buyer, "http://testserver", "keyboard", 5000, "USD", place_order=True)
        assert result["quote"]["body"]["total_minor"] >= 4400  # cents
        pending = result["order_reply"]
        assert pending["type"] == "REJECT" and pending["body"]["code"] == "awaiting_seller_approval"
        assert pending["body"]["retryable"] is True
        deal = c.get("/v1/market/agent/inbox", headers=h).json()["deals"][0]
        assert deal["state"] == "order_pending" and deal["pending_order"]["total"] == result["quote"]["body"][
            "total_minor"] / 100
        assert c.post(f"/v1/market/agent/deals/{deal['deal_id']}/approve", headers=h,
                      json={"user_approved": True}).status_code == 200
        out = auto_buyer.place(c, buyer, result["seller"], result["rfq"], result["quote"])
        assert out["type"] == "ORDER_CONFIRM"
        assert any("over_budget" in line for line in buyer.log)  # it really haggled
        assert c.get(f"/v1/market/items/{it['id']}", headers=h).json()["status"] == "reserved"
        inbox = c.get("/v1/market/agent/inbox", headers=h).json()["deals"][0]
        assert inbox["state"] == "confirmed" and inbox["counterparty"]["agent_id"] == "onaa-pilot-auto-buyer"
