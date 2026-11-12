"""Reference SELLER agent (SAMPLE). Answers onaa.commerce/v0 RFQs with QUOTEs over A2A 1.0.

The catalog and prices are fictional sample data.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from starlette.applications import Starlette

from . import a2a
from .commerce import (
    EXTENSION_URI,
    EnvelopeError,
    ReplayGuard,
    extract_envelope,
    new_envelope,
    validate_envelope,
)

SELLER_AGENT_ID = "sample-seller-agent"
QUOTE_TTL = timedelta(minutes=15)

# Fictional SAMPLE catalog; prices in minor units.
CATALOG: dict[str, dict[str, Any]] = {
    "widget-std": {"description": "Standard widget (SAMPLE)", "unit_price_minor": {"USD": 1250, "EUR": 1150}},
    "widget-pro": {"description": "Pro widget (SAMPLE)", "unit_price_minor": {"USD": 4999, "EUR": 4599}},
}


def commerce_extension_decl(required: bool = True) -> dict[str, Any]:
    return {
        "uri": EXTENSION_URI,
        "description": "ONAA commerce envelope onaa.commerce/v0 (DRAFT, not an official A2A extension)",
        "required": required,
        "params": {"spec": "onaa.commerce/v0", "message_types": ["RFQ", "QUOTE", "REJECT"]},
    }


def reject(env_in: dict[str, Any] | None, sender: dict[str, str], code: str, message: str) -> dict[str, Any]:
    return new_envelope(
        "REJECT",
        {"code": code, "message": message},
        sender=sender,
        in_reply_to=(env_in or {}).get("id"),
        ttl=timedelta(minutes=5),
    )


def reply_message(env: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    return a2a.make_message(
        a2a.ROLE_AGENT,
        [a2a.data_part(env)],
        context_id=incoming.get("contextId"),
        extensions=[EXTENSION_URI],
    )


class SellerAgent:
    def __init__(self, base_url: str, agent_id: str = SELLER_AGENT_ID) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.sender = {"agent_id": agent_id, "agent_card_url": self.base_url + a2a.AGENT_CARD_PATH}
        self.guard = ReplayGuard()
        self.request_log: list[dict[str, Any]] = []
        self.card = a2a.build_agent_card(
            name="ONAA Sample Seller Agent",
            description="Reference SAMPLE seller for the ONAA direct-trade demo. Fictional catalog.",
            version="0.1.0",
            base_url=self.base_url,
            skills=[
                {
                    "id": "onaa-rfq-quote",
                    "name": "RFQ to QUOTE",
                    "description": "Accepts an onaa.commerce/v0 RFQ and returns an expiring QUOTE.",
                    "tags": ["commerce", "rfq", "quote", "sample"],
                }
            ],
            extensions=[commerce_extension_decl()],
            provider={"organization": "ONAA reference sample (not a real business)",
                      "url": self.base_url},
        )

    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        env: dict[str, Any] | None = None
        try:
            env = extract_envelope(message)
            validate_envelope(env, expected_types=("RFQ",))
            cached = self.guard.check(env)
            if cached is not None:
                return reply_message(cached, message)
            out = self._quote(env)
        except EnvelopeError as exc:
            out = reject(env if isinstance(env, dict) else None, self.sender, exc.code, exc.message)
            return reply_message(out, message)
        self.guard.remember(env, out)
        return reply_message(out, message)

    def _quote(self, rfq: dict[str, Any]) -> dict[str, Any]:
        body = rfq["body"]
        currency = body["currency"]
        lines = []
        for item in body["items"]:
            entry = CATALOG.get(item["sku"])
            if entry is None:
                raise EnvelopeError("unknown_sku", f"sku {item['sku']!r} not offered")
            price = entry["unit_price_minor"].get(currency)
            if price is None:
                raise EnvelopeError("unsupported_currency", f"{currency} not offered")
            lines.append({
                "sku": item["sku"],
                "description": entry["description"],
                "quantity": item["quantity"],
                "unit_price_minor": price,
                "line_total_minor": price * item["quantity"],
            })
        total = sum(ln["line_total_minor"] for ln in lines)
        if "max_total_minor" in body and total > body["max_total_minor"]:
            raise EnvelopeError("over_budget", "quote total exceeds max_total_minor")
        return new_envelope(
            "QUOTE",
            {
                "rfq_id": rfq["id"],
                "currency": currency,
                "line_items": lines,
                "total_minor": total,
                "settlement": {
                    "escrow_required": True,
                    "accepted_service_types": ["escrow"],
                    "note": "Buyer selects any registry-listed escrow provider; seller holds no buyer funds.",
                },
                "sample": True,
            },
            sender=self.sender,
            recipient=rfq["sender"],
            in_reply_to=rfq["id"],
            ttl=QUOTE_TTL,
        )

    def app(self) -> Starlette:
        return a2a.create_agent_app(self.card, self.handle, required_extensions={EXTENSION_URI},
                                    request_log=self.request_log)
