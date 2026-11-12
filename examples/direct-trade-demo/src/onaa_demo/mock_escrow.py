"""MOCK escrow service (ENG-017 mock part). NO REAL FUNDS. NOT AN ESCROW AGENT.

Accepts an onaa.commerce/v0 ESCROW_HANDOFF_REQUEST over A2A 1.0 and returns an
ESCROW_HANDOFF_ACK carrying a ``MOCK-`` reference. It moves no money, stores no
payment data, holds nothing (``funds_held_minor`` is always 0) and is never a
merchant of record. Any real provider integration needs a vendor-confirmed
sandbox and explicit approval by the ONAA maintainers.
"""

from __future__ import annotations

import hashlib
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
    parse_ts,
    utcnow,
    validate_envelope,
)
from .seller import reject, reply_message

ESCROW_AGENT_ID = "mock-escrow-service"
MOCK_LABEL = "MOCK ESCROW - NO REAL FUNDS - NOT A LICENSED ESCROW SERVICE"


class MockEscrow:
    def __init__(self, base_url: str, agent_id: str = ESCROW_AGENT_ID) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.sender = {"agent_id": agent_id, "agent_card_url": self.base_url + a2a.AGENT_CARD_PATH}
        self.guard = ReplayGuard()
        self.request_log: list[dict[str, Any]] = []
        self.handoffs: dict[str, dict[str, Any]] = {}
        self.card = a2a.build_agent_card(
            name="ONAA MOCK Escrow Service",
            description=MOCK_LABEL + ". Demo handoff only; returns a mock transaction reference.",
            version="0.1.0",
            base_url=self.base_url,
            skills=[
                {
                    "id": "onaa-mock-escrow-handoff",
                    "name": "Mock escrow handoff",
                    "description": "Accepts ESCROW_HANDOFF_REQUEST; returns a MOCK reference. No funds move.",
                    "tags": ["escrow", "mock", "sandbox", "sample"],
                }
            ],
            extensions=[{
                "uri": EXTENSION_URI,
                "description": "ONAA commerce envelope onaa.commerce/v0 (DRAFT)",
                "required": True,
                "params": {"message_types": ["ESCROW_HANDOFF_REQUEST", "ESCROW_HANDOFF_ACK", "REJECT"],
                           "mock": True},
            }],
            provider={"organization": "ONAA reference MOCK (not a real escrow provider)", "url": self.base_url},
        )

    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        env: dict[str, Any] | None = None
        try:
            env = extract_envelope(message)
            validate_envelope(env, expected_types=("ESCROW_HANDOFF_REQUEST",))
            cached = self.guard.check(env)
            if cached is not None:
                return reply_message(cached, message)
            body = env["body"]
            if parse_ts(body["quote_expires_at"], "quote_expires_at") <= utcnow():
                raise EnvelopeError("quote_expired", "referenced quote has expired")
            ref = "MOCK-ESC-" + hashlib.sha256(
                (env["sender"]["agent_id"] + ":" + env["idempotency_key"]).encode()
            ).hexdigest()[:16].upper()
            out = new_envelope(
                "ESCROW_HANDOFF_ACK",
                {
                    "mock": True,
                    "label": MOCK_LABEL,
                    "escrow_reference": ref,
                    "state": "MOCK_CREATED",
                    "quote_id": body["quote_id"],
                    "currency": body["currency"],
                    "amount_minor": body["amount_minor"],
                    "funds_held_minor": 0,
                    "next_step": "None. In a real flow the buyer would follow the provider's own funding "
                                 "instructions; ONAA and this mock never touch funds.",
                },
                sender=self.sender,
                recipient=env["sender"],
                in_reply_to=env["id"],
                ttl=timedelta(hours=1),
            )
        except EnvelopeError as exc:
            out = reject(env if isinstance(env, dict) else None, self.sender, exc.code, exc.message)
            return reply_message(out, message)
        self.handoffs[ref] = out
        self.guard.remember(env, out)
        return reply_message(out, message)

    def app(self) -> Starlette:
        return a2a.create_agent_app(self.card, self.handle, required_extensions={EXTENSION_URI},
                                    request_log=self.request_log)
