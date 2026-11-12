"""MOCK escrow service (ENG-017 mock part). NO REAL FUNDS. NOT AN ESCROW AGENT.

Implements the ONAA Protocol v0.1 generic service handoff with ``service_type=escrow`` and
``mode=mock``: signed SERVICE_HANDOFF_REQUEST -> signed SERVICE_HANDOFF_ACK (``MOCK-`` reference),
SERVICE_STATUS_QUERY -> signed SERVICE_STATUS. It also accepts the legacy ``ESCROW_HANDOFF_REQUEST``
alias at spec_version 0.1.0 (spec section 8.6). It moves no money, stores no payment data, holds
nothing (``funds_held_minor`` is always 0), never reports SECURED/HELD and is never a merchant of record.
Any real provider integration needs a vendor-confirmed sandbox and founder approval.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import timedelta
from typing import Any

from onaa_protocol import ProtocolError, new_envelope
from onaa_protocol.envelope import LEGACY_SPEC_VERSION, format_ts, parse_ts, utcnow

from .node import DemoNode

ESCROW_AGENT_ID = "mock-escrow-service"
MAX_HANDOFFS = 10_000  # mock handoffs kept in memory; new requests are refused (rate_limited) beyond this
MOCK_LABEL = "MOCK ESCROW - NO REAL FUNDS - NOT A LICENSED ESCROW SERVICE"


class MockEscrow(DemoNode):
    accepts = ("SERVICE_HANDOFF_REQUEST", "SERVICE_STATUS_QUERY", "ESCROW_HANDOFF_REQUEST")

    def __init__(self, base_url: str, agent_id: str = ESCROW_AGENT_ID, **kw: Any) -> None:
        super().__init__(
            base_url, agent_id, name="ONAA MOCK Escrow Service",
            description=MOCK_LABEL + ". Demo handoff only; returns a mock transaction reference.",
            roles=["service_provider"],
            skills=[{"id": "onaa-mock-escrow-handoff", "name": "Mock escrow handoff",
                     "description": "Accepts SERVICE_HANDOFF_REQUEST (escrow, mock); returns a MOCK reference.",
                     "tags": ["escrow", "mock", "sample"]}],
            provider={"organization": "ONAA reference MOCK (not a real escrow provider)",
                      "url": base_url.rstrip("/")},
            service_types=["escrow"], service_modes=["mock"], regions=["GLOBAL"], currencies=["USD", "EUR"], **kw)
        self._lock = threading.Lock()
        self.handoffs: dict[str, dict[str, Any]] = {}

    def _ref(self, env: dict[str, Any]) -> str:
        digest = hashlib.sha256((env["sender"]["agent_id"] + ":" + env["idempotency_key"]).encode()).hexdigest()
        return "MOCK-ESC-" + digest[:16].upper()

    def dispatch(self, env: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if env["type"] != "SERVICE_STATUS_QUERY" and len(self.handoffs) >= MAX_HANDOFFS:
                raise ProtocolError("rate_limited", "too many mock handoffs")
            return getattr(self, "_on_" + env["type"].lower())(env)

    def _on_service_handoff_request(self, env: dict[str, Any]) -> dict[str, Any]:
        b = env["body"]
        if b["service_type"] != "escrow":
            raise ProtocolError("unsupported_service_type", "this provider only offers escrow")
        if b["mode"] != "mock":
            raise ProtocolError("unsupported_mode", "this provider only offers mode=mock")
        if "quote_expires_at" in b and parse_ts(b["quote_expires_at"], "quote_expires_at") <= utcnow():
            raise ProtocolError("quote_expired", "referenced quote has expired")
        ref = self._ref(env)
        now = utcnow()
        self.handoffs[ref] = {"order_id": b["order_id"], "state": "CREATED", "updated_at": format_ts(now),
                              "requester": env["sender"]["agent_id"],
                              "parties": {env["sender"]["agent_id"], *b["parties"].values()}}
        return new_envelope("SERVICE_HANDOFF_ACK", {
            "service_type": "escrow", "mode": "mock", "mock": True, "label": MOCK_LABEL, "handoff_reference": ref,
            "state": "CREATED", "provider_state": "MOCK_CREATED", "provider_confirmed": False,
            "order_id": b["order_id"], "currency": b["currency"], "amount_minor": b["amount_minor"],
            "funds_held_minor": 0,
            "next_step": "None. In a real flow the buyer would follow the provider's own funding instructions; "
                         "ONAA and this mock never touch funds.",
        }, sender=self.sender, recipient=env["sender"], in_reply_to=env["id"], ttl=timedelta(hours=1), now=now,
            signer=self.signer)

    def _on_service_status_query(self, env: dict[str, Any]) -> dict[str, Any]:
        h = self.handoffs.get(env["body"]["handoff_reference"])
        # Spec 8.5: disclose status only to the parties named in the request. Non-parties get the same
        # answer as an unknown reference, so the existence of a handoff is not revealed.
        if h is None or env["sender"]["agent_id"] not in h["parties"]:
            raise ProtocolError("unknown_reference", "handoff_reference is not known to this provider")
        return new_envelope("SERVICE_STATUS", {
            "service_type": "escrow", "mode": "mock", "mock": True,
            "handoff_reference": env["body"]["handoff_reference"], "state": h["state"],
            "provider_state": "MOCK_CREATED", "provider_confirmed": False, "order_id": h["order_id"],
            "funds_held_minor": 0, "updated_at": h["updated_at"],
        }, sender=self.sender, recipient=env["sender"], in_reply_to=env["id"], ttl=timedelta(minutes=15),
            signer=self.signer)

    def _on_escrow_handoff_request(self, env: dict[str, Any]) -> dict[str, Any]:
        """Legacy v0 alias (spec_version 0.1.0, unsigned): answered in the legacy shape, mock only."""
        b = env["body"]
        if parse_ts(b["quote_expires_at"], "quote_expires_at") <= utcnow():
            raise ProtocolError("quote_expired", "referenced quote has expired")
        ref = self._ref(env)
        self.handoffs[ref] = {"order_id": b["quote_id"], "state": "CREATED", "updated_at": format_ts(utcnow()),
                              "requester": env["sender"]["agent_id"],
                              "parties": {env["sender"]["agent_id"], b["buyer_agent_id"], b["seller_agent_id"]}}
        return new_envelope("ESCROW_HANDOFF_ACK", {
            "mock": True, "label": MOCK_LABEL, "escrow_reference": ref, "state": "MOCK_CREATED",
            "quote_id": b["quote_id"], "currency": b["currency"], "amount_minor": b["amount_minor"],
            "funds_held_minor": 0,
        }, sender={"agent_id": self.agent_id}, recipient=env["sender"], in_reply_to=env["id"],
            ttl=timedelta(hours=1), spec_version=LEGACY_SPEC_VERSION)
