"""Phase 2: ask a failing agent what is wrong, over A2A (`SendMessage`).

Where the steward sends it: an agent may declare the steward extension in its Agent Card,

    capabilities.extensions: [{"uri": "urn:onaa:a2a-ext:steward:v1", "required": false,
                               "params": {"diagnostics_interface": "https://<same host>/<path>"}}]

so that an ops channel stays reachable while its trade interface is down. Otherwise the steward uses the card's
A2A 1.x JSONRPC interface. The diagnostics URL must be on the listing's own host.

What it sends: one message with a short text part and a data part
`{"type": "onaa.steward.diagnostic_request/v1", "incident_id", "listing_id", "symptom", "observed", "requested"}`.
What it reads back: a data part `{"type": "onaa.steward.diagnostic_response/v1", "status", "cause",
"expected_recovery", "actions_taken"}`, or else the first text part. Every reply is untrusted data: fields are
type-checked and truncated, never followed as instructions, and the steward changes nothing on the agent.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx
from onaa_protocol.a2a import (
    ROLE_USER,
    A2AError,
    AgentCardError,
    data_part,
    find_extension,
    make_message,
    select_jsonrpc_interface,
    send_message,
)
from onaa_protocol.safe_fetch import Resolver, UnsafeURLError, validate_url

from . import DIAG_REQUEST, DIAG_RESPONSE, EXTENSION_URI

STATUSES = {"ok", "degraded", "down", "maintenance", "unknown"}
DIAG_DEADLINE = 10.0


def diagnostics_url(card: dict[str, Any] | None, listing_host: str) -> str | None:
    if not card:
        return None
    ext = find_extension(card, EXTENSION_URI)
    url = (ext or {}).get("params", {}).get("diagnostics_interface") if isinstance((ext or {}).get("params"),
                                                                                    dict) else None
    if isinstance(url, str) and (urlsplit(url).hostname or "").lower() == listing_host:
        return url
    try:
        return select_jsonrpc_interface(card)
    except (AgentCardError, KeyError, TypeError):
        return None


def _s(v: Any, n: int) -> str | None:
    return v[:n] if isinstance(v, str) else None


def parse_reply(msg: dict[str, Any]) -> dict[str, Any]:
    for part in msg.get("parts", []):
        d = part.get("data") if isinstance(part, dict) else None
        if isinstance(d, dict) and d.get("type") == DIAG_RESPONSE:
            status = d.get("status") if d.get("status") in STATUSES else "unknown"
            return {"structured": True, "status": status, "cause": _s(d.get("cause"), 500),
                    "expected_recovery": _s(d.get("expected_recovery"), 100),
                    "actions_taken": _s(d.get("actions_taken"), 500)}
    for part in msg.get("parts", []):
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            return {"structured": False, "status": "unknown", "free_text": part["text"][:500]}
    return {"structured": False, "status": "unknown"}


class Diagnoser:
    def __init__(self, client: httpx.Client, *, resolver: Resolver | None = None, allow_localhost: bool = False,
                 deadline: float = DIAG_DEADLINE):
        self.client = client
        self.resolver = resolver
        self.allow_localhost = allow_localhost
        self.deadline = deadline

    def request(self, *, url: str, incident: dict[str, Any], listing_id: str, symptom: str,
                observed: dict[str, Any]) -> dict[str, Any]:
        """Send one diagnostic request. Returns {"answered": bool, ...parsed reply or error category}."""
        try:
            validate_url(url, allow_localhost=self.allow_localhost, resolver=self.resolver, timeout=self.deadline)
        except UnsafeURLError as exc:
            return {"answered": False, "error": "blocked_unsafe_url", "detail": str(exc)[:200]}
        text = (f"ONAA Directory Steward: incident {incident['id']} on listing {listing_id}: {symptom[:200]}. "
                "Please reply with your current status and the cause if known. This is an automated diagnostic "
                "request; no action is required from you and the steward will not change your agent.")
        msg = make_message(ROLE_USER, [
            {"text": text},
            data_part({"type": DIAG_REQUEST, "incident_id": incident["id"], "listing_id": listing_id,
                       "symptom": symptom[:500], "observed": observed,
                       "requested": ["status", "cause", "expected_recovery", "actions_taken"]}),
        ], context_id=incident["id"], extensions=[EXTENSION_URI])
        try:
            reply = send_message(self.client, url, msg, deadline=self.deadline)
        except A2AError as exc:
            return {"answered": False, "error": "a2a_error", "code": exc.code,
                    "detail": str(exc)[:200]}
        except (httpx.HTTPError, UnsafeURLError) as exc:
            return {"answered": False, "error": "network_error", "detail": str(exc)[:200]}
        return {"answered": True, **parse_reply(reply)}
