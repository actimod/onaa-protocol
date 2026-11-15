"""Health and basic A2A compatibility probes against registered agents (untrusted peers).

All outbound requests use `onaa_protocol.safe_fetch.request_bytes`: https only, every resolved address must be
public, the connection is pinned to the checked address, no redirects, size cap and a total deadline. Bodies
are untrusted data: parsed with strict JSON, never executed, and only bounded summaries are kept.

Probe steps for an agent listing:
1. GET the Agent Card (listing `agent_card_url`, else the endpoint origin + /.well-known/agent-card.json) and
   validate it against the A2A 1.0 structure.
2. Compatibility: POST one harmless JSON-RPC 2.0 request (`GetTask` for a task id that cannot exist) with
   `A2A-Version: 1.0` to the card's A2A 1.x JSONRPC interface. Any well-formed JSON-RPC answer, result or
   error, shows the endpoint speaks A2A JSON-RPC.
Services and hosting listings without a card get one GET of their endpoint (or documentation) URL.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from onaa_protocol.a2a import (
    A2A_VERSION,
    AGENT_CARD_PATH,
    AgentCardError,
    select_jsonrpc_interface,
    validate_agent_card,
)
from onaa_protocol.safe_fetch import Resolver, UnsafeURLError, loads_json, request_bytes

PROBE_DEADLINE = 8.0
PROBE_METHOD = "GetTask"


@dataclass
class ProbeResult:
    result: str                      # registry health category (ok, timeout, http_5xx, bad_card, not_jsonrpc, ...)
    latency_ms: int | None = None
    card: dict[str, Any] | None = None
    card_error: str | None = None
    rpc_url: str | None = None
    jsonrpc_ok: bool | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def healthy(self) -> bool:
        return self.result == "ok"


def card_url_for(listing: dict[str, Any]) -> str | None:
    if listing.get("agent_card_url"):
        return listing["agent_card_url"]
    ep = listing.get("endpoint_url")
    if not ep:
        return None
    p = urlsplit(ep)
    return urlunsplit((p.scheme, p.netloc, AGENT_CARD_PATH, "", ""))


def _classify(exc: Exception) -> str:
    msg = str(exc).lower()
    if isinstance(exc, httpx.TimeoutException) or "deadline" in msg or "timed out" in msg:
        return "timeout"
    if isinstance(exc, UnsafeURLError):
        if "resolve" in msg:
            return "unresolved"
        if "too large" in msg:
            return "too_large"
        return "blocked_unsafe_url"
    return "network_error"


class Prober:
    def __init__(self, client: httpx.Client, *, resolver: Resolver | None = None, allow_localhost: bool = False,
                 deadline: float = PROBE_DEADLINE):
        self.client = client
        self.resolver = resolver
        self.allow_localhost = allow_localhost
        self.deadline = deadline

    def _req(self, method: str, url: str, **kw: Any) -> tuple[int, bytes, int]:
        t0 = time.monotonic()
        status, _headers, body = request_bytes(self.client, method, url, allow_localhost=self.allow_localhost,
                                               resolver=self.resolver, deadline=self.deadline, **kw)
        return status, body, int((time.monotonic() - t0) * 1000)

    def fetch_card(self, url: str) -> tuple[dict | None, str | None, str, int | None]:
        """(card, card_error, result_category, latency_ms)."""
        try:
            status, body, ms = self._req("GET", url, headers={"Accept": "application/json"})
        except (UnsafeURLError, httpx.HTTPError) as exc:
            return None, str(exc)[:200], _classify(exc), None
        if status >= 500:
            return None, f"HTTP {status}", "http_5xx", ms
        if status != 200:
            return None, f"HTTP {status}", "http_4xx", ms
        try:
            card = validate_agent_card(loads_json(body))
        except (ValueError, AgentCardError) as exc:
            return None, str(exc)[:200], "bad_card", ms
        return card, None, "ok", ms

    def jsonrpc_ping(self, url: str) -> tuple[bool, str, dict[str, Any]]:
        """(speaks_jsonrpc, result_category, detail)."""
        body = {"jsonrpc": "2.0", "id": f"onaa-steward-{uuid.uuid4().hex[:12]}", "method": PROBE_METHOD,
                "params": {"id": f"onaa-steward-probe-{uuid.uuid4().hex[:8]}"}}
        try:
            status, raw, _ms = self._req("POST", url, json=body,
                                         headers={"A2A-Version": A2A_VERSION, "Content-Type": "application/json"})
        except (UnsafeURLError, httpx.HTTPError) as exc:
            return False, _classify(exc), {"error": str(exc)[:200]}
        if status >= 500:
            return False, "http_5xx", {"http_status": status}
        try:
            payload = loads_json(raw)
        except ValueError:
            return False, "not_jsonrpc", {"http_status": status}
        is_rpc = isinstance(payload, dict) and payload.get("jsonrpc") == "2.0"
        if is_rpc and ("result" in payload or "error" in payload):
            err = payload.get("error") if isinstance(payload.get("error"), dict) else None
            return True, "ok", {"http_status": status, "rpc_error_code": err.get("code") if err else None}
        return False, "not_jsonrpc", {"http_status": status}

    def probe(self, listing: dict[str, Any]) -> ProbeResult:
        if listing.get("listing_type") != "agent":
            target = listing.get("endpoint_url") or listing.get("documentation_url")
            if not target:
                return ProbeResult("no_target")
            try:
                status, _b, ms = self._req("GET", target)
            except (UnsafeURLError, httpx.HTTPError) as exc:
                return ProbeResult(_classify(exc), detail={"error": str(exc)[:200]})
            return ProbeResult("ok" if status < 500 else "http_5xx", ms, detail={"http_status": status})
        url = card_url_for(listing)
        if not url:
            return ProbeResult("no_target")
        card, err, result, ms = self.fetch_card(url)
        if card is None:
            return ProbeResult(result, ms, card_error=err, detail={"card_url": url})
        try:
            rpc_url = select_jsonrpc_interface(card)
        except AgentCardError as exc:
            return ProbeResult("bad_card", ms, card=card, card_error=str(exc)[:200])
        ok, category, detail = self.jsonrpc_ping(rpc_url)
        return ProbeResult(category, ms, card=card, rpc_url=rpc_url, jsonrpc_ok=ok, detail=detail)
