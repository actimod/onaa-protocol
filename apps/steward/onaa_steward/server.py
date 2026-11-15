"""The steward's own A2A 1.0 agent (JSON-RPC `SendMessage`) plus a small read-only REST view.

Routes (relative to where the app is mounted, `/steward` on the hosted registry):
    GET  /.well-known/agent-card.json   A2A Agent Card
    POST /a2a/v1                        A2A JSON-RPC: SendMessage with a data part {"skill": ..., ...}
    GET  /v1/activity?listing_id=...    recent steward activity (ids, result categories, no personal data)
    GET  /v1/health

Skills (data part `{"skill": "<id>", "listing_id": "...", ...}`). A plain-text message is a question in natural
language: when conversation is enabled (onaa_steward.chat, needs a model API key) the steward answers it using
these same skills; otherwise it gets the help text.
    validate_listing     {"listing_id"}                      registration / metadata findings
    check_health         {"listing_id"}                      probe now (confirmed) and record the result
    compatibility_test   {"listing_id"}                      Agent Card + A2A JSON-RPC check, no state change
    report_issue         {"listing_id", "symptom"}           report a problem with another agent
    incident_status      {"listing_id"}                      open and recent incidents
    network_status       {}                                  network snapshot (Phase 3 groundwork)
    search_listings      {"query", "kind"?: agents|services}  registry search; both kinds if omitted
    get_listing          {"listing_id"}                      registry record
    ask                  {"question"}                        natural-language question (same as a text message)

Requests are untrusted: the steward only probes listings that are already in the registry (never a URL from
the message), and every caller is rate limited.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import anyio
import httpx
from onaa_protocol.a2a import (
    A2A_VERSION,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    JSONRPC_BINDING,
    METHOD_NOT_FOUND,
    METHOD_SEND_MESSAGE,
    PARSE_ERROR,
    ROLE_AGENT,
    VERSION_NOT_SUPPORTED,
    A2AError,
    data_part,
    make_message,
    validate_message,
)
from onaa_protocol.safe_fetch import loads_json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import EXTENSION_URI, __version__
from .chat import ChatUnavailable, StewardChat
from .optimization import snapshot
from .steward import Steward

MAX_BODY = 64 * 1024
LISTING_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_")

SKILLS = [
    ("validate_listing", "Validate a listing", "Check a registry listing for missing fields, card mismatches and "
     "duplicates.", ["registry", "validation", "onboarding"]),
    ("check_health", "Check health", "Probe a listed agent now and record the result in the registry.",
     ["health", "monitoring"]),
    ("compatibility_test", "A2A compatibility test", "Check the Agent Card and A2A 1.0 JSON-RPC endpoint of a "
     "listed agent.", ["a2a", "compatibility", "testing"]),
    ("report_issue", "Report an issue", "Report a problem with another listed agent; the steward verifies it, "
     "asks that agent for a diagnosis and tracks an incident.", ["support", "incident", "diagnosis"]),
    ("incident_status", "Incident status", "Open and recent incidents for a listing.", ["incident", "status"]),
    ("network_status", "Network status", "Aggregate network snapshot: supply by capability, reachability, open "
     "incidents.", ["network", "analytics"]),
    ("search_listings", "Search listings", "Search the registry by free text.", ["registry", "search"]),
    ("get_listing", "Get listing", "Registry record of one listing.", ["registry"]),
    ("ask", "Ask the steward", "Ask a question in natural language (any language); the steward runs the checks "
     "it needs and answers. Also triggered by a plain-text message.", ["support", "chat", "help"]),
]

HELP = ("ONAA Registry Steward. Ask in plain text when conversation is enabled, or send a data part "
        "{\"skill\": <id>, \"listing_id\": <id>} with one of: "
        + ", ".join(s[0] for s in SKILLS)
        + ". report_issue also takes \"symptom\". The steward never relays trades and cannot change your agent; "
        "registry changes go through the ONAA policy service.")


def build_card(public_url: str, registry_url: str) -> dict[str, Any]:
    return {
        "name": "ONAA Registry Steward",
        "description": "System agent of the ONAA registry: validates listings, checks agent health and A2A "
                       "compatibility, tracks incidents and asks failing agents for a diagnosis. Not in the trade "
                       "path; no admin rights.",
        "version": __version__,
        "provider": {"organization": "ONAA (Open Network for AI Agents)", "url": registry_url},
        "documentationUrl": f"{registry_url}/llms.txt",
        "supportedInterfaces": [{"url": f"{public_url}/a2a/v1", "protocolBinding": JSONRPC_BINDING,
                                 "protocolVersion": A2A_VERSION}],
        "capabilities": {"streaming": False, "pushNotifications": False, "extensions": [
            {"uri": EXTENSION_URI, "description": "ONAA steward diagnostics: diagnostic_request/response data parts",
             "required": False, "params": {}}]},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "skills": [{"id": i, "name": n, "description": d, "tags": t} for i, n, d, t in SKILLS],
    }


class Limiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            if len(self.hits) > 10_000:
                self.hits.pop(next(iter(self.hits)))
            return True


def default_client_key(trusted_proxy_hops: int = 0) -> Callable[[Request], str]:
    def key(request: Request) -> str:
        peer = request.client.host if request.client else "unknown"
        if trusted_proxy_hops > 0:
            chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
            if len(chain) >= trusted_proxy_hops:
                peer = chain[-trusted_proxy_hops]
        try:
            ip = ipaddress.ip_address(peer)
            if isinstance(ip, ipaddress.IPv6Address):
                return str(ipaddress.ip_network(f"{ip}/64", strict=False))
        except ValueError:
            pass
        return peer
    return key


def _rpc_error(rid: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def _listing_id(args: dict[str, Any]) -> str:
    lid = args.get("listing_id")
    if not isinstance(lid, str) or not 3 <= len(lid) <= 40 or not set(lid) <= LISTING_ID_CHARS:
        raise A2AError(INVALID_PARAMS, "listing_id (a registry listing id) is required")
    return lid


def create_app(steward: Steward, *, public_url: str, registry_url: str, per_minute: int = 30,
               client_key: Callable[[Request], str] | None = None, chat_client: Any = None,
               chat_options: dict[str, Any] | None = None) -> Starlette:
    card = build_card(public_url.rstrip("/"), registry_url.rstrip("/"))
    limiter = Limiter(per_minute)
    report_limiter = Limiter(max(1, per_minute // 6))
    chat_limiter = Limiter(max(1, per_minute // 6))
    key_of = client_key or default_client_key()
    chat = StewardChat(lambda name, args: run_skill(name, args, "chat"), client=chat_client, **(chat_options or {}))

    def ask(question: Any, caller: str, context_id: str | None) -> dict[str, Any]:
        if not isinstance(question, str) or not question.strip():
            raise A2AError(INVALID_PARAMS, "question (text) is required")
        if not chat.enabled:
            return {"answer": HELP, "conversation_enabled": False}
        if not chat_limiter.allow(f"{caller}|chat"):
            raise A2AError(INVALID_REQUEST, "too many questions; try again in a minute")
        try:
            out = chat.ask(question, context_id=f"{caller}|{context_id}" if context_id else None)
        except ChatUnavailable as exc:
            return {"answer": str(exc), "conversation_enabled": True, "unavailable": True}
        steward.log.record("chat", None, tools_used=out.get("tools_used"), refused=out.get("refused"))
        return {**out, "conversation_enabled": True}

    def run_skill(skill: str, args: dict[str, Any], caller: str) -> Any:
        if skill == "validate_listing":
            return steward.validate(_listing_id(args))
        if skill == "check_health":
            return steward.check(_listing_id(args))
        if skill == "compatibility_test":
            return steward.compatibility_test(_listing_id(args))
        if skill == "report_issue":
            lid = _listing_id(args)
            symptom = args.get("symptom")
            if not isinstance(symptom, str) or not symptom.strip():
                raise A2AError(INVALID_PARAMS, "symptom (short text) is required")
            if not report_limiter.allow(f"{caller}|report"):
                raise A2AError(INVALID_REQUEST, "too many reports; try again later")
            reporter = args.get("reporter_listing_id") if isinstance(args.get("reporter_listing_id"), str) else None
            return steward.handle_report(lid, symptom.strip()[:500], reporter=(reporter or "")[:40] or None)
        if skill == "incident_status":
            lid = _listing_id(args)
            return {"listing_id": lid, "incidents": steward.registry.incidents(listing_id=lid)[:20]}
        if skill == "network_status":
            return asdict(snapshot(steward.registry))
        if skill == "search_listings":
            q = args.get("query") if isinstance(args.get("query"), str) else ""
            # No kind given: search both, so "escrow" also finds escrow services, not only agents.
            kinds = [args["kind"]] if args.get("kind") in ("agents", "services") else ["agents", "services"]
            return [{"id": r["id"], "display_name": r.get("display_name"), "status": r.get("status"),
                     "listing_type": r.get("listing_type"), "service_type": r.get("service_type"),
                     "reachability": (r.get("trust") or {}).get("reachability"),
                     "capabilities": (r.get("capabilities") or [])[:10]}
                    for kind in kinds for r in steward.registry.search(kind, q=q[:200], limit=10)]
        if skill == "get_listing":
            return steward.registry.get_listing(_listing_id(args))
        raise A2AError(INVALID_PARAMS, f"unknown skill; use one of {[s[0] for s in SKILLS]}")

    def agent_card(request: Request) -> JSONResponse:
        return JSONResponse(card)

    def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "agent": "onaa-registry-steward", "version": __version__})

    def activity(request: Request) -> JSONResponse:
        lid = request.query_params.get("listing_id")
        try:
            limit = max(1, min(int(request.query_params.get("limit", "100")), 200))
        except ValueError:
            limit = 100
        return JSONResponse({"items": steward.log.entries(lid[:40] if lid else None, limit)})

    async def rpc(request: Request) -> JSONResponse:
        caller = key_of(request)
        if not limiter.allow(caller):
            return JSONResponse({"error": "rate limited"}, status_code=429)
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return JSONResponse({"error": "body too large"}, status_code=413)
        try:
            req = loads_json(raw)
        except ValueError:
            return _rpc_error(None, PARSE_ERROR, "invalid JSON")
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return _rpc_error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        rid = req.get("id") if isinstance(req.get("id"), (str, int)) else None
        if request.headers.get("a2a-version", "").split(".")[0] != "1":
            return _rpc_error(rid, VERSION_NOT_SUPPORTED, "send A2A-Version: 1.0")
        if req["method"] != METHOD_SEND_MESSAGE:
            return _rpc_error(rid, METHOD_NOT_FOUND, "only SendMessage is supported")
        try:
            msg = validate_message((req.get("params") or {}).get("message") if isinstance(req.get("params"), dict)
                                   else None)
            args = next((p["data"] for p in msg["parts"] if isinstance(p.get("data"), dict)), None)
            text = "\n".join(p["text"] for p in msg["parts"] if isinstance(p.get("text"), str)).strip()
            if (args is None or not isinstance(args.get("skill"), str)) and text:
                out = await anyio.to_thread.run_sync(ask, text, caller, msg.get("contextId"))
                parts = [{"text": out["answer"]}, data_part({k: v for k, v in out.items() if k != "answer"})]
            elif args is not None and args.get("skill") == "ask":
                out = await anyio.to_thread.run_sync(ask, args.get("question"), caller, msg.get("contextId"))
                parts = [{"text": out["answer"]}, data_part({"skill": "ask", "result": out})]
            elif args is None or not isinstance(args.get("skill"), str):
                parts = [{"text": HELP}, data_part({"skills": [s[0] for s in SKILLS]})]
            else:
                result = await anyio.to_thread.run_sync(run_skill, args["skill"], args, caller)
                parts = [data_part({"skill": args["skill"], "result": result})]
        except A2AError as exc:
            return _rpc_error(rid, exc.code, exc.message)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            return _rpc_error(rid, INVALID_PARAMS if code == 404 else INTERNAL_ERROR,
                              "listing not found" if code == 404 else "registry error")
        except Exception:  # noqa: BLE001 - never leak internals to callers
            steward.log.record("error", None, where="rpc")
            return _rpc_error(rid, INTERNAL_ERROR, "internal error")
        reply = make_message(ROLE_AGENT, parts, context_id=msg.get("contextId"))
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"message": reply}})

    return Starlette(routes=[
        Route("/.well-known/agent-card.json", agent_card),
        Route("/a2a/v1", rpc, methods=["POST"]),
        Route("/v1/activity", activity),
        Route("/v1/health", health),
    ])
