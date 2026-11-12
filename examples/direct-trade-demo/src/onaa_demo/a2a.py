"""A2A 1.0 JSON-RPC server subset for the demo agents (client side lives in ``onaa_protocol.a2a``).

Verified against https://a2a-protocol.org/v1.0.1/specification/ on 2026-11-12 (see the
``onaa_protocol.a2a`` docstring for the field-level notes). Only message-only ``SendMessage`` is
implemented: no Task lifecycle, streaming, push notifications or auth schemes.
"""

from __future__ import annotations

import functools
import ipaddress
from collections.abc import Callable
from typing import Any

import anyio
from onaa_protocol.a2a import (  # re-exported for the demo modules and tests
    A2A_VERSION,
    AGENT_CARD_PATH,
    EXTENSION_SUPPORT_REQUIRED,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    JSONRPC_BINDING,
    METHOD_NOT_FOUND,
    METHOD_SEND_MESSAGE,
    PARSE_ERROR,
    ROLE_AGENT,
    ROLE_USER,
    VERSION_NOT_SUPPORTED,
    A2AError,
    AgentCardError,
    card_extension_uris,
    data_part,
    make_message,
    select_jsonrpc_interface,
    send_message,
    validate_agent_card,
    validate_message,
)
from onaa_protocol.agent_card import JWKS_PATH
from onaa_protocol.safe_fetch import loads_json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

__all__ = [
    "A2A_VERSION", "AGENT_CARD_PATH", "EXTENSION_SUPPORT_REQUIRED", "INTERNAL_ERROR", "INVALID_PARAMS",
    "INVALID_REQUEST", "JSONRPC_BINDING", "JSONRPC_PATH", "JWKS_PATH", "METHOD_NOT_FOUND", "METHOD_SEND_MESSAGE",
    "PARSE_ERROR", "ROLE_AGENT", "ROLE_USER", "VERSION_NOT_SUPPORTED", "A2AError", "AgentCardError",
    "build_agent_card", "card_extension_uris", "create_agent_app", "data_part", "make_message",
    "select_jsonrpc_interface", "send_message", "validate_agent_card", "validate_message",
]

JSONRPC_PATH = "/a2a/v1"
MAX_BODY_BYTES = 256 * 1024
MAX_REQUEST_LOG = 256          # entries kept in a node's request_log (oldest dropped)
MAX_LOGGED_BODY = 16 * 1024    # bytes of each request body kept in the log
MAX_HANDLER_THREADS = 16       # concurrent message handlers per app (own limiter, not the shared pool)


def client_source(host: str | None) -> str | None:
    """Quota key for a client address: the IPv4 address, or the /64 prefix of an IPv6 address (one host
    usually owns a whole /64). None when unknown."""
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "host:" + host[:255]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return "ip:" + str(ip.ipv4_mapped)
        return "ip6:" + str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return "ip:" + str(ip)


def build_agent_card(
    *,
    name: str,
    description: str,
    version: str,
    base_url: str,
    skills: list[dict[str, Any]],
    extensions: list[dict[str, Any]] | None = None,
    provider: dict[str, str] | None = None,
) -> dict[str, Any]:
    card: dict[str, Any] = {
        "name": name,
        "description": description,
        "version": version,
        "supportedInterfaces": [
            {"url": base_url.rstrip("/") + JSONRPC_PATH, "protocolBinding": JSONRPC_BINDING,
             "protocolVersion": A2A_VERSION}
        ],
        "capabilities": {"streaming": False, "pushNotifications": False, "extensions": extensions or []},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    }
    if provider:
        card["provider"] = provider
    return card


MessageHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _rpc_error(req_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": err})


def _parse_ext_header(value: str | None) -> set[str]:
    return {v.strip() for v in (value or "").split(",") if v.strip()}


def create_agent_app(
    card: dict[str, Any],
    handler: MessageHandler,
    *,
    jwks: Callable[[], dict[str, Any]] | None = None,
    required_extensions: set[str] | None = None,
    request_log: list[dict[str, Any]] | None = None,
    pass_source: bool = False,
    max_handler_threads: int = MAX_HANDLER_THREADS,
) -> Starlette:
    """Starlette app serving the Agent Card, the ONAA JWKS and a JSON-RPC SendMessage endpoint.

    The handler runs off the event loop on this app's own bounded limiter (``max_handler_threads``), so
    slow handlers (key fetches) can neither stall the event loop nor exhaust the process-wide worker pool.
    With ``pass_source=True`` the handler is called as ``handler(message, source)`` with the client
    address quota key (:func:`client_source`)."""
    required = required_extensions or set()
    limiter = anyio.CapacityLimiter(max_handler_threads)

    async def agent_card(_: Request) -> JSONResponse:
        return JSONResponse(card)

    async def jwks_route(_: Request) -> JSONResponse:
        return JSONResponse(jwks() if jwks else {"keys": []})

    def record(request: Request, raw: bytes | None, size: int) -> None:
        if request_log is None:
            return
        body = "" if raw is None else raw[:MAX_LOGGED_BODY].decode("utf-8", "replace")
        request_log.append({"method": request.method, "path": request.url.path,
                            "client": request.client.host if request.client else None,
                            "body": body, "body_bytes": size, "truncated": raw is None or size > MAX_LOGGED_BODY})
        if len(request_log) > MAX_REQUEST_LOG:
            del request_log[:-MAX_REQUEST_LOG]

    async def jsonrpc(request: Request) -> JSONResponse:
        # Size cap BEFORE buffering: declared length first, then a streamed count (chunked bodies).
        declared = request.headers.get("content-length", "")
        if declared and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
            record(request, None, int(declared) if declared.isdigit() else -1)
            return _rpc_error(None, INVALID_REQUEST, "request too large")
        buf = bytearray()
        async for chunk in request.stream():
            buf.extend(chunk)
            if len(buf) > MAX_BODY_BYTES:
                record(request, None, len(buf))
                return _rpc_error(None, INVALID_REQUEST, "request too large")
        raw = bytes(buf)
        record(request, raw, len(raw))
        try:
            body = loads_json(raw)  # strict: no duplicate members, bounded nesting
        except ValueError:
            return _rpc_error(None, PARSE_ERROR, "parse error")
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or "method" not in body:
            return _rpc_error(None, INVALID_REQUEST, "invalid JSON-RPC request")
        req_id = body.get("id")
        if not (isinstance(req_id, str | int) and not isinstance(req_id, bool) and len(str(req_id)) <= 128):
            req_id = None  # JSON-RPC ids are short strings/numbers; never reflect anything else
        version = request.headers.get("A2A-Version", "").strip() or "0.3"
        if version.split(".")[0] != "1":
            return _rpc_error(req_id, VERSION_NOT_SUPPORTED, "A2A version not supported",
                              {"supported": [A2A_VERSION]})
        if body["method"] != METHOD_SEND_MESSAGE:
            return _rpc_error(req_id, METHOD_NOT_FOUND, "method not found")
        params = body.get("params")
        if not isinstance(params, dict):
            return _rpc_error(req_id, INVALID_PARAMS, "params must be an object")
        requested = _parse_ext_header(request.headers.get("A2A-Extensions"))
        missing = required - requested
        if missing:
            return _rpc_error(req_id, EXTENSION_SUPPORT_REQUIRED, "required extension not declared",
                              {"required": sorted(missing)})
        try:
            message = validate_message(params.get("message"))
            # The handler may verify signatures (network key fetches): keep it off the event loop so one
            # slow peer cannot stall the agent card, the JWKS or other trades. Its own limiter bounds the
            # threads it can hold; key fetches fail fast when busy (HttpKeyResolver, v0.1.2).
            call = functools.partial(handler, message, client_source(request.client.host if request.client
                                                                     else None)) if pass_source \
                else functools.partial(handler, message)
            reply = await anyio.to_thread.run_sync(call, limiter=limiter)
        except A2AError as exc:
            return _rpc_error(req_id, exc.code, exc.message, exc.data)
        resp = JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"message": reply}})
        activated = requested & card_extension_uris(card)
        if activated:
            resp.headers["A2A-Extensions"] = ",".join(sorted(activated))
        return resp

    return Starlette(routes=[
        Route(AGENT_CARD_PATH, agent_card, methods=["GET"]),
        Route(JWKS_PATH, jwks_route, methods=["GET"]),
        Route(JSONRPC_PATH, jsonrpc, methods=["POST"]),
    ])
