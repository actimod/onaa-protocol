"""Minimal hand-written A2A 1.0 JSON-RPC subset (no a2a-sdk dependency).

Verified against https://a2a-protocol.org/v1.0.1/specification/ on 2026-11-12:
- JSON-RPC method names are PascalCase (``SendMessage``); the 0.3-era
  ``message/send`` is NOT a 1.0 method and is answered with -32601.
- ``SendMessageRequest`` params: ``message`` (required), ``configuration``,
  ``metadata``, ``tenant`` (optional).
- ``Message``: ``messageId``, ``role`` (``ROLE_USER`` / ``ROLE_AGENT``), ``parts``
  required; ``contextId``, ``taskId``, ``extensions`` (URI list), ``metadata``,
  ``referenceTaskIds`` optional.
- ``Part`` holds exactly one of ``text`` / ``raw`` / ``url`` / ``data`` plus optional
  ``mediaType`` / ``filename`` / ``metadata``. There is no ``kind`` discriminator.
- Result is ``{"message": Message}`` or ``{"task": Task}``.
- Clients send ``A2A-Version``; an empty/missing value means 0.3, so a 1.0-only
  server answers VersionNotSupportedError (-32009). ``A2A-Extensions`` lists the
  extension URIs the client uses; a missing required extension is
  ExtensionSupportRequiredError (-32008).
- Agent Card required: name, description, supportedInterfaces[{url,
  protocolBinding, protocolVersion}], version, capabilities, defaultInputModes,
  defaultOutputModes, skills[{id, name, description, tags}].

Only the subset needed for the demo is implemented: SendMessage returning a
Message (no Task lifecycle, streaming, push notifications, or auth schemes).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

A2A_VERSION = "1.0"
JSONRPC_BINDING = "JSONRPC"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
JSONRPC_PATH = "/a2a/v1"
ROLE_USER = "ROLE_USER"
ROLE_AGENT = "ROLE_AGENT"
METHOD_SEND_MESSAGE = "SendMessage"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
EXTENSION_SUPPORT_REQUIRED = -32008
VERSION_NOT_SUPPORTED = -32009

MAX_BODY_BYTES = 256 * 1024
_PART_CONTENT_KEYS = ("text", "raw", "url", "data")


class A2AError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class AgentCardError(ValueError):
    pass


# ---------------------------------------------------------------- objects


def data_part(data: Any, media_type: str = "application/json") -> dict[str, Any]:
    return {"data": data, "mediaType": media_type}


def make_message(
    role: str,
    parts: list[dict[str, Any]],
    *,
    context_id: str | None = None,
    extensions: list[str] | None = None,
    message_id: str | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "messageId": message_id or str(uuid.uuid4()),
        "role": role,
        "parts": parts,
    }
    if context_id:
        msg["contextId"] = context_id
    if extensions:
        msg["extensions"] = list(extensions)
    return msg


def validate_message(msg: Any) -> dict[str, Any]:
    if not isinstance(msg, dict):
        raise A2AError(INVALID_PARAMS, "params.message must be an object")
    if not isinstance(msg.get("messageId"), str) or not msg["messageId"]:
        raise A2AError(INVALID_PARAMS, "message.messageId is required")
    if msg.get("role") not in (ROLE_USER, ROLE_AGENT):
        raise A2AError(INVALID_PARAMS, "message.role must be ROLE_USER or ROLE_AGENT")
    parts = msg.get("parts")
    if not isinstance(parts, list) or not parts:
        raise A2AError(INVALID_PARAMS, "message.parts must be a non-empty array")
    for part in parts:
        if not isinstance(part, dict):
            raise A2AError(INVALID_PARAMS, "each part must be an object")
        if "kind" in part:
            raise A2AError(INVALID_PARAMS, "'kind' discriminator was removed in A2A 1.0")
        present = [k for k in _PART_CONTENT_KEYS if k in part]
        if len(present) != 1:
            raise A2AError(INVALID_PARAMS, "a part must contain exactly one of text/raw/url/data")
    ext = msg.get("extensions", [])
    if not isinstance(ext, list) or not all(isinstance(e, str) for e in ext):
        raise A2AError(INVALID_PARAMS, "message.extensions must be a list of URI strings")
    return msg


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
            {
                "url": base_url.rstrip("/") + JSONRPC_PATH,
                "protocolBinding": JSONRPC_BINDING,
                "protocolVersion": A2A_VERSION,
            }
        ],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "extensions": extensions or [],
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    }
    if provider:
        card["provider"] = provider
    return card


def validate_agent_card(card: Any) -> dict[str, Any]:
    """Structural check of an untrusted Agent Card (subset of A2A 1.0 §4.4)."""
    if not isinstance(card, dict):
        raise AgentCardError("agent card must be a JSON object")
    for key, typ in (
        ("name", str),
        ("description", str),
        ("version", str),
        ("supportedInterfaces", list),
        ("capabilities", dict),
        ("defaultInputModes", list),
        ("defaultOutputModes", list),
        ("skills", list),
    ):
        if not isinstance(card.get(key), typ):
            raise AgentCardError(f"agent card field '{key}' missing or not {typ.__name__}")
    for iface in card["supportedInterfaces"]:
        if not isinstance(iface, dict) or not all(
            isinstance(iface.get(k), str) for k in ("url", "protocolBinding", "protocolVersion")
        ):
            raise AgentCardError("each supportedInterfaces entry needs url/protocolBinding/protocolVersion")
    for skill in card["skills"]:
        if not isinstance(skill, dict) or not all(
            isinstance(skill.get(k), str) for k in ("id", "name", "description")
        ) or not isinstance(skill.get("tags"), list):
            raise AgentCardError("each skill needs id/name/description/tags")
    return card


def select_jsonrpc_interface(card: dict[str, Any]) -> str:
    for iface in card["supportedInterfaces"]:
        if iface["protocolBinding"] == JSONRPC_BINDING and iface["protocolVersion"].split(".")[0] == "1":
            return iface["url"]
    raise AgentCardError("agent card offers no A2A 1.x JSONRPC interface")


def card_extension_uris(card: dict[str, Any]) -> set[str]:
    exts = card.get("capabilities", {}).get("extensions", []) or []
    return {e["uri"] for e in exts if isinstance(e, dict) and isinstance(e.get("uri"), str)}


# ---------------------------------------------------------------- client


def send_message(
    client: httpx.Client,
    url: str,
    message: dict[str, Any],
    *,
    extensions: list[str] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """POST a JSON-RPC SendMessage and return the reply Message (raises A2AError)."""
    headers = {"A2A-Version": A2A_VERSION, "Content-Type": "application/json"}
    if extensions:
        headers["A2A-Extensions"] = ",".join(extensions)
    body = {
        "jsonrpc": "2.0",
        "id": request_id or str(uuid.uuid4()),
        "method": METHOD_SEND_MESSAGE,
        "params": {"message": message},
    }
    resp = client.post(url, json=body, headers=headers, follow_redirects=False)
    if resp.status_code != 200:
        raise A2AError(INTERNAL_ERROR, f"unexpected HTTP status {resp.status_code}")
    payload = resp.json()
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        raise A2AError(INVALID_REQUEST, "response is not JSON-RPC 2.0")
    if "error" in payload:
        err = payload["error"] or {}
        raise A2AError(int(err.get("code", INTERNAL_ERROR)), str(err.get("message", "")), err.get("data"))
    result = payload.get("result")
    if not isinstance(result, dict) or "message" not in result:
        raise A2AError(INVALID_REQUEST, "expected result.message (Task results are not used in this demo)")
    return validate_message(result["message"])


# ---------------------------------------------------------------- server

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
    required_extensions: set[str] | None = None,
    request_log: list[dict[str, Any]] | None = None,
) -> Starlette:
    """Starlette app serving the Agent Card and a JSON-RPC SendMessage endpoint."""
    required = required_extensions or set()

    async def agent_card(_: Request) -> JSONResponse:
        return JSONResponse(card)

    async def jsonrpc(request: Request) -> JSONResponse:
        raw = await request.body()
        if request_log is not None:
            request_log.append(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "client": request.client.host if request.client else None,
                    "body": raw.decode("utf-8", "replace"),
                }
            )
        if len(raw) > MAX_BODY_BYTES:
            return _rpc_error(None, INVALID_REQUEST, "request too large")
        try:
            body = json.loads(raw)
        except ValueError:
            return _rpc_error(None, PARSE_ERROR, "parse error")
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or "method" not in body:
            return _rpc_error(None, INVALID_REQUEST, "invalid JSON-RPC request")
        req_id = body.get("id")
        version = request.headers.get("A2A-Version", "").strip() or "0.3"
        if version.split(".")[0] != "1":
            return _rpc_error(req_id, VERSION_NOT_SUPPORTED, f"A2A version {version} not supported",
                              {"supported": [A2A_VERSION]})
        if body["method"] != METHOD_SEND_MESSAGE:
            return _rpc_error(req_id, METHOD_NOT_FOUND, f"method {body['method']!r} not found")
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
            reply = handler(message)
        except A2AError as exc:
            return _rpc_error(req_id, exc.code, exc.message, exc.data)
        resp = JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"message": reply}})
        activated = requested & card_extension_uris(card)
        if activated:
            resp.headers["A2A-Extensions"] = ",".join(sorted(activated))
        return resp

    return Starlette(
        routes=[
            Route(AGENT_CARD_PATH, agent_card, methods=["GET"]),
            Route(JSONRPC_PATH, jsonrpc, methods=["POST"]),
        ]
    )
