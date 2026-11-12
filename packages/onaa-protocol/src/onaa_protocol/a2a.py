"""Minimal A2A 1.0 JSON-RPC *client* subset and Agent Card checks used by ONAA Protocol v0.1.

Verified against https://a2a-protocol.org/v1.0.1/specification/ (retrieved 2026-11-12):
- method names are PascalCase (``SendMessage``); the 0.3-era ``message/send`` is not a 1.0 method;
- ``Message``: ``messageId``, ``role`` (``ROLE_USER``/``ROLE_AGENT``), ``parts`` required; ``contextId``,
  ``extensions`` (URI list), ``metadata`` optional; ``Part`` holds exactly one of text/raw/url/data and has
  no ``kind`` field;
- clients send ``A2A-Version`` (missing means 0.3 -> -32009) and ``A2A-Extensions`` (comma separated);
  a missing required extension is ExtensionSupportRequiredError (-32008);
- ``AgentExtension`` = {uri, description, required, params} (section 4.4.4), declared in
  ``capabilities.extensions`` (section 4.6.1).

No server code lives here (the package has no web-framework dependency).
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx

from .safe_fetch import deadline_extensions, loads_json, read_capped

A2A_VERSION = "1.0"
JSONRPC_BINDING = "JSONRPC"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
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

MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_RPC_DEADLINE = 15.0  # seconds, total per JSON-RPC call
_PART_CONTENT_KEYS = ("text", "raw", "url", "data")


class A2AError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class AgentCardError(ValueError):
    pass


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
    msg: dict[str, Any] = {"messageId": message_id or str(uuid.uuid4()), "role": role, "parts": parts}
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
        if len([k for k in _PART_CONTENT_KEYS if k in part]) != 1:
            raise A2AError(INVALID_PARAMS, "a part must contain exactly one of text/raw/url/data")
    ext = msg.get("extensions", [])
    if not isinstance(ext, list) or not all(isinstance(e, str) for e in ext):
        raise A2AError(INVALID_PARAMS, "message.extensions must be a list of URI strings")
    return msg


def validate_agent_card(card: Any) -> dict[str, Any]:
    """Structural check of an untrusted Agent Card (subset of A2A 1.0 section 4.4)."""
    if not isinstance(card, dict):
        raise AgentCardError("agent card must be a JSON object")
    for key, typ in (("name", str), ("description", str), ("version", str), ("supportedInterfaces", list),
                     ("capabilities", dict), ("defaultInputModes", list), ("defaultOutputModes", list),
                     ("skills", list)):
        if not isinstance(card.get(key), typ):
            raise AgentCardError(f"agent card field '{key}' missing or not {typ.__name__}")
    for iface in card["supportedInterfaces"]:
        if not isinstance(iface, dict) or not all(
                isinstance(iface.get(k), str) for k in ("url", "protocolBinding", "protocolVersion")):
            raise AgentCardError("each supportedInterfaces entry needs url/protocolBinding/protocolVersion")
    for skill in card["skills"]:
        if not isinstance(skill, dict) or not isinstance(skill.get("tags"), list) or not all(
                isinstance(skill.get(k), str) for k in ("id", "name", "description")):
            raise AgentCardError("each skill needs id/name/description/tags")
    exts = card["capabilities"].get("extensions", [])
    if exts is not None and (not isinstance(exts, list) or not all(isinstance(e, dict) for e in exts)):
        raise AgentCardError("capabilities.extensions must be a list of AgentExtension objects")
    return card


def select_jsonrpc_interface(card: dict[str, Any]) -> str:
    for iface in card["supportedInterfaces"]:
        if iface["protocolBinding"] == JSONRPC_BINDING and iface["protocolVersion"].split(".")[0] == "1":
            return iface["url"]
    raise AgentCardError("agent card offers no A2A 1.x JSONRPC interface")


def card_extension_uris(card: dict[str, Any]) -> set[str]:
    exts = card.get("capabilities", {}).get("extensions", []) or []
    return {e["uri"] for e in exts if isinstance(e, dict) and isinstance(e.get("uri"), str)}


def find_extension(card: dict[str, Any], uri: str) -> dict[str, Any] | None:
    for e in card.get("capabilities", {}).get("extensions", []) or []:
        if isinstance(e, dict) and e.get("uri") == uri:
            return e
    return None


def rpc_call(
    client: httpx.Client,
    url: str,
    method: str,
    params: Any,
    *,
    headers: dict[str, str] | None = None,
    request_id: str | None = None,
    deadline: float = DEFAULT_RPC_DEADLINE,
) -> dict[str, Any]:
    """POST one JSON-RPC request and return the decoded response object.

    No redirects, size-capped, strict JSON (no duplicate members, bounded nesting) and a TOTAL ``deadline``
    in seconds (checked per received chunk, and used as the per-phase httpx timeout). Callers validate
    ``url`` (``safe_fetch.validate_url``); use ``safe_fetch.safe_client`` to also pin the connected IP.
    """
    body = {"jsonrpc": "2.0", "id": request_id or str(uuid.uuid4()), "method": method, "params": params}
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    deadline_at = time.monotonic() + deadline

    def err(msg: str) -> A2AError:
        return A2AError(INTERNAL_ERROR, msg)

    # The absolute deadline also reaches safe_client's transport (name resolution, connect, TLS, headers).
    with client.stream("POST", url, json=body, headers=hdrs, follow_redirects=False,
                       timeout=httpx.Timeout(deadline), extensions=deadline_extensions(deadline_at)) as resp:
        if resp.status_code != 200:
            raise A2AError(INTERNAL_ERROR, f"unexpected HTTP status {resp.status_code}")
        raw = read_capped(resp, max_bytes=MAX_RESPONSE_BYTES, deadline_at=deadline_at, error=err)
    try:
        payload = loads_json(raw)
    except ValueError as exc:
        raise A2AError(PARSE_ERROR, "response is not JSON") from exc
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        raise A2AError(INVALID_REQUEST, "response is not JSON-RPC 2.0")
    return payload


def send_message(
    client: httpx.Client,
    url: str,
    message: dict[str, Any],
    *,
    extensions: list[str] | None = None,
    request_id: str | None = None,
    deadline: float = DEFAULT_RPC_DEADLINE,
) -> dict[str, Any]:
    """SendMessage and return the reply Message (raises A2AError on JSON-RPC errors or Task results)."""
    headers = {"A2A-Version": A2A_VERSION}
    if extensions:
        headers["A2A-Extensions"] = ",".join(extensions)
    payload = rpc_call(client, url, METHOD_SEND_MESSAGE, {"message": message}, headers=headers,
                       request_id=request_id, deadline=deadline)
    if "error" in payload:
        err = payload["error"] if isinstance(payload["error"], dict) else {}
        code = err.get("code")
        raise A2AError(code if isinstance(code, int) else INTERNAL_ERROR, str(err.get("message", ""))[:500],
                       err.get("data"))
    result = payload.get("result")
    if not isinstance(result, dict) or "message" not in result:
        raise A2AError(INVALID_REQUEST, "expected result.message (Task results are not used in ONAA v0.1)")
    return validate_message(result["message"])
