"""Hosted (remote) ONAA Registry MCP endpoint: the Registry API plus MCP Streamable HTTP at ``/mcp``.

One ASGI process serves both, so any MCP client can connect by URL (``https://<registry-host>/mcp``)
without installing anything. Tools: search_agents, search_services, get_listing (read-only) and, while the
registry allows self-registration, get_terms, self_register_start and self_register_complete. Those are
stateless: the registration secret and the issued API key go back to the calling agent, as in the REST flow
(``/llms.txt``); nothing is stored here. Each tool call reaches the Registry API with the caller's IP in
``X-Forwarded-For``, so the API's per-IP signup and write limits apply per remote agent, not to this server.

Transport: stateless Streamable HTTP with JSON responses (no server-side sessions), so it works behind
Fly's proxy and survives restarts. The MCP tools call the Registry API over loopback without credentials,
exactly like any public client.

Run (the container entrypoint does this):

    uvicorn --factory onaa_mcp_registry.hosted:create_app --port 8080

Environment:
    ONAA_MCP_ENABLED        "1" (default) mounts /mcp; "0" serves the Registry API only.
    ONAA_MCP_UPSTREAM       Registry base URL the tools call (default http://127.0.0.1:$PORT).
    ONAA_MCP_ALLOWED_HOSTS  Comma-separated extra Host values accepted on /mcp (DNS-rebinding protection).
                            The host of ONAA_PUBLIC_BASE_URL, <FLY_APP_NAME>.fly.dev and loopback are always allowed.
    ONAA_MCP_SELF_REGISTRATION  "1" (default) offers the self-registration tools when the registry has
                            self-registration enabled; "0" keeps /mcp read-only.
    ONAA_ISSUER_ROOT_JWK    Pinned issuer root public JWK (JSON or file path) for the verify_attestations tool.
                            Unset = the tool answers no_pinned_root_key and vouches for nothing.
    ONAA_VERIFY_ALLOW_TEST_ONLY  "1" accepts TEST-ONLY (staging) attestations in verify_attestations.
    (describe_need)         Always offered: free-text buying requests answered with matching stores; the Registry
                            removes personal data and keeps the redacted text (ONAA_NEED_TEXT_RETENTION_DAYS, 7).
    ONAA_STEWARD_ENABLED    "1" (default) mounts the Registry Steward A2A agent at /steward (apps/steward) and runs
                            its periodic sweep; "0" turns it off. Without ONAA_STEWARD_TOKEN a random per-process
                            token is generated and shared in-process with the registry's Policy Service.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context
from mcp.server.transport_security import TransportSecuritySettings
from onaa import OnaaClient

from .server import build_server, root_jwk_from_env

try:  # traffic origin (external / ours / probes); absent when this package runs without the registry
    from onaa_registry import traffic as _traffic
except ImportError:  # pragma: no cover
    _traffic = None

MCP_PATH = "/mcp"
STEWARD_PREFIX = "/steward"
# A2A 1.0 well-known path, plus the pre-1.0 name that older crawlers still request.
ROOT_AGENT_CARD_PATHS = ("/.well-known/agent-card.json", "/.well-known/agent.json")
log = logging.getLogger("onaa.hosted")
Scope = MutableMapping[str, Any]
ASGIApp = Callable[[Scope, Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[None]]], Awaitable[None]]


def allowed_hosts(public_base_url: str | None = None, extra: str | None = None,
                  fly_app: str | None = None) -> list[str]:
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", "127.0.0.1", "localhost"]
    public = urlsplit(public_base_url or "").hostname
    if public:
        hosts += [public, f"{public}:*"]
    if fly_app:
        hosts += [f"{fly_app}.fly.dev", f"{fly_app}.fly.dev:*"]
    hosts += [h.strip() for h in (extra or "").split(",") if h.strip()]
    return list(dict.fromkeys(hosts))


class _Dispatcher:
    """Routes ``/mcp`` (exact path) to the MCP app and everything else to the Registry API.

    A plain Starlette ``Mount`` would redirect ``/mcp`` to ``/mcp/``, which several MCP clients do not follow
    for POST. Lifespan runs the MCP session manager around the Registry app's own lifespan.
    """

    def __init__(self, registry_app: ASGIApp, mcp_app: Any, steward_app: ASGIApp | None = None,
                 on_startup: Callable[[], None] | None = None, on_shutdown: Callable[[], None] | None = None,
                 usage: Any = None):
        self.registry_app = registry_app
        # Anonymous counters (onaa_registry.traffic.Usage); the registry app counts its own paths.
        self.usage = usage if usage is not None else getattr(getattr(registry_app, "state", None), "usage", None)
        self.mcp_app = mcp_app
        self.steward_app = steward_app
        self.on_startup, self.on_shutdown = on_startup, on_shutdown

    async def __call__(self, scope: Scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            if self.on_startup:
                self.on_startup()
            try:
                if self.mcp_app is not None:
                    async with self.mcp_app.router.lifespan_context(self.mcp_app):
                        await self.registry_app(scope, receive, send)
                else:
                    await self.registry_app(scope, receive, send)
            finally:
                if self.on_shutdown:
                    self.on_shutdown()
            return
        path = scope.get("path", "")
        if self.usage is not None and scope["type"] == "http" and (
                path in ROOT_AGENT_CARD_PATHS or path.startswith((MCP_PATH, STEWARD_PREFIX))):
            doc = None
            if path.startswith(MCP_PATH) and scope.get("method") == "POST":
                doc, receive = await _read_body(receive)
            await self._counted(scope, receive, send, path, doc)
            return
        await self._route(scope, receive, send, path)

    async def _counted(self, scope: Scope, receive, send, path: str, doc: Any) -> None:
        """Count the request with its origin, then serve it with that origin set for the loopback calls it makes."""
        ua, internal = _header(scope, b"user-agent"), _header(scope, b"x-onaa-traffic")
        origin = None
        if _traffic is not None:
            origin = _traffic.origin_of(_traffic.path_group(path), _traffic.agent_class(ua), internal)
            if doc is not None:
                origin = _traffic.mcp_origin(doc, origin)
        client = (_traffic.scope_client_ip(scope, getattr(self.usage, "trusted_proxy_hops", 0))
                  if _traffic is not None else None)
        self.usage.hit_http(path, ua, internal, origin=origin, client=client)
        if doc is not None:
            _count_mcp_doc(doc, self.usage, origin)
        if _traffic is None:
            await self._route(scope, receive, send, path)
            return
        token = _traffic.current_origin.set(origin)
        try:
            await self._route(scope, receive, send, path)
        finally:
            _traffic.current_origin.reset(token)

    async def _route(self, scope: Scope, receive, send, path: str) -> None:
        if self.steward_app is not None and scope["type"] == "http" and path in ROOT_AGENT_CARD_PATHS:
            # A2A clients and crawlers look for an Agent Card at the host root. The registry itself is not an A2A
            # agent, so the root card is the steward's: the one agent on this host that answers A2A (its
            # interface URL is absolute, under /steward).
            sub = "/.well-known/agent-card.json"
            scope = dict(scope, path=sub, raw_path=sub.encode(), root_path=scope.get("root_path", "") + STEWARD_PREFIX)
            await self.steward_app(scope, receive, send)
            return
        if self.steward_app is not None and scope["type"] == "http" and (
                path == STEWARD_PREFIX or path.startswith(STEWARD_PREFIX + "/")):
            sub = path[len(STEWARD_PREFIX):] or "/"
            scope = dict(scope, path=sub, raw_path=sub.encode(), root_path=scope.get("root_path", "") + STEWARD_PREFIX)
            await self.steward_app(scope, receive, send)
            return
        if self.mcp_app is None:
            await self.registry_app(scope, receive, send)
            return
        if scope["type"] == "http" and (path == MCP_PATH or path == MCP_PATH + "/"):
            if scope.get("method") != "POST":
                # Stateless server: no standalone SSE stream (GET) or session to end (DELETE). Answering 405
                # (allowed by the Streamable HTTP spec) also stops idle GET streams from holding connections.
                await _method_not_allowed(send)
                return
            if path.endswith("/"):
                scope = dict(scope, path=MCP_PATH, raw_path=MCP_PATH.encode())
            await self.mcp_app(scope, receive, send)
            return
        await self.registry_app(scope, receive, send)


def _header(scope: Scope, name: bytes) -> str | None:
    return next((v.decode("latin-1") for k, v in scope.get("headers") or [] if k == name), None)


MAX_COUNTED_BODY = 1024 * 1024


async def _read_body(receive):
    """Read the JSON-RPC body once; returns (parsed document or None, a receive that replays it unchanged)."""
    chunks, size, more = [], 0, True
    while more:
        msg = await receive()
        if msg["type"] != "http.request":
            return None, _replay([], msg)
        chunks.append(msg.get("body", b""))
        size += len(chunks[-1])
        more = msg.get("more_body", False)
        if size > MAX_COUNTED_BODY:
            return None, _replay(chunks, None, more_pending=more, upstream=receive)
    body = b"".join(chunks)
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        doc = None
    return doc, _replay([body], None)


def _count_mcp_doc(doc: Any, usage, origin: str | None = None) -> None:
    """Count tools/call names (and other list/initialize methods) of a parsed JSON-RPC body."""
    try:
        for call in doc if isinstance(doc, list) else [doc]:
            if not isinstance(call, dict):
                continue
            method = str(call.get("method", ""))[:40]
            if method == "tools/call":
                name = (call.get("params") or {}).get("name")
                usage.hit("mcp_tool", str(name)[:60] if name else "unknown", origin=origin)
            elif method in ("initialize", "tools/list", "resources/list", "prompts/list"):
                usage.hit("mcp_method", method, origin=origin)
                if method == "initialize" and _traffic is not None:
                    info = (call.get("params") or {}).get("clientInfo") or {}
                    usage.hit("mcp_client", _traffic.mcp_client_name(info.get("name")), origin=origin)
    except (ValueError, TypeError, AttributeError):
        pass


def _replay(chunks: list[bytes], final_msg, *, more_pending: bool = False, upstream=None):
    queue = [{"type": "http.request", "body": c, "more_body": True} for c in chunks]
    if queue and not more_pending:
        queue[-1]["more_body"] = False
    if final_msg is not None:
        queue.append(final_msg)

    async def receive():
        if queue:
            return queue.pop(0)
        if upstream is not None:
            return await upstream()
        return {"type": "http.disconnect"}
    return receive


async def _method_not_allowed(send) -> None:
    body = b'{"error":"method not allowed: POST JSON-RPC to /mcp"}'
    await send({"type": "http.response.start", "status": 405,
                "headers": [(b"allow", b"POST"), (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def caller_ip(ctx: Context | None, trusted_proxy_hops: int) -> str | None:
    """The MCP caller's IP, resolved exactly like the Registry API's client_ip()."""
    request = getattr(getattr(ctx, "request_context", None), "request", None) if ctx is not None else None
    if request is None:
        return None
    client = getattr(request, "client", None)
    peer = client.host if client else None
    if trusted_proxy_hops <= 0:
        return peer
    chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return chain[-trusted_proxy_hops] if len(chain) >= trusted_proxy_hops else peer


def _origin_header() -> dict[str, str]:
    """X-ONAA-Origin for loopback calls made while serving a request, so counts there keep the caller's origin."""
    return {"X-ONAA-Origin": _traffic.current_origin.get()} if _traffic is not None else {}


def origin_forwarding(client: OnaaClient) -> OnaaClient:
    """Make a shared loopback client send the origin of the MCP request being served with each call."""
    def add(request) -> None:
        request.headers.update(_origin_header())
    client._http.event_hooks["request"] = [*client._http.event_hooks.get("request", []), add]
    return client


def forwarding_client_factory(upstream: str, trusted_proxy_hops: int, *, timeout: float = 15.0):
    """Per-call credential-free OnaaClient whose requests carry the caller's IP as the last X-Forwarded-For hop.

    The loopback API reads the client IP from X-Forwarded-For only when ONAA_TRUSTED_PROXY_HOPS > 0 (the hosted
    setup). If no caller IP is known the header is omitted and limits fall back to the loopback address."""
    def make(ctx: Context | None) -> OnaaClient:
        ip = caller_ip(ctx, trusted_proxy_hops)
        headers = {"X-Forwarded-For": ip} if ip else {}
        headers.update(_origin_header())
        return OnaaClient(upstream, timeout=timeout, headers=headers)
    return make


def steward_asker(upstream: str, trusted_proxy_hops: int, *, timeout: float = 120.0):
    """ask_steward backend: one A2A SendMessage to the in-process steward, carrying the MCP caller's IP so the
    steward's per-caller limits apply per remote agent."""
    import uuid

    import httpx

    url = f"{upstream.rstrip('/')}{STEWARD_PREFIX}/a2a/v1"

    def ask(question: str, conversation_id: str | None, ctx: Context | None) -> dict:
        ip = caller_ip(ctx, trusted_proxy_hops)
        msg = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": question}]}
        if conversation_id:
            msg["contextId"] = conversation_id
        try:
            headers = {"A2A-Version": "1.0", **_origin_header()}
            if ip:
                headers["X-Forwarded-For"] = ip
            r = httpx.post(url, timeout=timeout, headers=headers,
                           json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}})
            body = r.json()
        except (httpx.HTTPError, ValueError):
            return {"error": "steward unavailable"}
        if "error" in body:
            return {"error": body["error"].get("message", "error")}
        parts = body["result"]["message"]["parts"]
        answer = "\n".join(p["text"] for p in parts if "text" in p)
        meta = next((p["data"] for p in parts if isinstance(p.get("data"), dict)), {})
        return {"answer": answer, "tools_used": meta.get("tools_used", []), "conversation_id": conversation_id}
    return ask


def build_hosted_app(registry_app: ASGIApp, registry: OnaaClient, *, hosts: list[str],
                     remote_client=None, steward=None, steward_ask=None, need_client=None) -> ASGIApp:
    allow_test_only = os.environ.get("ONAA_VERIFY_ALLOW_TEST_ONLY") == "1"
    mcp = build_server(registry, remote_client=remote_client,  # refuses an API key
                       root_jwk=root_jwk_from_env(), allow_test_only=allow_test_only, steward_ask=steward_ask,
                       need_client=need_client)
    mcp_app = mcp.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]),
    )
    steward_app, start, stop = steward or (None, None, None)
    return _Dispatcher(registry_app, mcp_app, steward_app, start, stop)


def build_steward(upstream: str):
    """(steward ASGI app, start, stop) or None when the steward package is not installed or is disabled."""
    if os.environ.get("ONAA_STEWARD_ENABLED", "1") == "0":
        return None
    try:
        from onaa_steward.runtime import Scheduler, StewardConfig, build
    except ImportError:
        log.warning("onaa-steward is not installed; /steward is not served")
        return None
    cfg = StewardConfig(registry_url=upstream)
    _steward, app = build(cfg)
    first_delay = float(os.environ.get("ONAA_STEWARD_FIRST_DELAY", "20"))
    holder: dict[str, Scheduler] = {}

    def start() -> None:
        holder["s"] = Scheduler(_steward, cfg, first_delay=first_delay)
        holder["s"].start()

    def stop() -> None:
        if "s" in holder:
            holder["s"].stop()
    return app, start, stop


def create_app() -> ASGIApp:
    from onaa_registry.main import create_app as create_registry_app

    if os.environ.get("ONAA_STEWARD_ENABLED", "1") != "0" and not os.environ.get("ONAA_STEWARD_TOKEN"):
        # In-process secret shared by the registry's Policy Service and the steward; never logged or stored.
        os.environ["ONAA_STEWARD_TOKEN"] = secrets.token_urlsafe(32)
    registry_app = create_registry_app()
    upstream = os.environ.get("ONAA_MCP_UPSTREAM") or f"http://127.0.0.1:{os.environ.get('PORT', '8000')}"
    steward = build_steward(upstream)
    if os.environ.get("ONAA_MCP_ENABLED", "1") == "0":
        if steward is None:
            return registry_app
        return _Dispatcher(registry_app, None, steward[0], steward[1], steward[2])
    hosts = allowed_hosts(registry_app.state.settings.public_base_url, os.environ.get("ONAA_MCP_ALLOWED_HOSTS"),
                          os.environ.get("FLY_APP_NAME"))
    settings = registry_app.state.settings
    remote = None
    if settings.self_registration_enabled and os.environ.get("ONAA_MCP_SELF_REGISTRATION", "1") != "0":
        remote = forwarding_client_factory(upstream, settings.trusted_proxy_hops)
    asker = None
    if steward is not None and os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("ONAA_STEWARD_CHAT", "1") != "0":
        asker = steward_asker(upstream, settings.trusted_proxy_hops)
    return build_hosted_app(registry_app, origin_forwarding(OnaaClient(upstream)), hosts=hosts, remote_client=remote,
                            steward=steward, steward_ask=asker,
                            need_client=forwarding_client_factory(upstream, settings.trusted_proxy_hops))
