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

import datetime as dt
import json
import logging
import os
import re
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from contextlib import AsyncExitStack
from typing import Any
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context
from mcp.server.transport_security import TransportSecuritySettings
from onaa import OnaaClient

from .pilot import SCOPE_KEY as PILOT_SCOPE_KEY
from .pilot import build_pilot_server, http_caller
from .server import build_server, root_jwk_from_env

try:  # traffic origin (external / ours / probes); absent when this package runs without the registry
    from onaa_registry import traffic as _traffic
except ImportError:  # pragma: no cover
    _traffic = None

MCP_PATH = "/mcp"
# Selling-agent pilot: personal connector URLs /pilot/<token>/mcp (see pilot.py). The token is taken out of the
# path before anything logs it.
PILOT_PATH = re.compile(r"^/pilot/(pilot_[A-Za-z0-9_-]{16,64})/mcp/?$")
PILOT_LOGGED_PATH = "/pilot/-/mcp"
PILOT_OAUTH_PATH = "/pilot/mcp"  # one public URL for everyone; OAuth access token in the Authorization header
# Decision 2026-11-19 (review): a token in the URL is a password anyone who sees the address can use, so the
# personal URLs are retired. Until this date they keep working and every answer tells the assistant to have its
# user reconnect with /mcp (sign-in); from it they answer 410 Gone. ONAA_PILOT_TOKEN_URL_RETIRE_AT overrides it.
TOKEN_URL_RETIRE_AT = "2026-12-17"
LEGACY_URL_KEY = "onaa.legacy_token_url"
# ONAA_MCP_LOGIN=1: /mcp serves the registry tools to anyone and the member tools (inbox, messages) after sign-in
# ("mixed auth"): calling a member tool without a token is answered with the OAuth challenge each host expects,
# HTTP 401 + WWW-Authenticate (MCP spec, Claude) or, for ChatGPT, a tool error carrying _meta mcp/www_authenticate.
# /pilot/mcp keeps working as a sign-in-first name for the same server.
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
                 usage: Any = None, pilot_app: Any = None, member_tools: frozenset[str] = frozenset()):
        self.registry_app = registry_app
        # Anonymous counters (onaa_registry.traffic.Usage); the registry app counts its own paths.
        self.usage = usage if usage is not None else getattr(getattr(registry_app, "state", None), "usage", None)
        self.mcp_app = mcp_app
        self.steward_app = steward_app
        self.pilot_app = pilot_app
        # Hosted member agents (<label>.<domain>, see onaa_registry.hosting) are served by the registry app.
        self.hosting_suffix = ("." + os.environ["ONAA_HOSTING_DOMAIN"].lower().strip(".")
                               if os.environ.get("ONAA_HOSTING_DOMAIN") else None)
        self.on_startup, self.on_shutdown = on_startup, on_shutdown
        self.member_tools = member_tools
        self.login_mcp = os.environ.get("ONAA_MCP_LOGIN") == "1" and pilot_app is not None and bool(member_tools)
        self.token_url_retire_at = os.environ.get("ONAA_PILOT_TOKEN_URL_RETIRE_AT") or TOKEN_URL_RETIRE_AT

    async def __call__(self, scope: Scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            if self.on_startup:
                self.on_startup()
            try:
                async with AsyncExitStack() as stack:
                    for sub in (self.mcp_app, self.pilot_app):
                        if sub is not None:
                            await stack.enter_async_context(sub.router.lifespan_context(sub))
                    await self.registry_app(scope, receive, send)
            finally:
                if self.on_shutdown:
                    self.on_shutdown()
            return
        path = scope.get("path", "")
        if scope["type"] == "http" and path.startswith(SECRET_QUERY_PREFIXES) and scope.get("query_string"):
            send = _scrub_query_before_log(scope, send)
        if scope["type"] == "http" and path in (PILOT_OAUTH_PATH, PILOT_OAUTH_PATH + "/"):
            await self._pilot_oauth(scope, receive, send)
            return
        if self.login_mcp and scope["type"] == "http" and path in (MCP_PATH, MCP_PATH + "/"):
            await self._mixed(scope, receive, send)
            return
        if scope["type"] == "http" and path.startswith("/pilot/"):
            await self._pilot(scope, receive, send, path)
            return
        if self.hosting_suffix and scope["type"] == "http":
            host = (_header(scope, b"host") or "").rsplit(":", 1)[0].lower().rstrip(".")
            if host.endswith(self.hosting_suffix):
                await self.registry_app(scope, receive, send)
                return
        if self.usage is not None and scope["type"] == "http" and (
                path in ROOT_AGENT_CARD_PATHS or path.startswith((MCP_PATH, STEWARD_PREFIX))):
            doc = None
            if path.startswith(MCP_PATH) and scope.get("method") == "POST":
                doc, receive = await _read_body(receive)
            await self._counted(scope, receive, send, path, doc)
            return
        await self._route(scope, receive, send, path)

    async def _mixed(self, scope: Scope, receive, send) -> None:
        """/mcp with mixed auth: registry tools for anyone, member tools after OAuth sign-in."""
        if scope.get("method") != "POST":
            await _method_not_allowed(send)
            return
        from onaa_registry import oauth

        settings = self.registry_app.state.settings
        doc, receive = await _read_body(receive)
        auth = _header(scope, b"authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        member_ok = False
        if token:
            def check() -> bool:
                with self.registry_app.state.sessionmaker() as session:
                    return oauth.member_for_bearer(session, token) is not None
            import anyio

            # an OAuth access token, or a member's own pilot_ token in the header (server agents; it no longer goes
            # in the URL, decision 2026-11-19)
            member_ok = token.startswith((oauth.ACCESS_PREFIX, "pilot_")) and await anyio.to_thread.run_sync(check)
        meta = oauth.resource_metadata_url(settings, MCP_PATH)
        if token and not member_ok:  # expired or revoked: the host refreshes or signs in again
            await _challenge(send, f'Bearer resource_metadata="{meta}", scope="{oauth.SCOPE}", error="invalid_token"')
            return
        if not member_ok and _calls_tool(doc, self.member_tools):
            challenge = (f'Bearer resource_metadata="{meta}", scope="{oauth.SCOPE}", error="invalid_token", '
                         'error_description="Sign in to ONAA to use your inbox and messages"')
            if "openai" in (_header(scope, b"user-agent") or "").lower() and isinstance(doc, dict):
                await _tool_auth_error(send, doc.get("id"), challenge)  # ChatGPT's tool-level sign-in signal
            else:
                await _challenge(send, challenge)
            return
        sub = dict(scope, path=MCP_PATH, raw_path=MCP_PATH.encode())
        if member_ok:
            sub[PILOT_SCOPE_KEY] = token

        async def serve(scope, receive, send):
            await self.pilot_app(scope, receive, send)
        if self.usage is not None:
            await self._counted(sub, receive, send, MCP_PATH, doc, serve=serve)
        else:
            await serve(sub, receive, send)

    async def _pilot_oauth(self, scope: Scope, receive, send, label: str = PILOT_OAUTH_PATH) -> None:
        """The one public pilot connector URL (/pilot/mcp). OAuth 2.1: no valid access token = 401 with the
        protected-resource metadata URL, which is how MCP hosts discover our sign-in."""
        settings = self.registry_app.state.settings
        try:
            from onaa_registry import oauth
        except ImportError:  # pragma: no cover
            await _not_found(send)
            return
        if self.pilot_app is None or not oauth.enabled(settings):
            await _not_found(send)
            return
        if self.usage is not None:
            self.usage.hit_http(label, _header(scope, b"user-agent"), _header(scope, b"x-onaa-traffic"))
        if scope.get("method") != "POST":
            await _method_not_allowed(send)
            return
        auth = _header(scope, b"authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        member_ok = False
        if token.startswith((oauth.ACCESS_PREFIX, "pilot_")):
            def check() -> bool:
                with self.registry_app.state.sessionmaker() as session:
                    return oauth.member_for_bearer(session, token) is not None
            import anyio

            member_ok = await anyio.to_thread.run_sync(check)
        if not member_ok:
            meta = oauth.resource_metadata_url(settings, label)
            challenge = f'Bearer resource_metadata="{meta}", scope="{oauth.SCOPE}"'
            if token:
                challenge += ', error="invalid_token"'
            body = b'{"error":"sign in required: connect this server in your app and sign in with your email"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", challenge.encode()),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        sub = dict(scope, path=MCP_PATH, raw_path=MCP_PATH.encode())
        sub[PILOT_SCOPE_KEY] = token
        await self.pilot_app(sub, receive, send)

    async def _pilot(self, scope: Scope, receive, send, path: str) -> None:
        """Personal pilot connector. The token never reaches access logs or counters: the server's own scope path
        is replaced (uvicorn logs it after the response) and the MCP app sees /mcp plus the token in its scope."""
        m = PILOT_PATH.match(path)
        scope["path"], scope["raw_path"] = PILOT_LOGGED_PATH, PILOT_LOGGED_PATH.encode()
        scope["query_string"] = b""
        if self.pilot_app is None or m is None:
            await _not_found(send)
            return
        if self.usage is not None:
            self.usage.hit_http(PILOT_LOGGED_PATH, _header(scope, b"user-agent"), _header(scope, b"x-onaa-traffic"))
        if dt.date.today().isoformat() >= self.token_url_retire_at:
            await _gone(send, b'{"error":"This personal connection address was retired. Reconnect ONAA in your app '
                              b'with the address ending in /mcp and sign in with your email or Google."}')
            return
        if scope.get("method") != "POST":
            await _method_not_allowed(send)
            return
        sub = dict(scope, path=MCP_PATH, raw_path=MCP_PATH.encode())
        sub[PILOT_SCOPE_KEY] = m.group(1)
        sub[LEGACY_URL_KEY] = self.token_url_retire_at
        await self.pilot_app(sub, receive, send)

    async def _counted(self, scope: Scope, receive, send, path: str, doc: Any, serve=None) -> None:
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
        if serve is None:
            async def serve(scope, receive, send):
                await self._route(scope, receive, send, path)
        if _traffic is None:
            await serve(scope, receive, send)
            return
        token = _traffic.current_origin.set(origin)
        try:
            await serve(scope, receive, send)
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



def _calls_tool(doc: Any, names: frozenset[str]) -> bool:
    for call in doc if isinstance(doc, list) else [doc]:
        if isinstance(call, dict) and call.get("method") == "tools/call" and \
                (call.get("params") or {}).get("name") in names:
            return True
    return False


async def _challenge(send, www_authenticate: str) -> None:
    body = b'{"error":"invalid_token","error_description":"Sign in to ONAA to use your inbox and messages"}'
    await send({"type": "http.response.start", "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"www-authenticate", www_authenticate.encode()),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def _tool_auth_error(send, rpc_id: Any, www_authenticate: str) -> None:
    body = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": {
        "isError": True, "content": [{"type": "text", "text": "Sign in to ONAA to use your inbox and messages."}],
        "_meta": {"mcp/www_authenticate": [www_authenticate]}}}).encode()
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def _mark_auth(mcp: Any, member_names: set[str], scope: str = "pilot") -> None:
    """Per-tool auth for hosts that read it (ChatGPT securitySchemes): registry tools anonymous, member tools OAuth."""
    for name, tool in mcp._tool_manager._tools.items():
        schemes = [{"type": "oauth2", "scopes": [scope]}] if name in member_names else [{"type": "noauth"}]
        tool.meta = {**(tool.meta or {}), "securitySchemes": schemes}

MAX_COUNTED_BODY = 1024 * 1024


async def _read_body(receive):
    """Read the JSON-RPC body once; returns (parsed document or None, a receive that replays it unchanged).

    After the replayed body the real receive takes over, so a streaming response (subscriptions/listen) waits for
    the client's actual disconnect instead of seeing a made-up one before it starts (500 "returned without
    starting response")."""
    chunks, size, more = [], 0, True
    while more:
        msg = await receive()
        if msg["type"] != "http.request":
            return None, _replay([], msg, upstream=receive)
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
    return doc, _replay([body], None, upstream=receive)


# One-time codes travel in the query string of these links (key claim, store verification). uvicorn writes the
# access-log line from the server's scope when the response starts, so the query is cleared at that moment: the
# route has already read it, and the code never reaches the logs (review 2026-11-19).
SECRET_QUERY_PREFIXES = ("/claim-key/", "/verify-store/")


def _scrub_query_before_log(scope: Scope, send):
    async def wrapped(message):
        if message["type"] == "http.response.start":
            scope["query_string"] = b""
        await send(message)
    return wrapped


_TOOL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,59}")
MAX_COUNTED_CALLS = 20  # per JSON-RPC batch


def _count_mcp_doc(doc: Any, usage, origin: str | None = None) -> None:
    """Count tools/call names (and other list/initialize methods) of a parsed JSON-RPC body."""
    try:
        for call in (doc if isinstance(doc, list) else [doc])[:MAX_COUNTED_CALLS]:
            if not isinstance(call, dict):
                continue
            method = str(call.get("method", ""))[:40]
            if method == "tools/call":
                name = (call.get("params") or {}).get("name")
                # caller-chosen text: keep only tool-shaped names, so the public stats hold no free text
                ok = isinstance(name, str) and _TOOL_NAME.fullmatch(name)
                label = name if ok else ("other" if name else "unknown")
                usage.hit("mcp_tool", label, origin=origin)
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


async def _not_found(send) -> None:
    body = b'{"detail":"Not Found"}'
    await send({"type": "http.response.start", "status": 404,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def _gone(send, body: bytes) -> None:
    await send({"type": "http.response.start", "status": 410,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


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


def forwarding_client_factory(upstream: str, trusted_proxy_hops: int, *, timeout: float = 30.0):
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
                     remote_client=None, steward=None, steward_ask=None, need_client=None,
                     pilot_upstream: str | None = None) -> ASGIApp:
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
    pilot_app, member_tools = None, frozenset()
    if pilot_upstream:
        signed_in = None
        if os.environ.get("ONAA_MCP_LOGIN") == "1":  # one signed-in server: registry tools + the member's inbox
            signed_in = build_server(registry, remote_client=remote_client, root_jwk=root_jwk_from_env(),
                                     allow_test_only=allow_test_only, steward_ask=steward_ask, need_client=need_client)
        caller = http_caller(pilot_upstream, extra_headers=_origin_header)
        public_names = set(signed_in._tool_manager._tools) if signed_in is not None else set()
        pilot_server = build_pilot_server(caller, signed_in)
        if signed_in is not None:
            member_tools = frozenset(set(pilot_server._tool_manager._tools) - public_names)
            _mark_auth(pilot_server, set(member_tools))
        pilot_app = pilot_server.streamable_http_app(
            streamable_http_path=MCP_PATH, stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]))
    return _Dispatcher(registry_app, mcp_app, steward_app, start, stop, pilot_app=pilot_app, member_tools=member_tools)


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
                            need_client=forwarding_client_factory(upstream, settings.trusted_proxy_hops),
                            pilot_upstream=upstream if settings.pilot_enabled else None)
