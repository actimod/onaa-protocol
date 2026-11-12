"""Hosted (remote) ONAA Registry MCP endpoint: the Registry API plus MCP Streamable HTTP at ``/mcp``.

One ASGI process serves both, so any MCP client can connect by URL (``https://<registry-host>/mcp``)
without installing anything. The hosted endpoint is always **read-only** (search_agents, search_services,
get_listing): it never offers the self-registration tools, because the issued API key would land on this
server instead of with the registering agent. Agents that want to register use the REST API (``/llms.txt``)
or the local MCP server with ``--enable-self-registration``.

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
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from mcp.server.transport_security import TransportSecuritySettings
from onaa import OnaaClient

from .server import build_server

MCP_PATH = "/mcp"
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

    def __init__(self, registry_app: ASGIApp, mcp_app: Any):
        self.registry_app = registry_app
        self.mcp_app = mcp_app

    async def __call__(self, scope: Scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            async with self.mcp_app.router.lifespan_context(self.mcp_app):
                await self.registry_app(scope, receive, send)
            return
        path = scope.get("path", "")
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


async def _method_not_allowed(send) -> None:
    body = b'{"error":"method not allowed: POST JSON-RPC to /mcp"}'
    await send({"type": "http.response.start", "status": 405,
                "headers": [(b"allow", b"POST"), (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def build_hosted_app(registry_app: ASGIApp, registry: OnaaClient, *, hosts: list[str]) -> ASGIApp:
    mcp = build_server(registry)  # read-only; refuses an API key
    mcp_app = mcp.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]),
    )
    return _Dispatcher(registry_app, mcp_app)


def create_app() -> ASGIApp:
    from onaa_registry.main import create_app as create_registry_app

    registry_app = create_registry_app()
    if os.environ.get("ONAA_MCP_ENABLED", "1") == "0":
        return registry_app
    upstream = os.environ.get("ONAA_MCP_UPSTREAM") or f"http://127.0.0.1:{os.environ.get('PORT', '8000')}"
    hosts = allowed_hosts(registry_app.state.settings.public_base_url, os.environ.get("ONAA_MCP_ALLOWED_HOSTS"),
                          os.environ.get("FLY_APP_NAME"))
    return build_hosted_app(registry_app, OnaaClient(upstream), hosts=hosts)
