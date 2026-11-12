"""Hosted /mcp end to end: real Registry API (SQLite) + MCP Streamable HTTP in one uvicorn process,
driven by the official MCP client over HTTP. Needs apps/api installed in the same env (skipped otherwise)."""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time

import httpx
import pytest

pytest.importorskip("onaa_registry")
uvicorn = pytest.importorskip("uvicorn")

from mcp import Client  # noqa: E402

from onaa_mcp_registry.hosted import allowed_hosts  # noqa: E402

READ_TOOLS = {"search_agents", "search_services", "get_listing", "get_terms", "get_vocabulary"}
WRITE_TOOLS = {"self_register_start", "self_register_complete"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def hosted(tmp_path_factory):
    port = _free_port()
    admin = secrets.token_urlsafe(24)
    db = tmp_path_factory.mktemp("db") / "reg.db"
    env = {"ONAA_DATABASE_URL": f"sqlite:///{db}", "ONAA_AUTO_CREATE_SCHEMA": "1", "ONAA_ADMIN_TOKEN": admin,
           "PORT": str(port), "ONAA_PUBLIC_BASE_URL": "https://api.onaa.example", "ONAA_TRUSTED_PROXY_HOPS": "1",
           "ONAA_SELF_REGISTRATION_PER_IP_PER_HOUR": "2"}
    mp = pytest.MonkeyPatch()
    for k, v in env.items():
        mp.setenv(k, v)
    mp.delenv("ONAA_MCP_ENABLED", raising=False)
    mp.delenv("ONAA_MCP_UPSTREAM", raising=False)
    mp.delenv("ONAA_MCP_SELF_REGISTRATION", raising=False)
    mp.delenv("ONAA_TERMS_VERSION", raising=False)
    from onaa_mcp_registry.hosted import create_app

    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/v1/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    r = httpx.post(f"{base}/v1/admin/discovered", headers={"Authorization": f"Bearer {admin}"}, json={
        "display_name": "Hosted Seller", "agent_card_url": "https://seller.example.com/.well-known/agent-card.json",
        "source_url": "https://seller.example.com/", "roles": ["seller_agent"],
        "capabilities": ["commerce.quote.issue"]})
    assert r.status_code == 201, r.text
    yield base, r.json()["id"]
    server.should_exit = True
    t.join(timeout=10)
    mp.undo()


def _payload(result) -> dict:
    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc)
    return json.loads(result.content[0].text)


@pytest.mark.anyio
async def test_remote_client_lists_tools_and_reads_registry(hosted):
    base, listing_id = hosted
    async with Client(f"{base}/mcp") as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == READ_TOOLS | WRITE_TOOLS
        assert all(tools[n].annotations.read_only_hint for n in READ_TOOLS)
        assert not any(tools[n].annotations.read_only_hint for n in WRITE_TOOLS)
        got = _payload(await client.call_tool("get_listing", {"listing_id": listing_id}))
    assert got["listing"]["id"] == listing_id
    assert got["listing"]["untrusted_operator_content"]["display_name"] == "Hosted Seller"
    assert got["listing"]["trust"]["endpoint_control_verified"] is False


@pytest.mark.anyio
async def test_trailing_slash_also_works(hosted):
    base, _ = hosted
    async with Client(f"{base}/mcp/") as client:
        assert len((await client.list_tools()).tools) == 7


def test_registry_api_still_served_and_mcp_rejects_foreign_host(hosted):
    base, _ = hosted
    assert httpx.get(f"{base}/llms.txt").status_code == 200
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    hdrs = {"Accept": "application/json, text/event-stream", "Host": "evil.example"}
    assert httpx.post(f"{base}/mcp", json=body, headers=hdrs).status_code == 421
    assert httpx.get(f"{base}/mcp", headers={"Accept": "text/event-stream"}, timeout=5).status_code == 405


def test_allowed_hosts():
    hosts = allowed_hosts("https://api.onaa.net", "mcp.example.org, ", "onaa-registry-test")
    assert {"api.onaa.net", "onaa-registry-test.fly.dev", "mcp.example.org", "127.0.0.1:*"} <= set(hosts)
    assert "evil.example" not in hosts


def _call(base: str, name: str, args: dict, ip: str) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    r = httpx.post(f"{base}/mcp", json=body, timeout=15, headers={
        "Accept": "application/json, text/event-stream", "X-Forwarded-For": ip})
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    sc = res.get("structuredContent") or json.loads(res["content"][0]["text"])
    return sc.get("result", sc)


def _start_args(host: str, terms: dict, **over) -> dict:
    args = {"display_name": f"Agent {host}", "agent_card_url": f"https://{host}/.well-known/agent-card.json",
            "roles": ["seller_agent"], "accept_terms_version": terms["version"],
            "accept_terms_sha256": terms["sha256"], "confirm_operator_authority": True}
    return args | over


def test_remote_self_registration_is_stateless_and_rate_limited_per_caller_ip(hosted):
    base, _ = hosted
    terms = _call(base, "get_terms", {}, "198.51.100.7")
    assert terms["version"] and len(terms["sha256"]) == 64 and terms["text"]

    refused = _call(base, "self_register_start", _start_args("a0.example.org", terms,
                                                             confirm_operator_authority=False), "198.51.100.7")
    assert refused["error"]["status"] == 400 and "authorisation" in refused["error"]["detail"]
    wrong_terms = _call(base, "self_register_start", _start_args("a0.example.org", terms,
                                                                 accept_terms_version="draft-0.0"), "198.51.100.7")
    assert "error" in wrong_terms

    a1 = _call(base, "self_register_start", _start_args("a1.example.org", terms), "198.51.100.7")
    assert a1["registration_id"].startswith("sreg_") and a1["token"] and a1["registration_secret"]
    assert a1["challenge_url"].startswith("https://a1.example.org/.well-known/onaa-verification/")
    # Limit is 2 starts per IP per hour (wrong_terms already counted): this caller is now blocked...
    blocked = _call(base, "self_register_start", _start_args("a2.example.org", terms), "198.51.100.7")
    assert blocked["error"]["status"] == 429
    # ...but another agent's IP is not: the limit follows the caller, not the MCP server's loopback address.
    b1 = _call(base, "self_register_start", _start_args("b1.example.org", terms), "203.0.113.9")
    assert b1["registration_id"].startswith("sreg_")

    bad = _call(base, "self_register_complete", {"registration_id": a1["registration_id"],
                                                 "registration_secret": "onaa_srs_wrong"}, "198.51.100.7")
    assert "error" in bad and "api_key" not in bad
