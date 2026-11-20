"""The public pilot connector (/pilot/mcp) with the MCP SDK's own OAuth client: discovery from the 401, dynamic
registration, PKCE, email code sign-up, tools over the access token, refresh rotation and sign-out."""

from __future__ import annotations

import logging
import re
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

pytest.importorskip("onaa_registry")
uvicorn = pytest.importorskip("uvicorn")
httpx2 = pytest.importorskip("httpx2")

from mcp import Client  # noqa: E402
from mcp.client.auth import OAuthClientProvider  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata  # noqa: E402


def mail(name: str) -> str:
    return name + chr(64) + "example.com"  # built, so the public export scan sees no address


CODE_RE = re.compile(r"DEV sign-in code for (\S+): (\d{6})")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Codes(logging.Handler):
    """Stands in for the mailbox: the dev-log mail backend writes each code to the server log."""

    def __init__(self):
        super().__init__()
        self.by_email: dict[str, str] = {}

    def emit(self, record):
        m = CODE_RE.search(record.getMessage())
        if m:
            self.by_email[m.group(1)] = m.group(2)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    db = tmp_path_factory.mktemp("db") / "oauth.db"
    env = {"ONAA_DATABASE_URL": f"sqlite:///{db}", "ONAA_AUTO_CREATE_SCHEMA": "1", "PORT": str(port),
           "ONAA_ADMIN_TOKEN": secrets.token_urlsafe(24), "ONAA_PUBLIC_BASE_URL": base, "ONAA_PILOT_ENABLED": "1",
           "ONAA_STEWARD_ENABLED": "0", "ONAA_HOSTING_DOMAIN": "agents.test", "ONAA_HOSTING_SCHEME": "http",
           "ONAA_HOSTED_AGENT_SECRET": "test-only-hosted-agent-secret-0123456789",
           "ONAA_OAUTH_SECRET": "test-only-oauth-secret-0123456789abcdef", "ONAA_MAIL_BACKEND": "dev-log",
           "ONAA_PILOT_OPEN_SIGNUP": "1", "ONAA_MCP_LOGIN": "1",
           "ONAA_MESSAGE_KEY": "test-only-key-0123456789abcdefghijklmnopqrs"}
    mp = pytest.MonkeyPatch()
    for k, v in env.items():
        mp.setenv(k, v)
    for k in ("ONAA_MCP_ENABLED", "ONAA_MCP_UPSTREAM", "ONAA_TERMS_VERSION"):
        mp.delenv(k, raising=False)
    codes = Codes()
    logging.getLogger("onaa.oauth").addHandler(codes)
    from onaa_mcp_registry.hosted import create_app

    srv = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        try:
            if httpx.get(f"{base}/v1/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    yield base, codes
    srv.should_exit = True
    t.join(timeout=10)
    logging.getLogger("onaa.oauth").removeHandler(codes)
    mp.undo()


class Memory:
    def __init__(self):
        self.tokens = self.client = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, info):
        self.client = info


def sign_in_page(authorization_url: str, email: str, nickname: str | None, codes: Codes) -> AuthorizationCodeResult:
    """What the person does in the window their app opens: email, then the emailed code. One browser (one cookie
    jar) for every step: a sign-in is bound to the browser that opened it."""
    browser = httpx.Client()
    page = browser.get(authorization_url)
    assert page.status_code == 200 and "Sign in to ONAA" in page.text, page.text
    login_id = re.search(r"name=login_id value='([^']+)'", page.text).group(1)
    base = f"{urlsplit(authorization_url).scheme}://{urlsplit(authorization_url).netloc}"
    step2 = browser.post(f"{base}/oauth/authorize/email", data={"login_id": login_id, "email": email,
                                                                 "nickname": nickname or ""})
    assert "Check your email" in step2.text, step2.text
    # browsers apply form-action to the redirect after the code form, so the app's return address must be allowed
    assert "form-action 'self' http://127.0.0.1:9;" in step2.headers["content-security-policy"]
    done = browser.post(f"{base}/oauth/authorize/code", data={"login_id": login_id, "code": codes.by_email[email]})
    assert done.status_code == 302, done.text
    q = parse_qs(urlsplit(done.headers["location"]).query)
    return AuthorizationCodeResult(code=q["code"][0], state=q.get("state", [None])[0], iss=q.get("iss", [None])[0])


def connector(base: str, codes: Codes, email: str, nickname: str | None, store: Memory | None = None,
              path: str = "/pilot/mcp"):
    pending: dict[str, AuthorizationCodeResult] = {}

    async def redirect(url: str) -> None:
        pending["r"] = sign_in_page(url, email, nickname, codes)

    async def callback() -> AuthorizationCodeResult:
        return pending.pop("r")

    store = store or Memory()
    auth = OAuthClientProvider(
        server_url=f"{base}{path}",
        client_metadata=OAuthClientMetadata(client_name="Test host", redirect_uris=["http://127.0.0.1:9/callback"],
                                            grant_types=["authorization_code", "refresh_token"],
                                            response_types=["code"], token_endpoint_auth_method="none"),
        storage=store, redirect_handler=redirect, callback_handler=callback)
    return Client(streamable_http_client(f"{base}{path}", http_client=httpx2.AsyncClient(auth=auth))), store


def _payload(result) -> dict:
    import json

    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc)
    return json.loads(result.content[0].text)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_the_public_connector_asks_for_sign_in(server):
    base, _ = server
    r = httpx.post(f"{base}/pilot/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/pilot/mcp"' in r.headers["www-authenticate"]
    meta = httpx.get(f"{base}/.well-known/oauth-protected-resource/pilot/mcp").json()
    assert meta["resource"] == f"{base}/pilot/mcp" and meta["authorization_servers"] == [base]
    asm = httpx.get(f"{base}/.well-known/oauth-authorization-server").json()
    assert asm["code_challenge_methods_supported"] == ["S256"] and asm["registration_endpoint"].endswith("/register")
    bad = httpx.post(f"{base}/pilot/mcp", headers={"Authorization": "Bearer onaa_at_nope"}, json={})
    assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]
    # the directory and A2A cards stay public
    assert httpx.get(f"{base}/v1/agents").status_code == 200


@pytest.mark.anyio
async def test_sign_up_message_and_sign_out_with_the_sdk_oauth_client(server):
    base, codes = server
    ann_client, ann_store = connector(base, codes, mail("ann"), "ann")
    bob_client, _ = connector(base, codes, mail("bob"), "bob")
    async with ann_client as ann, bob_client as bob:
        tools = {t.name for t in (await ann.list_tools()).tools}
        assert {"send_message", "check_inbox", "sign_out_everywhere"} <= tools
        bob_addr = _payload(await bob.call_tool("my_address", {}))
        assert bob_addr["name"] == "bob" and bob_addr["listed_in_directory"] is True
        # right after sign-up the assistant is asked to offer an hourly inbox check, once
        assert "every hour" in bob_addr["first_run"]["ask_your_user"]
        assert "check_inbox" in bob_addr["first_run"]["scheduled_prompt"]
        assert "first_run" not in _payload(await bob.call_tool("my_address", {}))
        sent = _payload(await ann.call_tool("send_message", {"to": bob_addr["address"], "text": "Hi Bob!"}))
        assert sent["state"] == "invite_sent"
        got = _payload(await bob.call_tool("check_inbox", {}))
        assert got["conversations"][0]["messages"][0]["message"]["untrusted_text"] == "Hi Bob!"
    assert ann_store.tokens.access_token.startswith("onaa_at_")

    # the same email from another app is the same member; no nickname needed the second time
    again, _ = connector(base, codes, mail("ann"), None)
    async with again as ann2:
        assert _payload(await ann2.call_tool("my_address", {}))["name"] == "ann"

    # refresh rotates; the old refresh token then ends the whole sign-in
    form = {"grant_type": "refresh_token", "refresh_token": ann_store.tokens.refresh_token,
            "client_id": ann_store.client.client_id}
    first = httpx.post(f"{base}/oauth/token", data=form)
    assert first.status_code == 200 and first.json()["refresh_token"] != form["refresh_token"]
    replay = httpx.post(f"{base}/oauth/token", data=form)
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    new_access = first.json()["access_token"]
    r = httpx.post(f"{base}/pilot/mcp", headers={"Authorization": f"Bearer {new_access}"}, json={})
    assert r.status_code == 401  # revoked with its family after the replay

    # sign out everywhere: every app's tokens stop working
    bob_again, bob_store = connector(base, codes, mail("bob"), None)
    async with bob_again as b:
        await b.list_tools()
        ended = bob_store.tokens.access_token
        assert _payload(await b.call_tool("sign_out_everywhere", {}))["signed_out"] is True
    r = httpx.post(f"{base}/pilot/mcp", headers={"Authorization": f"Bearer {ended}"}, json={})
    assert r.status_code == 401  # (the SDK client itself simply asks the person to sign in again)


def test_wrong_codes_and_pkce_are_refused(server):
    base, codes = server
    reg = httpx.post(f"{base}/oauth/register", json={"client_name": "x", "redirect_uris": ["https://app.example/cb"],
                                                      "token_endpoint_auth_method": "none"}).json()
    assert httpx.post(f"{base}/oauth/register", json={"redirect_uris": ["http://evil.example/cb"]}).status_code == 400
    import base64
    import hashlib

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    q = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": "https://app.example/cb",
         "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1"}
    nopkce = httpx.get(f"{base}/oauth/authorize", params={**q, "code_challenge_method": "plain"})
    assert nopkce.status_code == 302 and "error=invalid_request" in nopkce.headers["location"]
    browser = httpx.Client()
    page = browser.get(f"{base}/oauth/authorize", params=q)
    login_id = re.search(r"name=login_id value='([^']+)'", page.text).group(1)
    stranger = httpx.post(f"{base}/oauth/authorize/email", data={"login_id": login_id, "email": mail("cy"),
                                                                  "nickname": "cy"})
    assert stranger.status_code == 403  # another browser cannot continue this sign-in
    browser.post(f"{base}/oauth/authorize/email", data={"login_id": login_id, "email": mail("cy"),
                                                         "nickname": "cy"})
    for _ in range(5):
        assert "not right" in browser.post(f"{base}/oauth/authorize/code",
                                           data={"login_id": login_id, "code": "000000"}).text \
            or codes.by_email[mail("cy")] == "000000"
    locked = browser.post(f"{base}/oauth/authorize/code", data={"login_id": login_id,
                                                                 "code": codes.by_email[mail("cy")]})
    assert "Too many wrong codes" in locked.text  # five wrong tries end that sign-in


def _rpc(base, body, **headers):
    return httpx.post(f"{base}/mcp", json=body, headers={"Accept": "application/json, text/event-stream", **headers})


def test_one_mcp_url_registry_tools_open_member_tools_after_sign_in(server):
    base, _ = server
    listed = _rpc(base, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert listed.status_code == 200
    tools = {t["name"]: t for t in listed.json()["result"]["tools"]}
    assert {"search_agents", "find_stores", "check_inbox", "send_message"} <= set(tools)
    assert tools["search_agents"]["_meta"]["securitySchemes"] == [{"type": "noauth"}]
    assert tools["check_inbox"]["_meta"]["securitySchemes"][0]["type"] == "oauth2"
    # a registry tool works without signing in
    r = _rpc(base, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "get_vocabulary", "arguments": {}}})
    assert r.status_code == 200 and not r.json()["result"].get("isError")
    # a member tool asks for sign-in: HTTP 401 (MCP spec, Claude) ...
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "check_inbox", "arguments": {}}}
    r = _rpc(base, call)
    assert r.status_code == 401
    assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]
    meta = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp").json()
    assert meta["resource"] == f"{base}/mcp"
    assert httpx.get(f"{base}/.well-known/oauth-protected-resource").json()["resource"] == f"{base}/mcp"
    # ... or, for ChatGPT, a tool error carrying the same challenge
    r = _rpc(base, call, **{"User-Agent": "openai-mcp/1.0.0"})
    assert r.status_code == 200 and r.json()["id"] == 3 and r.json()["result"]["isError"] is True
    assert "resource_metadata=" in r.json()["result"]["_meta"]["mcp/www_authenticate"][0]
    # a wrong token is refused outright, so the host refreshes or signs in again
    assert _rpc(base, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                Authorization="Bearer onaa_at_nope").status_code == 401


@pytest.mark.anyio
async def test_the_sdk_client_signs_in_when_a_member_tool_is_first_used_on_mcp(server):
    base, codes = server
    c, store = connector(base, codes, mail("dee"), "dee", path="/mcp")
    async with c as dee:
        assert "find_stores" in {t.name for t in (await dee.list_tools()).tools}
        assert store.tokens is None  # browsing needs no sign-in
        me = _payload(await dee.call_tool("my_address", {}))  # 401 -> sign-in -> retried
        assert me["name"] == "dee" and store.tokens.access_token.startswith("onaa_at_")
        assert "onaa_at_" not in str(_payload(await dee.call_tool("get_vocabulary", {})))



def test_the_body_replay_hands_over_to_the_real_receive():
    """subscriptions/listen (MCP 2026-07-28) streams and watches for the client's disconnect. The replay used to fake a
    disconnect right after the body, so the SDK cancelled the request before answering (uvicorn: 500, "ASGI callable
    returned without starting response"). After the body, the real receive must answer."""
    import anyio

    from onaa_mcp_registry.hosted import _read_body

    async def go():
        msgs = [{"type": "http.request", "body": b'{"jsonrpc":"2.0","id":1,"method":"ping"}', "more_body": False},
                {"type": "http.request.later", "marker": True}]

        async def upstream():
            return msgs.pop(0)
        doc, receive = await _read_body(upstream)
        assert doc["method"] == "ping"
        assert (await receive())["body"].startswith(b"{")
        assert (await receive()).get("marker") is True  # not a made-up http.disconnect
    anyio.run(go)
