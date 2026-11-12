"""Live suite safety: SSRF-safe fetching, no traffic to blocked targets, failures are reported."""

from __future__ import annotations

import httpx

from onaa_protocol.conformance import run_live, run_registry_live
from onaa_protocol.keys import HttpKeyResolver
from onaa_protocol.vectors import jwks, party, signer

PUBLIC = "93.184.215.14"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_blocked_card_url_is_never_fetched(monkeypatch):
    monkeypatch.delenv("ONAA_DEMO_ALLOW_LOCALHOST", raising=False)
    calls = []
    http = _client(lambda r: calls.append(r) or httpx.Response(200, json={}))
    for url in ("https://169.254.169.254/.well-known/agent-card.json", "http://127.0.0.1/.well-known/agent-card.json",
                "https://10.0.0.1/.well-known/agent-card.json"):
        report = run_live(url, "seller_agent", http=http, resolver=lambda h, p: [PUBLIC])
        res = {r["id"]: r for r in report["results"]}
        assert res["ONAA-C-MUST-001"]["outcome"] == "fail"
        assert res["ONAA-C-MUST-020"]["outcome"] == "skip"
        assert report["summary"]["verdict"] == "fail"
    assert calls == []


def test_non_well_known_path_and_redirect_fail():
    http = _client(lambda r: httpx.Response(302, headers={"Location": "https://169.254.169.254/"}))
    for url in ("https://seller.example.com/card.json", "https://seller.example.com/.well-known/agent-card.json"):
        report = run_live(url, "seller_agent", http=http, resolver=lambda h, p: [PUBLIC])
        assert report["results"][0]["outcome"] == "fail"


def test_registry_relay_detected():
    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"items": [], "total": 0, "limit": 20, "offset": 0})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "1", "result": {"message": {}}})
    report = run_registry_live("https://registry.example.com", http=_client(handler),
                               resolver=lambda h, p: [PUBLIC])
    res = {r["id"]: r["outcome"] for r in report["results"]}
    assert res == {"ONAA-C-MUST-040": "pass", "ONAA-C-MUST-041": "pass", "ONAA-C-MUST-042": "fail",
                   "ONAA-C-SHOULD-040": "pass"}


def _card(base, jwks_uri, revoked=()):
    from onaa_protocol.agent_card import build_extension_params, extension_declaration
    params = build_extension_params(roles=["buyer_agent"], jwks_uri=jwks_uri, revoked_kids=list(revoked))
    return {"name": "n", "description": "d", "version": "1", "supportedInterfaces": [
        {"url": base + "/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
        "capabilities": {"extensions": [extension_declaration(params)]}, "defaultInputModes": [],
        "defaultOutputModes": [], "skills": []}


def test_http_key_resolver_same_origin_revocation_and_rotation():
    base = "https://buyer.example.com"
    state = {"jwks": jwks("buyer"), "jwks_uri": base + "/.well-known/onaa/jwks.json", "revoked": []}
    fetched = []

    def handler(req):
        fetched.append(str(req.url))
        if req.url.path == "/.well-known/agent-card.json":
            return httpx.Response(200, json=_card(base, state["jwks_uri"], state["revoked"]))
        return httpx.Response(200, json=state["jwks"])

    sender = party("buyer")
    kid = signer("buyer").kid
    r = HttpKeyResolver(_client(handler), resolver=lambda h, p: [PUBLIC], refetch_seconds=0)
    assert r.resolve(sender, kid)
    # rotation: a new kid triggers one re-fetch
    new = signer("buyer-rotated")
    state["jwks"] = {"keys": [signer("buyer").public_jwk(), new.public_jwk()]}
    assert r.resolve(sender, new.kid)
    # revocation via card params
    state["revoked"] = [kid]
    r2 = HttpKeyResolver(_client(handler), resolver=lambda h, p: [PUBLIC])
    try:
        r2.resolve(sender, kid)
        raise AssertionError("revoked kid accepted")
    except Exception as exc:  # noqa: BLE001
        assert getattr(exc, "code", "") == "key_revoked"
    # cross-origin jwks_uri is refused
    state["revoked"] = []
    state["jwks_uri"] = "https://cdn.example.net/jwks.json"
    r3 = HttpKeyResolver(_client(handler), resolver=lambda h, p: [PUBLIC])
    try:
        r3.resolve(sender, kid)
        raise AssertionError("cross-origin jwks accepted")
    except Exception as exc:  # noqa: BLE001
        assert getattr(exc, "code", "") == "jwks_unavailable"
    assert not any("cdn.example.net" in u for u in fetched)
