"""SSRF policy for Agent Card / endpoint fetches. No real DNS or network: resolvers are injected."""

from __future__ import annotations

import httpx
import pytest

from onaa_demo.safe_fetch import UnsafeURLError, fetch_json, validate_url

PUBLIC = "93.184.215.14"


def resolver_to(*addrs):
    def _r(host, port):
        return list(addrs)
    return _r


@pytest.mark.parametrize("url", [
    "http://seller.example.com/.well-known/agent-card.json",     # not https
    "ftp://seller.example.com/x",
    "file:///etc/passwd",
    "https://user:pw@seller.example.com/x",
    "https://127.0.0.1/x",
    "https://[::1]/x",
    "https://10.0.0.5/x",
    "https://192.168.1.1/x",
    "https://172.16.0.1/x",
    "https://169.254.169.254/latest/meta-data",
    "https://100.64.0.1/x",                                        # CGNAT
    "https://[fd00::1]/x",                                         # ULA
    "https://[::ffff:10.0.0.1]/x",                                 # IPv4-mapped private
    "https://0.0.0.0/x",
    "https:///nohost",
])
def test_rejected_in_strict_mode(strict_mode, url):
    with pytest.raises(UnsafeURLError):
        validate_url(url, resolver=resolver_to(PUBLIC))


@pytest.mark.parametrize("addrs", [("127.0.0.1",), ("10.1.2.3",), (PUBLIC, "192.168.0.10"), ()])
def test_hostname_resolving_to_private_is_rejected(strict_mode, addrs):
    with pytest.raises(UnsafeURLError):
        validate_url("https://rebind.example.com/x", resolver=resolver_to(*addrs))


def test_public_https_accepted(strict_mode):
    assert validate_url("https://seller.example.com/.well-known/agent-card.json",
                        resolver=resolver_to(PUBLIC)) == [PUBLIC]


def test_localhost_requires_explicit_env(strict_mode, monkeypatch):
    url = "http://127.0.0.1:8080/.well-known/agent-card.json"
    with pytest.raises(UnsafeURLError):
        validate_url(url)
    monkeypatch.setenv("ONAA_DEMO_ALLOW_LOCALHOST", "true")        # only the exact value "1" counts
    with pytest.raises(UnsafeURLError):
        validate_url(url)
    monkeypatch.setenv("ONAA_DEMO_ALLOW_LOCALHOST", "1")
    assert validate_url(url) == ["127.0.0.1"]


def test_demo_mode_still_blocks_other_private_ranges(allow_localhost):
    for url in ("http://10.0.0.1/x", "https://169.254.169.254/x", "http://seller.example.com/x"):
        with pytest.raises(UnsafeURLError):
            validate_url(url, resolver=resolver_to(PUBLIC))
    with pytest.raises(UnsafeURLError):  # http to a host that resolves to loopback AND public
        validate_url("http://mixed.example.com/x", resolver=resolver_to("127.0.0.1", PUBLIC))


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_refuses_redirects(strict_mode):
    def h(req):
        return httpx.Response(302, headers={"Location": "https://169.254.169.254/"})
    with pytest.raises(UnsafeURLError, match="redirect"):
        fetch_json(_client(h), "https://seller.example.com/.well-known/agent-card.json",
                   resolver=resolver_to(PUBLIC))


def test_fetch_size_cap_and_content_type(strict_mode):
    big = _client(lambda r: httpx.Response(200, json={"x": "a" * 1000}))
    with pytest.raises(UnsafeURLError, match="too large"):
        fetch_json(big, "https://s.example.com/a", resolver=resolver_to(PUBLIC), max_bytes=100)
    html = _client(lambda r: httpx.Response(200, text="<html>", headers={"content-type": "text/html"}))
    with pytest.raises(UnsafeURLError, match="content-type"):
        fetch_json(html, "https://s.example.com/a", resolver=resolver_to(PUBLIC))


def test_fetch_never_contacts_blocked_url(strict_mode):
    calls = []
    c = _client(lambda r: calls.append(r) or httpx.Response(200, json={}))
    with pytest.raises(UnsafeURLError):
        fetch_json(c, "https://internal.example.com/a", resolver=resolver_to("10.0.0.7"))
    assert calls == []
