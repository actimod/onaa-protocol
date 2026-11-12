from __future__ import annotations

import httpx
import pytest

from onaa import OnaaClient, OnaaError
from onaa.client import _params


def test_refuses_key_over_plain_http_to_remote_host():
    with pytest.raises(ValueError):
        OnaaClient("http://registry.example.com", api_key="onaa_sk_x")
    OnaaClient("http://localhost:8000", api_key="onaa_sk_x").close()
    OnaaClient("https://registry.example.com", api_key="onaa_sk_x").close()


def test_auth_required_calls_fail_without_key():
    with OnaaClient("https://registry.example.com") as c, pytest.raises(ValueError):
        c.me()


def test_param_encoding():
    assert _params({"region": ["US", "KR"], "verified_only": True, "certified_only": False, "q": None,
                    "status_": "registered", "limit": 5}) == [
        ("region", "US"), ("region", "KR"), ("verified_only", "true"), ("status", "registered"), ("limit", "5")]


def test_error_mapping_and_bearer_header():
    seen = {}

    def handler(request: httpx.Request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(409, json={"detail": "conflict here"})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    c = OnaaClient("https://registry.example.com", api_key="onaa_sk_abc", http_client=http)
    with pytest.raises(OnaaError) as ei:
        c.register_agent(display_name="x", roles=["seller_agent"], agent_card_url="https://x.example.com/card")
    assert ei.value.status_code == 409 and ei.value.detail == "conflict here"
    assert seen["auth"] == "Bearer onaa_sk_abc"
