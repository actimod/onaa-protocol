"""The safety rules reach the assistant: clients keep only about the first 4,000 characters of instructions."""

from __future__ import annotations

from onaa_mcp_registry import pilot, server

CLIENT_CUT = 4000


def test_rules_come_first_and_survive_the_client_cut():
    combined = (server.INSTRUCTIONS + "\n\n" + pilot.INSTRUCTIONS)
    kept = combined[:CLIENT_CUT]
    assert pilot.RULES in kept
    for words in ("user_approved=true only after their yes", "prohibited_item", "member_terms",
                  "never negotiates"):
        assert words in kept, words
    assert len(pilot.RULES) < 1500  # rules 9-11 (2026-11-20); what matters is that they survive the cut


def test_ids_that_would_change_the_endpoint_are_refused(monkeypatch):
    import httpx

    sent = []
    monkeypatch.setattr(pilot, "token_of", lambda ctx: "oa_token")
    monkeypatch.setattr(httpx, "request", lambda *a, **k: sent.append(a) or httpx.Response(200, json={}))
    call = pilot.http_caller("https://api.example.test")
    for bad in ("../../me/sign-out-everywhere#", "x?y=1", "a/b", "..", "it 1", ""):
        out = call("POST", f"/v1/market/agent/deals/{pilot._id(bad)}/decline", None)
        assert out["error"]["status"] == 400, bad
    assert call("POST", "/v1/market/agent/deals/../../me/sign-out-everywhere", None)["error"]["status"] == 400
    assert sent == []
    assert call("GET", "/v1/market/items/it_AbC-12_x", None) == {}
    assert len(sent) == 1
