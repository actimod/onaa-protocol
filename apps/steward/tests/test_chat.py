"""Natural-language conversation: Claude picks steward skills as tools; guardrails hold. The model is faked."""

from __future__ import annotations

from types import SimpleNamespace as NS

from conftest import register
from onaa_protocol.a2a import ROLE_USER, make_message
from starlette.testclient import TestClient

from onaa_steward.chat import TOOLS
from onaa_steward.server import create_app


class FakeClaude:
    """Replays scripted responses; records every request."""

    def __init__(self, script):
        self.script, self.requests = list(script), []
        self.beta = NS(messages=NS(create=self._create))
        self.messages = NS(create=self._create)

    def _create(self, **kw):
        self.requests.append(kw)
        return self.script.pop(0)


def tool_use(name, inp, i="t1"):
    return NS(stop_reason="tool_use", model="claude-opus-5-5",
              content=[NS(type="tool_use", id=i, name=name, input=inp)])


def text(t):
    return NS(stop_reason="end_turn", model="claude-opus-5-5", content=[NS(type="text", text=t)])


def ask(st, question, ctx=None):
    msg = make_message(ROLE_USER, [{"text": question}], context_id=ctx)
    r = st.post("/a2a/v1", headers={"A2A-Version": "1.0"},
                json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}})
    return r.json()["result"]["message"]["parts"]


def app(steward, fake, **opts):
    return TestClient(create_app(steward, public_url="https://api.example.com/steward",
                                 registry_url="https://api.example.com", chat_client=fake, chat_options=opts))


def test_question_runs_skills_and_answers(registry, steward, seller):
    sid = register(registry, seller, "seller_agent", ["commerce.rfq.receive"])
    fake = FakeClaude([tool_use("search_listings", {"query": "Parts Seller", "kind": "agents"}),
                       tool_use("check_health", {"listing_id": sid}, "t2"),
                       text("Example Parts Seller 는 정상입니다.")])
    with app(steward, fake) as st:
        parts = ask(st, "Example Parts Seller 상태 어때?", ctx="c1")
    assert parts[0]["text"] == "Example Parts Seller 는 정상입니다."
    assert parts[1]["data"]["tools_used"] == ["search_listings", "check_health"]
    req = fake.requests[-1]
    assert req["model"] == "claude-opus-5-5" and req["fallbacks"] == "default"
    assert {t["name"] for t in req["tools"]} == {t["name"] for t in TOOLS}
    results = [b for m in req["messages"] if m["role"] == "user" and isinstance(m["content"], list)
               for b in m["content"]]
    assert all(r["content"].startswith("<untrusted_tool_result>") for r in results)
    assert sid in results[0]["content"]  # search found it
    assert seller.ping_requests == 1      # the health check really ran
    assert "untrusted" in req["system"]


def test_history_kept_per_context(steward):
    fake = FakeClaude([text("first"), text("second")])
    with app(steward, fake) as st:
        ask(st, "hello", ctx="c9")
        ask(st, "and again?", ctx="c9")
    msgs = fake.requests[-1]["messages"]
    assert [m["content"] for m in msgs] == ["hello", "first", "and again?"]


def test_disabled_without_key_returns_help(steward):
    with app(steward, None) as st:
        parts = ask(st, "hi")
    assert "data part" in parts[0]["text"] and parts[1]["data"]["conversation_enabled"] is False


def test_daily_limit_and_tool_errors(steward):
    fake = FakeClaude([tool_use("get_listing", {"listing_id": "agt_missing"}), text("not found")])
    with app(steward, fake, daily_limit=1) as st:
        assert ask(st, "agt_missing?")[0]["text"] == "not found"
        assert "daily" in ask(st, "again")[0]["text"]
    err = fake.requests[-1]["messages"][-1]["content"][0]
    assert err["is_error"] is True and "HTTPStatusError" in err["content"]


def test_tool_rounds_are_capped(steward):
    fake = FakeClaude([tool_use("network_status", {}, f"t{i}") for i in range(10)])
    with app(steward, fake, max_tool_rounds=2) as st:
        parts = ask(st, "loop forever")
    assert len(fake.requests) == 3 and "ran out of steps" in parts[0]["text"]
