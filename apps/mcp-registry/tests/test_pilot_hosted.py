"""Selling-agent pilot over the hosted personal connector URL /pilot/<token>/mcp: two members, one deal, driven by
the official MCP client against the real Registry API (SQLite) in one uvicorn process."""

from __future__ import annotations

import json
import logging
import secrets
import socket
import threading
import time

import httpx
import pytest

pytest.importorskip("onaa_registry")
uvicorn = pytest.importorskip("uvicorn")

from mcp import Client  # noqa: E402

DETAILS = {"currency": "USD", "region": "Austin TX", "trade_methods": ["in_person", "shipping"],
           "payment_methods": ["cash"],
           "quantity": 1, "condition": "used_good"}
PILOT_TOOLS = {"list_item", "update_item", "search_items", "make_offer", "my_offers", "respond_offer", "my_deals",
               "my_agent", "update_my_agent", "approve_order", "decline_order", "agent_inbox", "agent_deal",
               "wait_for_updates", "publish_check_schedule", "post_want", "search_wants", "answer_want", "update_want",
               "find_matches", "start_shopping", "my_shopping", "shopping_action",
               "my_address", "claim_agent", "my_agents", "disable_agent", "update_my_card", "send_message",
               "check_inbox",
               "wait_for_messages", "conversations", "read_conversation", "conversation_action",
               "sign_out_everywhere", "listing_questions", "ask_about_listing", "answer_listing_question",
               "moderate_listing_question",
               "cancel_agent_order",
               "deal_action", "deal_rules", "update_deal_rules", "report_listing", "save_price_range",
               "price_ranges", "clear_price_range"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def pilot(tmp_path_factory):
    port = _free_port()
    admin = secrets.token_urlsafe(24)
    db = tmp_path_factory.mktemp("db") / "pilot.db"
    env = {"ONAA_DATABASE_URL": f"sqlite:///{db}", "ONAA_AUTO_CREATE_SCHEMA": "1", "ONAA_ADMIN_TOKEN": admin,
           "PORT": str(port), "ONAA_PUBLIC_BASE_URL": "https://api.onaa.example", "ONAA_PILOT_ENABLED": "1",
           "ONAA_STEWARD_ENABLED": "0", "ONAA_HOSTING_DOMAIN": "agents.test", "ONAA_HOSTING_SCHEME": "http",
           "ONAA_HOSTED_AGENT_SECRET": "test-only-hosted-agent-secret-0123456789",
           "ONAA_PILOT_TOKEN_URL_RETIRE_AT": "2099-01-01"}
    mp = pytest.MonkeyPatch()
    for k, v in env.items():
        mp.setenv(k, v)
    for k in ("ONAA_MCP_ENABLED", "ONAA_MCP_UPSTREAM", "ONAA_TERMS_VERSION"):
        mp.delenv(k, raising=False)
    from onaa_mcp_registry.hosted import create_app

    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="info"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/v1/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    hdrs = {"Authorization": f"Bearer {admin}"}
    members = {}
    for nick, contact in (("seller", "phone:+1-555-0101"), ("buyer", "phone:+1-555-0102")):
        r = httpx.post(f"{base}/v1/admin/market/members", headers=hdrs,
                       json={"nickname": nick, "contact": contact, "region": "Austin TX", "a2a_enabled": True})
        assert r.status_code == 201, r.text
        members[nick] = r.json()["token"]
    yield base, members
    server.should_exit = True
    t.join(timeout=10)
    mp.undo()


def _payload(result) -> dict:
    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc)
    return json.loads(result.content[0].text)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_two_members_make_a_deal_over_their_connectors(pilot):
    base, tokens = pilot
    seller_url, buyer_url = (f"{base}/pilot/{tokens[n]}/mcp" for n in ("seller", "buyer"))
    lines: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: lines.append(record.getMessage())
    access = logging.getLogger("uvicorn.access")
    access.addHandler(handler)
    try:
        async with Client(seller_url) as seller, Client(buyer_url) as buyer:
            tools = {t.name for t in (await seller.list_tools()).tools}
            assert tools == PILOT_TOOLS
            ask = _payload(await seller.call_tool("list_item", {"title": "Mechanical keyboard", "price": 50,
                                                                "description": "brown switches"}))
            assert ask["listed"] is False and {"currency", "region"} <= set(ask["missing"])
            assert "Austin TX" in ask["next_step"]
            # the personal token address is retired: every answer says so until the date (decision 2026-11-19)
            assert ask["connection_notice"]["retires_on"] == "2099-01-01"
            assert "/mcp" in ask["connection_notice"]["tell_your_user"]
            # first use: the assistant accepted the member terms for its user and is told to say so, with the link
            terms = ask["member_terms"]
            assert terms["accepted_version"].startswith("member-") and terms["url"].endswith("/member-terms")
            assert "on their behalf" in terms["tell_your_user"] and "object" not in terms["tell_your_user"]
            it = _payload(await seller.call_tool("list_item", {"title": "Mechanical keyboard", "price": 50,
                                                               "description": "brown switches", **DETAILS}))
            assert it["mine"] is True and it["region"] == "Austin TX"
            # repeated for a few minutes (the first answer can be an error); the assistant tells its user once
            assert "already told them" in it["member_terms"]["tell_your_user"]
            found = _payload(await buyer.call_tool("search_items", {"query": "keyboard", "max_price": 60}))
            assert [i["id"] for i in found["items"]] == [it["id"]]
            q = _payload(await buyer.call_tool("ask_about_listing", {"item_id": it["id"],
                                                                     "text": "Which layout, ANSI or ISO?"}))
            assert q["posted"] and q["by"]["name"].startswith("buyer-")
            ans = _payload(await seller.call_tool("answer_listing_question", {"question_id": q["id"],
                                                                              "text": "ANSI"}))
            assert ans["by"]["name"] == "Seller"
            qa = _payload(await buyer.call_tool("listing_questions", {"item_id": it["id"]}))
            assert qa["questions"][0]["answers"][0]["content"]["untrusted_text"] == "ANSI"
            cursor = _payload(await seller.call_tool("wait_for_updates", {"wait_seconds": 0}))["cursor"]
            # the buyer's rules say ask (the default): nothing happens until the assistant says the user agreed
            held = _payload(await buyer.call_tool("make_offer", {"item_id": it["id"], "amount": 40}))
            assert held["done"] is False and "40 USD" in held["ask_your_user"]
            offer = _payload(await buyer.call_tool("make_offer", {"item_id": it["id"], "amount": 40,
                                                                  "user_approved": True}))
            news = _payload(await seller.call_tool("wait_for_updates", {"since": cursor, "wait_seconds": 5}))
            assert news["changed"] and news["offers"][0]["id"] == offer["id"]
            inbox = _payload(await seller.call_tool("my_offers", {}))
            assert inbox["waiting_for_you"] == 1
            _payload(await seller.call_tool("respond_offer", {"offer_id": offer["id"], "action": "counter",
                                                              "amount": 45, "user_approved": True}))
            done = _payload(await buyer.call_tool("respond_offer", {"offer_id": offer["id"], "action": "accept",
                                                                    "user_approved": True}))
            assert done["status"] == "accepted" and "contact" not in done["counterparty"]
            assert "555-010" not in json.dumps(done)  # the contact numbers (not digits in a timestamp)
            # the seller's assistant proposes a handoff; the buyer agrees: arranged
            prop = _payload(await seller.call_tool("deal_action", {
                "offer_id": offer["id"], "action": "propose", "payment_method": "cash",
                "trade_method": "in_person", "handoff_time": "Sat 3pm", "handoff_place": "Central Library",
                "user_approved": True}))
            assert prop["deal"]["arrangement"]["proposed_by"] == "you"
            mine = _payload(await buyer.call_tool("my_deals", {}))["deals"][0]["deal"]["arrangement"]
            agreed = _payload(await buyer.call_tool("deal_action", {"offer_id": offer["id"], "action": "agree",
                                                                    "proposal_at": mine["proposal_at"],
                                                                    "user_approved": True}))
            assert agreed["deal"]["state"] == "arranged"
            deals = _payload(await seller.call_tool("my_deals", {}))
            assert deals["deals"][0]["deal"]["state"] == "arranged" and deals["deals"][0]["amount"] == 45
    finally:
        access.removeHandler(handler)
    logged = " ".join(lines)  # uvicorn's access log: where a token in the URL would leak
    assert "/pilot/-/mcp" in logged
    assert tokens["seller"] not in logged and tokens["buyer"] not in logged


def test_bad_or_missing_token_and_public_mcp_untouched(pilot):
    base, _ = pilot
    init = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    hdrs = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    assert httpx.post(f"{base}/pilot/nope/mcp", json=init, headers=hdrs).status_code == 404
    assert httpx.get(f"{base}/pilot/pilot_{'a' * 32}/mcp").status_code == 405
    # A well-formed but unknown token reaches the tools, which answer 401 from the API.
    r = httpx.post(f"{base}/pilot/pilot_{'a' * 32}/mcp", headers=hdrs, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "my_deals", "arguments": {}}})
    assert r.status_code == 200 and "401" in r.text
    names = {t["name"] for t in httpx.post(f"{base}/mcp", json=init, headers=hdrs).json()["result"]["tools"]}
    assert not names & PILOT_TOOLS


@pytest.mark.anyio
async def test_agents_trade_over_hosted_a2a_addresses(pilot):
    base, tokens = pilot
    seller_url, buyer_url = (f"{base}/pilot/{tokens[n]}/mcp" for n in ("seller", "buyer"))
    async with Client(seller_url) as seller, Client(buyer_url) as buyer:
        me = _payload(await seller.call_tool("my_agent", {}))
        assert me["a2a_enabled"] is True and me["agent_card_url"].startswith("http://pm-")
        it = _payload(await seller.call_tool("list_item", {"title": "Film camera Olympus", "price": 120,
                                                           "floor_price": 100, **DETAILS}))
        # Buying from another member goes through offers; the tools that had ONAA sign quotes for the buyer
        # (find_seller_agents, browse_agent_catalog, request_quote, accept_quote) are gone.
        offer = _payload(await buyer.call_tool("make_offer", {"item_id": it["id"], "amount": 105,
                                                              "user_approved": True}))
        assert offer["status"] == "open"
        mine = _payload(await seller.call_tool("my_offers", {"role": "seller"}))
        assert mine["offers"][0]["id"] == offer["id"]  # the seller sees it where both sides look
    # The agent card is served on the member's own host through the same process.
    host = me["agent_card_url"].split("/")[2]
    card = httpx.get(f"{base}/.well-known/agent-card.json", headers={"Host": host})
    assert card.status_code == 200 and card.json()["supportedInterfaces"][0]["url"].startswith(f"http://{host}")


@pytest.mark.anyio
async def test_messages_between_connectors_and_a_polling_run(pilot):
    """What a 5-minute scheduled run does: check_inbox, show what is new, nothing twice."""
    base, tokens = pilot
    seller_url, buyer_url = (f"{base}/pilot/{tokens[n]}/mcp" for n in ("seller", "buyer"))
    async with Client(seller_url) as seller, Client(buyer_url) as buyer:
        addr = _payload(await seller.call_tool("my_address", {}))
        assert addr["address"].startswith("http://pm-") and addr["check_schedule"]["checks_every_minutes"] is None
        _payload(await seller.call_tool("check_inbox", {}))  # start from a clean mark
        sent = _payload(await buyer.call_tool("send_message", {"to": addr["address"],
                                                               "text": "Hi, do you still have the camera?"}))
        assert sent["state"] == "invite_sent"
        run1 = _payload(await seller.call_tool("check_inbox", {}))
        assert run1["new_requests"] == 1
        conv = run1["conversations"][0]
        assert conv["messages"][0]["message"]["untrusted_text"] == "Hi, do you still have the camera?"
        run2 = _payload(await seller.call_tool("check_inbox", {}))
        assert run2["new_messages"] == 0 and run2["summary"].startswith("Nothing new.")
        reply = _payload(await seller.call_tool("send_message", {"to": conv["conversation_id"],
                                                                 "text": "Yes, it is."}))
        assert reply["state"] == "open"
        got = _payload(await buyer.call_tool("check_inbox", {}))
        assert got["conversations"][0]["messages"][0]["message"]["untrusted_text"] == "Yes, it is."
        blocked = _payload(await seller.call_tool("conversation_action", {"conversation_id": conv["conversation_id"],
                                                                           "action": "block"}))
        assert blocked["state"] == "blocked"
        # the block made in messaging also stops offers between the two
        it = _payload(await seller.call_tool("list_item", {"title": "Tripod", "price": 20, **DETAILS}))
        refused = _payload(await buyer.call_tool("make_offer", {"item_id": it["id"], "amount": 15,
                                                                "user_approved": True}))
        assert refused["error"]["status"] == 409
        unblocked = _payload(await seller.call_tool("conversation_action", {
            "conversation_id": conv["conversation_id"], "action": "unblock"}))
        assert unblocked["state"] != "blocked"


def _values(x):
    if isinstance(x, dict):
        return [v for y in x.values() for v in _values(y)]
    if isinstance(x, list):
        return [v for y in x for v in _values(y)]
    return [x]


@pytest.mark.anyio
async def test_ranges_are_private_notes_and_only_the_members_ais_negotiate(pilot):
    """ONAA never negotiates: a saved range makes no move. Each side's own AI offers and answers, within its user's
    range and deal rules, and both see the same offer."""
    base, tokens = pilot
    seller_url, buyer_url = (f"{base}/pilot/{tokens[n]}/mcp" for n in ("seller", "buyer"))
    async with Client(seller_url) as seller, Client(buyer_url) as buyer:
        it = _payload(await seller.call_tool("list_item", {"title": "Brass desk lamp", "price": 40, **DETAILS}))
        r = _payload(await seller.call_tool("save_price_range", {"item_id": it["id"], "lowest_price": 30}))
        assert r["saved"] is True and r["range"]["lowest_price"] == 30 and "never" in r["private"]
        b = _payload(await buyer.call_tool("save_price_range", {"item_id": it["id"], "highest_price": 36}))
        assert b["range"]["highest_price"] == 36
        before = _payload(await seller.call_tool("my_offers", {"state": "all"}))["offers"]
        assert not [x for x in before if x["item"]["id"] == it["id"]]  # the server made no move
        # each saved range is that user's permission to close alone inside it, on this item only
        rules = _payload(await buyer.call_tool("deal_rules", {}))
        assert "confirm_deal" not in rules["rules"] and "per item" in rules["prices"]
        o = _payload(await buyer.call_tool("make_offer", {"item_id": it["id"], "amount": 32}))
        assert o["status"] == "open" and o["your_range"]["highest_price"] == 36  # within the limit: no question
        seen = next(x for x in _payload(await seller.call_tool("my_offers", {}))["offers"] if x["id"] == o["id"])
        assert seen["id"] == o["id"] and seen["your_turn"] and seen["your_range"]["lowest_price"] == 30
        # The buyer's private limit never shows (check values, not the text: timestamps can contain "36").
        assert "highest_price" not in str(seen) and 36 not in _values(seen["counterparty"])
        ok = _payload(await seller.call_tool("respond_offer", {"offer_id": o["id"], "action": "accept"}))
        assert ok["status"] == "accepted" and ok["deal"]["state"] == "arranging"
        ranges = _payload(await seller.call_tool("price_ranges", {}))
        assert ranges["active"] == [] or all(x["item"]["status"] == "reserved" for x in ranges["active"])


@pytest.mark.anyio
async def test_retired_token_address_answers_410():
    from onaa_mcp_registry.hosted import _Dispatcher

    app = _Dispatcher.__new__(_Dispatcher)
    app.pilot_app, app.usage, app.token_url_retire_at = object(), None, "2000-01-01"
    sent = []

    async def send(message):
        sent.append(message)

    await app._pilot({"type": "http", "method": "POST", "path": "/pilot/pilot_" + "a" * 20 + "/mcp"}, None, send,
                     "/pilot/pilot_" + "a" * 20 + "/mcp")
    assert sent[0]["status"] == 410 and b"/mcp" in sent[1]["body"]
