"""One-call sign-up for server-hosted agents: address + token, member terms accepted for the operator, per-tier
message caps, the agent accepts requests itself, token rotation and revocation."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from conftest import ITEM_REQUIRED, WANT_REQUIRED
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_messaging import DOMAIN, env, inbox, join, send  # noqa: F401  (env is a fixture)

from onaa_registry import member_terms, models
from onaa_registry.config import AGENT_LIMIT_DEFAULTS
from onaa_registry.main import create_app
from onaa_registry.security import RateLimiter


def terms(c):
    r = c.get("/v1/member-terms")
    assert r.status_code == 200, r.text
    return r.json()


def operator(c, nick="op", google=True):
    c.app.state.pilot_join_limiter = RateLimiter(1000, window_seconds=3600)
    h, _addr = join(c, nick)
    me = c.get("/v1/market/me", headers=h).json()
    if google:
        with c.app.state.sessionmaker() as s:
            s.get(models.PilotMember, me["member_id"]).google_verified_at = models.utcnow()
            s.commit()
    return h


def raw_signup(c, name="bot", **extra):
    t = terms(c)
    r = c.post("/v1/market/agents/signup", json={"name": name, "accept_terms_version": t["version"],
                                                "accept_terms_sha256": t["sha256"], "operator_authorized": True,
                                                **extra})
    assert r.status_code == 201, r.text
    body = r.json()
    return {"Authorization": f"Bearer {body['token']}"}, body


def signup(c, name="bot", op=None, **extra):
    """Sign up and have an operator (a person signed in with Google) claim the agent."""
    h, body = raw_signup(c, name, **extra)
    op = op or operator(c, "op-" + name)
    r = c.post("/v1/market/me/agents/claim", headers=op, json={"claim_code": body["claim"]["code"]})
    assert r.status_code == 200, r.text
    return h, body


def member(c, member_id):
    with c.app.state.sessionmaker() as s:
        return s.get(models.PilotMember, member_id)


def test_signup_returns_address_and_token_and_records_terms(env):  # noqa: F811
    c, _ = env
    h, body = signup(c, about="answers questions about bikes")
    assert DOMAIN in body["address"] and body["address"].endswith("/.well-known/agent-card.json")
    assert body["token"].startswith("pilot_") and body["connector_url"].endswith("/mcp")
    assert body["limits"]["tier"] == "new"
    assert body["limits"]["requests_per_day"] == AGENT_LIMIT_DEFAULTS["new"]["requests_per_day"]
    m = member(c, body["member_id"])
    t = member_terms.current()
    assert (m.kind, m.terms_version, m.terms_sha256, m.terms_accepted_via) == (
        "agent", t.version, t.sha256, "agent_on_behalf_of_operator")
    assert m.terms_accepted_at is not None and m.email_hash is None
    a = c.get("/v1/market/msg/address", headers=h).json()
    assert a["kind"] == "agent" and a["limits"]["used"]["messages_today"] == 0 and "agent_rules" in a


@pytest.mark.parametrize("patch,status", [
    ({"accept_terms_version": "member-draft-0.1"}, 422),
    ({"accept_terms_sha256": "0" * 64}, 422),
    ({"operator_authorized": False}, 422),
    ({"operator_authorized": None}, 422),
])
def test_signup_needs_current_terms_and_operator_authorisation(env, patch, status):  # noqa: F811
    c, _ = env
    t = terms(c)
    body = {"name": "bot", "accept_terms_version": t["version"], "operator_authorized": True} | patch
    body = {k: v for k, v in body.items() if v is not None}
    assert c.post("/v1/market/agents/signup", json=body).status_code == status


def test_signup_can_be_turned_off_and_is_rate_limited(fetcher, txt, runner, env):  # noqa: F811
    c, _ = env
    for i in range(5):
        signup(c, f"b{i}")
    t = terms(c)
    r = c.post("/v1/market/agents/signup", json={"name": "b5", "accept_terms_version": t["version"],
                                                "operator_authorized": True})
    assert r.status_code == 429
    s = dataclasses.replace(c.app.state.settings, pilot_agent_signup=False)
    with TestClient(create_app(s, fetcher, txt, runner)) as c2:
        assert c2.post("/v1/market/agents/signup", json={"name": "x", "accept_terms_version": t["version"],
                                                         "operator_authorized": True}).status_code == 404


def test_agent_accepts_a_request_itself_and_sees_agent_guidance(env):  # noqa: F811
    c, _ = env
    bot, body = signup(c)
    ann, _ = join(c, "ann")
    assert send(c, ann, body["address"], "hi bot, do you fix bikes?").status_code == 200
    box = inbox(c, bot)
    conv = box["conversations"][0]
    assert conv["state"] == "request" and "yourself" in conv["next_step"] and "yourself" in box["next_step"]
    r = c.post(f"/v1/market/msg/conversations/{conv['conversation_id']}/accept", headers=bot)
    assert r.status_code == 200 and r.json()["state"] == "open"
    # ann sees the bot labelled as a signed-up agent, not an email-checked member
    ann_conv = c.get("/v1/market/msg/conversations", headers=ann).json()["conversations"][0]
    assert ann_conv["with"]["trust"]["level"] == "onaa_signed_up_agent"


def test_agent_message_caps_new_tier(env):  # noqa: F811
    c, _ = env
    c.app.state.pilot_join_limiter = RateLimiter(1000, window_seconds=3600)
    caps = {"new": {"requests_per_day": 2, "messages_per_day": 5, "messages_per_hour": 4},
            "established": {"requests_per_day": 50, "messages_per_day": 1000, "messages_per_hour": 120},
            "restricted": {"requests_per_day": 1, "messages_per_day": 2, "messages_per_hour": 2}}
    c.app.state.settings = dataclasses.replace(c.app.state.settings, agent_limits=caps)
    c.app.state.hosting.settings = c.app.state.settings
    bot, _ = signup(c)
    people = [join(c, f"p{i}") for i in range(3)]
    assert send(c, bot, people[0][1], "hello 0").status_code == 200
    assert send(c, bot, people[1][1], "hello 1").status_code == 200
    r = send(c, bot, people[2][1], "hello 2")
    assert r.status_code == 429 and "new conversation requests" in r.json()["detail"]
    # open the two conversations so the bot can keep writing, then hit the hourly cap (4)
    for h, _addr in people[:2]:
        conv = inbox(c, h)["conversations"][0]["conversation_id"]
        assert c.post(f"/v1/market/msg/conversations/{conv}/accept", headers=h).status_code == 200
    convs = [x["conversation_id"] for x in c.get("/v1/market/msg/conversations", headers=bot).json()["conversations"]]
    assert send(c, bot, convs[0], "more 1").status_code == 200
    assert send(c, bot, convs[1], "more 2").status_code == 200
    r = send(c, bot, convs[0], "more 3")
    assert r.status_code == 429 and "hourly" in r.json()["detail"]
    lim = c.get("/v1/market/msg/address", headers=bot).json()["limits"]
    assert lim["used"] == {"requests_today": 2, "messages_today": 4, "messages_this_hour": 4}


def test_tiers_follow_age_and_blocks(env):  # noqa: F811
    c, _ = env
    c.app.state.pilot_join_limiter = RateLimiter(1000, window_seconds=3600)
    bot, body = signup(c)
    with c.app.state.sessionmaker() as s:
        m = s.get(models.PilotMember, body["member_id"])
        m.created_at = m.claimed_at = models.utcnow() - dt.timedelta(days=8)
        s.commit()
    assert c.get("/v1/market/msg/address", headers=bot).json()["limits"]["tier"] == "established"
    blockers = [join(c, f"q{i}") for i in range(3)]
    for i, (h, addr) in enumerate(blockers):
        assert send(c, bot, addr, f"buy my stuff {i}").status_code == 200
        conv = inbox(c, h)["conversations"][0]["conversation_id"]
        assert c.post(f"/v1/market/msg/conversations/{conv}/block", headers=h).status_code == 200
        tier = c.get("/v1/market/msg/address", headers=bot).json()["limits"]["tier"]
        assert tier == ("restricted" if i == 2 else "new")


def test_people_are_not_affected_by_agent_caps(env):  # noqa: F811
    c, _ = env
    ann, _ = join(c, "ann")
    a = c.get("/v1/market/msg/address", headers=ann).json()
    assert "limits" not in a and "kind" not in a


def test_personal_details_are_still_held_for_agents(env):  # noqa: F811
    c, _ = env
    bot, _ = signup(c)
    _, addr = join(c, "ann")
    r = send(c, bot, addr, "call me on +1 415 555 0100")
    assert r.status_code == 200 and r.json()["sent"] is False and r.json()["needs_operator_rule"] is True


def test_token_rotation_and_revocation(env):  # noqa: F811
    c, _ = env
    bot, body = signup(c)
    r = c.post("/v1/market/me/reset-link", headers=bot)
    assert r.status_code == 200
    new = {"Authorization": f"Bearer {r.json()['token']}"}
    assert c.get("/v1/market/msg/address", headers=bot).status_code == 401
    assert c.get("/v1/market/msg/address", headers=new).status_code == 200
    r = c.post("/v1/market/me/sign-out-everywhere", headers=new)
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert c.get("/v1/market/msg/address", headers=new).status_code == 401
    with c.app.state.sessionmaker() as s:
        assert s.scalar(select(models.PilotMember.status).where(models.PilotMember.id == body["member_id"])) == "active"


def test_signups_are_limited_per_network(env):  # noqa: F811
    c, _ = env
    s = c.app.state.settings
    c.app.state.settings = dataclasses.replace(s, pilot_agent_signups_per_ip_hour=100,
                                               pilot_agent_signups_per_network_day=3)
    for i in range(3):
        signup(c, f"n{i}")
    t = terms(c)
    r = c.post("/v1/market/agents/signup", json={"name": "n3", "accept_terms_version": t["version"],
                                                "operator_authorized": True})
    assert r.status_code == 429


def test_network_of_ipv6_is_a_48():
    from onaa_registry.routes.pilot import _network
    assert _network("2001:db8:1:2::5") == _network("2001:db8:1:ffff::9") == "2001:db8:1::/48"
    assert _network("203.0.113.7") == "203.0.113.0/24"


def test_fresh_agents_blocking_do_not_restrict_another_agent(env):  # noqa: F811
    c, _ = env
    c.app.state.pilot_agent_signup_ip_limiter = RateLimiter(100, window_seconds=3600)
    c.app.state.pilot_agent_signup_net_limiter = RateLimiter(100, window_seconds=86400)
    target, body = signup(c, "target")
    with c.app.state.sessionmaker() as s:
        t = s.get(models.PilotMember, body["member_id"])
        t.created_at = t.claimed_at = models.utcnow() - dt.timedelta(days=8)
        s.commit()
    for i in range(3):
        fake, fb = signup(c, f"fake{i}")
        assert send(c, fake, body["address"], f"hi {i}").status_code == 200
        conv = inbox(c, target)["conversations"][0]["conversation_id"]
        assert c.post(f"/v1/market/msg/conversations/{conv}/accept", headers=target).status_code == 200
        conv_f = c.get("/v1/market/msg/conversations", headers=fake).json()["conversations"][0]["conversation_id"]
        assert c.post(f"/v1/market/msg/conversations/{conv_f}/block", headers=fake).status_code == 200
    assert c.get("/v1/market/msg/address", headers=target).json()["limits"]["tier"] == "established"


def test_one_member_takes_few_first_messages_from_new_agents(env):  # noqa: F811
    c, _ = env
    c.app.state.pilot_agent_signup_ip_limiter = RateLimiter(100, window_seconds=3600)
    c.app.state.pilot_agent_signup_net_limiter = RateLimiter(100, window_seconds=86400)
    _, addr = join(c, "ann")
    for i in range(5):
        bot, _ = signup(c, f"s{i}")
        assert send(c, bot, addr, f"hello {i}").status_code == 200
    bot, _ = signup(c, "s5")
    r = send(c, bot, addr, "hello 5")
    assert r.status_code == 429 and "new agents" in r.json()["detail"]


def test_unclaimed_agent_sees_only_its_own_account(env):  # noqa: F811
    c, _ = env
    bot, body = raw_signup(c)
    assert body["status"] == "unclaimed" and body["claim"]["code"].startswith("onaa_claim_")
    a = c.get("/v1/market/msg/address", headers=bot).json()
    assert a["claimed"] is False and a["reachable_by_outside_agents"] is False
    _, addr = join(c, "ann")
    for method, path, kw in (("POST", "/v1/market/msg/send", {"json": {"to": addr, "text": "hi"}}),
                             ("GET", "/v1/market/msg/inbox", {}), ("GET", "/v1/market/matches", {})):
        r = c.request(method, path, headers=bot, **kw)
        assert r.status_code == 403 and "operator" in r.json()["detail"], path
    # nobody can write to it either: its address is not active yet
    assert send(c, operator(c, "x"), body["address"], "hello").status_code == 404
    r = c.post("/v1/market/agents/claim-code", headers=bot)
    assert r.status_code == 200 and r.json()["code"] != body["claim"]["code"]
    op = operator(c, "boss")
    old = c.post("/v1/market/me/agents/claim", headers=op, json={"claim_code": body["claim"]["code"]})
    assert old.status_code == 404  # the earlier code stopped working
    assert c.post("/v1/market/me/agents/claim", headers=op, json={"claim_code": r.json()["code"]}).status_code == 200
    a = c.get("/v1/market/msg/address", headers=bot).json()
    assert a["claimed"] is True and a["operator"] == "boss" and a["reachable_by_outside_agents"] is True
    assert send(c, bot, addr, "hi ann").status_code == 200


def test_claim_needs_a_google_signed_in_person(env):  # noqa: F811
    c, _ = env
    _, body = raw_signup(c)
    code = {"claim_code": body["claim"]["code"]}
    r = c.post("/v1/market/me/agents/claim", headers=operator(c, "emailonly", google=False), json=code)
    assert r.status_code == 403 and "Google" in r.json()["detail"]
    other, _ = signup(c, "other-bot")
    assert c.post("/v1/market/me/agents/claim", headers=other, json=code).status_code == 403  # agents can't operate
    assert c.post("/v1/market/me/agents/claim", headers=operator(c, "g"), json=code).status_code == 200
    assert c.post("/v1/market/me/agents/claim", headers=operator(c, "g2"), json=code).status_code == 404  # one use


def test_limits_are_shared_by_one_operators_agents(env):  # noqa: F811
    c, _ = env
    caps = {"new": {"requests_per_day": 3, "messages_per_day": 100, "messages_per_hour": 100},
            "established": {"requests_per_day": 50, "messages_per_day": 1000, "messages_per_hour": 120},
            "restricted": {"requests_per_day": 1, "messages_per_day": 2, "messages_per_hour": 2}}
    c.app.state.settings = dataclasses.replace(c.app.state.settings, agent_limits=caps)
    c.app.state.hosting.settings = c.app.state.settings
    op = operator(c, "boss")
    a, _ = signup(c, "a", op=op)
    b, _ = signup(c, "b", op=op)
    people = [join(c, f"r{i}")[1] for i in range(4)]
    assert send(c, a, people[0], "hi").status_code == 200
    assert send(c, a, people[1], "hi").status_code == 200
    assert send(c, b, people[2], "hi").status_code == 200
    assert send(c, b, people[3], "hi").status_code == 429  # 3 requests a day for the operator, not per agent
    mine = c.get("/v1/market/me/agents", headers=op).json()
    assert [x["name"] for x in mine["agents"]] == ["a", "b"] and mine["limits"]["used"]["requests_today"] == 3


def test_operator_disables_an_agent(env):  # noqa: F811
    c, _ = env
    op = operator(c, "boss")
    bot, body = signup(c, op=op)
    r = c.post(f"/v1/market/me/agents/{body['member_id']}/disable", headers=op)
    assert r.status_code == 200 and r.json()["agent"]["status"] == "disabled"
    assert c.get("/v1/market/msg/address", headers=bot).status_code == 401
    assert c.post(f"/v1/market/me/agents/{body['member_id']}/disable",
                  headers=operator(c, "stranger")).status_code == 404


def test_operator_agent_cap(env):  # noqa: F811
    c, _ = env
    c.app.state.settings = dataclasses.replace(c.app.state.settings, agent_max_per_operator=1)
    op = operator(c, "boss")
    signup(c, "one", op=op)
    _, body = raw_signup(c, "two")
    r = c.post("/v1/market/me/agents/claim", headers=op, json={"claim_code": body["claim"]["code"]})
    assert r.status_code == 409


def _market(c):
    """One member with an item and a want in a fine-grained area."""
    seller, addr = join(c, "sally")
    r = c.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": "road bike", "price": 300,
                                                       "region": "Yeoksam-dong, Gangnam-gu, Seoul",
                                                       "trade_methods": ["in_person"]})
    assert r.status_code == 201, r.text
    w = c.post("/v1/market/wants", headers=seller, json={**WANT_REQUIRED, "title": "bike helmet",
                                                        "region": "역삼동 강남구 서울"})
    assert w.status_code == 201, w.text
    return seller, addr, r.json()["id"], w.json()


def test_unclaimed_agent_browses_with_rough_area_and_no_contact(env):  # noqa: F811
    c, _ = env
    _seller, addr, item_id, want = _market(c)
    bot, _ = raw_signup(c)
    r = c.get("/v1/market/items", headers=bot, params={"q": "bike"})
    assert r.status_code == 200, r.text
    it = r.json()["items"][0]
    assert it["region"] == "Seoul" and it["seller"] == {"nickname": "sally"}
    assert "claim" in r.json()["next_step"] and addr not in r.text and "online" not in it["seller"]
    one = c.get(f"/v1/market/items/{item_id}", headers=bot).json()
    assert one["region"] == "Seoul" and "message_address" not in one["seller"]
    qa = c.get(f"/v1/market/items/{item_id}/questions", headers=bot)
    assert qa.status_code == 200 and qa.json()["questions"] == []
    assert c.post(f"/v1/market/items/{item_id}/questions", headers=bot,
                  json={"text": "Is the frame aluminium?"}).status_code == 403
    ws = c.get("/v1/market/wants", headers=bot).json()
    assert ws["wants"][0]["region"] == "서울" and "claim" in ws["next_step"]
    # area search matches only what it is shown: a neighbourhood name finds nothing
    assert c.get("/v1/market/items", headers=bot, params={"region": "Yeoksam"}).json()["total"] == 0
    assert c.get("/v1/market/items", headers=bot, params={"region": "seoul"}).json()["total"] == 1
    assert c.get("/v1/market/wants", headers=bot, params={"region": "역삼동"}).json()["wants"] == []
    assert len(c.get("/v1/market/wants", headers=bot, params={"region": "서울"}).json()["wants"]) == 1
    # sending anything still needs the operator
    for path, body in ((f"/v1/market/items/{item_id}/offers", {"amount": 250}),
                       (f"/v1/market/msg/wants/{want['id']}/answer", {"title": "helmet"}),
                       ("/v1/market/items", {**ITEM_REQUIRED, "title": "x", "price": 1}),
                       ("/v1/market/msg/send", {"to": addr, "text": "hi"})):
        r = c.post(path, headers=bot, json=body)
        assert r.status_code == 403 and "operator" in r.json()["detail"], path
    # a person (and a claimed agent) still sees the full area and the address
    op = operator(c, "boss")
    full = c.get("/v1/market/items", headers=op, params={"q": "bike"}).json()["items"][0]
    assert full["region"].startswith("Yeoksam") and full["seller"]["message_address"] == addr


def test_unclaimed_agent_reads_are_capped(env):  # noqa: F811
    c, _ = env
    bot, _ = raw_signup(c)
    c.app.state.pilot_unlinked_limiters = (("ua:", RateLimiter(3, window_seconds=3600)),)
    for _ in range(3):
        assert c.get("/v1/market/wants", headers=bot).status_code == 200
    r = c.get("/v1/market/wants", headers=bot)
    assert r.status_code == 429 and "claim" in r.json()["detail"]
    signup(c, "linked")  # claimed agents and people have no read caps
    other, _ = signup(c, "linked2")
    for _ in range(5):
        assert c.get("/v1/market/wants", headers=other).status_code == 200


def test_old_nickname_accounts_are_browse_only(env):  # noqa: F811
    c, _ = env
    _seller, addr, item_id, _want = _market(c)
    old, old_addr = join(c, "legacy")
    with c.app.state.sessionmaker() as s:  # what migration 0030 does to accounts the retired /join made
        m = s.scalar(select(models.PilotMember).where(models.PilotMember.nickname == "legacy"))
        m.kind, m.a2a_enabled = "nickname", False
        s.commit()
    r = c.get("/v1/market/items", headers=old, params={"q": "bike"})
    assert r.status_code == 200 and r.json()["items"][0]["region"] == "Seoul" and addr not in r.text
    r = c.post(f"/v1/market/items/{item_id}/offers", headers=old, json={"user_approved": True, "amount": 250})
    assert r.status_code == 403 and "retired" in r.json()["detail"]
    assert c.post("/v1/market/msg/send", headers=old, json={"to": addr, "text": "hi"}).status_code == 403
    assert send(c, operator(c, "p"), old_addr, "hello").status_code == 404  # no longer takes messages
    assert c.get("/v1/market/me", headers=old).status_code == 200  # can still see and close its account


def test_claim_without_google_gives_a_one_time_google_check_link(env, monkeypatch):  # noqa: F811
    from urllib.parse import parse_qs, urlsplit

    from onaa_registry import oauth

    c, _ = env
    c.app.state.settings = dataclasses.replace(c.app.state.settings, google_client_id="gid", google_client_secret="gs",
                                               oauth_secret=c.app.state.settings.oauth_secret or "x" * 32)
    at = chr(64)
    h = operator(c, "emailonly", google=False)
    me = c.get("/v1/market/me", headers=h).json()["member_id"]
    with c.app.state.sessionmaker() as s:
        s.get(models.PilotMember, me).email_hash = oauth.email_hash(c.app.state.settings, "ann" + at + "example.org")
        s.commit()
    _, body = raw_signup(c)
    code = {"claim_code": body["claim"]["code"]}
    r = c.post("/v1/market/me/agents/claim", headers=h, json=code)
    assert r.status_code == 403 and "Google" in r.json()["detail"]
    link = r.json()["google_verify_url"]
    assert link in r.json()["detail"] and "/oauth/google/start?login_id=ol_" in link
    login_id = parse_qs(urlsplit(link).query)["login_id"][0]
    # the link never turns into an app sign-in (no emailed code, no authorization code)
    assert "expired" in c.post("/oauth/authorize/email", data={"login_id": login_id, "email": "x" + at + "y.org"}).text

    def google_back(email):
        monkeypatch.setattr(oauth, "google_userinfo",
                            lambda *a: {"sub": "1", "email": email, "email_verified": True})
        url = c.post("/v1/market/me/agents/claim", headers=h, json=code).json()["google_verify_url"]
        go = c.get(url.replace("http://testserver", ""), follow_redirects=False)
        assert go.status_code == 302 and go.headers["location"].startswith(oauth.GOOGLE_AUTH)
        state = parse_qs(urlsplit(go.headers["location"]).query)["state"][0]
        return c.get("/oauth/google/callback", params={"state": state, "code": "g"}, follow_redirects=False)

    wrong = google_back("someone-else" + at + "example.org")
    assert wrong.status_code == 403 and "different email" in wrong.text
    assert c.post("/v1/market/me/agents/claim", headers=h, json=code).status_code == 403  # still not verified
    ok = google_back("Ann" + at + "Example.org")
    assert ok.status_code == 200 and "confirmed" in ok.text
    again = c.get("/oauth/google/callback", params={"state": "x.y", "code": "g"})
    assert "expired" in again.text
    r = c.post("/v1/market/me/agents/claim", headers=h, json=code)
    assert r.status_code == 200 and r.json()["claimed"] is True
