"""Founder decisions after the 2026-11-19 review: prohibited words, report abuse limits, deal text retention,
loosening deal rules only through a confirm link the user opens."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from conftest import ADMIN, ITEM_REQUIRED
from fastapi.testclient import TestClient

from onaa_registry import prohibited, report_rules
from onaa_registry.main import create_app
from onaa_registry.models import PilotItem, PilotItemQuestion, PilotMember


def test_prohibited_covers_cannabis_meth_and_explosives_without_garden_and_brand_false_positives():
    for text in ("cannabis gummies", "weed 1g", "Marijuana pre-rolls", "meth", "THC carts", "hand grenade", "grenade",
                 "dynamite sticks", "C4 explosive", "semtex", "blasting caps", "수류탄", "다이너마이트", "마리화나"):
        assert prohibited.check(text), text
    for text in ("weed killer spray", "weed trimmer", "seaweed snack", "tumbleweed decor", "grenade protein bar",
                 "Citroen C4 2015", "TNT express shipping", "explosive sound speaker", "method book"):
        assert prohibited.check(text) is None, text


# --- shared helpers -------------------------------------------------------------------------------------------------

A = {"Authorization": f"Bearer {ADMIN}"}
AT = chr(64)
OK = {"user_approved": True}


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick, *, days_old: int = 0):
    r = c.post("/v1/admin/market/members", headers=A, json={"nickname": nick, "contact": "", "region": "Austin TX"})
    assert r.status_code == 201, r.text
    mid = r.json()["member_id"]
    if days_old:
        with c.app.state.sessionmaker() as s:
            s.get(PilotMember, mid).created_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=days_old)
            s.commit()
    return {"Authorization": f"Bearer {r.json()['token']}"}, mid


def item(c, h, **kw):
    body = {**ITEM_REQUIRED, "title": "Road bike 54cm", "price": 300, "currency": "USD"} | kw
    r = c.post("/v1/market/items", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def status(c, item_id):
    with c.app.state.sessionmaker() as s:
        return s.get(PilotItem, item_id).status


# --- decision 3: report abuse -----------------------------------------------------------------------------------------

def test_new_accounts_count_half_toward_hiding_a_listing(pc, monkeypatch):
    monkeypatch.setattr(report_rules, "NEW_ACCOUNT_DAYS", 7)
    seller, _ = member(pc, "s")
    it = item(pc, seller)
    fresh = [member(pc, f"n{i}")[0] for i in range(5)]
    for h in fresh:  # 5 x 0.5 = 2.5, below 3
        pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "scam"})
    assert status(pc, it["id"]) == "available"
    old, _ = member(pc, "old", days_old=30)  # + 1 = 3.5
    pc.post(f"/v1/market/items/{it['id']}/report", headers=old, json={"reason": "scam"})
    assert status(pc, it["id"]) == "under_review"


def test_daily_report_cap_per_operator(pc, monkeypatch):
    monkeypatch.setattr(report_rules, "REPORTS_PER_DAY", 2)
    seller, _ = member(pc, "s")
    rep, _ = member(pc, "r")
    items = [item(pc, seller, title=f"Desk {i}") for i in range(3)]
    for it in items[:2]:
        assert pc.post(f"/v1/market/items/{it['id']}/report", headers=rep, json={"reason": "scam"}).status_code == 200
    assert pc.post(f"/v1/market/items/{items[2]['id']}/report", headers=rep, json={"reason": "scam"}).status_code == 429


def test_unreviewed_hide_lapses_after_a_week_and_the_same_reporters_cannot_hide_it_again(pc):
    from onaa_registry.routes import pilot_reports

    seller, _ = member(pc, "s")
    it = item(pc, seller)
    reps = [member(pc, f"r{i}")[0] for i in range(3)]
    for h in reps:
        pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "scam"})
    assert status(pc, it["id"]) == "under_review"
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=8)
    with pc.app.state.sessionmaker() as s:
        assert pilot_reports.lapse_unreviewed(s, pc.app.state.settings, later) == 1
        s.commit()
    assert status(pc, it["id"]) == "available"
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["review"]["state"] == "restored"
    for h in reps:
        assert pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "scam"}).json()["already"]
    assert status(pc, it["id"]) == "available"


def test_qa_reports_weighted_and_lapse(pc, monkeypatch):
    from onaa_registry.routes import pilot_qa

    monkeypatch.setattr(report_rules, "NEW_ACCOUNT_DAYS", 7)
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    q = pc.post(f"/v1/market/items/{it['id']}/questions", headers=buyer, json={"text": "Is it still available?"}).json()
    for i in range(4):  # 4 x 0.5 = 2
        pc.post(f"/v1/market/questions/{q['id']}/report", headers=member(pc, f"n{i}")[0], json={"reason": "spam"})
    old, _ = member(pc, "old", days_old=30)
    pc.post(f"/v1/market/questions/{q['id']}/report", headers=old, json={"reason": "spam"})
    with pc.app.state.sessionmaker() as s:
        assert s.get(PilotItemQuestion, q["id"]).status == "hidden"
        assert pilot_qa.lapse_unreviewed(s, dt.datetime.now(dt.UTC) + dt.timedelta(days=8)) == 1
        s.commit()
        assert s.get(PilotItemQuestion, q["id"]).status == "visible"
    assert pc.post(f"/v1/market/questions/{q['id']}/report", headers=old, json={"reason": "spam"}).json()["already"]
    with pc.app.state.sessionmaker() as s:
        assert s.get(PilotItemQuestion, q["id"]).status == "visible"


# --- decision 8: toy and airsoft guns -------------------------------------------------------------------------------

def test_toy_and_airsoft_versions_of_gun_names_are_allowed_but_real_ones_are_not():
    for text in ("AK-47 airsoft", "AK-47 airsoft rifle", "airsoft AK-47 rifle", "toy Glock 17",
                 "Glock 17 gel blaster", "nerf rifle",
                 "BB ammo", "airsoft grenade", "장난감 권총", "비비탄 총", "에어소프트 소총", "물총"):
        assert prohibited.check(text) is None, text
    for text in ("AK-47", "real AK-47 rifle", "glock 19", "9mm ammo", "권총", "실탄"):
        assert prohibited.check(text), text


# --- decision 2: loosening deal rules only through the person's confirm link ------------------------------------------

def test_loosening_needs_the_persons_confirm_link_not_user_approved(pc):
    from urllib.parse import urlsplit

    h, _ = member(pc, "b")
    r = pc.patch("/v1/market/rules", headers=h, json={"share_address": "auto", **OK}).json()
    assert r["done"] is False and r["needs_user_confirmation"] and "confirm_url" in r
    assert pc.get("/v1/market/rules", headers=h).json()["rules"]["share_address"] == "ask"
    path = urlsplit(r["confirm_url"]).path
    page = pc.get(path)  # opening (or a link preview) changes nothing
    assert page.status_code == 200 and "Confirm" in page.text
    assert pc.get("/v1/market/rules", headers=h).json()["rules"]["share_address"] == "ask"
    assert pc.post(path).status_code == 200
    assert pc.get("/v1/market/rules", headers=h).json()["rules"]["share_address"] == "auto"
    assert pc.post(path).status_code == 404  # one use
    assert pc.post(path[:-3] + "xyz").status_code == 404
    # tightening applies at once, without a link
    assert pc.patch("/v1/market/rules", headers=h, json={"share_address": "ask"}).json()["done"] is True


def test_prices_are_per_item_for_people_not_an_account_rule(pc):
    """Founder decision 2026-11-20: no account-wide price rule for people; per item the AI asks and saves a range."""
    h, _ = member(pc, "s")
    for body in ({"confirm_deal": "auto", "only_in_range": True, **OK},
                 {"confirm_deal_max": {"amount": 50, "currency": "USD"}, **OK}):
        r = pc.patch("/v1/market/rules", headers=h, json=body)
        assert r.status_code == 422 and "save_price_range" in r.text
    tightened = pc.patch("/v1/market/rules", headers=h, json={"cancel_deal": "ask"}).json()
    assert tightened["done"] and "confirm_deal" not in tightened["rules"]  # the answer shows the same view
    view = pc.get("/v1/market/rules", headers=h).json()
    assert "confirm_deal" not in view["rules"] and "per item" in view["prices"]
    assert view["hourly_check"] == {"running": False}
    out = pc.patch("/v1/market/rules", headers=h, json={"share_address": "auto", **OK}).json()
    assert out["needs_user_confirmation"] and out["confirm_url"]  # other rules keep the confirm link


def test_confirm_link_expires(pc, monkeypatch):
    from urllib.parse import urlsplit

    from onaa_registry import deal_rules

    h, _ = member(pc, "b")
    monkeypatch.setattr(deal_rules, "CONFIRM_MINUTES", -1)
    r = pc.patch("/v1/market/rules", headers=h, json={"share_contact": "auto"}).json()
    assert pc.post(urlsplit(r["confirm_url"]).path).status_code == 404
    assert pc.get("/v1/market/rules", headers=h).json()["rules"]["share_contact"] == "ask"


# --- decision 4: deal text deleted 30 days after the end; idle deals cancelled after 60 days -------------------------

def test_deal_free_text_goes_30_days_after_the_end_and_idle_deals_are_cancelled(pc):
    from onaa_registry import deal_rules
    from onaa_registry.models import PilotOffer

    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 280, "message": "hi", **OK})
    r = pc.post(f"/v1/market/offers/{o.json()['id']}/respond", headers=seller, json={"action": "accept", **OK})
    oid = r.json()["id"]
    pc.post(f"/v1/market/deals/{oid}", headers=seller, json={
        "action": "propose", "terms": {"payment_method": "cash", "trade_method": "in_person",
                                       "handoff_time": "Sat 3pm", "handoff_place": "Central Library"}, **OK})
    now = dt.datetime.now(dt.UTC)
    with pc.app.state.sessionmaker() as s:
        assert deal_rules.cancel_idle(s, pc.app.state.settings, now) == 0
        s.get(PilotOffer, oid).updated_at = now - dt.timedelta(days=61)
        s.commit()
        assert deal_rules.cancel_idle(s, pc.app.state.settings, now) == 1
        s.commit()
    assert status(pc, it["id"]) == "available"
    with pc.app.state.sessionmaker() as s:
        o = s.get(PilotOffer, oid)
        assert o.deal_state == "cancelled" and o.cancelled_by == "idle"
        o.updated_at = now - dt.timedelta(days=31)
        s.commit()
        assert deal_rules.purge_personal(s, now) >= 3  # the offer message, handoff time and place
        s.commit()
        o = s.get(PilotOffer, oid)
        assert o.arrangement["terms"]["handoff_place"] == deal_rules.REMOVED
        assert o.arrangement["terms"]["payment_method"] == "cash"
        assert all(e.get("message") in (None, deal_rules.REMOVED) for e in o.history)
        assert deal_rules.purge_personal(s, now) == 0


# --- decision 7: currency is required ---------------------------------------------------------------------------------

def test_listing_and_want_ask_for_the_currency_instead_of_assuming_dollars(pc):
    h, _ = member(pc, "s")
    body = {**ITEM_REQUIRED, "title": "Desk", "price": 50000}
    body.pop("currency")
    r = pc.post("/v1/market/items", headers=h, json=body).json()
    assert r["listed"] is False and r["missing"] == ["currency"]
    assert item(pc, h, title="Desk", price=50000, currency="krw")["currency"] == "KRW"
    w = pc.post("/v1/market/wants", headers=h, json={"title": "Chair", "max_price": 30, "region": "Austin TX",
                                                    "trade_methods": ["in_person"], "payment_methods": ["cash"],
                                                    "quantity": 1, "conditions": ["used_good"]}).json()
    assert w["missing"] == ["currency"]


# --- decision 9: item status follows the deal; the item cannot change under a deal ------------------------------

def test_status_follows_deals_and_item_is_locked_during_a_deal(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    url = f"/v1/market/items/{it['id']}"
    assert pc.patch(url, headers=seller, json={"status": "reserved"}).status_code == 409
    o = pc.post(f"{url}/offers", headers=buyer, json={"amount": 280, **OK}).json()
    pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept", **OK})
    assert status(pc, it["id"]) == "reserved"
    assert pc.patch(url, headers=seller, json={"status": "available"}).status_code == 409
    r = pc.patch(url, headers=seller, json={"description": "actually it has a cracked frame"})
    assert r.status_code == 409 and "description" in r.json()["detail"]
    assert pc.patch(url, headers=seller, json={"photo_url": None}).status_code == 200  # other details are fine
    pc.post(f"/v1/market/deals/{o['id']}", headers=seller, json={"action": "cancel", **OK})
    assert status(pc, it["id"]) == "available"
    assert pc.patch(url, headers=seller, json={"title": "Road bike 56cm"}).status_code == 200
    assert pc.patch(url, headers=seller, json={"status": "sold"}).status_code == 200
    assert pc.patch(url, headers=seller, json={"status": "available"}).status_code == 200  # more stock


# --- decisions 10 and 13: sign-in tells nothing about accounts; mail allowance ---------------------------------------

def _oauth_app(settings, fetcher, txt, runner, **extra):
    base = {"pilot_enabled": True, "pilot_open_signup": True, "mail_backend": "dev-log",
            "oauth_secret": "test-only-oauth-secret-0123456789abcdef"}
    s = dataclasses.replace(settings, **(base | extra))
    return TestClient(create_app(s, fetcher, txt, runner))


def _sign_in_page(c):
    import base64
    import hashlib
    import re
    import secrets

    reg = c.post("/oauth/register", json={"client_name": "Claude", "token_endpoint_auth_method": "none",
                                          "redirect_uris": ["https://app.example/cb"]}).json()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(secrets.token_urlsafe(48).encode()).digest()).decode()
    page = c.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": "https://app.example/cb",
        "code_challenge": challenge.rstrip("="), "code_challenge_method": "S256", "state": "st"})
    return re.search(r"name=login_id value='([A-Za-z0-9_-]+)'", page.text).group(1)


def test_invite_only_sign_in_looks_the_same_for_unknown_emails_and_sends_nothing(settings, fetcher, txt, runner,
                                                                                 monkeypatch):
    from onaa_registry import oauth

    sent = []
    monkeypatch.setattr(oauth, "send_code", lambda s, email, code: sent.append((email, code)))
    with _oauth_app(settings, fetcher, txt, runner, pilot_open_signup=False) as c:
        r = c.post("/oauth/authorize/email",
                   data={"login_id": _sign_in_page(c), "email": "nobody" + AT + "example.org"})
        assert "If this email can sign in" in r.text and "no account" not in r.text and sent == []
        assert getattr(c.app.state, "oauth_send_all_limiter", None) is None  # nothing charged


def test_new_member_picks_a_nickname_after_the_code(settings, fetcher, txt, runner, monkeypatch):
    from onaa_registry import oauth

    sent = {}
    monkeypatch.setattr(oauth, "send_code", lambda s, email, code: sent.update({email: code}))
    with _oauth_app(settings, fetcher, txt, runner) as c:
        login_id = _sign_in_page(c)
        r = c.post("/oauth/authorize/email", data={"login_id": login_id, "email": "new" + AT + "example.org"})
        assert "If this email can sign in" in r.text and "First time" not in r.text
        r = c.post("/oauth/authorize/code", data={"login_id": login_id, "code": sent["new" + AT + "example.org"]})
        assert "Pick a nickname" in r.text
        done = c.post("/oauth/google/nickname", data={"login_id": login_id, "nickname": "newbie"},
                      follow_redirects=False)
        assert done.status_code == 302 and done.headers["location"].startswith("https://app.example/cb?code=")


def test_one_address_cannot_use_up_the_hourly_mail_allowance(settings, fetcher, txt, runner, monkeypatch):
    from onaa_registry import oauth

    monkeypatch.setattr(oauth, "send_code", lambda s, email, code: None)
    with _oauth_app(settings, fetcher, txt, runner, mail_per_hour=8) as c:
        texts = [c.post("/oauth/authorize/email", data={"login_id": _sign_in_page(c),
                                                        "email": f"u{i}{AT}example.org"}).text for i in range(3)]
        assert "6-digit" in texts[0] and "6-digit" in texts[1] and "Too many sign-ins from here" in texts[2]
        assert c.app.state.oauth_send_all_limiter.remaining("all") == 6
