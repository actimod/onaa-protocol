"""After a deal is accepted: per-member deal rules, arranging payment and handoff, no stored contacts, personal
details deleted after the deal, cancel / done / report / block, listing reports and takedown, digital products."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from conftest import ADMIN, ITEM_REQUIRED, WANT_REQUIRED
from fastapi.testclient import TestClient

from onaa_registry import deal_rules
from onaa_registry.main import create_app
from onaa_registry.models import PilotOffer

A = {"Authorization": f"Bearer {ADMIN}"}
OK = {"user_approved": True}


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick):
    r = c.post("/v1/admin/market/members", headers=A, json={"nickname": nick, "contact": "kakao:secret-" + nick,
                                                            "region": "Austin TX"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}, r.json()["member_id"]


def item(c, h, **kw):
    body = {**ITEM_REQUIRED, "title": "Road bike 54cm", "price": 300, "currency": "USD",
            "payment_methods": ["cash", "escrow"], "trade_methods": ["in_person", "shipping"]} | kw
    r = c.post("/v1/market/items", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def deal(c, seller, buyer, **kw):
    it = item(c, seller, **kw)
    o = c.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 280, **OK}).json()
    r = c.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept", **OK})
    assert r.status_code == 200 and r.json()["status"] == "accepted", r.text
    return it, r.json()


def act(c, h, offer_id, **body):
    return c.post(f"/v1/market/deals/{offer_id}", headers=h, json=body)


def test_no_contact_is_kept_or_shown(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    assert "contact" not in pc.get("/v1/market/me", headers=seller).json()
    _, d = deal(pc, seller, buyer)
    assert "secret" not in str(d) and "secret" not in str(pc.get("/v1/market/deals", headers=buyer).json())


def test_rules_default_to_ask_and_hold_the_step(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    held = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 250})
    assert held.status_code == 200 and held.json()["done"] is False and held.json()["rules"] == ["confirm_deal"]
    assert "250 USD" in held.json()["ask_your_user"]
    assert pc.get("/v1/market/offers", headers=seller).json()["offers"] == []  # nothing was made
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 250, **OK}).json()
    # the seller's assistant tries to accept on its own: held, and the buyer only sees that it waits
    held = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept"}).json()
    assert held["done"] is False
    mine = pc.get("/v1/market/offers", headers=buyer).json()["offers"][0]
    assert mine["their_side"] == deal_rules.WAITING_FOR_OTHER and "rules" not in str(mine["counterparty"])
    # decline needs no approval
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                   json={"action": "decline"}).json()["status"] == "declined"


def test_the_ai_confirms_a_price_alone_only_inside_that_items_saved_range(pc):
    """Founder decision 2026-11-20: per item, not per account. No range on an item: every price asks."""
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    held = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 150}).json()
    assert held["done"] is False and "item_limit" in held and "**" in held["next_step"]
    assert pc.post("/v1/market/ranges", headers=buyer, json={"item_id": it["id"], "highest_price": 200}).status_code \
        == 201
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 150})
    assert o.status_code == 201 and "item_limit" not in o.json()  # inside the item's range: alone
    it2 = item(pc, seller, title="Second bike")
    assert pc.post(f"/v1/market/items/{it2['id']}/offers", headers=buyer,
                   json={"amount": 10}).json()["done"] is False  # the range of another item does not carry over
    it3 = item(pc, seller, title="Euro bike", currency="EUR")
    pc.post("/v1/market/ranges", headers=buyer, json={"item_id": it3["id"], "highest_price": 200})
    assert pc.post(f"/v1/market/items/{it3['id']}/offers", headers=buyer,
                   json={"amount": 250}).json()["done"] is False  # above the range: ask
    listed = pc.post("/v1/market/items", headers=seller, json={
        **ITEM_REQUIRED, "title": "Lamp", "description": "a lamp", "price": 40}).json()
    assert "from what price" in listed["item_limit"]["ask_your_user"]


def test_arrange_payment_and_handoff_then_done(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it, d = deal(pc, seller, buyer)
    oid = d["id"]
    assert d["deal"]["state"] == "arranging" and d["deal"]["options"]["payment_methods"] == ["cash", "escrow"]
    bad = act(pc, seller, oid, action="propose", terms={"payment_method": "crypto"}, **OK)
    assert bad.status_code == 422
    held = act(pc, seller, oid, action="propose", terms={"payment_method": "escrow", "payment_detail": "Escrow.com",
                                                         "trade_method": "shipping", "handoff_time": "ships Fri"})
    assert held.json()["done"] is False and set(held.json()["rules"]) == {"choose_payment", "set_handoff"}
    assert pc.get("/v1/market/deals", headers=buyer).json()["deals"][0]["deal"]["their_side"]
    r = act(pc, seller, oid, action="propose", terms={"payment_method": "escrow", "payment_detail": "Escrow.com",
                                                      "trade_method": "shipping", "handoff_time": "ships Fri"}, **OK)
    assert r.status_code == 200 and r.json()["deal"]["arrangement"]["proposed_by"] == "you"
    b = pc.get("/v1/market/deals", headers=buyer).json()["deals"][0]["deal"]
    assert b["arrangement"]["proposed_by"] == "them" and "agree" in b["you_can"] and "their_side" not in b
    at = b["arrangement"]["proposal_at"]
    assert act(pc, buyer, oid, action="agree", **OK).status_code == 422  # which terms did the user see?
    assert act(pc, buyer, oid, action="agree", proposal_at=at, **OK).json()["deal"]["state"] == "arranged"
    assert act(pc, buyer, oid, action="agree", proposal_at=at, **OK).status_code == 409
    assert act(pc, buyer, oid, action="done").json()["done"] is False  # confirm_done: ask
    assert act(pc, buyer, oid, action="done", **OK).json()["deal"]["done"] == {"you": True, "them": False}
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "reserved"
    assert act(pc, seller, oid, action="done", **OK).json()["deal"]["state"] == "done"
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "sold"
    assert act(pc, seller, oid, action="cancel", **OK).status_code == 409
    rec = pc.get("/v1/market/offers", headers=buyer, params={"state": "all"}).json()["offers"][0]
    assert rec["counterparty"]["record"]["deals_done"] == 1


def test_personal_details_only_by_choice_and_deleted_after_the_deal(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it, d = deal(pc, seller, buyer)
    oid = d["id"]
    held = act(pc, buyer, oid, action="message", text="call me at +1 512 555 0199").json()
    assert held["done"] is False and held["rules"] == ["share_contact"] and "phone number" in held["ask_your_user"]
    held = act(pc, buyer, oid, action="message", text="ship to 12 Elm St", shares_address=True).json()
    assert held["rules"] == ["share_address"]
    act(pc, buyer, oid, action="message", text="call me at +1 512 555 0199", **OK)
    act(pc, buyer, oid, action="message", text="see you there", **OK)
    hist = pc.get("/v1/market/deals", headers=seller).json()["deals"][0]["history"]
    assert hist[-2]["message"].endswith("0199") and hist[-2]["personal"] and "personal" not in hist[-1]
    assert act(pc, seller, oid, action="cancel", **OK).json()["deal"]["state"] == "cancelled"
    assert pc.get(f"/v1/market/items/{it['id']}", headers=buyer).json()["status"] == "available"
    with pc.app.state.sessionmaker() as s:
        assert deal_rules.purge_personal(s, dt.datetime.now(dt.UTC)) == 0  # not yet 30 days
        o = s.get(PilotOffer, oid)
        o.updated_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=31)
        s.commit()
        assert deal_rules.purge_personal(s, dt.datetime.now(dt.UTC)) == 2
        s.commit()
    hist = pc.get("/v1/market/offers", headers=seller, params={"state": "all"}).json()["offers"][0]["history"]
    msgs = [e.get("message") for e in hist]
    assert not any("0199" in (x or "") for x in msgs) and hist[-3]["message"] == deal_rules.REMOVED
    # every deal message goes 30 days after the end, not only those flagged personal (decision 2026-11-19)
    assert hist[-2]["message"] == deal_rules.REMOVED


def test_report_and_block_only_with_approval(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it, d = deal(pc, seller, buyer)
    oid = d["id"]
    assert act(pc, buyer, oid, action="report", reason="no_show").json()["done"] is False
    assert act(pc, buyer, oid, action="report", reason="no_show", **OK).json()["done"] is True
    assert act(pc, buyer, oid, action="block").json()["done"] is False
    r = act(pc, buyer, oid, action="block", **OK).json()
    assert r["deal"]["state"] == "cancelled"
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "available"
    # blocked: no new offers between them
    assert pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                   json={"amount": 1, **OK}).status_code == 409
    rec = pc.get("/v1/market/offers", headers=buyer, params={"state": "all"}).json()["offers"][0]
    assert rec["counterparty"]["record"]["reports_from_others"] == 1


def test_listing_reports_hide_then_takedown_notifies_owner(pc):
    seller, sid = member(pc, "s")
    reporters = [member(pc, f"r{i}")[0] for i in range(3)]
    it = item(pc, seller, title="Suspicious pills")
    assert pc.post(f"/v1/market/items/{it['id']}/report", headers=seller, json={"reason": "illegal"}).status_code == 409
    for h in reporters[:2]:
        assert pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "illegal"}).json()["reported"]
    assert pc.post(f"/v1/market/items/{it['id']}/report", headers=reporters[0],
                   json={"reason": "illegal"}).json()["already"]
    mine = pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()
    assert mine["status"] == "available" and mine["review"]["state"] == "reported"
    pc.post(f"/v1/market/items/{it['id']}/report", headers=reporters[2], json={"reason": "illegal"})
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "under_review"
    assert pc.get(f"/v1/market/items/{it['id']}", headers=reporters[0]).status_code == 404
    assert pc.get("/v1/market/items", headers=reporters[0], params={"q": "pills"}).json()["total"] == 0
    assert pc.patch(f"/v1/market/items/{it['id']}", headers=seller, json={"status": "available"}).status_code == 409
    q = pc.get("/v1/admin/market/listing-reports", headers=A).json()["open"]
    assert q[0]["id"] == it["id"] and len(q[0]["reports"]) == 3
    r = pc.post(f"/v1/admin/market/listings/item/{it['id']}/takedown", headers=A, json={"reason": "illegal drugs"})
    assert r.json()["status"] == "removed" and r.json()["review"]["state"] == "taken_down"
    mine = pc.get("/v1/market/items", headers=seller, params={"mine": True}).json()["items"]
    gone = pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()
    assert gone["review"]["reason"] == "illegal drugs" and gone["status"] == "removed" and mine == []
    with pc.app.state.sessionmaker() as s:
        from onaa_registry.models import PilotMember
        from onaa_registry.routes.pilot_reports import notices

        owner = s.get(PilotMember, sid)
        news = notices(s, owner, dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5))
        assert news[0]["state"] == "taken_down" and news[0]["reason"] == "illegal drugs"
    assert pc.get("/v1/admin/market/listing-reports", headers=A).json()["open"] == []


def test_admin_clear_restores_a_hidden_want(pc):
    buyer, _ = member(pc, "b")
    reporters = [member(pc, f"r{i}")[0] for i in range(3)]
    w = pc.post("/v1/market/wants", headers=buyer, json={"title": "logo design", "category": "services",
                                                        "max_price": 100, "currency": "USD", "region": "remote",
                                                        "trade_methods": ["online"], "payment_methods": ["card"]})
    assert w.status_code == 201, w.text
    w = w.json()
    assert w["region"] == "online"
    for h in reporters:
        pc.post(f"/v1/market/wants/{w['id']}/report", headers=h, json={"reason": "scam"})
    assert pc.get("/v1/market/wants", headers=buyer, params={"mine": True}).json()["wants"][0]["status"] == \
        "under_review"
    r = pc.post(f"/v1/admin/market/listings/want/{w['id']}/clear", headers=A, json={"reason": "fine"}).json()
    assert r["status"] == "open" and r["review"]["state"] == "cleared"


def test_digital_and_remote_need_no_city_or_condition(pc):
    seller, _ = member(pc, "s")
    r = pc.post("/v1/market/items", headers=seller, json={"title": "Lightroom preset pack", "price": 15,
                                                         "currency": "USD", "category": "digital",
                                                         "payment_methods": ["payment_app"]})
    assert r.status_code == 201, r.text
    assert r.json()["region"] == "online" and r.json()["trade_methods"] == ["online"]
    assert r.json()["condition"] is None and "missing_info" not in r.json()
    r = pc.post("/v1/market/items", headers=seller, json={"title": "Python tutoring", "price": 40,
                                                         "currency": "USD", "category": "services", "region": "Remote",
                                                         "trade_methods": ["online"], "payment_methods": ["card"]})
    assert r.status_code == 201 and r.json()["region"] == "online"
    r = pc.post("/v1/market/items", headers=seller, json={"title": "E-book", "price": 5, "category": "digital",
                                                         "trade_methods": ["shipping"], "payment_methods": ["card"]})
    assert r.status_code == 422
    # a physical item still needs its details
    r = pc.post("/v1/market/items", headers=seller, json={"title": "Desk", "price": 50, "payment_methods": ["cash"]})
    assert r.json()["listed"] is False and {"region", "condition"} <= set(r.json()["missing"])


def test_hosted_seller_confirms_alone_only_within_its_limit(pc):
    _, sid = member(pc, "s")
    with pc.app.state.sessionmaker() as s:
        from onaa_registry.models import PilotMember

        m = s.get(PilotMember, sid)
        assert deal_rules.allows(m, "confirm_deal", amount=10, currency="USD") is False  # no range: ask
        floor = {"amount": 100, "currency": "USD"}
        assert deal_rules.allows(m, "confirm_deal", amount=100, currency="usd", side="sell", range_limit=floor)
        assert not deal_rules.allows(m, "confirm_deal", amount=99, currency="USD", side="sell", range_limit=floor)
        assert not deal_rules.allows(m, "confirm_deal", amount=150, currency="EUR", side="sell", range_limit=floor)
        m.deal_rules = {"confirm_deal": "auto", "confirm_deal_max": {"amount": 500, "currency": "USD"}}
        assert deal_rules.allows(m, "confirm_deal", amount=10, currency="USD") is False  # old account limits: gone


def test_review_fixes_no_double_sale_no_stale_agree_no_cancel_after_done(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it, d = deal(pc, seller, buyer)
    oid = d["id"]
    # a reserved item with a live deal cannot be put back on sale or sold behind the deal's back
    for st in ("available", "sold"):
        assert pc.patch(f"/v1/market/items/{it['id']}", headers=seller, json={"status": st}).status_code == 409
    act(pc, seller, oid, action="propose", terms={"payment_method": "cash", "handoff_place": "Library"}, **OK)
    held = act(pc, buyer, oid, action="agree").json()
    seen = held["proposal_at"]
    act(pc, seller, oid, action="propose", terms={"payment_method": "escrow", "handoff_place": "call 512 555 0199"},
        **OK)
    assert act(pc, buyer, oid, action="agree", proposal_at=seen, **OK).status_code == 409
    # once one side marked it done, the other cannot cancel
    act(pc, seller, oid, action="done", **OK)
    assert act(pc, buyer, oid, action="cancel", **OK).status_code == 409
    # one report per side
    act(pc, buyer, oid, action="report", reason="scam", **OK)
    assert act(pc, buyer, oid, action="report", reason="scam", **OK).json()["already_reported"]
    with pc.app.state.sessionmaker() as s:
        o = s.get(PilotOffer, oid)
        assert len(o.reports) == 1 and o.arrangement["personal"]


def test_personal_terms_are_purged_and_cleared_listing_can_be_hidden_again(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it, d = deal(pc, seller, buyer)
    oid = d["id"]
    act(pc, seller, oid, action="propose", terms={"handoff_place": "my flat, 12 Elm St, phone 512 555 0199"}, **OK)
    act(pc, seller, oid, action="cancel", **OK)
    with pc.app.state.sessionmaker() as s:
        o = s.get(PilotOffer, oid)
        o.updated_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=31)
        s.commit()
        deal_rules.purge_personal(s, dt.datetime.now(dt.UTC))
        s.commit()
        assert "0199" not in str(s.get(PilotOffer, oid).arrangement)
    reps = [member(pc, f"r{i}")[0] for i in range(6)]
    for h in reps[:3]:
        pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "illegal"})
    pc.post(f"/v1/admin/market/listings/item/{it['id']}/clear", headers=A, json={"reason": "ok"})
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "available"
    for h in reps[3:]:
        pc.post(f"/v1/market/items/{it['id']}/report", headers=h, json={"reason": "illegal"})
    assert pc.get(f"/v1/market/items/{it['id']}", headers=seller).json()["status"] == "under_review"
    assert pc.get(f"/v1/market/items/{it['id']}/questions", headers=reps[0]).status_code == 404


@pytest.mark.parametrize("title", ["Glock 19 with ammo", "1g cocaine", "AR-15 lower receiver", "Xanax 2mg",
                                   "magic mushrooms", "권총 팝니다", "대마초", "9mm ammo, 50 rounds"])
def test_drugs_and_firearms_are_refused_everywhere(pc, title):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    r = pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": title, "price": 10})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "prohibited_item", r.text
    r = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "anything",
                                                        "description": f"looking for {title}"})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "prohibited_item", r.text
    it = item(pc, seller)
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=seller, json={"description": title})
    assert r.status_code == 422, r.text
    w = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "camping gear"})
    assert w.status_code == 201, w.text
    r = pc.patch(f"/v1/market/wants/{w.json()['id']}", headers=buyer, json={"title": title})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("title", ["Kids water gun", "Nerf rifle blaster", "Hot glue gun", "Massage gun",
                                   "Air rifle scope", "Bullet journal", "Rifle Paper Co. planner", "Top Gun poster",
                                   "Breaking Bad DVD box set", "Drug store gift card", "Surge suppressor"])
def test_toys_tools_and_books_are_not_refused(pc, title):
    seller, _ = member(pc, "s")
    r = pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": title, "price": 10})
    assert r.status_code == 201, r.text


def test_a_messaging_block_also_stops_offers(pc):
    seller, sid = member(pc, "s")
    buyer, bid = member(pc, "b")
    it = item(pc, seller)
    with pc.app.state.sessionmaker() as s:
        from onaa_registry.models import PilotConversation

        # a block made in messaging is keyed by the buyer's agent card URL, not "onaa-hosted:<id>"
        s.add(PilotConversation(member_id=sid, peer_agent_id="https://pm-x.agents.test/.well-known/agent-card.json",
                                peer_member_id=bid, state="blocked"))
        s.commit()
    r = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"amount": 250, **OK})
    assert r.status_code == 409, r.text
    with pc.app.state.sessionmaker() as s:
        from onaa_registry.messaging import _member_blocked

        assert _member_blocked(s, sid, bid) and not _member_blocked(s, bid, sid)


def test_limits_by_side_and_saved_range_bound_what_the_ai_confirms_alone(pc):
    """A seller's range is a floor and a buyer's a ceiling, on that item only."""
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    lamp = item(pc, seller, title="Desk lamp", price=50)
    pc.post("/v1/market/ranges", headers=seller, json={"item_id": lamp["id"], "lowest_price": 35})
    o = pc.post(f"/v1/market/items/{lamp['id']}/offers", headers=buyer, json={"amount": 10, **OK}).json()
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                   json={"action": "accept"}).json()["done"] is False  # below the floor: ask
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "counter", "amount": 45})
    assert r.status_code == 200 and r.json()["status"] == "open", r.text
    pc.post("/v1/market/ranges", headers=buyer, json={"item_id": lamp["id"], "highest_price": 45})
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=buyer,
                   json={"action": "counter", "amount": 46}).json()["done"] is False  # above the ceiling
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=buyer, json={"action": "counter", "amount": 40})
    assert r.status_code == 200 and r.json()["amount"] == 40, r.text
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept"})
    assert r.status_code == 200 and r.json()["status"] == "accepted", r.text


def test_listing_the_same_title_again_warns_about_the_older_one(pc):
    seller, _ = member(pc, "s")
    old = item(pc, seller, title="Desk lamp", price=50)
    new = item(pc, seller, title="  desk   LAMP ", price=50)
    assert [d["id"] for d in new["possible_duplicates"]] == [old["id"]]
    assert "possible_duplicates" in new["next_step"]
    assert "possible_duplicates" not in item(pc, seller, title="Desk chair")


def test_published_run_time_is_kept_for_later_hourly_checks():
    import datetime as dt
    from types import SimpleNamespace

    from onaa_registry.hosting import availability

    now = dt.datetime(2026, 11, 19, 9, 40, tzinfo=dt.UTC)
    m = SimpleNamespace(last_seen_at=None, check_every_minutes=60, next_check_at=None,
                        check_anchor_at=dt.datetime(2026, 11, 19, 7, 28, tzinfo=dt.UTC),
                        last_check_at=dt.datetime(2026, 11, 19, 9, 28, tzinfo=dt.UTC))
    assert availability(m, now)["next_check_at"].startswith("2026-11-19T10:28")
    m.next_check_at = dt.datetime(2026, 11, 19, 10, 0, tzinfo=dt.UTC)  # a one-off extra check, earlier
    assert availability(m, now)["next_check_at"].startswith("2026-11-19T10:00")
    m.next_check_at = dt.datetime(2026, 11, 19, 9, 0, tzinfo=dt.UTC)  # a past one-off: the hourly minute again
    assert availability(m, now)["next_check_at"].startswith("2026-11-19T10:28")
    m.check_anchor_at = None
    assert availability(m, now)["next_check_at"].startswith("2026-11-19T10:00")


def test_a_schedule_that_stopped_checking_in_no_longer_counts(pc):
    """Bookshelf retest 2026-11-19: an old 5-minute schedule from an earlier test kept showing "next check in 1 min"
    and hid set_up_checks. A schedule counts only while its runs call check_inbox (or right after publishing)."""
    import datetime as dt
    from types import SimpleNamespace

    from onaa_registry.hosting import availability, schedule_running
    from onaa_registry.models import PilotMember

    now = dt.datetime(2026, 11, 19, 9, 0, tzinfo=dt.UTC)
    m = SimpleNamespace(last_seen_at=now - dt.timedelta(minutes=3), check_every_minutes=5, next_check_at=None,
                        check_anchor_at=None, last_check_at=now - dt.timedelta(hours=3))
    assert not schedule_running(m, now) and availability(m, now)["next_check_at"] is None
    m.last_check_at = now - dt.timedelta(minutes=10)
    assert schedule_running(m, now) and availability(m, now)["next_check_at"] is not None

    seller, sid = member(pc, "s")
    buyer, bid = member(pc, "b")
    shelf = item(pc, seller, title="Bookshelf", price=90)
    assert pc.patch("/v1/market/me", headers=buyer, json={"check_every_minutes": 5}).status_code == 200
    first = pc.post(f"/v1/market/items/{shelf['id']}/offers", headers=buyer, json={"amount": 55, **OK}).json()
    assert "set_up_checks" not in first  # just published: counts
    pc.post(f"/v1/market/offers/{first['id']}/withdraw", headers=buyer)
    with pc.app.state.sessionmaker() as s:
        s.get(PilotMember, bid).last_check_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)
        s.commit()
    shelf2 = item(pc, seller, title="Bookcase", price=80)
    o = pc.post(f"/v1/market/items/{shelf2['id']}/offers", headers=buyer, json={"amount": 50, **OK}).json()
    assert o["set_up_checks"]["ask_your_user"] in o["next_step"]  # stale: ask again, as a plain question
    assert pc.patch("/v1/market/me", headers=buyer, json={"check_every_minutes": 5}).status_code == 200  # again
    again = pc.get("/v1/market/offers", headers=seller).json()["offers"][0]["counterparty"]["availability"]
    assert again["checks_every_minutes"] == 5


def test_check_times_line_up_with_a_one_off_check_at_the_other_sides_time(pc):
    """Founder 2026-11-19: hourly checks on both sides can fall at different minutes; from the second message on
    the AIs line up. ONAA only relays the times and suggests a one-off check at the other side's next check."""
    import datetime as dt

    from onaa_registry.models import PilotMember

    seller, sid = member(pc, "s")
    buyer, bid = member(pc, "b")
    lamp = item(pc, seller, title="Desk lamp", price=50)
    o = pc.post(f"/v1/market/items/{lamp['id']}/offers", headers=buyer, json={"amount": 35, **OK}).json()
    nxt = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)).replace(minute=28, second=0, microsecond=0)
    r = pc.patch("/v1/market/me", headers=seller, json={"check_every_minutes": 60, "next_check_at": nxt.isoformat()})
    assert r.status_code == 200, r.text
    with pc.app.state.sessionmaker() as s:  # neither side online now
        for mid in (sid, bid):
            s.get(PilotMember, mid).last_seen_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
        s.commit()
    pc.patch("/v1/market/me", headers=buyer, json={"check_every_minutes": 60})
    with pc.app.state.sessionmaker() as s:
        s.get(PilotMember, bid).last_seen_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
        s.commit()
    mine = [x for x in pc.get("/v1/market/offers", headers=buyer).json()["offers"] if x["id"] == o["id"]][0]
    assert mine["counterparty"]["availability"]["next_check_at"].startswith(nxt.isoformat()[:16])
    meet = mine["meet_live"]
    assert meet["their_next_check_at"].startswith(nxt.isoformat()[:16]) and "one-time" in meet["how"]
    # once the buyer adds that one-off check, the times match and the hint goes away
    pc.patch("/v1/market/me", headers=buyer, json={"next_check_at": nxt.isoformat()})
    with pc.app.state.sessionmaker() as s:
        s.get(PilotMember, bid).last_seen_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
        s.commit()
    mine = [x for x in pc.get("/v1/market/offers", headers=buyer).json()["offers"] if x["id"] == o["id"]][0]
    assert "meet_live" not in mine


def test_waiting_answers_carry_set_up_checks_until_a_schedule_is_published(pc):
    """Retest 2026-11-19: without the words "scheduled check" in the prompt neither AI made one, so offers waited
    until the user asked again. Answers that leave something waiting now carry the step."""
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    chair = item(pc, seller, title="Office chair", price=80)
    assert "scheduled_prompt" in chair["set_up_checks"] and chair["next_step"].startswith("Before ending your turn")
    o = pc.post(f"/v1/market/items/{chair['id']}/offers", headers=buyer, json={"amount": 60, **OK}).json()
    assert "set_up_checks" in o
    r = pc.post("/v1/market/ranges", headers=buyer, json={"item_id": chair["id"], "highest_price": 70}).json()
    assert "set_up_checks" in r
    nxt = (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=40)).isoformat()
    assert pc.patch("/v1/market/me", headers=seller, json={"check_every_minutes": 60, "next_check_at": nxt}
                    ).status_code == 200
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "counter", "amount": 75, **OK})
    assert r.status_code == 200 and "set_up_checks" not in r.json()
    assert "set_up_checks" not in item(pc, seller, title="Desk")


def test_a_held_offer_asks_the_hourly_check_question_with_the_price(pc):
    """Road bike test 2026-11-20: the AI asked to confirm the first offer but not about checks; ask both together."""
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    bike = item(pc, seller, title="Road bike", price=250)
    held = pc.post(f"/v1/market/items/{bike['id']}/offers", headers=buyer, json={"amount": 175}).json()
    assert held["done"] is False and held["set_up_checks"]["ask_your_user"] in held["next_step"]
    assert "**" in held["next_step"]  # asked in bold


def test_admin_clears_a_members_cancel_record_without_touching_open_offers(pc):
    seller, sid = member(pc, "s")
    buyer, bid = member(pc, "b")
    _, d = deal(pc, seller, buyer)
    act(pc, buyer, d["id"], action="cancel", **OK)
    it2 = item(pc, seller, title="Guitar amp")
    open_offer = pc.post(f"/v1/market/items/{it2['id']}/offers", headers=buyer, json={"amount": 250, **OK}).json()

    def rec():
        offers = pc.get("/v1/market/offers", headers=seller, params={"state": "all"}).json()["offers"]
        return next(o for o in offers if o["id"] == d["id"])["counterparty"]["record"]

    assert rec()["deals_cancelled_by_them"] == 1
    assert pc.post(f"/v1/admin/market/members/{bid}/clear-cancel-record").status_code in (401, 403)
    r = pc.post(f"/v1/admin/market/members/{bid}/clear-cancel-record", headers=A)
    assert r.status_code == 200 and r.json()["cleared"] == 1
    assert rec()["deals_cancelled_by_them"] == 0
    seen = pc.get("/v1/market/deals", headers=buyer).json()["deals"]
    assert next(x for x in seen if x["id"] == d["id"])["deal"]["cancelled_by"] == "you"  # history still says who
    still = pc.get("/v1/market/offers", headers=buyer, params={"state": "open"}).json()["offers"]
    assert any(o["id"] == open_offer["id"] for o in still)
    assert pc.post(f"/v1/admin/market/members/{bid}/clear-cancel-record", headers=A).json()["cleared"] == 0
    assert pc.post(f"/v1/admin/market/members/{sid}/clear-cancel-record", headers=A).json()["cleared"] == 0


def test_the_other_side_sees_a_scheduled_check_run_and_go_quiet():
    """Founder 2026-11-20: each side should know the other is on automatic checks. ONAA records each scheduled
    run (check_inbox) and shows it; no message between the AIs."""
    from types import SimpleNamespace

    from onaa_registry.hosting import availability

    now = dt.datetime(2026, 11, 20, 4, 30, tzinfo=dt.UTC)
    m = SimpleNamespace(last_seen_at=now - dt.timedelta(minutes=30), check_every_minutes=60, next_check_at=None,
                        check_anchor_at=None, last_check_at=now - dt.timedelta(minutes=30))
    a = availability(m, now)
    assert a["scheduled_check"] == "running" and a["scheduled_check_running"] is True
    assert a["last_scheduled_check_at"] == m.last_check_at.isoformat()
    assert a["summary"].startswith("Scheduled check running (last ran 2026-11-20 04:00 UTC).")
    m.last_check_at = m.last_seen_at = now - dt.timedelta(hours=4)
    q = availability(m, now)
    assert q["scheduled_check"] == "quiet" and q["next_check_at"] is None and "gone quiet" in q["summary"]
    m.check_every_minutes = None
    assert availability(m, now)["scheduled_check"] == "none"


@pytest.fixture
def hc(settings, fetcher, txt, runner):
    s = dataclasses.replace(settings, pilot_enabled=True, hosting_domain="agents.test.example",
                            hosting_scheme="http", hosted_agent_secret="test-only-hosted-agent-secret-0123456789")
    with TestClient(create_app(s, fetcher, txt, runner)) as c:
        yield c


def test_scheduled_checks_keep_working_on_agreed_deals_until_done(hc):
    """Amp retest 2026-11-20: both AIs stopped at the agreed price and offered to turn the hourly check off; the
    seller's AI read its floor of 100 as "above 100" / "101" and took the first offer far under asking."""
    from onaa_registry.routes.pilot import SCHEDULED_CHECK_PROMPT

    assert "until every deal is done or cancelled" in SCHEDULED_CHECK_PROMPT
    assert "counter at least once" in SCHEDULED_CHECK_PROMPT
    seller, _ = member(hc, "s")
    buyer, _ = member(hc, "b")
    amp = item(hc, seller, title="Guitar amplifier", price=150)
    rng = hc.post("/v1/market/ranges", headers=seller, json={"item_id": amp["id"], "lowest_price": 100}).json()
    assert "100 USD or more (100 USD itself included" in str(rng) and "counter at least once" in str(rng)
    o = hc.post(f"/v1/market/items/{amp['id']}/offers", headers=buyer, json={"amount": 110, **OK}).json()
    hc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept", **OK})
    assert hc.patch("/v1/market/me", headers=seller, json={"check_every_minutes": 60}).status_code == 200
    hc.get("/v1/market/msg/inbox", headers=seller)
    box = hc.get("/v1/market/msg/inbox", headers=buyer).json()
    assert [d["offer_id"] for d in box["deals_in_progress"]] == [o["id"]]
    d = box["deals_in_progress"][0]
    assert d["deal"]["state"] == "arranging" and "do not suggest turning it off" in d["deal"]["next_step"]
    assert "ask them once" in box["next_step"] and "Keep the scheduled check running" in box["next_step"]
    them = d["counterparty"]["availability"]
    assert them["scheduled_check"] == "running" and them["last_scheduled_check_at"]
    act(hc, buyer, o["id"], action="cancel", **OK)
    assert hc.get("/v1/market/msg/inbox", headers=buyer).json()["deals_in_progress"] == []
