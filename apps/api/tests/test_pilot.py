"""Selling-agent pilot (stage 1): invite-only items, offers and deals between members."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from conftest import ADMIN, ITEM_REQUIRED, WANT_REQUIRED
from fastapi.testclient import TestClient

from onaa_registry.main import create_app

A = {"Authorization": f"Bearer {ADMIN}"}


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick, contact="kakao:" + "x", region="Seoul Mapo"):
    r = c.post("/v1/admin/market/members", headers=A, json={"nickname": nick, "contact": contact, "region": region})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["connector_url"].endswith("/mcp") and body["token"] not in body["connector_url"]
    return {"Authorization": f"Bearer {body['token']}"}, body["member_id"]


def item(c, h, **kw):
    body = {**ITEM_REQUIRED,
        "title": "iPad Air 4 64GB", "description": "good condition, with case", "price": 350000} | kw
    r = c.post("/v1/market/items", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_off_by_default(client):
    assert client.get("/v1/market/items").status_code == 404
    assert client.post("/v1/admin/market/members", headers=A, json={"nickname": "a", "contact": "b"}).status_code == 404


def test_member_token_required_and_admin_only(pc):
    assert pc.get("/v1/market/items").status_code == 401
    assert pc.get("/v1/market/items", headers={"Authorization": "Bearer pilot_nope"}).status_code == 401
    assert pc.post("/v1/admin/market/members", json={"nickname": "a", "contact": "b"}).status_code in (401, 403)


def test_old_pilot_paths_still_work_and_point_to_market(pc):
    """The API moved to /v1/market; /v1/pilot answers the same during the transition, marked deprecated."""
    old = pc.post("/v1/admin/pilot/members", headers=A, json={"nickname": "old", "contact": "kakao:x",
                                                              "region": "Seoul Mapo"})
    assert old.status_code == 201 and old.headers["deprecation"] == "true"
    assert "/v1/admin/market/members" in old.headers["link"]
    h = {"Authorization": f"Bearer {old.json()['token']}"}
    r = pc.get("/v1/pilot/items", headers=h, params={"q": "lamp"})
    assert r.status_code == 200 and r.json() == pc.get("/v1/market/items", headers=h, params={"q": "lamp"}).json()
    assert "deprecation" not in pc.get("/v1/market/items", headers=h).headers


def test_full_deal_contact_only_after_accept(pc):
    seller, _ = member(pc, "seller", contact="kakao:seller1")
    buyer, _ = member(pc, "buyer", contact="kakao:buyer1")
    it = item(pc, seller)
    assert it["mine"] is True and it["currency"] == "USD" and it["region"] == "Seoul Mapo"

    found = pc.get("/v1/market/items", headers=buyer, params={"q": "ipad", "max_price": 400000}).json()
    assert [i["id"] for i in found["items"]] == [it["id"]]
    assert "contact" not in str(found)
    # sellers do not see their own items in search, only with mine=true
    assert pc.get("/v1/market/items", headers=seller, params={"q": "ipad"}).json()["total"] == 0
    assert pc.get("/v1/market/items", headers=seller, params={"mine": True}).json()["total"] == 1
    assert pc.get("/v1/market/items", headers=buyer, params={"q": "ipad", "max_price": 300000}).json()["total"] == 0

    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                json={"user_approved": True, "amount": 300000, "message": "30?"}).json()
    assert o["status"] == "open" and o["your_turn"] is False and "contact" not in o["counterparty"]
    # buyer cannot answer its own offer; seller sees it waiting
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=buyer,
                   json={"user_approved": True, "action": "accept"}).status_code == 409
    inbox = pc.get("/v1/market/offers", headers=seller).json()
    assert inbox["waiting_for_you"] == 1 and inbox["offers"][0]["you_can"] == ["accept", "decline", "counter"]

    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                json={"user_approved": True, "action": "counter", "amount": 330000, "message": "33 ok"})
    assert r.status_code == 200 and r.json()["amount"] == 330000 and r.json()["your_turn"] is False
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=buyer, json={"user_approved": True, "action": "accept"})
    assert r.status_code == 200, r.text
    deal = r.json()
    # no contact is revealed on acceptance (ONAA keeps none); the deal goes on on the offer itself
    assert deal["status"] == "accepted" and "contact" not in deal["counterparty"] and "kakao" not in str(deal)
    assert deal["deal"]["state"] == "arranging" and "propose" in deal["deal"]["you_can"]
    assert [e["action"] for e in deal["history"]] == ["offer", "counter", "accept"]

    sd = pc.get("/v1/market/deals", headers=seller).json()["deals"]
    assert "contact" not in sd[0]["counterparty"] and sd[0]["amount"] == 330000
    assert pc.get(f"/v1/market/items/{it['id']}", headers=buyer).json()["status"] == "reserved"
    # reserved items leave search
    assert pc.get("/v1/market/items", headers=buyer, params={"q": "ipad"}).json()["total"] == 0

    m = pc.get("/v1/admin/market/metrics", headers=A).json()
    assert m["offers_by_status"]["accepted"] == 1 and m["counter_offers"] == 1 and m["members"] == 2


def test_others_cannot_touch(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    third, _ = member(pc, "t")
    it = item(pc, seller)
    assert pc.patch(f"/v1/market/items/{it['id']}", headers=buyer, json={"price": 1}).status_code == 403
    assert pc.post(f"/v1/market/items/{it['id']}/offers", headers=seller,
                   json={"user_approved": True, "amount": 1}).status_code == 409
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                json={"user_approved": True, "amount": 1000}).json()
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=third,
                   json={"user_approved": True, "action": "accept"}).status_code == 404
    assert pc.get("/v1/market/offers", headers=third).json()["offers"] == []
    # one open offer per buyer per item
    assert pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                   json={"user_approved": True, "amount": 2000}).status_code == 409


def test_accept_closes_other_offers_and_sold_closes_open(pc):
    seller, _ = member(pc, "s")
    b1, _ = member(pc, "b1")
    b2, _ = member(pc, "b2")
    it = item(pc, seller)
    o1 = pc.post(f"/v1/market/items/{it['id']}/offers", headers=b1, json={"user_approved": True, "amount": 1}).json()
    o2 = pc.post(f"/v1/market/items/{it['id']}/offers", headers=b2, json={"user_approved": True, "amount": 2}).json()
    assert pc.post(f"/v1/market/offers/{o2['id']}/respond", headers=seller,
                   json={"user_approved": True, "action": "accept"}).status_code == 200
    closed = pc.get("/v1/market/offers", headers=b1, params={"state": "closed"}).json()["offers"]
    assert closed[0]["id"] == o1["id"] and closed[0]["status"] == "declined"
    assert "contact" not in closed[0]["counterparty"]

    it2 = item(pc, seller, title="Keyboard", price=50000)
    o3 = pc.post(f"/v1/market/items/{it2['id']}/offers", headers=b1,
                 json={"user_approved": True, "amount": 40000}).json()
    assert pc.patch(f"/v1/market/items/{it2['id']}", headers=seller, json={"status": "sold"}).status_code == 200
    assert pc.get("/v1/market/offers", headers=b1, params={"state": "closed"}).json()["offers"][0]["id"] == o3["id"]


def test_counter_limit_and_withdraw(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    it = item(pc, seller)
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"user_approved": True, "amount": 1}).json()
    turns = [seller, buyer] * 3
    for i, h in enumerate(turns[:5]):
        r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=h,
                    json={"user_approved": True, "action": "counter", "amount": 10 + i})
        assert r.status_code == 200, r.text
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=turns[5], json={"action": "counter", "amount": 99})
    assert r.status_code == 409
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                json={"user_approved": True, "action": "withdraw"})
    assert r.status_code == 409
    r = pc.post(f"/v1/market/offers/{o['id']}/respond", headers=buyer,
                json={"user_approved": True, "action": "withdraw"})
    assert r.status_code == 200 and r.json()["status"] == "withdrawn"


def test_validation_and_disable_and_wipe(pc):
    seller, sid = member(pc, "s")
    assert pc.post("/v1/market/items", headers=seller,
                   json={**ITEM_REQUIRED,
                       "title": "x y", "price": 1, "photo_url": "http://169.254.169.254/"}).status_code == 422
    assert pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED,
        "title": "x y", "price": -1}).status_code == 422
    item(pc, seller)
    assert pc.delete(f"/v1/admin/market/members/{sid}", headers=A).status_code == 204
    assert pc.get("/v1/market/me", headers=seller).status_code == 401
    assert pc.delete("/v1/admin/market", headers=A).status_code == 400
    r = pc.delete("/v1/admin/market", headers=A, params={"confirm": "delete-all-pilot-data"})
    assert r.status_code == 200 and r.json()["deleted"] == {
        "pilot_chat_messages": 0, "pilot_conversations": 0, "pilot_a2a_messages": 0, "pilot_a2a_deals": 0,
        "pilot_agent_notes": 0, "pilot_mandates": 0,
        "pilot_offers": 0, "pilot_items": 1, "pilot_wants": 0, "pilot_oauth_tokens": 0, "pilot_oauth_logins": 0,
        "pilot_oauth_clients": 0, "pilot_members": 1, "pilot_question_reports": 0, "pilot_item_questions": 0,
        "pilot_inbox_counters": 0}


def test_services_and_new_goods_not_only_used(pc):
    seller, _ = member(pc, "tutor", contact="phone:+1-555-0110")
    buyer, _ = member(pc, "parent", contact="phone:+1-555-0111")
    lesson = item(pc, seller, title="Piano lessons, 1 hour", description="beginners welcome", price=40,
                  category="services", condition="used_good")
    assert lesson["category"] == "services" and lesson["condition"] is None  # condition is for goods only
    new = item(pc, seller, title="Handmade piano bench", price=120, condition="new")
    assert new["category"] == "for_sale" and new["condition"] == "new"
    plain = pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": "Piano tuning hammer",
                                                               "price": 15, "condition": None})
    assert plain.status_code == 200 and plain.json()["missing"] == ["condition"]  # no used-goods default
    svc = pc.get("/v1/market/items", headers=buyer, params={"q": "piano", "category": "services"}).json()
    assert [i["id"] for i in svc["items"]] == [lesson["id"]]
    assert pc.get("/v1/market/items", headers=buyer, params={"q": "piano"}).json()["total"] == 2
    assert pc.get("/v1/market/items", headers=buyer, params={"category": "housing"}).status_code == 422


def test_wait_for_updates_long_polls_until_the_other_side_answers(pc):
    import threading
    import time

    seller, _ = member(pc, "s2", contact="phone:+1-555-0120")
    buyer, _ = member(pc, "b2", contact="phone:+1-555-0121")
    it = item(pc, seller, title="Desk lamp", price=30)
    first = pc.get("/v1/market/updates", headers=buyer, params={"wait": 0}).json()
    assert first["changed"] is False
    cursor = first["cursor"]
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"user_approved": True, "amount": 25}).json()
    # the seller sees the new offer at once
    got = pc.get("/v1/market/updates", headers=seller, params={"since": cursor, "wait": 5}).json()
    assert got["changed"] and [x["id"] for x in got["offers"]] == [o["id"]]
    # the buyer waits; the seller answers 1s later and the wait returns early with the counter
    mine = pc.get("/v1/market/updates", headers=buyer, params={"wait": 0}).json()["cursor"]
    t = threading.Timer(1.0, lambda: pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                                             json={"user_approved": True, "action": "counter", "amount": 28}))
    t.start()
    start = time.monotonic()
    got = pc.get("/v1/market/updates", headers=buyer, params={"since": mine, "wait": 10}).json()
    t.join()
    assert got["changed"] and got["offers"][0]["amount"] == 28 and time.monotonic() - start < 8
    # nothing new after the returned cursor
    quiet = pc.get("/v1/market/updates", headers=buyer, params={"since": got["cursor"], "wait": 1}).json()
    assert quiet["changed"] is False and "wait_for_updates" in quiet["next_step"]
    assert pc.get("/v1/market/updates", headers=buyer, params={"wait": 51}).status_code == 422


def test_check_schedule_is_shared_with_the_counterparty(pc):
    import datetime as dt

    from onaa_registry import hosting
    from onaa_registry.models import PilotMember

    seller, sid = member(pc, "s3", contact="phone:+1-555-0130")
    buyer, _ = member(pc, "b3", contact="phone:+1-555-0131")
    it = item(pc, seller, title="Bike repair", price=60, category="services")
    assert pc.get("/v1/market/me", headers=seller).json()["check_schedule"]["checks_every_minutes"] is None
    r = pc.patch("/v1/market/me", headers=seller, json={"check_every_minutes": 60})
    assert r.status_code == 200 and r.json()["check_schedule"]["checks_every_minutes"] == 60
    o = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer, json={"user_approved": True, "amount": 50}).json()
    assert o["counterparty"]["availability"]["online_now"] is True  # the seller just connected
    # an hour later the seller is offline; the buyer sees the next expected check instead
    with pc.app.state.sessionmaker() as s:
        m = s.get(PilotMember, sid)
        later = m.last_seen_at.replace(tzinfo=dt.UTC) + dt.timedelta(minutes=70)
        a = hosting.availability(m, now=later)
    assert a["online_now"] is False and "have your reply in" in a["summary"]
    assert dt.datetime.fromisoformat(a["next_check_at"]) > later
    soon = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=3)).isoformat()
    r = pc.patch("/v1/market/me", headers=seller, json={"next_check_at": soon})
    assert r.status_code == 200  # a one-off extra check; the hourly run before it still shows first
    with pc.app.state.sessionmaker() as s:
        assert s.get(PilotMember, sid).next_check_at.isoformat().startswith(soon[:16])
    r = pc.patch("/v1/market/me", headers=seller, json={"check_every_minutes": None, "clear": True})
    r = pc.patch("/v1/market/me", headers=seller, json={"next_check_at": soon})
    assert r.json()["check_schedule"]["next_check_at"].startswith(soon[:16])
    far = (dt.datetime.now(dt.UTC) + dt.timedelta(days=8)).isoformat()
    assert pc.patch("/v1/market/me", headers=seller, json={"next_check_at": far}).status_code == 422
    r = pc.patch("/v1/market/me", headers=seller, json={"clear": True}).json()["check_schedule"]
    assert r["checks_every_minutes"] is None and r["online_now"] is True


def test_listing_needs_region_trade_payment_quantity_condition_from_the_user(pc):
    seller, _ = member(pc, "s", region="Austin TX")
    r = pc.post("/v1/market/items", headers=seller, json={"title": "Box of pencils", "price": 5})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["listed"] is False and body["status"] == "needs_info"
    assert body["missing"] == ["currency", "region", "trade_methods", "payment_methods", "quantity", "condition"]
    assert "language they are using" in body["next_step"] and "Austin TX" in body["next_step"]  # suggested, not set
    assert {q["field"] for q in body["questions"] if "options" in q} == {"trade_methods", "payment_methods",
                                                                        "condition"}
    assert pc.get("/v1/market/items", headers=seller, params={"mine": True}).json()["total"] == 0  # nothing listed

    # services: no quantity/condition; online-only needs no area; shipping is not a service method
    svc = item(pc, seller, title="Spanish tutoring", price=30, category="services", region=None,
               trade_methods=["online"], payment_methods=["payment_app"])
    assert svc["listed"] is True and svc["region"] == "online" and svc["quantity"] is None
    assert svc["optional_questions"] and "optional_questions" in svc["next_step"]
    bad = pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": "Haircut", "price": 20,
                                                           "category": "services", "trade_methods": ["shipping"]})
    assert bad.status_code == 422
    assert pc.post("/v1/market/items", headers=seller, json={**ITEM_REQUIRED, "title": "Pens", "price": 2,
                                                            "payment_methods": ["iou"]}).status_code == 422

    full = item(pc, seller, title="Box of pencils", price=5, quantity=12, condition="new",
                trade_methods=["in_person", "shipping"], payment_methods=["cash", "payment_app"])
    assert full["quantity"] == 12 and full["trade_methods"] == ["in_person", "shipping"]
    assert full["payment_methods"] == ["cash", "payment_app"] and "missing_info" not in full
    r = pc.patch(f"/v1/market/items/{full['id']}", headers=seller, json={"trade_methods": []})
    assert r.status_code == 422  # a required detail cannot be emptied


def test_older_listing_without_details_is_flagged_for_the_seller(pc):
    from sqlalchemy import update

    from onaa_registry.models import PilotItem

    seller, _ = member(pc, "s")
    it = item(pc, seller)
    with pc.app.state.sessionmaker() as s:  # simulate a row created before the requirement
        s.execute(update(PilotItem).where(PilotItem.id == it["id"]).values(trade_methods=None, payment_methods=None))
        s.commit()
    mine = pc.get("/v1/market/items", headers=seller, params={"mine": True}).json()["items"][0]
    assert mine["missing_info"] == ["trade_methods", "payment_methods"] and "update_item" in mine["missing_info_step"]
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=seller,
                 json={"trade_methods": ["shipping"], "payment_methods": ["bank_transfer"]})
    assert r.status_code == 200 and "missing_info" not in r.json()


def test_search_uses_region_and_trade_method(pc):
    seoul, _ = member(pc, "seoul")
    busan, _ = member(pc, "busan", region="Busan Haeundae")
    buyer, _ = member(pc, "buyer")
    local = item(pc, seoul, title="Desk lamp", price=20)
    far = item(pc, busan, title="Desk lamp brass", price=25, region="Busan Haeundae", trade_methods=["in_person"])
    ships = item(pc, busan, title="Desk lamp LED", price=30, region="Busan Haeundae",
                 trade_methods=["in_person", "shipping"], payment_methods=["bank_transfer"])
    res = pc.get("/v1/market/items", headers=buyer, params={"q": "lamp", "region": "Seoul"}).json()
    assert [(i["id"], i["reach"]) for i in res["items"]] == [(local["id"], "local"), (ships["id"], "shipping")]
    assert far["id"] not in str(res)
    near = pc.get("/v1/market/items", headers=buyer,
                  params={"q": "lamp", "region": "Seoul", "trade_method": "in_person"}).json()
    assert [i["id"] for i in near["items"]] == [local["id"]]
    paid = pc.get("/v1/market/items", headers=buyer, params={"q": "lamp", "payment_method": "bank_transfer"}).json()
    assert [i["id"] for i in paid["items"]] == [ships["id"]]


def test_matching_skips_items_the_buyer_cannot_get(pc):
    busan, _ = member(pc, "busan", region="Busan Haeundae")
    buyer, _ = member(pc, "buyer")
    item(pc, busan, title="Road bike", price=300, region="Busan Haeundae", trade_methods=["in_person"])
    ships = item(pc, busan, title="Road bike helmet", price=40, region="Busan Haeundae",
                 trade_methods=["in_person", "shipping"])
    w = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "road bike"}).json()
    assert [(m["their_item"]["id"], m["trade_fit"]) for m in w["matches"]] == [(ships["id"], ["shipping"])]
    w2 = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "bike helmet", "region": "Busan",
                                                         "trade_methods": ["in_person"]}).json()
    assert w2["trade_methods"] == ["in_person"]
    assert [m["trade_fit"] for m in w2["matches"]] == [["in person (Busan Haeundae)"]] * 2


def test_want_needs_budget_area_trade_payment_quantity_condition(pc):
    buyer, _ = member(pc, "b")
    r = pc.post("/v1/market/wants", headers=buyer, json={"title": "HB pencils"})
    assert r.status_code == 200 and r.json()["status"] == "needs_info"
    assert r.json()["missing"] == ["max_price", "currency", "region", "trade_methods", "payment_methods",
                                   "quantity", "conditions"]
    assert "post_want" in r.json()["next_step"] and "Seoul Mapo" in r.json()["next_step"]
    assert pc.get("/v1/market/wants", headers=buyer, params={"mine": True}).json()["wants"] == []
    svc = pc.post("/v1/market/wants", headers=buyer, json={"title": "Guitar lessons", "category": "services",
                                                          "max_price": 40, "currency": "USD",
                                                          "trade_methods": ["online"],
                                                          "payment_methods": ["card"]})
    assert svc.status_code == 201 and svc.json()["region"] == "online" and svc.json()["quantity"] is None


def test_posting_the_same_want_twice_keeps_one(pc):
    buyer, _ = member(pc, "b")
    a = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "Road bike"}).json()
    b = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "road bike"}).json()
    assert b["id"] == a["id"] and b["already_posted"] is True
    assert len(pc.get("/v1/market/wants", headers=buyer, params={"mine": True}).json()["wants"]) == 1


def test_matching_checks_condition_payment_and_quantity(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    item(pc, seller, title="HB pencils box", price=5, quantity=12, condition="used_fair")
    new = item(pc, seller, title="HB pencils pack", price=4, quantity=6, condition="new",
               payment_methods=["cash", "bank_transfer"])
    item(pc, seller, title="HB pencils crate", price=9, quantity=50, condition="new", payment_methods=["crypto"])
    w = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": "HB pencils", "quantity": 10,
                                                        "conditions": ["new"], "payment_methods": ["cash"]}).json()
    assert [(m["their_item"]["id"], m["payment_fit"], m["quantity_fit"]) for m in w["matches"]] == [
        (new["id"], ["cash"], "only 6 of 10")]


def test_buying_needs_no_want_search_filters_and_points_to_offer_or_message(pc):
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    used = item(pc, seller, title="Camera tripod", price=30)
    new = item(pc, seller, title="Camera tripod pro", price=80, condition="new")
    res = pc.get("/v1/market/items", headers=buyer, params={"q": "tripod", "condition": ["new", "like_new"]}).json()
    assert [i["id"] for i in res["items"]] == [new["id"]]
    assert "make_offer" in res["next_step"] and "send_message" in res["next_step"]
    both = pc.get("/v1/market/items", headers=buyer, params={"q": "tripod", "max_price": 50, "region": "Mapo",
                                                            "trade_method": "in_person",
                                                            "payment_method": "cash"}).json()
    assert [i["id"] for i in both["items"]] == [used["id"]]
    o = pc.post(f"/v1/market/items/{used['id']}/offers", headers=buyer, json={"user_approved": True, "amount": 28})
    assert o.status_code == 201  # offer straight from search, no want posted


def test_member_terms_accepted_for_the_member_on_first_use(pc, monkeypatch):
    """Founder decision 2026-11-18: the assistant accepts the member terms for its user on first use, with no ask;
    ONAA records version + hash + time and flags that answer so the assistant tells its user (with the link)."""
    h, mid = member(pc, "terms")
    info = pc.get("/v1/member-terms").json()
    assert info["version"].startswith("member-") and info["url"].endswith("/member-terms") and info["summary"]
    assert pc.get("/member-terms.md").text.startswith("# ONAA Member Terms")
    # first call: a needs_info answer (its own JSONResponse) still carries the header
    first = pc.post("/v1/market/items", headers=h, json={"title": "Desk", "price": 40})
    assert first.status_code == 200 and first.json()["listed"] is False
    assert first.headers["x-onaa-member-terms-accepted"] == info["version"]
    # repeated for a few minutes (the first answer may be an error or one of parallel calls), then no more
    me = pc.get("/v1/market/me", headers=h)
    assert me.headers["x-onaa-member-terms-accepted"] == info["version"]
    with pc.app.state.sessionmaker() as s:
        from onaa_registry.models import PilotMember

        s.get(PilotMember, mid).terms_accepted_at -= dt.timedelta(minutes=11)
        s.commit()
    me = pc.get("/v1/market/me", headers=h)
    assert "x-onaa-member-terms-accepted" not in me.headers
    acc = me.json()["member_terms"]
    assert acc["version"] == info["version"] and acc["sha256"] == info["sha256"] and acc["via"] == "assistant_auto"
    assert acc["current"] is True and acc["accepted_at"]
    assert acc["url"] == info["url"]  # the link stays with the account after the notice window
    listed = pc.get("/v1/admin/market/members", headers=A).json()["items"]
    assert next(x for x in listed if x["member_id"] == mid)["member_terms"]["version"] == info["version"]
    # a new text (different hash) is accepted again on the next use
    from onaa_registry import member_terms
    from onaa_registry.terms import Terms
    monkeypatch.setattr(member_terms, "current", lambda: Terms("member-test-9", "changed", "0" * 64))
    again = pc.get("/v1/market/me", headers=h)
    assert again.headers["x-onaa-member-terms-accepted"] == "member-test-9"
    assert again.json()["member_terms"]["version"] == "member-test-9"


def test_sign_out_does_not_accept_member_terms(pc):
    h, _ = member(pc, "leaver")
    r = pc.post("/v1/market/me/sign-out-everywhere", headers=h)
    assert r.status_code == 200 and "x-onaa-member-terms-accepted" not in r.headers
