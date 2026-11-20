"""Removed listings and closed wants are deleted for good 30 days after removal, unless a report or an unfinished
deal on them is still open (pilot_retention.py)."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from conftest import ADMIN, ITEM_REQUIRED, WANT_REQUIRED
from fastapi.testclient import TestClient

from onaa_registry.main import create_app
from onaa_registry.models import (
    PilotItem,
    PilotItemQuestion,
    PilotListingReport,
    PilotOffer,
    PilotQuestionReport,
    PilotWant,
)

A = {"Authorization": f"Bearer {ADMIN}"}
OK = {"user_approved": True}


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick):
    r = c.post("/v1/admin/market/members", headers=A, json={"nickname": nick, "contact": "kakao:x-" + nick,
                                                            "region": "Seoul"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def item(c, h, title="Road bike 54cm"):
    r = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED, "title": title, "price": 300})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def remove(c, h, item_id):
    r = c.patch(f"/v1/market/items/{item_id}", headers=h, json={"status": "removed"})
    assert r.status_code == 200, r.text
    return r.json()


def age(c, model, row_id, days):
    with c.app.state.sessionmaker() as s:
        s.get(model, row_id).updated_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
        s.commit()


def purge(c):
    r = c.post("/v1/admin/market/purge-expired", headers=A)
    assert r.status_code == 200, r.text
    return r.json()["deleted_removed"]


def exists(c, model, row_id):
    with c.app.state.sessionmaker() as s:
        return s.get(model, row_id) is not None


def test_removed_listing_and_its_qa_are_deleted_after_30_days(pc):
    seller, buyer, other = member(pc, "s"), member(pc, "b"), member(pc, "o")
    it, young, back = item(pc, seller), item(pc, seller, "Desk lamp"), item(pc, seller, "Chair")
    q = pc.post(f"/v1/market/items/{it}/questions", headers=buyer, json={"text": "Any scratches on the frame?"}).json()
    pc.post(f"/v1/market/questions/{q['id']}/answer", headers=seller, json={"text": "A small one on the fork."})
    r = pc.post(f"/v1/market/questions/{q['id']}/report", headers=other, json={"reason": "spam"})
    assert r.status_code == 200, r.text
    with pc.app.state.sessionmaker() as s:
        assert s.query(PilotQuestionReport).count() == 1
    pc.post(f"/v1/market/items/{it}/offers", headers=buyer, json={"amount": 250, **OK})
    out = remove(pc, seller, it)
    assert out["removal"]["retention_days"] == 30 and "30 days" in out["removal"]["note"]
    assert dt.datetime.fromisoformat(out["removal"]["deleted_after"]) > dt.datetime.now(dt.UTC) + dt.timedelta(29)
    remove(pc, seller, young)
    remove(pc, seller, back)
    for i in (it, young, back):
        age(pc, PilotItem, i, 31 if i != young else 29)
    assert pc.patch(f"/v1/market/items/{back}", headers=seller, json={"status": "available"}).status_code == 200
    assert purge(pc) == {"items": 1, "wants": 0, "held": 0}
    assert not exists(pc, PilotItem, it) and exists(pc, PilotItem, young) and exists(pc, PilotItem, back)
    with pc.app.state.sessionmaker() as s:
        assert s.query(PilotItemQuestion).filter_by(item_id=it).count() == 0
        assert s.query(PilotQuestionReport).count() == 0
        assert s.query(PilotOffer).filter_by(item_id=it).count() == 0
    assert pc.get(f"/v1/market/items/{it}", headers=seller).status_code == 404
    assert purge(pc) == {"items": 0, "wants": 0, "held": 0}


def test_open_report_or_unfinished_deal_holds_the_listing_until_resolved(pc):
    seller, buyer, rep = member(pc, "s"), member(pc, "b"), member(pc, "r")
    reported = item(pc, seller, "Old phone")
    pc.post(f"/v1/market/items/{reported}/report", headers=rep, json={"reason": "scam"})
    remove(pc, seller, reported)
    dealt = item(pc, seller, "Bookshelf")
    o = pc.post(f"/v1/market/items/{dealt}/offers", headers=buyer, json={"amount": 280, **OK}).json()
    assert pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller,
                   json={"action": "accept", **OK}).json()["status"] == "accepted"
    for i in (reported, dealt):
        with pc.app.state.sessionmaker() as s:  # removal by any route (status set directly for the live deal)
            s.get(PilotItem, i).status = "removed"
            s.commit()
        age(pc, PilotItem, i, 40)
    assert purge(pc) == {"items": 0, "wants": 0, "held": 2}
    with pc.app.state.sessionmaker() as s:
        s.query(PilotListingReport).update({"status": "dismissed"})
        s.get(PilotItem, reported).review = None
        s.commit()
    assert pc.post(f"/v1/market/deals/{o['id']}", headers=seller, json={"action": "cancel", **OK}).status_code == 200
    with pc.app.state.sessionmaker() as s:
        s.get(PilotItem, dealt).status = "removed"
        s.commit()
    age(pc, PilotItem, dealt, 40)
    assert purge(pc) == {"items": 2, "wants": 0, "held": 0}


def test_a_report_on_a_deal_keeps_the_listing(pc):
    seller, buyer = member(pc, "s"), member(pc, "b")
    it = item(pc, seller)
    o = pc.post(f"/v1/market/items/{it}/offers", headers=buyer, json={"amount": 280, **OK}).json()
    pc.post(f"/v1/market/offers/{o['id']}/respond", headers=seller, json={"action": "accept", **OK})
    assert pc.post(f"/v1/market/deals/{o['id']}", headers=buyer,
                   json={"action": "report", "reason": "no_show", **OK}).json()["done"] is True
    pc.post(f"/v1/market/deals/{o['id']}", headers=seller, json={"action": "cancel", **OK})
    remove(pc, seller, it)
    age(pc, PilotItem, it, 40)
    assert purge(pc)["held"] == 1 and exists(pc, PilotItem, it)


def test_closed_want_is_deleted_after_30_days_unless_reported(pc):
    buyer, rep = member(pc, "b"), member(pc, "r")
    ids = []
    for title in ("Kids bike", "Camping tent"):
        r = pc.post("/v1/market/wants", headers=buyer, json={**WANT_REQUIRED, "title": title})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    pc.post(f"/v1/market/wants/{ids[1]}/report", headers=rep, json={"reason": "scam"})
    for w in ids:
        out = pc.patch(f"/v1/market/wants/{w}", headers=buyer, json={"status": "closed"}).json()
        assert out["removal"]["retention_days"] == 30
        age(pc, PilotWant, w, 31)
    assert pc.patch(f"/v1/market/wants/{ids[0]}", headers=buyer, json={"status": "found"}).json().get("removal") is None
    age(pc, PilotWant, ids[0], 31)
    assert purge(pc) == {"items": 0, "wants": 0, "held": 1}
    pc.patch(f"/v1/market/wants/{ids[0]}", headers=buyer, json={"status": "closed"})
    age(pc, PilotWant, ids[0], 31)
    assert purge(pc) == {"items": 0, "wants": 1, "held": 1}
    assert not exists(pc, PilotWant, ids[0]) and exists(pc, PilotWant, ids[1])
