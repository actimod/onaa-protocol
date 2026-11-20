"""Multi-listing search and comparison, step 1 (founder decisions 2026-11-20): shipping cost on listings, a compare
block with the same fields for every search result, sorting by price plus shipping (also per unit), and the
guidance for the buyer's AI (one table, never use another seller's price to bargain)."""

from __future__ import annotations

import dataclasses

import pytest
from conftest import ADMIN, ITEM_REQUIRED
from fastapi.testclient import TestClient

from onaa_registry.main import create_app


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick, region="Seoul Mapo"):
    r = c.post("/v1/admin/market/members", headers={"Authorization": f"Bearer {ADMIN}"},
               json={"nickname": nick, "contact": "kakao:x", "region": region})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def item(c, h, **kw):
    r = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300} | kw)
    assert r.status_code == 201, r.text
    return r.json()


SHIP = {"trade_methods": ["shipping"], "payment_methods": ["bank_transfer"], "region": "Busan"}


def test_shipping_cost_is_listed_and_needs_shipping(pc):
    s = member(pc, "seller")
    it = item(pc, s, **SHIP, shipping_cost=30)
    assert it["shipping_cost"] == 30
    r = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Lamp", "price": 20,
                                                     "shipping_cost": 5})  # in person only
    assert r.status_code == 422 and "shipping" in r.text
    # no longer shipping: the cost goes away; shipping again: it can be set again
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"trade_methods": ["in_person"]})
    assert r.status_code == 200 and r.json()["shipping_cost"] is None
    assert pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"shipping_cost": 9}).status_code == 422
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"trade_methods": ["shipping"], "shipping_cost": 0})
    assert r.status_code == 200 and r.json()["shipping_cost"] == 0


def test_bike_from_four_sellers_compares_on_total(pc):
    """The plan's story 1: same bike, four sellers; the cheapest total is not the cheapest price."""
    buyer = member(pc, "buyer")
    a = item(pc, member(pc, "a"), **SHIP, price=380, shipping_cost=30)
    b = item(pc, member(pc, "b"), **SHIP, price=350, shipping_cost=40)
    c = item(pc, member(pc, "c"), **SHIP, price=360, shipping_cost=0)
    d = item(pc, member(pc, "d"), **SHIP, price=370)  # depends on the address
    res = pc.get("/v1/market/items", headers=buyer, params={"q": "bike", "sort": "total"}).json()
    by_id = {i["id"]: i["compare"] for i in res["items"]}
    assert [i["id"] for i in res["items"]][:3] == [c["id"], d["id"], b["id"]]  # 360, 370 (shipping unknown), 390
    assert by_id[c["id"]]["shipping"] == "free" and by_id[c["id"]]["total"] == 360
    assert by_id[a["id"]]["total"] == 410 and by_id[b["id"]]["total"] == 390
    assert by_id[d["id"]]["shipping"] == "ask the seller" and by_id[d["id"]]["total"] is None
    assert by_id[d["id"]]["price_without_shipping"] == 370
    seller = by_id[a["id"]]["seller"]
    assert seller["deals_done"] == 0 and "next_reply" in seller
    by_price = pc.get("/v1/market/items", headers=buyer, params={"q": "bike", "sort": "price"}).json()
    assert [i["id"] for i in by_price["items"]] == [b["id"], c["id"], d["id"], a["id"]]
    step = res["next_step"]
    assert "numbered table" in step and "Never tell a seller another seller's price" in step
    assert "Do not announce" in step and "never convert" in step


def test_chairs_sort_per_unit(pc):
    """The plan's story 2: several units, compared per unit including shipping."""
    buyer = member(pc, "buyer")
    one = item(pc, member(pc, "a"), title="Folding chair", price=8, quantity=1)  # in person
    four = item(pc, member(pc, "c"), title="Folding chairs", **SHIP, price=36, quantity=4, shipping_cost=0)
    two = item(pc, member(pc, "b"), title="Folding chairs pair", **SHIP, price=18, quantity=2, shipping_cost=4)
    five = item(pc, member(pc, "d"), title="Folding chairs set", **SHIP, price=40, quantity=5, shipping_cost=5)
    res = pc.get("/v1/market/items", headers=buyer, params={"q": "chair", "sort": "unit_total"}).json()
    ids = [i["id"] for i in res["items"]]
    assert ids[0] == one["id"] and ids[-1] == two["id"] and set(ids[1:3]) == {four["id"], five["id"]}
    cmp = {i["id"]: i["compare"] for i in res["items"]}
    assert cmp[five["id"]]["unit_total"] == 9 and cmp[two["id"]]["unit_total"] == 11
    assert cmp[one["id"]]["shipping"].startswith("not shipped") and cmp[one["id"]]["in_person_area"] == "Seoul Mapo"
    assert "unit_total" not in cmp[one["id"]]


def test_default_order_unchanged_and_own_items_have_no_compare(pc):
    s = member(pc, "seller")
    buyer = member(pc, "buyer")
    old = item(pc, s, title="Desk lamp", price=10)
    new = item(pc, member(pc, "other"), title="Desk lamp LED", price=50)
    res = pc.get("/v1/market/items", headers=buyer, params={"q": "lamp"}).json()
    assert [i["id"] for i in res["items"]] == [new["id"], old["id"]]
    mine = pc.get("/v1/market/items", headers=s, params={"mine": True}).json()["items"]
    assert mine and "compare" not in mine[0]
    single = pc.get("/v1/market/items", headers=buyer, params={"q": "LED"}).json()
    assert "numbered table" not in single["next_step"]
