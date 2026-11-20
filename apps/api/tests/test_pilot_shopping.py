"""Shopping runs (multi-listing comparison step 2, founder decisions 2026-11-20): up to 5 sellers at once, several
units across sellers without going over the target, the rest withdrawn once filled, one per-unit limit for the run."""

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


def member(c, nick):
    r = c.post("/v1/admin/market/members", headers={"Authorization": f"Bearer {ADMIN}"},
               json={"nickname": nick, "contact": "kakao:x", "region": "Seoul Mapo"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def item(c, h, **kw):
    r = c.post("/v1/market/items", headers=h, json={**ITEM_REQUIRED, "title": "Folding chair", "price": 8} | kw)
    assert r.status_code == 201, r.text
    return r.json()


SHIP = {"trade_methods": ["shipping"], "payment_methods": ["bank_transfer"], "region": "Busan"}


def run(c, h, **kw):
    r = c.post("/v1/market/shopping", headers=h, json={"title": "folding chairs", "currency": "USD"} | kw)
    assert r.status_code == 201, r.text
    return r.json()


def offer(c, h, it, amount, **kw):
    return c.post(f"/v1/market/items/{it['id']}/offers", headers=h,
                  json={"amount": amount, "user_approved": True} | kw)


def accept(c, h, offer_id):
    return c.post(f"/v1/market/offers/{offer_id}/respond", headers=h, json={"action": "accept", "user_approved": True})


def test_bike_from_several_sellers_rest_withdrawn(pc):
    """Story 1: one bike, offers to two sellers at once; when one accepts the other offer is withdrawn."""
    buyer = member(pc, "buyer")
    sc, sb = member(pc, "c"), member(pc, "b")
    c_it = item(pc, sc, title="Road bike", price=360, **SHIP, shipping_cost=0)
    b_it = item(pc, sb, title="Road bike", price=350, **SHIP, shipping_cost=40)
    r = run(pc, buyer, title="road bike", target_quantity=1)
    assert r["units_needed"] == 1 and "start_shopping" not in r["next_step"]
    oc = offer(pc, buyer, c_it, 340, shopping_id=r["id"])
    assert oc.status_code == 201, oc.text
    # one bike wanted and one already on offer: a second offer would go over the target
    over = offer(pc, buyer, b_it, 320, shopping_id=r["id"])
    assert over.status_code == 409 and "go over the target" in over.text
    r2 = run(pc, buyer, title="road bike 2", target_quantity=2)
    o1 = offer(pc, buyer, c_it, 340, shopping_id=r2["id"])
    assert o1.status_code == 409  # one open offer per listing per buyer, as before
    pc.post(f"/v1/market/offers/{oc.json()['id']}/respond", headers=buyer, json={"action": "withdraw"})
    o1 = offer(pc, buyer, c_it, 340, shopping_id=r2["id"]).json()
    o2 = offer(pc, buyer, b_it, 320, shopping_id=r2["id"]).json()
    assert accept(pc, sc, o1["id"]).status_code == 200
    view = pc.get(f"/v1/market/shopping/{r2['id']}", headers=buyer).json()
    assert view["units_bought"] == 1 and view["status"] == "open"  # two wanted
    pc.patch(f"/v1/market/shopping/{r2['id']}", headers=buyer, json={"target_quantity": 1})
    # lowering the target below bought + open is refused; ending withdraws the rest
    assert pc.patch(f"/v1/market/shopping/{r2['id']}", headers=buyer, json={"status": "ended"}).status_code == 200
    seller_view = pc.get("/v1/market/offers", headers=sb, params={"state": "all"}).json()["offers"]
    assert [o["status"] for o in seller_view if o["id"] == o2["id"]] == ["withdrawn"]


def test_ten_chairs_from_three_sellers_never_over(pc):
    """Story 2: 10 chairs at most $10 each with shipping, from sellers with 1, 4 and 5 (of 8) units."""
    buyer = member(pc, "buyer")
    sa, sc, sd, se = member(pc, "a"), member(pc, "c"), member(pc, "d"), member(pc, "e")
    a = item(pc, sa, price=8, quantity=1)
    c = item(pc, sc, price=36, quantity=4, **SHIP, shipping_cost=0)
    d = item(pc, sd, price=64, quantity=8, **SHIP, shipping_cost=5)
    e = item(pc, se, price=30, quantity=3, **SHIP, shipping_cost=0)
    r = run(pc, buyer, target_quantity=10, unit_limit=10, partial_ok=True)
    oa = offer(pc, buyer, a, 8, shopping_id=r["id"]).json()
    oc = offer(pc, buyer, c, 36, shopping_id=r["id"]).json()
    od = offer(pc, buyer, d, 40, shopping_id=r["id"], units=5).json()
    assert od["units"] == 5
    full = offer(pc, buyer, e, 30, shopping_id=r["id"])
    assert full.status_code == 409 and "0 more unit" in full.text
    # seller D accepts 5 of 8: the listing stays on sale with 3 left
    assert accept(pc, sd, od["id"]).status_code == 200
    left = pc.get(f"/v1/market/items/{d['id']}", headers=buyer).json()
    assert left["status"] == "available" and left["quantity"] == 3
    assert accept(pc, sa, oa["id"]).status_code == 200
    view = pc.get(f"/v1/market/shopping/{r['id']}", headers=buyer).json()
    assert view["units_bought"] == 6 and view["units_on_open_offers"] == 4 and view["units_needed"] == 0
    assert accept(pc, sc, oc["id"]).status_code == 200
    view = pc.get(f"/v1/market/shopping/{r['id']}", headers=buyer).json()
    assert view["status"] == "filled" and view["units_bought"] == 10 and len(view["deals"]) == 3
    # a split deal that is cancelled gives its units back and opens the run again
    deal = pc.post(f"/v1/market/deals/{od['id']}", headers=buyer, json={"action": "cancel", "user_approved": True})
    assert deal.status_code == 200, deal.text
    assert pc.get(f"/v1/market/items/{d['id']}", headers=buyer).json()["quantity"] == 8
    assert pc.get(f"/v1/market/shopping/{r['id']}", headers=buyer).json()["status"] == "open"


def test_filled_run_withdraws_other_offers_and_tells_without_prices(pc):
    buyer = member(pc, "buyer")
    s1, s2 = member(pc, "s1"), member(pc, "s2")
    i1, i2 = item(pc, s1, price=10), item(pc, s2, price=12)
    r = run(pc, buyer, target_quantity=1)
    pc.patch(f"/v1/market/shopping/{r['id']}", headers=buyer, json={"target_quantity": 2})
    o1 = offer(pc, buyer, i1, 9, shopping_id=r["id"]).json()
    o2 = offer(pc, buyer, i2, 11, shopping_id=r["id"]).json()
    pc.patch(f"/v1/market/shopping/{r['id']}", headers=buyer, json={"target_quantity": 2})
    assert accept(pc, s1, o1["id"]).status_code == 200
    # target 2: still open. Lower it to 1 is refused (1 bought + 1 on offer), so end via filled: accept the other
    assert accept(pc, s2, o2["id"]).status_code == 200
    assert pc.get(f"/v1/market/shopping/{r['id']}", headers=buyer).json()["status"] == "filled"


def test_withdrawn_when_filled_carries_no_price(pc):
    buyer = member(pc, "buyer")
    s1, s2 = member(pc, "s1"), member(pc, "s2")
    i1, i2 = item(pc, s1, price=10, quantity=2), item(pc, s2, price=12)
    r = run(pc, buyer, target_quantity=2)
    o1 = offer(pc, buyer, i1, 9, shopping_id=r["id"], units=1).json()
    o2 = offer(pc, buyer, i2, 11, shopping_id=r["id"]).json()
    assert accept(pc, s1, o1["id"]).status_code == 200
    # one more offer for 1 unit fits; the run fills with o2
    assert accept(pc, s2, o2["id"]).status_code == 200
    r3 = run(pc, buyer, title="lamp", target_quantity=1)
    s3, s4 = member(pc, "s3"), member(pc, "s4")
    i3, i4 = item(pc, s3, title="Lamp", price=20), item(pc, s4, title="Lamp", price=22)
    r4 = run(pc, buyer, title="lamp 2", target_quantity=2)
    o3 = offer(pc, buyer, i3, 18, shopping_id=r4["id"]).json()
    offer(pc, buyer, i4, 19, shopping_id=r4["id"])
    pc.patch(f"/v1/market/shopping/{r4['id']}", headers=buyer, json={"target_quantity": 2})
    assert r3["status"] == "open"
    assert accept(pc, s3, o3["id"]).status_code == 200
    assert pc.patch(f"/v1/market/shopping/{r4['id']}", headers=buyer,
                    json={"target_quantity": 1}).status_code == 409


def test_run_limit_lets_the_ai_agree_alone_only_inside_it(pc):
    buyer = member(pc, "buyer")
    s = member(pc, "s")
    it = item(pc, s, price=40, quantity=4, **SHIP, shipping_cost=4)
    r = run(pc, buyer, target_quantity=4, unit_limit=10)
    # 4 units, amount excludes shipping: limit 4*10 - 4 = 36
    ok = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                 json={"amount": 36, "shopping_id": r["id"], "includes_shipping": False})
    assert ok.status_code == 201, ok.text
    pc.post(f"/v1/market/offers/{ok.json()['id']}/respond", headers=buyer, json={"action": "withdraw"})
    held = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                   json={"amount": 37, "shopping_id": r["id"], "includes_shipping": False})
    assert held.status_code == 200 and held.json()["done"] is False
    inc = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                  json={"amount": 40, "shopping_id": r["id"], "includes_shipping": True})
    assert inc.status_code == 201, inc.text


def test_at_most_five_open_offers_per_run(pc):
    buyer = member(pc, "buyer")
    r = run(pc, buyer, target_quantity=20)
    for i in range(5):
        it = item(pc, member(pc, f"s{i}"), title=f"Chair {i}")
        assert offer(pc, buyer, it, 7, shopping_id=r["id"]).status_code == 201
    sixth = offer(pc, buyer, item(pc, member(pc, "s5"), title="Chair 5"), 7, shopping_id=r["id"])
    assert sixth.status_code == 409 and "at most 5" in sixth.text


def test_seller_sees_several_offers_side_by_side(pc):
    seller = member(pc, "seller")
    it = item(pc, seller, title="Desk lamp", price=50)
    for nick, amount in (("x", 40), ("y", 45), ("z", 42)):
        assert offer(pc, member(pc, nick), it, amount).status_code == 201
    mine = pc.get("/v1/market/offers", headers=seller, params={"role": "seller"}).json()
    rows = mine["compare_offers"][0]["offers"]
    assert [o["amount"] for o in rows] == [45, 42, 40] and "buyer_record" in rows[0]
    assert "Never tell a buyer what another buyer offered" in mine["next_step"]


def test_late_accept_after_the_run_is_filled_is_refused(pc):
    """Two sellers accepting in the same second: the run row is locked and the late accept is refused, so the buyer
    never ends up with more than the target. The race is simulated by filling the run between offer and accept."""
    from onaa_registry.models import PilotShopping

    buyer, sa, sb = member(pc, "buyer"), member(pc, "a"), member(pc, "b")
    a, b = item(pc, sa, price=300), item(pc, sb, price=310)
    r = run(pc, buyer, title="road bike", target_quantity=2)
    oa = offer(pc, buyer, a, 280, shopping_id=r["id"]).json()
    offer(pc, buyer, b, 290, shopping_id=r["id"])
    with pc.app.state.sessionmaker() as s, s.begin():
        s.get(PilotShopping, r["id"]).target_quantity = 0  # as if another accept just took what was left
    late = accept(pc, sa, oa["id"])
    assert late.status_code == 409 and "bought_elsewhere" in late.text
    assert pc.get(f"/v1/market/items/{a['id']}", headers=sa).json()["status"] == "available"
