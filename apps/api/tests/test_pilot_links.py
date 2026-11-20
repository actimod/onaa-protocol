"""Photos and product pages as links only (founder decisions 2026-11-20): up to 3 https links per listing and per
message, never opened by ONAA, always labelled as unverified, listing links shown only while it is on sale."""

from __future__ import annotations

import dataclasses

import pytest
from conftest import ADMIN, ITEM_REQUIRED
from fastapi.testclient import TestClient
from test_messaging import env, inbox, join  # noqa: F401  (env is a fixture)

from onaa_registry import links
from onaa_registry.main import create_app

P1, P2, P3, P4 = (f"https://photos.example/bike-{i}.jpg" for i in range(1, 5))


@pytest.fixture
def pc(settings, fetcher, txt, runner):
    with TestClient(create_app(dataclasses.replace(settings, pilot_enabled=True), fetcher, txt, runner)) as c:
        yield c


def member(c, nick):
    r = c.post("/v1/admin/market/members", headers={"Authorization": f"Bearer {ADMIN}"},
               json={"nickname": nick, "contact": "kakao:x", "region": "Seoul Mapo"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_find_and_view():
    assert links.find("see https://a.example/x.jpg, and www.b.example.") == ["https://a.example/x.jpg",
                                                                           "www.b.example"]
    v = links.view(["https://a.example/1", "http://b.example/2"], links.MESSAGE_LABEL)
    assert v["unverified_urls"] == ["https://a.example/1"] and "not https" in v["not_shown"]
    assert "did not open" in v["label"]


def test_listing_links_up_to_three_shown_labelled_while_on_sale(pc):
    s, buyer = member(pc, "seller"), member(pc, "buyer")
    r = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300,
                                                     "links": [P1, P2, P3, P4]})
    assert r.status_code == 422
    r = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300,
                                                     "links": ["http://photos.example/x.jpg"]})
    assert r.status_code == 422 and "https" in r.text
    # links in the description count toward the 3
    r = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300,
                                                     "description": f"more at {P4}", "links": [P1, P2, P3]})
    assert r.status_code == 422 and "at most 3 links" in r.text
    it = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300,
                                                      "links": [P1, P2]}).json()
    seen = pc.get("/v1/market/items", headers=buyer, params={"q": "bike"}).json()["items"][0]
    assert seen["links"]["unverified_urls"] == [P1, P2] and "did not open" in seen["links"]["label"]
    assert pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"links": [P1, P2, P3, P4]}).status_code == 422
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"links": [P3]})
    assert r.status_code == 200 and r.json()["links"]["unverified_urls"] == [P3]
    # sold: the links go away with the listing
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"status": "sold"})
    assert r.status_code == 200 and "links" not in r.json()
    r = pc.patch(f"/v1/market/items/{it['id']}", headers=s, json={"status": "available"})
    assert "links" not in r.json()


def test_offer_message_links_capped(pc):
    s, buyer = member(pc, "seller"), member(pc, "buyer")
    it = pc.post("/v1/market/items", headers=s, json={**ITEM_REQUIRED, "title": "Road bike", "price": 300}).json()
    r = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                json={"amount": 250, "message": f"like {P1} {P2} {P3} {P4}"})
    assert r.status_code == 422 and "at most 3 links" in r.text
    r = pc.post(f"/v1/market/items/{it['id']}/offers", headers=buyer,
                json={"amount": 250, "message": f"like {P1}?", "user_approved": True})
    assert r.status_code == 201, r.text
    mine = pc.get("/v1/market/offers", headers=s).json()["offers"][0]
    msgs = [e for e in mine["history"] if e.get("message")]
    assert msgs and msgs[0]["links"]["unverified_urls"] == [P1]


def test_message_links_travel_in_the_text_and_arrive_labelled(env):  # noqa: F811
    c, _ = env
    ann, _ = join(c, "ann")
    bob, bob_addr = join(c, "bob")
    over = c.post("/v1/market/msg/send", headers=ann, json={"to": bob_addr, "text": f"photos: {P1}",
                                                            "links": [P2, P3, P4]})
    assert over.status_code == 422 and "at most 3 links" in over.text
    r = c.post("/v1/market/msg/send", headers=ann, json={"to": bob_addr, "text": "Here is the bike:",
                                                         "links": [P1, P2]})
    assert r.status_code == 200, r.text
    m = inbox(c, bob)["conversations"][0]["messages"][0]["message"]
    assert P1 in m["untrusted_text"] and m["links"]["unverified_urls"] == [P1, P2]
    assert "contains_link" in m["flags"] and "did not open" in m["links"]["label"]
