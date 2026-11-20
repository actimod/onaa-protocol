"""Reasons to register (founder decision 2026-11-17): trust level, one-click email verification for stores,
store-stated details, lookup counts, daily re-checks, free Founding Cohort seats and the optional ranking boost."""

from __future__ import annotations

import re

from conftest import SERVICE, admin_headers
from sqlalchemy.orm import Session
from test_self_registration import publish_and_complete, start
from test_stores import _store

from onaa_registry import registrant
from onaa_registry.checker_loop import due_listing_ids
from onaa_registry.models import Listing, Operator, StoreInvite


def _invite(client, store="alpha.example", email="hello@alpha.example.com"):
    r = client.post(f"/v1/admin/stores/{store}/invites", headers=admin_headers(),
                    json={"email": email, "email_source_url": "https://alpha.example/pages/contact"})
    assert r.status_code == 201, r.text
    return r.json()


def _code(inv):
    return inv["verify_url"].split("code=")[1]


def _verify(client, inv):
    page = client.get(f"/verify-store/{inv['invite_id']}", params={"code": _code(inv)})
    assert page.status_code == 200 and "Verify my store" in page.text and "phone book" in page.text
    assert "no payment, no forms, no extra information" in page.text
    r = client.post(f"/verify-store/{inv['invite_id']}", data={"code": _code(inv), "accept_terms": "draft-0.2"})
    assert r.status_code == 200, r.text
    key = re.search(r"<pre>(onaa_sk_[^<]+)</pre>", r.text).group(1)
    return key, r


def test_discovered_store_shows_lowest_trust_level(client):
    a = _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    assert a["trust"]["level"] == "discovered_unverified" and "not registered" in a["trust"]["level_label"]
    rec = client.get("/v1/stores/alpha.example").json()
    assert rec["trust"]["level"] == "discovered_unverified" and rec["store_stated"] == "unknown"
    found = client.get("/v1/buying/stores", params={"country": "US"}).json()["items"][0]
    assert found["store"]["trust_level"] == "discovered_unverified"


def test_store_verifies_by_published_email_link(client):
    a = _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    inv = _invite(client)
    # opening the link (mail scanners, previews) changes nothing
    assert client.get(f"/verify-store/{inv['invite_id']}", params={"code": _code(inv)}).status_code == 200
    assert client.get("/v1/stores/alpha.example").json()["trust"]["level"] == "discovered_unverified"
    # wrong code, no terms
    assert client.get(f"/verify-store/{inv['invite_id']}", params={"code": "nope"}).status_code == 404
    assert client.post(f"/verify-store/{inv['invite_id']}", data={"code": _code(inv)}).status_code == 422
    key, page = _verify(client, inv)
    assert "Founding Cohort" in page.text and "Optional" in page.text
    rec = client.get(f"/v1/services/{a['id']}").json()
    t = rec["trust"]
    assert t["level"] == "operator_confirmed_by_email" and t["owner_confirmed_via"] == "published_email"
    assert t["registration_method"] == "store_email_link" and t["endpoint_control_verified"] is False
    assert rec["status"] == "registered" and rec["agent_checkout"]["status"] == "checkout_ready"
    assert "hello@alpha.example.com" not in str(rec)  # the address stays private
    # single use
    assert client.post(f"/verify-store/{inv['invite_id']}",
                       data={"code": _code(inv), "accept_terms": "draft-0.2"}).status_code == 410
    # already registered: no new invites
    assert client.post("/v1/admin/stores/alpha.example/invites", headers=admin_headers(),
                       json={"email": "x@alpha.example.com", "email_source_url": "https://alpha.example/"}
                       ).status_code == 409
    # the key works with the API too
    me = client.get("/v1/operators/me", headers={"Authorization": f"Bearer {key}"}).json()
    assert me["id"] == rec["operator_id"]
    with Session(client.app.state.engine) as s:
        op = s.get(Operator, rec["operator_id"])
        assert op.operator_contact == "hello@alpha.example.com" and op.terms_acceptance_method == "store_email_link"
        assert op.founding_cohort_until is not None
        inv_row = s.get(StoreInvite, inv["invite_id"])
        assert inv_row.used_at is not None and inv_row.email_source_url.endswith("/pages/contact")


def test_invite_expires_and_other_links_stop(client):
    _store(client, "alpha.example", "checkout_ready")
    first, second = _invite(client), _invite(client)
    _verify(client, second)
    assert client.get(f"/verify-store/{first['invite_id']}", params={"code": _code(first)}).status_code in (409, 410)
    bad = client.post("/v1/admin/stores/alpha.example/invites", headers=admin_headers(),
                      json={"email": "not-an-email", "email_source_url": "https://alpha.example/"})
    assert bad.status_code in (409, 422)
    assert client.post("/v1/admin/stores/alpha.example/invites",
                       json={"email": "a@b.example.com", "email_source_url": "https://alpha.example/"}).status_code in (
        401, 403)


def test_store_states_optional_details_labelled_as_store_stated(client):
    a = _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    key, _ = _verify(client, _invite(client))
    page = client.post("/manage-store", data={"key": key})
    assert page.status_code == 200 and "Agents looking you up" in page.text
    saved = client.post("/manage-store", data={
        "key": key, "listing_id": a["id"], "action": "save", "ships_to": "us, ca", "payment_methods": "card, paypal",
        "returns_accepted": "yes", "returns_window_days": "30", "categories": "coffee",
        "returns_policy_url": "https://alpha.example/policies/refund-policy"})
    assert "Saved" in saved.text, saved.text
    rec = client.get("/v1/stores/alpha.example").json()
    st = rec["store_stated"]
    assert st["ships_to"] == ["CA", "US"] and st["payment_methods"] == ["card", "paypal"]
    assert st["returns"] == {"accepted": True, "window_days": 30,
                             "policy_url": "https://alpha.example/policies/refund-policy"}
    assert st["source"] == "store_stated" and "Not verified by ONAA" in st["note"] and st["stated_at"]
    assert rec["shipping"]["ships_to"] == ["US"]  # ONAA's own observation is untouched
    html = client.get("/stores/alpha.example").text
    assert "What the store states (not verified by ONAA)" in html
    bad = client.post("/manage-store", data={"key": key, "action": "save", "ships_to": "USA"})
    assert "Not saved" in bad.text
    assert client.post("/manage-store", data={"key": "onaa_sk_wrong"}).status_code == 401


def test_store_stated_is_for_stores_only(client, op):
    _, headers = op
    r = client.post("/v1/services", headers=headers, json={**SERVICE, "store_stated": {"ships_to": ["US"]}})
    assert r.status_code == 422 and "marketplace" in r.text
    store = {"display_name": "Own Shop", "service_type": "marketplace",
             "endpoint_url": "https://ownshop.example/api/ucp/mcp",
             "store_stated": {"ships_worldwide": True, "payment_methods": ["card"]}}
    r = client.post("/v1/services", headers=headers, json=store)
    assert r.status_code == 201, r.text
    assert r.json()["store_stated"]["ships_worldwide"] is True
    assert r.json()["trust"]["level"] == "operator_registered"


def test_lookups_are_counted_for_registered_listings_only(client):
    a = _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    b = _store(client, "beta.example", "checkout_ready", ships_to=["US"])
    key, _ = _verify(client, _invite(client))
    headers = {"Authorization": f"Bearer {key}"}
    client.get("/v1/stores/alpha.example")
    client.get("/v1/stores/beta.example")
    client.get("/v1/stores/check", params={"url": "https://alpha.example/products/x"})
    client.get("/v1/buying/stores", params={"country": "US"})
    client.get("/v1/stores")
    # ONAA's own traffic is not counted
    client.get("/v1/stores/alpha.example", headers={"X-ONAA-Traffic": "internal"})
    client.app.state.usage.flush()
    got = client.get(f"/v1/services/{a['id']}/lookups", headers=headers).json()
    week = got["this_week"]
    assert (week["detail"], week["check"], week["search"]) == (1, 1, 2) and week["total"] == 4
    assert "nothing about who asked" in got["note"]
    assert client.get(f"/v1/services/{b['id']}/lookups", headers=headers).status_code == 403
    assert client.get(f"/v1/services/{a['id']}/lookups").status_code == 401
    # not published in the public stats
    assert a["id"] not in client.get("/v1/stats/usage").text


def test_ranking_boost_is_on_and_can_be_turned_off(client, monkeypatch):
    monkeypatch.setenv("ONAA_RANK_REGISTERED_FIRST", "0")
    # same answer for both stores; "zeta" sorts after "alpha" by name
    _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    z = _store(client, "zeta.example", "checkout_ready", ships_to=["US"])
    _verify(client, _invite(client, "zeta.example", "hi@zeta.example.com"))
    names = lambda r: [i["store"]["name"] for i in r.json()["items"]]  # noqa: E731
    before = client.get("/v1/buying/stores", params={"country": "US"})
    assert names(before) == ["alpha.example", "zeta.example"]
    assert [i["name"] for i in client.get("/v1/stores").json()["items"]] == ["alpha.example", "zeta.example"]
    monkeypatch.setenv("ONAA_RANK_REGISTERED_FIRST", "1")
    after = client.get("/v1/buying/stores", params={"country": "US"})
    assert names(after) == ["zeta.example", "alpha.example"]
    assert [i["name"] for i in client.get("/v1/stores").json()["items"]] == ["zeta.example", "alpha.example"]
    svc = client.get("/v1/services", params={"type": "marketplace"}).json()["items"]
    assert svc[0]["id"] == z["id"]
    # a better answer still wins over registration
    b = _store(client, "beta.example", "checkout_ready", ships_to=["US", "KR"],
               autonomous_payment="after_one_time_link")
    first = client.get("/v1/buying/stores", params={"country": "US"}).json()["items"][0]
    assert first["store"]["id"] == b["id"]


def test_registered_stores_are_rechecked_daily(client):
    import datetime as dt

    a = _store(client, "alpha.example", "checkout_ready")
    b = _store(client, "beta.example", "checkout_ready")
    _verify(client, _invite(client))
    old = (dt.datetime.now(dt.UTC) - dt.timedelta(days=2)).isoformat()
    with Session(client.app.state.engine) as s:
        for lid in (a["id"], b["id"]):
            row = s.get(Listing, lid)
            row.agent_checkout = {**row.agent_checkout, "checked_at": old}
            row.updated_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
        s.commit()
        assert due_listing_ids(s, 10, recheck_days=7) == [a["id"]]
        assert due_listing_ids(s, 10, recheck_days=7, registered_recheck_days=0) == []


def test_self_registered_store_keeps_its_check_history_and_gets_a_seat(client, fetcher):
    d = _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    svc = {"display_name": "Alpha", "service_type": "marketplace",
           "endpoint_url": "https://alpha.myshopify.example/api/ucp/mcp"}
    r = start(client, service=svc)
    assert r.status_code == 201, r.text
    done = publish_and_complete(client, fetcher, r.json())
    assert done.status_code == 201, done.text
    body = done.json()
    rec = body["listing"]
    assert rec["agent_checkout"]["status"] == "checkout_ready"
    assert rec["documentation_url"] == "https://alpha.example/.well-known/ucp"
    assert rec["provenance"] is None and rec["trust"]["level"] == "operator_registered"
    assert any("Founding Cohort" in s for s in body["next_steps"])
    assert client.get(f"/v1/services/{d['id']}").status_code in (404, 410)
    assert client.get("/v1/stores/alpha.example").json()["id"] == rec["id"]


def test_cohort_seats_run_out(client, settings):
    import dataclasses

    client.app.state.settings = dataclasses.replace(settings, founding_cohort_size=1)
    _store(client, "alpha.example", "checkout_ready")
    _store(client, "beta.example", "checkout_ready")
    _, first = _verify(client, _invite(client))
    _, second = _verify(client, _invite(client, "beta.example", "hi@beta.example.com"))
    assert "Founding Cohort" in first.text and "Founding Cohort" not in second.text


def test_trust_level_order():
    lv = registrant.trust_level
    assert lv(operator_id=None, lifecycle_status="discovered", endpoint_verified=False) == "discovered_unverified"
    assert lv(operator_id="op", lifecycle_status="claim_pending", endpoint_verified=False) == "discovered_unverified"
    assert lv(operator_id="op", lifecycle_status="registered", endpoint_verified=False) == "operator_registered"
    assert lv(operator_id="op", lifecycle_status="registered", endpoint_verified=False,
              owner_confirmed_via="published_email") == "operator_confirmed_by_email"
    assert lv(operator_id="op", lifecycle_status="endpoint_verified", endpoint_verified=True,
              owner_confirmed_via="published_email") == "operator_endpoint_verified"
    assert lv(operator_id="op", lifecycle_status="certified", endpoint_verified=True, certified=True) == "certified"
