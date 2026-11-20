"""Second batch of fixes from the 2026-11-19 review: the personal-details purge reaches every closed offer, a
price limit that cannot be checked means ask, search words are literal, and matching uses whole Latin words."""

from __future__ import annotations

import datetime as dt
import functools
import types

from test_pilot_deals import OK, act, deal, member, pc  # noqa: F401 - pc is a fixture

from onaa_registry import deal_rules
from onaa_registry.models import PilotOffer
from onaa_registry.routes.pilot import _like_escape, _overlap


def test_purge_reaches_offers_past_the_first_page(pc, monkeypatch):  # noqa: F811
    monkeypatch.setattr(deal_rules, "_in_pages", functools.partial(deal_rules._in_pages, size=1))
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    ids = []
    for i in range(3):
        _, d = deal(pc, seller, buyer, title=f"Road bike {i}")
        if i == 2:
            act(pc, buyer, d["id"], action="message", text="call me at +1 512 555 0199", **OK)
        assert act(pc, seller, d["id"], action="cancel", **OK).status_code == 200
        ids.append(d["id"])
    with pc.app.state.sessionmaker() as s:
        for oid in ids:
            s.get(PilotOffer, oid).updated_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=31)
        s.commit()
        assert deal_rules.purge_personal(s, dt.datetime.now(dt.UTC)) == 1
        s.commit()
        assert not any("0199" in (e.get("message") or "") for e in s.get(PilotOffer, ids[2]).history)


def test_a_price_limit_without_an_amount_means_ask():
    m = types.SimpleNamespace(kind="agent", deal_rules={"confirm_deal": "auto",  # account limits: server agents only
                                                        "confirm_deal_max": {"amount": 100, "currency": "USD"}})
    assert deal_rules.allows(m, "confirm_deal", amount=90, currency="usd") is True
    assert deal_rules.allows(m, "confirm_deal", amount=None) is False
    assert deal_rules.allows(m, "confirm_deal", amount=101, currency="USD") is False
    odd = types.SimpleNamespace(kind="agent", deal_rules={"confirm_deal": "auto", "confirm_deal_max": {"amount": True,
                                                                                         "currency": "USD"}})
    assert "confirm_deal_max" not in deal_rules.rules_of(odd)


def test_search_words_are_literal(pc):  # noqa: F811
    seller, _ = member(pc, "s")
    buyer, _ = member(pc, "b")
    deal(pc, seller, buyer, title="Road bike 54cm")
    for q in ("%", "_", "b_ke"):
        assert pc.get("/v1/market/items", headers=buyer, params={"q": q}).json()["items"] == [], q
    assert _like_escape("50%_off\\") == "50\\%\\_off\\\\"


def test_matching_uses_whole_latin_words():
    assert _overlap("car", "wool scarf") == []
    assert _overlap("car", "two cars for sale") == ["car"]
    assert _overlap("box", "boxes of books") == ["box"]
    assert _overlap("자전거", "중고 자전거를 팝니다") == ["자전거"]
