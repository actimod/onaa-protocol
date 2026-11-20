""""How your store looks to an AI shopping agent": information-only store page and the domain lookup."""

from __future__ import annotations

from test_stores import _manifest_site, _store


def test_store_page_shows_what_the_agent_saw_without_asking_anything(client):
    _store(client, "alpha.example", "buyer_step_required", ships_to=["US"], no_shipping_to=["KR"],
           payment_handlers=["shopify.card"], manifest_payment_handlers=["shop_pay", "shopify.card"],
           buyer_info_required=["delivery_address_required"], delivery_test="address")
    page = client.get("/stores/alpha.example").text
    assert "How alpha.example looks to an AI shopping agent" in page
    assert "a person then has to finish a step" in page
    for text in ("Searching the catalog", "Creating a checkout for one item", "Paying: payment not tested",
                 "Offered at ONAA&#x27;s test checkout", "Declared in the store&#x27;s agent manifest",
                 "a delivery option was offered", "the store said it does not deliver there", "delivery address",
                 "What stopped or slowed the agent"):
        assert text in page, text
    # information only: no sign-up, verification or ranking pitch
    for pitch in ("Verify my store", "register", "ranked", "Sign up", "sign up"):
        assert pitch not in page, pitch


def test_lookup_opens_listed_store_and_explains_missing_endpoint(client, fetcher):
    _store(client, "alpha.example", "checkout_ready", ships_to=["US"])
    form = client.get("/stores/lookup")
    assert form.status_code == 200 and 'name="q"' in form.text
    r = client.get("/stores/lookup", params={"q": "https://www.alpha.example/products/mug"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/stores/alpha.example"
    _manifest_site(fetcher, "newshop.example.com")
    r = client.get("/stores/lookup", params={"q": "newshop.example.com"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/stores/newshop.example.com"
    assert "has not run its test checkout here yet" in client.get("/stores/newshop.example.com").text
    fetcher.routes["https://plain.example.com/robots.txt"] = (404, "")
    miss = client.get("/stores/lookup", params={"q": "plain.example.com"})
    assert miss.status_code == 200 and "does not publish an agent shopping endpoint" in miss.text
    fetcher.routes["https://htmlhome.example.com/robots.txt"] = (404, "")
    fetcher.routes["https://htmlhome.example.com/.well-known/ucp"] = (200, "<!doctype html><title>Shop</title>")
    html_home = client.get("/stores/lookup", params={"q": "htmlhome.example.com"}).text
    assert "does not publish an agent shopping endpoint" in html_home and "publishes an agent manifest" not in html_home
    fetcher.routes["https://otherucp.example.com/robots.txt"] = (404, "")
    fetcher.routes["https://otherucp.example.com/.well-known/ucp"] = (200, '{"ucp": {"services": {}}}')
    assert "publishes an agent manifest" in client.get("/stores/lookup", params={"q": "otherucp.example.com"}).text
    bad = client.get("/stores/lookup", params={"q": "not a domain"})
    assert bad.status_code == 422 and "<script>" not in client.get(
        "/stores/lookup", params={"q": "<script>x.com"}).text
