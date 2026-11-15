"""Human home page: stores agents can buy from, over the public search, escaped, with trust tiers kept distinct."""

from __future__ import annotations

from conftest import AGENT, SERVICE, admin_headers

HTML = {"accept": "text/html,application/xhtml+xml,*/*;q=0.8"}


STORE = {"display_name": "shoes.example.com", "service_type": "marketplace",
         "documentation_url": "https://shoes.example.com/.well-known/ucp",
         "source_url": "https://shoes.example.com/.well-known/ucp", "description": "Store with a UCP manifest",
         "regions": ["US"]}


def _store(client, status="buyer_step_required"):
    r = client.post("/v1/admin/discovered/services", headers=admin_headers(), json=STORE)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    r = client.post(f"/v1/admin/listings/{sid}/agent-checkout", headers=admin_headers(),
                    json={"status": status, "steps": ["tools_list", "search", "checkout", "cancel"]})
    assert r.status_code == 200, r.text
    return sid


def test_home_leads_with_stores_agents_can_buy_from(client, op):
    _, headers = op
    assert client.post("/v1/agents", headers=headers, json=AGENT).status_code == 201
    assert client.post("/v1/services", headers=headers, json=SERVICE).status_code == 201
    _store(client)
    page = client.get("/", headers=HTML).text
    assert "Stores your AI agent can actually buy from" in page and "tested checkout requirements" in page
    assert "Classifieds" not in page and "classifieds" not in page
    assert "shoes.example.com" in page and "Checkout reached, buyer step needed" in page
    assert "How to buy here" in page and "Store manifest" in page
    assert "Payments and services" in page and "Seller agents" in page
    services = client.get("/", params={"section": "services"}, headers=HTML).text
    assert "Example Sandbox Escrow" in services
    page = client.get("/", params={"section": "for-sale"}, headers=HTML).text
    assert "Example Parts Seller" in page
    assert "A2A" in page and "never touches the money" in page and "llms.txt" in page
    page = client.get("/", headers=HTML).text
    assert "Development build" not in page and "not a production service" not in page
    assert "Unclaimed" in page and "merchant of record" in page


def test_store_sections_filter_by_checkout_result(client):
    _store(client, "buyer_step_required")
    step = client.get("/", params={"section": "stores-buyer-step"}, headers=HTML).text
    ready = client.get("/", params={"section": "stores-ready"}, headers=HTML).text
    assert "shoes.example.com" in step.split('id="post"')[0].split('class="list-h">Checkout reached')[-1]
    assert "shoes.example.com" not in ready.split('class="list-h">Checkout ready</h2>')[1]


def test_home_sections_and_search_filter(client, op):
    _, headers = op
    client.post("/v1/agents", headers=headers, json=AGENT)
    client.post("/v1/services", headers=headers, json=SERVICE)
    sale = client.get("/", params={"section": "for-sale"}, headers=HTML).text
    assert "Example Parts Seller" in sale and "Example Sandbox Escrow" not in sale.split("<h2 class=\"list-h\">")[-1]
    escrow = client.get("/", params={"section": "escrow"}, headers=HTML).text
    listing_part = escrow.split('<h2 class="list-h">Escrow</h2>')[1].split('id="post"')[0]
    assert "Example Sandbox Escrow" in listing_part and "Example Parts Seller" not in listing_part
    found = client.get("/", params={"q": "refurbished", "section": "for-sale"}, headers=HTML).text
    assert 'Results for &quot;refurbished&quot; in Seller agents' in found and "Example Parts Seller" in found
    # Unknown sections are ignored rather than reflected.
    assert "bogus" not in client.get("/", params={"section": "bogus"}, headers=HTML).text


def test_home_escapes_untrusted_listing_text_and_query(client, op):
    _, headers = op
    evil = dict(AGENT, display_name="<script>alert(1)</script> Seller", description='"><img src=x onerror=1>')
    assert client.post("/v1/agents", headers=headers, json=evil).status_code == 201
    page = client.get("/", params={"q": '"><script>x</script>'}, headers=HTML).text
    assert "<script>" not in page and "<img src=x" not in page
    page = client.get("/", params={"section": "for-sale"}, headers=HTML).text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt; Seller" in page


def test_discovered_listing_is_marked_unclaimed(client):
    r = client.post("/v1/admin/discovered", headers=admin_headers(),
                    json={"display_name": "Found Escrow Co", "roles": ["seller_agent"],
                          "agent_card_url": "https://found.example.org/.well-known/agent-card.json",
                          "source_url": "https://directory.example.org/2"})
    assert r.status_code == 201, r.text
    page = client.get("/", params={"section": "for-sale"}, headers=HTML).text
    assert "Found Escrow Co" in page and ">Unclaimed<" in page


def test_root_json_keeps_machine_contract(client):
    data = client.get("/", headers={"accept": "application/json"}).json()
    assert data["name"] == "ONAA (Open Network for AI Agents)" and "buy from" in data["description"]
    assert data["links"]["mcp"].endswith("/mcp")
    wk = client.get("/.well-known/onaa-registry.json").json()
    assert wk["search"]["agents"].endswith("/v1/agents") and "status" not in wk
