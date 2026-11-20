

def test_discovery_document_and_llms_txt_list_every_hosted_mcp_tool(client):
    from onaa_registry.mcp_inventory import HOSTED_READ_ONLY, HOSTED_TOOLS
    mcp = client.get("/.well-known/onaa-registry.json").json()["onboarding"]["clients"]["remote_mcp"]
    assert mcp["tools"] == list(HOSTED_TOOLS) and mcp["read_only_tools"] == list(HOSTED_READ_ONLY)
    llms = client.get("/llms.txt").text
    assert f"{len(HOSTED_TOOLS)} tools" in llms
    assert all(name in llms for name in HOSTED_TOOLS)


def test_privacy_notice_states_the_running_retention(client):
    page = client.get("/privacy")
    assert page.status_code == 200 and "up to 7 days" in page.text and "Fly.io" in page.text
    assert "up to 7 days" in client.get("/privacy.txt").text
    assert "/privacy" in client.get("/", headers={"Accept": "text/html"}).text
    assert "deleted after 30 days" in page.text and "Continue with Google" in page.text  # member sign-in, messages
    terms = client.get("/terms")
    assert terms.status_code == 200 and "Terms of use" in terms.text and "/v1/terms" in terms.text
