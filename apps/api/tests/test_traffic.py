"""Anonymous agent-traffic counters: classes, path groups, no identifying data, public stats."""

from __future__ import annotations

import datetime as dt

from onaa_registry.models import UsageCounter
from onaa_registry.traffic import agent_class, mcp_origin, origin_of, path_group, split_origin


def test_agent_classes():
    assert agent_class("Mozilla/5.0 AppleWebKit/537.36; compatible; ChatGPT-User/1.0; +https://openai.com/bot") \
        == "chatgpt_user"
    assert agent_class("Mozilla/5.0 (compatible; Claude-User/1.0; +https://www.anthropic.com)") == "claude_user"
    assert agent_class("Mozilla/5.0 (compatible; PerplexityBot/1.0)") == "perplexity_crawler"
    assert agent_class("python-httpx/0.28.1") == "python_script"
    assert agent_class("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15") == "browser"
    assert agent_class(None) == "none"
    assert agent_class("weird-thing/1") == "other"


def test_path_groups_drop_ids():
    assert path_group("/v1/services/svc_123") == "/v1/services/{id}"
    assert path_group("/stores/example.com") == "/stores/{store}"
    assert path_group("/llms.txt") == "/llms.txt"
    assert path_group("/v1/stores/") == "/v1/stores"
    assert path_group("/wp-login.php") == "other"


def test_requests_counted_without_ip_or_user_agent(client):
    ua = "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)"
    client.get("/llms.txt", headers={"User-Agent": ua})
    client.get("/llms.txt", headers={"User-Agent": ua})
    client.get("/v1/services/svc_doesnotexist", headers={"User-Agent": "curl/8.5"})
    client.app.state.usage.hit_store_asked("Shop.Example.com")
    client.app.state.usage.hit_store_asked("not a domain; drop table")
    stats = client.get("/v1/stats/usage").json()
    ext = stats["external"]
    assert ext["by_path"]["/llms.txt"] == 2
    assert ext["ai_agents_by_path"]["/llms.txt"] == 2
    assert ext["by_agent_class"]["chatgpt_user"] == 2
    assert ext["by_path"]["/v1/services/{id}"] == 1
    assert ext["unlisted_stores_asked"] == {"shop.example.com": 1}
    day = next(iter(stats["by_day"].values()))["external"]
    assert day["requests"] >= 3 and day["ai_agent_requests"] == 2
    with client.app.state.sessionmaker() as s:
        keys = [r.key for r in s.query(UsageCounter).all()]
    assert not any("testclient" in k or "Mozilla" in k or "svc_" in k for k in keys)


def test_flush_adds_to_existing_rows(client):
    usage = client.app.state.usage
    usage.hit("mcp_tool", "find_stores")
    usage.flush()
    usage.hit("mcp_tool", "find_stores", 2)
    usage.flush()
    assert client.get("/v1/stats/usage").json()["external"]["mcp_tools"]["find_stores"] == 3


def test_origin_rules():
    assert origin_of("/llms.txt", "chatgpt_user") == "external"
    assert origin_of("/llms.txt", "python_script", "internal") == "ours"
    assert origin_of("/v1/admin", "python_script") == "ours"
    assert origin_of("/v1/health", agent_class("Consul Health Check")) == "ours"
    assert origin_of("/", agent_class("ONAA-Checkout-Checker/0.1 (+https://api.onaa.net/opt-out; run x)")) == "ours"
    assert origin_of("/mcp", agent_class("glama-mcp-checker/1.0")) == "probes"
    assert origin_of("/", agent_class("Mozilla/5.0+(compatible; UptimeRobot/2.0)")) == "probes"
    # Third parties using our published SDK are external.
    assert origin_of("/v1/agents", agent_class("onaa-sdk-python/0.1.0")) == "external"
    probe_call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "__mcpcheckup_probe_nonexistent_tool__"}}
    assert mcp_origin(probe_call, "external") == "probes"
    assert mcp_origin([{"method": "initialize", "params": {"clientInfo": {"name": "VerifyMCP"}}}],
                      "external") == "probes"
    assert mcp_origin({"method": "tools/call", "params": {"name": "find_stores"}}, "external") == "external"
    assert mcp_origin(probe_call, "ours") == "ours"


def test_legacy_rows_are_classified_best_effort():
    assert split_origin("/v1/admin|python_script", "http") == ("/v1/admin|python_script", "ours", True)
    assert split_origin("/mcp|onaa_own", "http")[1] == "ours"
    assert split_origin("/v1/other|other", "http")[1] == "ours"  # Fly health checks before /v1/health had a group
    assert split_origin("/mcp|mcp_client", "http") == ("/mcp|mcp_client", "external", True)
    assert split_origin("__verifymcp_auth_probe_1__", "mcp_tool")[1] == "probes"
    assert split_origin("/mcp|mcp_client|probes", "http") == ("/mcp|mcp_client", "probes", False)
    assert split_origin("listed|ours", "store_check") == ("listed", "ours", False)


def test_stats_split_into_three_groups(client):
    client.get("/llms.txt", headers={"User-Agent": "Claude-User/1.0"})
    client.get("/llms.txt", headers={"User-Agent": "python-httpx/0.28", "X-ONAA-Traffic": "internal"})
    client.get("/v1/admin/listings", headers={"User-Agent": "python-httpx/0.28"})
    client.get("/", headers={"User-Agent": "Mozilla/5.0 (compatible; UptimeRobot/2.0)"})
    client.app.state.usage.hit("mcp_tool", "__mcpcheckup_probe_nonexistent_tool__", origin="probes")
    today = dt.datetime.now(dt.UTC).date().isoformat()
    with client.app.state.sessionmaker() as s:  # a counter written before origins were recorded
        s.add(UsageCounter(day=today, kind="http", key="/v1/admin|python_script", count=36000))
        s.commit()
    stats = client.get("/v1/stats/usage").json()
    assert stats["summary"]["external"]["requests"] >= 1
    assert stats["external"]["by_agent_class"].get("python_script", 0) == 0
    assert stats["external"]["by_path"].get("/v1/admin", 0) == 0
    assert stats["ours"]["by_path"]["/v1/admin"] == 36001
    assert stats["ours"]["by_path"]["/llms.txt"] == 1
    assert stats["ours"]["counted_before_origin_tagging"] == 36000
    assert stats["probes"]["by_agent_class"]["uptime_monitor"] == 1
    assert stats["probes"]["mcp_tools"] == {"__mcpcheckup_probe_nonexistent_tool__": 1}
    assert stats["by_day"][today]["probes"]["mcp_tool_calls"] == 1
    assert stats["origin_tagging_since"] == today


def test_search_conditions_counted_from_fixed_vocabulary(client):
    ua = {"User-Agent": "Mozilla/5.0 (compatible; ChatGPT-User/1.0)"}
    client.get("/v1/buying/stores", params={"country": "kr", "pay_alone": "true", "payment": "USDC,shop pay",
                                            "agent": "My secret GPT agent", "q": "private words"}, headers=ua)
    client.get("/v1/buying/stores", params={"country": "KR", "offset": 20}, headers=ua)  # a later page: not counted
    client.get("/v1/stores", params={"ships_to": "de,xx1", "protocol": "ucp", "payment_handler": "weird-pay",
                                     "currency": "eur", "pays_alone": "false"}, headers=ua)
    client.get("/v1/stores/check", params={"url": "shop.example.com", "country": "UK", "payment": "paypal"},
               headers=ua)
    client.get("/v1/buying/stores", params={"country": "JP"}, headers={"X-ONAA-Traffic": "internal"})  # ours
    stats = client.get("/v1/stats/usage").json()
    sc = stats["external"]["search_conditions"]
    fs = sc["find_stores"]
    assert fs["_totals"]["searches"] == 1
    assert fs["country"] == {"KR": 1}
    assert fs["pays_alone"] == {"true": 1}
    assert fs["payment"] == {"shop_pay": 1, "stablecoin": 1}
    assert fs["agent"] == {"chatgpt": 1}
    assert fs["q"] == {"given": 1}
    assert sc["list"]["country"] == {"DE": 1, "invalid": 1}
    assert sc["list"]["payment"] == {"other": 1}
    assert sc["list"]["currency"] == {"EUR": 1}
    assert sc["list"]["pays_alone"] == {"false": 1}
    assert sc["check"]["country"] == {"GB": 1}
    assert sc["check"]["payment"] == {"paypal": 1}
    combos = stats["external"]["search_combinations"]["find_stores"]
    assert combos == {"agent=chatgpt&country=KR&include=possible&payment=shop_pay+stablecoin&pays_alone=true"
                      "&q=given": 1}
    assert stats["ours"]["search_conditions"] == {} and stats["ours"]["search_combinations"] == {}
    with client.app.state.sessionmaker() as s:
        keys = " ".join(r.key for r in s.query(UsageCounter).all())
    assert "secret" not in keys and "private" not in keys and "weird" not in keys and "xx1" not in keys.lower()


def test_search_with_no_results_is_counted(client):
    client.get("/v1/stores", params={"ships_to": "BR"})
    sc = client.get("/v1/stats/usage").json()["external"]["search_conditions"]
    assert sc["list"]["_totals"] == {"no_results": 1, "searches": 1}
    assert client.get("/v1/stats/usage").json()["external"]["search_combinations"]["list"] == {"country=BR": 1}


def test_hourly_counts_and_30_day_pruning(client):
    from onaa_registry import traffic
    from onaa_registry.models import UsageCounterHourly

    ua = "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)"
    client.get("/llms.txt", headers={"User-Agent": ua})
    usage = client.app.state.usage
    usage.hit("mcp_tool", "find_stores")
    old = (dt.datetime.now(dt.UTC) - dt.timedelta(days=31)).strftime("%Y-%m-%dT%H")
    with client.app.state.sessionmaker() as s:
        s.add(UsageCounterHourly(hour=old, kind="mcp_tool", key="find_stores|external", count=5))
        s.add(UsageCounter(day=old[:10], kind="mcp_tool", key="find_stores|external", count=5))
        s.commit()
    usage._pruned_at = None
    got = client.get("/v1/stats/usage/hourly", params={"hours": 720}).json()
    assert got["hours"] == 720 and got["keep_days"] == 30
    hour = traffic._this_hour()
    ext = got["by_hour"][hour]["external"]
    assert ext["by_agent_class"]["chatgpt_user"] == 1 and ext["mcp_tools"] == {"find_stores": 1}
    assert old not in got["by_hour"]
    with client.app.state.sessionmaker() as s:
        assert s.query(UsageCounterHourly).filter(UsageCounterHourly.hour == old).count() == 0  # pruned
        assert s.query(UsageCounter).filter(UsageCounter.day == old[:10]).count() == 1  # daily rows stay
        keys = [r.key for r in s.query(UsageCounterHourly).all()]
    assert not any("Mozilla" in k or "testclient" in k for k in keys)


def test_weekly_third_party_report_and_client_names(client):
    from onaa_registry.traffic import mcp_client_name

    assert mcp_client_name("OpenAI MCP") == "openai-mcp"
    assert mcp_client_name("<script>alert(1)</script>") == "script-alert-1-script"
    assert mcp_client_name(None) == "(none)" and len(mcp_client_name("x" * 99)) == 40
    usage = client.app.state.usage
    usage.hit_http("/v1/stores/shop.example", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)")
    usage.hit_http("/stores/shop.example", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)")
    usage.hit_http("/mcp", "mcpcheckup/1.0")  # a directory checker: probes, not third-party use
    usage.hit_http("/stores.json", "onaa-test/1")  # ours: excluded
    usage.hit("mcp_method", "initialize", origin="external")
    usage.hit("mcp_client", "openai-mcp", origin="external")
    usage.hit("mcp_tool", "find_stores", origin="external")
    got = client.get("/v1/stats/usage/weekly").json()
    w = got["series"][-1]
    assert w["crawler_requests"] == {"openai_crawler": 1}
    assert w["user_triggered_agent_requests"] == {"chatgpt_user": 1}
    assert w["store_data_fetches"]["total"] == 2 and "/stores.json" not in w["store_data_fetches"]["by_path"]
    assert w["mcp_connections"] == 1 and w["mcp_clients"] == {"openai-mcp": 1}
    assert w["mcp_tool_calls"] == {"find_stores": 1} and w["probe_requests"] == 1
    assert w["cumulative"]["crawler_requests"] == 1 and w["cumulative"]["mcp_tool_calls"] == 1
