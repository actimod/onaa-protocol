#!/usr/bin/env python3
"""Read-only discovery smoke test against a live ONAA registry (default https://api.onaa.net).

    python apps/mcp-registry/scripts/smoke_readonly.py [--base https://api.onaa.net] [--json]

Checks, in order: REST entry points (health, /llms.txt, well-known metadata), REST search with the trust filters,
an MCP Streamable HTTP handshake (initialize + tools/list), the tool annotations, and a few read-only tool calls
(search_agents, search_services, get_listing). It never calls a tool that is not on READ_ONLY_CALLS, so it cannot
register, change, probe or buy anything. Requests carry `X-ONAA-Traffic: internal` so usage stats count them as
ONAA's own traffic. Exit code 0 = all checks passed, 1 = at least one failed (each is printed).

This proves discovery only. The buyer -> seller trade then runs directly between the agents, never through the
registry; examples/direct-trade-demo shows that part on localhost.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

import httpx

READ_ONLY_CALLS = {"search_agents", "search_services", "get_listing"}
WRITE_TOOLS = {"self_register_start", "self_register_complete", "update_my_listing", "ask_steward", "describe_need"}
HEADERS = {"X-ONAA-Traffic": "internal", "User-Agent": "onaa-smoke-readonly/0.1"}
TIMEOUT = 30.0


README = Path(__file__).resolve().parents[1] / "README.md"


def documented_hosted_tools() -> set[str] | None:
    """Tools the README's 'Tools by profile' table marks as hosted (column 3), or None without a README."""
    if not README.is_file():
        return None
    section = README.read_text(encoding="utf-8").split("## Tools by profile", 1)[-1].split("\n## ", 1)[0]
    out = set()
    for line in section.splitlines():
        m = re.match(r"^\|\s*`([a-z_]+)`\s*\|[^|]*\|[^|]*\|\s*yes\s*\|", line)
        if m:
            out.add(m.group(1))
    return out


class Report:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append({"check": name, "ok": bool(ok), "detail": detail[:300]})
        return ok

    @property
    def ok(self) -> bool:
        return all(r["ok"] for r in self.rows)


def rest_checks(base: str, rep: Report) -> None:
    with httpx.Client(base_url=base, headers=HEADERS, timeout=TIMEOUT) as http:
        r = http.get("/v1/health")
        rep.check("rest.health", r.status_code == 200 and r.json().get("status") == "ok", f"HTTP {r.status_code}")
        r = http.get("/llms.txt")
        rep.check("rest.llms_txt", r.status_code == 200 and "/mcp" in r.text, f"HTTP {r.status_code}")
        r = http.get("/.well-known/onaa-registry.json")
        rep.check("rest.well_known", r.status_code == 200 and isinstance(r.json(), dict), f"HTTP {r.status_code}")

        all_agents = http.get("/v1/agents", params={"limit": 50}).json()
        claimed = http.get("/v1/agents", params={"limit": 50, "claimed_only": "true"}).json()
        statuses = {i["trust"]["registration_status"] for i in claimed["items"]}
        rep.check("rest.claimed_only_excludes_discovered", "discovered" not in statuses,
                  f"claimed {claimed['total']} of {all_agents['total']} agents; statuses {sorted(statuses)}")
        for item in all_agents["items"]:
            t = item["trust"]
            if t["registration_status"] == "discovered" and (t["claimed"] or t["endpoint_control_verified"]):
                rep.check("rest.discovered_is_not_claimed", False, item["id"])
                break
        else:
            rep.check("rest.discovered_is_not_claimed", True, "no discovered listing claims to be claimed/verified")
        verified = http.get("/v1/agents", params={"limit": 50, "verified_only": "true"}).json()
        rep.check("rest.verified_only", all(i["trust"]["endpoint_control_verified"] for i in verified["items"]),
                  f"{verified['total']} endpoint-verified agents")


async def mcp_checks(base: str, rep: Report) -> None:
    import httpx2  # the HTTP client the MCP SDK's transport uses
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx2.AsyncClient(headers=HEADERS, timeout=TIMEOUT) as hc, \
            streamable_http_client(base.rstrip("/") + "/mcp", http_client=hc) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            init = await session.initialize()
            rep.check("mcp.initialize", True, f"{init.server_info.name} {init.server_info.version}, "
                                               f"protocol {init.protocol_version}")
            tools = {t.name: t for t in (await session.list_tools()).tools}
            rep.check("mcp.tools_list", bool(tools), f"{len(tools)} tools: {', '.join(sorted(tools))}")
            documented = documented_hosted_tools()
            if documented is not None:
                rep.check("mcp.tools_match_readme", set(tools) == documented,
                          f"missing from live: {sorted(documented - set(tools))}; "
                          f"undocumented: {sorted(set(tools) - documented)}")
            for name in sorted(WRITE_TOOLS & set(tools)):
                ann = tools[name].annotations
                rep.check(f"mcp.annotation.{name}", bool(ann) and ann.read_only_hint is False, "must not be read-only")
            for name in sorted(READ_ONLY_CALLS):
                ann = tools.get(name) and tools[name].annotations
                rep.check(f"mcp.annotation.{name}", bool(ann) and ann.read_only_hint is True, "must be read-only")

            async def call(name: str, args: dict) -> dict:
                if name not in READ_ONLY_CALLS:  # hard stop: this script never mutates anything
                    raise RuntimeError(f"refusing to call non-allowlisted tool {name}")
                res = await session.call_tool(name, args)
                return json.loads(res.content[0].text)

            agents = await call("search_agents", {"limit": 5, "claimed_only": True})
            items = agents.get("items", [])
            rep.check("mcp.search_agents.claimed_only",
                      "error" not in agents and all(i["trust"]["registration_status"] != "discovered" for i in items),
                      f"{agents.get('total')} claimed agents")
            rep.check("mcp.untrusted_content_wrapped",
                      all("display_name" not in i and "untrusted_operator_content" in i for i in items),
                      "operator text only under untrusted_operator_content")
            services = await call("search_services", {"service_type": "escrow", "limit": 5})
            rep.check("mcp.search_services", "error" not in services, f"{services.get('total')} escrow providers")
            if items:
                one = await call("get_listing", {"listing_id": items[0]["id"]})
                rep.check("mcp.get_listing", one.get("listing", {}).get("id") == items[0]["id"], items[0]["id"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only ONAA discovery smoke test")
    ap.add_argument("--base", default="https://api.onaa.net")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--skip-mcp", action="store_true")
    args = ap.parse_args(argv)
    rep = Report()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        rest_checks(args.base, rep)
    except Exception as exc:  # network errors are results, not crashes
        rep.check("rest.reachable", False, f"{type(exc).__name__}: {exc}")
    if not args.skip_mcp:
        try:
            asyncio.run(mcp_checks(args.base, rep))
        except Exception as exc:
            rep.check("mcp.reachable", False, f"{type(exc).__name__}: {exc}")
    if args.json:
        print(json.dumps({"base": args.base, "started_at": started, "ok": rep.ok, "checks": rep.rows}, indent=2))
    else:
        print(f"ONAA read-only smoke test against {args.base} at {started}")
        for r in rep.rows:
            print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['check']}  {r['detail']}")
        print("OK" if rep.ok else "FAILED")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
