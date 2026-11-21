"""Tool inventory contract: the README table must match what each server profile really exposes.

Three profiles ship from the same code: the local default (read-only), local with --enable-self-registration,
and the hosted server at https://api.onaa.net/mcp (hosted.py). A tool added, removed or re-annotated without
updating README.md fails here, so published docs cannot drift from tools/list again.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from mcp import Client
from onaa import OnaaClient

from onaa_mcp_registry.server import build_server

README = Path(__file__).resolve().parents[1] / "README.md"
PROFILES = ("local", "local_self_registration", "hosted")
# These tools change registry state or reach out to third
# parties; they must never claim to be read-only.
MUST_BE_WRITE = {"self_register_start", "self_register_complete", "update_my_listing", "ask_steward"}


def _client() -> OnaaClient:
    return OnaaClient("https://registry.example.com",
                      http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))))


def _server(profile: str, tmp_path: Path):
    reg = _client()
    if profile == "local":
        return build_server(reg)
    if profile == "local_self_registration":
        return build_server(reg, key_file=tmp_path / "key")
    return build_server(reg, remote_client=lambda ctx: _client(), steward_ask=lambda q, c, ctx: {})


def _readme_table() -> dict[str, dict]:
    """Rows of the "Tools by profile" table: | `tool` | local | local+self-reg | hosted | read-only | purpose |"""
    text = README.read_text(encoding="utf-8")
    section = text.split("## Tools by profile", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        m = re.match(r"^\|\s*`([a-z_]+)`\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|", line)
        if m:
            name, *cells = m.groups()
            flags = [c.strip().lower() == "yes" for c in cells]
            profiles = {p for p, on in zip(PROFILES, flags[:3], strict=True) if on}
            rows[name] = {"profiles": profiles, "read_only": flags[3]}
    return rows


async def _tools(profile: str, tmp_path: Path) -> dict[str, bool]:
    async with Client(_server(profile, tmp_path)) as client:
        listed = (await client.list_tools()).tools
    return {t.name: bool(t.annotations and t.annotations.read_only_hint) for t in listed}


@pytest.mark.anyio
@pytest.mark.parametrize("profile", PROFILES)
async def test_readme_lists_exactly_the_tools_of_each_profile(profile, tmp_path):
    table = _readme_table()
    assert table, "README.md has no 'Tools by profile' table"
    actual = await _tools(profile, tmp_path)
    documented = {name for name, row in table.items() if profile in row["profiles"]}
    assert set(actual) == documented, f"{profile}: README drift, update the 'Tools by profile' table"
    for name, read_only in actual.items():
        assert table[name]["read_only"] == read_only, f"{name}: README readOnlyHint column is wrong"
        if name in MUST_BE_WRITE:
            assert read_only is False, f"{name} changes state or probes third parties; it must not be readOnlyHint"


def test_readme_profile_counts_match_table():
    table = _readme_table()
    text = README.read_text(encoding="utf-8")
    for profile, label in zip(PROFILES, ("Local default", "Local + self-registration", "Hosted"), strict=True):
        n = sum(profile in row["profiles"] for row in table.values())
        assert f"{label}: {n} tools" in text, f"README must state '{label}: {n} tools'"


def test_existing_tool_names_stay_compatible():
    """Tools agents already call keep their names; new tools are additions, never renames."""
    table = _readme_table()
    for name in ("search_agents", "search_services", "get_listing", "get_vocabulary", "verify_attestations",
                 "get_terms", "self_register_start",
                 "self_register_complete", "ask_steward"):
        assert "hosted" in table[name]["profiles"], name
    assert "update_my_listing" in table


def test_smoke_script_only_calls_read_only_hosted_tools():
    import importlib.util

    spec = importlib.util.spec_from_file_location("smoke", Path(__file__).resolve().parents[1] / "scripts" /
                                                  "smoke_readonly.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)  # type: ignore[union-attr]
    table = _readme_table()
    assert smoke.documented_hosted_tools() == {n for n, r in table.items() if "hosted" in r["profiles"]}
    assert all(table[n]["read_only"] for n in smoke.READ_ONLY_CALLS)
    assert smoke.WRITE_TOOLS == MUST_BE_WRITE


@pytest.mark.anyio
async def test_directory_discovery_document_lists_the_hosted_tools(tmp_path):
    """/.well-known/onaa-registry.json and llms.txt take their tool list from onaa_registry.mcp_inventory."""
    inventory = pytest.importorskip("onaa_registry.mcp_inventory")
    actual = await _tools("hosted", tmp_path)
    assert set(inventory.HOSTED_TOOLS) == set(actual), "update onaa_registry/mcp_inventory.py"
    assert {n for n, ro in actual.items() if ro} == set(inventory.HOSTED_READ_ONLY)


@pytest.mark.anyio
async def test_every_tool_has_a_title(tmp_path):
    """The Claude and ChatGPT directory reviews flag tools without a human-readable title (2026-11-20)."""
    from onaa_mcp_registry.pilot import build_pilot_server

    servers = [_server(p, tmp_path) for p in PROFILES] + [build_pilot_server(lambda *a, **k: {})]
    for server in servers:
        async with Client(server) as client:
            for t in (await client.list_tools()).tools:
                assert t.title and t.title.strip(), f"{t.name}: add title= to its @mcp.tool decorator"
