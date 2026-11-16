"""Claims that external reviews flagged must not come back anywhere in code, docs or public files.

ONAA's checker stops before payment, so nothing may say an agent "can buy" somewhere as an observed fact, and the
hosted MCP tool count must match the inventory. Add a pattern here whenever a review finds a wording problem, so
the fix covers every copy and stays fixed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from onaa_registry.mcp_inventory import HOSTED_TOOLS

ROOT = Path(__file__).resolve().parents[3]
SCAN = ("apps/api/onaa_registry", "apps/mcp-registry", "packages", "public", "docs", "README.md", "specs/openapi.json")
SUFFIXES = {".py", ".md", ".txt", ".json", ".html", ".toml", ".yaml", ".yml"}
# The banned patterns live in specs/onaa-facts.json, the single source of truth for public claims.
BANNED = re.compile("|".join(json.loads((ROOT / "specs" / "onaa-facts.json").read_text(encoding="utf-8"))
                             ["checkout_wording"]["banned_regex"]), re.I)


def _files():
    for entry in SCAN:
        p = ROOT / entry
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from (f for f in p.rglob("*") if f.suffix in SUFFIXES and "__pycache__" not in f.parts
                        and "tests" not in f.parts
                        # These quote banned wording on purpose: the facts page defines the ban, and the
                        # history file records the wording each change replaced.
                        and f.name not in {"CANONICAL_FACTS.md"})


def test_no_payment_success_wording():
    hits = [f"{f.relative_to(ROOT)}:{n}: {line.strip()[:100]}" for f in _files()
            for n, line in enumerate(f.read_text(errors="ignore").splitlines(), 1) if BANNED.search(line)]
    assert not hits, "checkout is observed, payment never tested; reword:\n" + "\n".join(hits)


def test_hosted_tool_count_is_the_same_everywhere():
    n = len(HOSTED_TOOLS)
    for f in _files():
        for m in re.finditer(r"[Hh]osted(?:[^.\n]{0,40}?)\b(\d{1,2}) tools|(\d{1,2}) hosted tools", f.read_text(
                errors="ignore")):
            count = int(m.group(1) or m.group(2))
            assert count == n, f"{f.relative_to(ROOT)} says {count} hosted tools, inventory has {n}"
