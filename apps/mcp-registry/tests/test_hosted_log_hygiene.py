"""Review 2026-11-19: one-time codes in query strings never reach the access log, and the usage counters keep
only tool-shaped names (no caller-chosen free text in the public stats)."""

from __future__ import annotations

import asyncio

from onaa_mcp_registry import hosted


def test_query_is_cleared_when_the_response_starts():
    scope = {"type": "http", "path": "/claim-key/kc_1", "query_string": b"code=onaa-claim-secret"}
    seen = []

    async def send(message):
        seen.append(dict(scope))  # what uvicorn's access log reads at this moment

    wrapped = hosted._scrub_query_before_log(scope, send)
    asyncio.run(wrapped({"type": "http.response.start", "status": 200, "headers": []}))
    assert seen[0]["query_string"] == b""


class _Usage:
    def __init__(self):
        self.hits = []

    def hit(self, kind, key, origin=None):
        self.hits.append((kind, key))


def test_only_tool_shaped_names_are_counted():
    u = _Usage()
    calls = [{"method": "tools/call", "params": {"name": n}}
             for n in ("search_items", "Buy cheap pills at example.com", "x" * 61, None)]
    hosted._count_mcp_doc(calls + [{"method": "tools/call", "params": {"name": "a"}}] * 50, u)
    names = [k for kind, k in u.hits if kind == "mcp_tool"]
    assert names[:4] == ["search_items", "other", "other", "unknown"]
    assert len(names) == hosted.MAX_COUNTED_CALLS
