#!/usr/bin/env python3
"""Call the buying tools over the real MCP transport (Streamable HTTP, JSON-RPC POST to /mcp) and fail if any call
errors, returns isError, or is too slow.

Why: on 2026-11-17 ChatGPT reported "Error executing tool find_stores" for include=all while the REST route answered
200. REST checks and tools/list checks did not catch it. This runs every combination a client can send:
find_stores with include buyable/possible/all x health filter none/relaxed/strict, plus can_i_buy_here, how_to_buy
and describe_need.

    python3 apps/mcp-registry/mcp_smoke.py --base https://api.onaa.net            # live (tagged as our own traffic)
    python3 apps/mcp-registry/mcp_smoke.py --base http://127.0.0.1:8080 --json    # machine-readable result

Standard library only. describe_need stores its (fixed, harmless) text as origin=internal, which demand review
leaves out; pass --skip-describe-need to make no write at all.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
           "User-Agent": "onaa-mcp-smoke/1", "X-ONAA-Traffic": "internal"}
INCLUDES = ("buyable", "possible", "all")
FILTERS = {"none": {}, "relaxed": {"reachable_only": True}, "strict": {"confirmed_reachable_only": True}}
STORE = "beurbanrunning.com"
NEED = "onaa smoke test: running shoes, ship to the US"


def cases(store: str = STORE, describe_need: bool = True) -> list[tuple[str, str, dict]]:
    out = [(f"find_stores include={inc} filter={name}", "find_stores",
            {"ship_to_country": "US", "limit": 5, "include": inc, **flt})
           for inc in INCLUDES for name, flt in FILTERS.items()]
    out += [(f"can_i_buy_here pay_alone={pa}", "can_i_buy_here",
             {"stores": [store], "ship_to_country": "US", "pay_alone": pa}) for pa in (False, True)]
    out.append(("how_to_buy", "how_to_buy", {"store": store, "ship_to_country": "US"}))
    if describe_need:
        out.append(("describe_need", "describe_need", {"request": NEED, "ship_to_country": "US"}))
    return out


def _parse(raw: bytes, content_type: str) -> dict:
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in content_type:  # one JSON-RPC message per "data:" line
        for line in text.splitlines():
            if line.startswith("data:"):
                msg = json.loads(line[5:])
                if "result" in msg or "error" in msg:
                    return msg
        raise ValueError("no JSON-RPC message in the event stream")
    return json.loads(text)


def call(base: str, tool: str, args: dict, timeout: float) -> tuple[dict, float, int]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/mcp", data=body, headers=HEADERS, method="POST")
    start = time.monotonic()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        msg = _parse(r.read(), r.headers.get("Content-Type", ""))
    return msg, time.monotonic() - start, len(body)


def problem(msg: dict) -> str | None:
    """Why this tool answer is a failure, or None."""
    if "error" in msg:
        return f"JSON-RPC error {msg['error']}"[:300]
    res = msg.get("result") or {}
    if res.get("isError"):
        text = " ".join(c.get("text", "") for c in res.get("content") or [])
        return f"isError: {text}"[:300]
    sc = res.get("structuredContent")
    if sc is None:
        try:
            sc = json.loads((res.get("content") or [{}])[0].get("text", ""))
        except ValueError:
            return "no structuredContent and the text is not JSON"
    sc = sc.get("result", sc) if isinstance(sc, dict) else sc
    if not isinstance(sc, dict):
        return "structuredContent is not an object"
    if "error" in sc or "error_code" in sc:
        return f"tool error: {sc.get('error') or sc.get('error_code')}"[:300]
    return None


def summary(msg: dict) -> str:
    res = msg.get("result") or {}
    sc = res.get("structuredContent") or {}
    sc = sc.get("result", sc) if isinstance(sc, dict) else {}
    if "total" in sc:
        return f"total={sc['total']} counts={sc.get('reachability_counts')} items={len(sc.get('items') or [])}"
    if "items" in sc:
        return f"items={len(sc['items'])}"
    if "applied_constraints" in sc:
        return f"status={sc.get('status')} matches={sc.get('total_matches')}"
    return ",".join(sorted(sc)[:6])


def run(base: str, *, max_seconds: float = 15.0, retry_seconds: float = 0.0, store: str = STORE,
        describe_need: bool = True) -> list[dict]:
    rows = []
    for label, tool, args in cases(store, describe_need):
        deadline = time.monotonic() + retry_seconds
        while True:
            row = {"case": label, "tool": tool, "arguments": args}
            try:
                msg, secs, _ = call(base, tool, args, timeout=max(max_seconds * 2, 30))
                row.update(seconds=round(secs, 2), problem=problem(msg), summary=summary(msg),
                           bytes=len(json.dumps(msg)))
                if row["problem"] is None and secs > max_seconds:
                    row["problem"] = f"too slow: {secs:.1f} s > {max_seconds:.0f} s"
            except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                row.update(seconds=None, problem=f"transport: {exc}"[:300], summary="")
            transient = row["problem"] and (row["problem"].startswith("transport") or "503" in row["problem"]
                                            or "being loaded" in row["problem"])
            slow = bool(row["problem"]) and row["problem"].startswith("too slow")
            if slow and not row.get("retried_slow"):
                # One slow answer right after a restart (a cache refresh or warm-up running) is retried once;
                # it fails only if the second answer is slow too.
                row_prev = row["problem"]
                time.sleep(5)
                msg2 = None
                try:
                    msg2, secs2, _ = call(base, tool, args, timeout=max(max_seconds * 2, 30))
                except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                    row["problem"] = f"transport: {exc}"[:300]
                if msg2 is not None:
                    row.update(seconds=round(secs2, 2), problem=problem(msg2), summary=summary(msg2),
                               first_try=row_prev)
                    if row["problem"] is None and secs2 > max_seconds:
                        row["problem"] = f"too slow twice: {secs2:.1f} s > {max_seconds:.0f} s"
                row["retried_slow"] = True
                break
            if not transient or time.monotonic() >= deadline:
                break
            time.sleep(10)  # the service is still starting or loading its store list
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="registry base URL, e.g. https://api.onaa.net")
    ap.add_argument("--max-seconds", type=float, default=15.0, help="fail a call slower than this")
    ap.add_argument("--retry-seconds", type=float, default=0.0,
                    help="retry transport errors for this long (use after a deploy)")
    ap.add_argument("--store", default=STORE)
    ap.add_argument("--skip-describe-need", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rows = run(a.base, max_seconds=a.max_seconds, retry_seconds=a.retry_seconds, store=a.store,
               describe_need=not a.skip_describe_need)
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            mark = "FAIL" if r["problem"] else "ok  "
            print(f"{mark} {r['case']:<45} {r['seconds']!s:>6} s  {r['problem'] or r['summary']}")
    failed = [r for r in rows if r["problem"]]
    print(f"{len(rows) - len(failed)}/{len(rows)} MCP calls passed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
