"""Collect public UCP store manifests into a links-only buying-channel seed (service_type=marketplace).

For each domain: read robots.txt, skip the domain unless our user agent may fetch /.well-known/ucp, then
fetch the manifest through the registry's SSRF-safe fetcher (https only, public IPs, size and time caps).
A store is kept only if the manifest declares a dev.ucp.shopping service with an https MCP endpoint.

What is stored: the domain, the manifest URL, the MCP endpoint and capability tokens derived from the
manifest's capability names. Never product data, prices, images, store descriptions or any other content.
Manifests are untrusted data: only the fields above are read, nothing in them is followed or executed.

    python scripts/collect_ucp_stores.py DOMAINS.csv --limit 20000 [--offset 200000] --out seed.json

DOMAINS is one domain per line, or "rank,domain" (Tranco format). Writing the seed to a public registry
is a separate, founder-gated step (import_discovered.py / import-discovered.yml).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from onaa_registry.netsafety import SafeFetcher
from onaa_registry.ucp import (  # noqa: F401 - re-exported for callers and tests
    CAPABILITY_TOKENS,
    DESCRIPTION,
    PLATFORM_WIDE_HOSTS,
    SHOPPING,
    USER_AGENT_TOKEN,
    WELL_KNOWN,
    parse_manifest,
    probe,
    robots_allows,
)

CHUNK = 2000


def load_domains(path: Path, limit: int | None, offset: int = 0) -> list[str]:
    out, seen, skipped = [], set(), 0
    for line in path.read_text().splitlines():
        d = line.strip().split(",")[-1].strip().lower().rstrip(".")
        if not d or d.startswith("#") or d in seen:
            continue
        seen.add(d)
        if skipped < offset:
            skipped += 1
            continue
        out.append(d)
        if limit and len(out) >= limit:
            break
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("domains", type=Path)
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--offset", type=int, default=0, help="skip this many domains first (slice a top list)")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--max-minutes", type=float, default=0,
                    help="stop starting new domains after this long and write what was found (0 = no limit); "
                         "the seed records next_offset so a later run can continue")
    args = ap.parse_args(argv)

    day = dt.date.today().isoformat()
    domains = load_domains(args.domains, args.limit, args.offset)
    fetcher = SafeFetcher()
    items, outcomes, endpoints = [], {}, set()
    started = time.monotonic()
    deadline = started + args.max_minutes * 60 if args.max_minutes > 0 else None
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, 64))) as pool:
        # Work in chunks so a time budget stops at a clean rank boundary (resume with --offset next_offset).
        for start in range(0, len(domains), CHUNK):
            if deadline is not None and time.monotonic() > deadline:
                break
            chunk = domains[start:start + CHUNK]
            for fut in as_completed([pool.submit(probe, fetcher, d, day) for d in chunk]):
                try:
                    outcome, item = fut.result()
                except Exception:  # noqa: BLE001 - one bad host must not stop the run
                    outcome, item = "error", None
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
                if item and item["endpoint_url"] not in endpoints:
                    endpoints.add(item["endpoint_url"])
                    items.append(item)
            done += len(chunk)
            print(f"{done}/{len(domains)} probed, {len(items)} stores, "
                  f"{round(time.monotonic() - started)} s", file=sys.stderr, flush=True)

    items.sort(key=lambda x: x["display_name"])
    args.out.write_text(json.dumps({
        "schema": "onaa-discovered-service-seed/0.1",
        "note": ("Public UCP store manifests (links only). Only domains whose robots.txt allows "
                 f"{USER_AGENT_TOKEN} to fetch {WELL_KNOWN}. No product data. Import is founder-gated."),
        "generated_on": day,
        "domains_probed": done,
        "domain_offset": args.offset,
        "next_offset": args.offset + done,
        "complete": done == len(domains),
        "outcomes": dict(sorted(outcomes.items())),
        "items": items,
    }, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps({"probed": done, "next_offset": args.offset + done, "stores": len(items),
                      "hit_rate_pct": round(100 * len(items) / done, 3) if done else 0, "outcomes": outcomes,
                      "seconds": round(time.monotonic() - started)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
