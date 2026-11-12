"""Import a discovery seed file into a Registry via the admin API.

Dry run by default: every entry is validated locally against the API schema and nothing is sent.
`--apply` writes to the registry at --registry-url using ONAA_ADMIN_TOKEN from the environment.

Applying to a public registry is a founder-gated step: it needs explicit approval and a live public
opt-out page (growth DISCOVERY_POLICY §7). Never put the admin token on the command line or in Git.

    python scripts/import_discovered.py path/to/seed.json
    ONAA_ADMIN_TOKEN=... python scripts/import_discovered.py SEED --apply --registry-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
from pydantic import ValidationError

from onaa_registry.schemas import DiscoveredCreate, DiscoveredServiceCreate

ALIASES = {"name": "display_name", "docs_url": "documentation_url", "type": "service_type"}


def load_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        data = data.get("services") or data.get("agents") or data.get("items") or []
    if not isinstance(data, list):
        raise SystemExit("seed must be a JSON list or an object with services/agents/items")
    return data


def to_body(entry: dict) -> tuple[str, dict]:
    """Return (admin path, validated body). Unknown seed fields (notes, status, ...) are dropped."""
    e = {k: v for k, v in entry.items() if v is not None and k not in ALIASES}
    for alias, canonical in ALIASES.items():
        if entry.get(alias) is not None:
            e.setdefault(canonical, entry[alias])
    if e.get("agent_card_url"):
        model, path = DiscoveredCreate, "/v1/admin/discovered"
    else:
        model, path = DiscoveredServiceCreate, "/v1/admin/discovered/services"
    fields = {k: v for k, v in e.items() if k in model.model_fields and v is not None}
    return path, model(**fields).model_dump(mode="json", exclude_none=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("seed", type=Path)
    ap.add_argument("--apply", action="store_true", help="send to the registry (default: validate only)")
    ap.add_argument("--registry-url", default="http://localhost:8000")
    args = ap.parse_args(argv)

    bodies, errors = [], 0
    for i, entry in enumerate(load_entries(args.seed)):
        try:
            bodies.append(to_body(entry))
        except (ValidationError, TypeError) as exc:
            errors += 1
            print(f"[{i}] invalid: {str(exc).splitlines()[0]}", file=sys.stderr)
    print(f"{len(bodies)} valid, {errors} invalid")
    if not args.apply:
        return 1 if errors else 0
    token = os.environ.get("ONAA_ADMIN_TOKEN")
    if not token:
        raise SystemExit("ONAA_ADMIN_TOKEN is not set")
    created = skipped = failed = 0
    with httpx.Client(base_url=args.registry_url.rstrip("/"), timeout=15,
                      headers={"Authorization": f"Bearer {token}"}) as http:
        for path, body in bodies:
            r = http.post(path, json=body)
            if r.status_code == 201:
                created += 1
            elif r.status_code == 409:
                skipped += 1  # already listed, or host owned by a verified operator
            else:
                failed += 1
                print(f"{body['display_name']}: HTTP {r.status_code}", file=sys.stderr)
    print(f"created {created}, skipped {skipped} (already listed or owned), failed {failed}")
    return 1 if failed or errors else 0


if __name__ == "__main__":
    sys.exit(main())
