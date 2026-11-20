"""UCP store manifests: fetch and read a store's public /.well-known/ucp, links only.

Shared by the bulk collector (scripts/collect_ucp_stores.py) and the on-demand "can I buy here?" check, which
probes a store an agent asked about when ONAA has not listed it yet. robots.txt is honoured; only the domain,
manifest URL, MCP endpoint, capability names and UCP version are read. Manifests are untrusted data.
"""

from __future__ import annotations

import json
import urllib.robotparser
from urllib.parse import urlsplit

from .netsafety import Fetcher, FetchError, UnsafeURLError, validate_public_url

USER_AGENT_TOKEN = "ONAA-Registry-Verifier"
WELL_KNOWN = "/.well-known/ucp"
SHOPPING = "dev.ucp.shopping"
CAPABILITY_TOKENS = {
    "dev.ucp.shopping.checkout": "checkout",
    "dev.ucp.shopping.cart": "cart",
    "dev.ucp.shopping.catalog": "catalog_search",
    "dev.ucp.shopping.catalog.search": "catalog_search",
    "dev.ucp.shopping.order": "order_tracking",
    "dev.ucp.shopping.fulfillment": "fulfillment",
}
# Endpoint hosts whose manifests are served platform-wide, including for sites that are not stores (the first run
# on 2026-11-14 found Wix manifests on parked, expired and non-shop domains). Skipped until a store can be told apart.
PLATFORM_WIDE_HOSTS = ("www.wixapis.com",)
DESCRIPTION = ("Online store that publishes a Universal Commerce Protocol (UCP) manifest at {manifest}, "
               "declaring an MCP endpoint for agent shopping. Buy there directly under the store's own terms. "
               "ONAA stores only this link, no product data. Not affiliated with ONAA; observed {day}.")


def robots_allows(fetcher: Fetcher, domain: str) -> bool:
    try:
        r = fetcher.fetch(f"https://{domain}/robots.txt")
    except (FetchError, UnsafeURLError):
        return False  # unreachable or unsafe host: do not fetch anything else
    if r.status_code in (401, 403) or r.status_code >= 500:
        return False
    if r.status_code >= 400:
        return True  # no robots.txt: crawling allowed by convention
    rp = urllib.robotparser.RobotFileParser()
    rp.parse(r.body.decode("utf-8", "replace").splitlines())
    return rp.can_fetch(USER_AGENT_TOKEN, WELL_KNOWN)


def _https(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        validate_public_url(url)
    except UnsafeURLError:
        return None
    return url


def parse_manifest(body: bytes) -> tuple[str, list[str], str] | None:
    """Return (mcp_endpoint, capability tokens, ucp version) or None if not a usable shopping manifest."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    ucp = doc.get("ucp") if isinstance(doc, dict) else None
    if not isinstance(ucp, dict):
        return None
    services = ucp.get("services")
    shopping = services.get(SHOPPING) if isinstance(services, dict) else None
    if not isinstance(shopping, list):
        return None
    endpoint = next((e for e in (_https(s.get("endpoint")) for s in shopping
                                 if isinstance(s, dict) and s.get("transport") == "mcp") if e), None)
    if not endpoint:
        return None
    caps = ucp.get("capabilities")
    tokens = {"protocol.ucp", "protocol.mcp"}
    if isinstance(caps, dict):
        tokens |= {CAPABILITY_TOKENS[k] for k in caps if k in CAPABILITY_TOKENS}
    version = ucp.get("version") if isinstance(ucp.get("version"), str) else ""
    return endpoint, sorted(tokens), version[:20]


def _looks_like_manifest(body: bytes) -> bool:
    """A JSON object with a `ucp` object: otherwise the file is simply not there (whatever the status)."""
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    return isinstance(doc, dict) and isinstance(doc.get("ucp"), dict)


def probe(fetcher: Fetcher, domain: str, day: str) -> tuple[str, dict | None]:
    try:
        validate_public_url(f"https://{domain}/")
    except UnsafeURLError:
        return "bad_domain", None
    if not robots_allows(fetcher, domain):
        return "robots_or_unreachable", None
    manifest = f"https://{domain}{WELL_KNOWN}"
    try:
        r = fetcher.fetch(manifest)
    except FetchError as exc:
        return f"fetch_{exc.category}", None
    except UnsafeURLError:
        return "unsafe", None
    if r.status_code != 200 or not _looks_like_manifest(r.body):
        return "no_manifest", None  # many sites answer any path with their HTML homepage (status 200)
    parsed = parse_manifest(r.body)
    if not parsed:
        return "not_shopping_manifest", None
    endpoint, caps, version = parsed
    if urlsplit(endpoint).hostname in PLATFORM_WIDE_HOSTS:
        return "platform_wide_manifest", None
    return "ok", {
        "status": "discovered",
        "claimed": False,
        "display_name": domain,
        "service_type": "marketplace",
        "endpoint_url": endpoint,
        "documentation_url": manifest,
        "source_url": manifest,
        "description": DESCRIPTION.format(manifest=manifest, day=day),
        "capabilities": caps,
        "ucp_version": version,
        "retrieved_on": day,
    }
