"""Endpoint health probes (ENG-011, certification policy §3.1).

A probe is one safe GET (SSRF-guarded SafeFetcher, 10 s total deadline) to the listing's endpoint, or to its
Agent Card when no endpoint URL is set. Any HTTP answer below 500 counts as reachable. Three consecutive failures
mark the listing `unreachable`. That is a separate reachability signal, not a revocation, and it never changes
registration, verification or certification status.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Listing, utcnow
from .netsafety import Fetcher, FetchError, UnsafeURLError

UNREACHABLE_AFTER = 3


def probe_target(listing: Listing) -> str | None:
    return listing.endpoint_url or listing.agent_card_url


def probe_listing(listing: Listing, fetcher: Fetcher) -> str:
    """Probe once and update the listing's health fields. Returns the result category."""
    target = probe_target(listing)
    listing.last_checked_at = utcnow()
    if not target:
        result = "no_target"
    else:
        try:
            res = fetcher.fetch(target)
            listing.last_check_latency_ms = res.elapsed_ms
            result = "ok" if res.status_code < 500 else f"http_{res.status_code // 100}xx"
        except UnsafeURLError:
            result = "blocked_unsafe_url"
        except FetchError as exc:
            result = exc.category
    listing.last_check_result = result
    if result == "ok":
        listing.consecutive_check_failures = 0
        listing.reachability = "reachable"
    elif result != "no_target":
        listing.consecutive_check_failures = (listing.consecutive_check_failures or 0) + 1
        if listing.consecutive_check_failures >= UNREACHABLE_AFTER:
            listing.reachability = "unreachable"
    return result


def run_health_checks(session: Session, fetcher: Fetcher, limit: int) -> dict[str, str]:
    """Probe up to `limit` public listings, least recently checked first."""
    rows = session.scalars(
        select(Listing)
        .where(Listing.lifecycle_status.in_(("registered", "endpoint_verified", "certified")))
        .order_by(Listing.last_checked_at.is_(None).desc(), Listing.last_checked_at.asc(), Listing.id)
        .limit(limit)
    ).all()
    return {row.id: probe_listing(row, fetcher) for row in rows}
