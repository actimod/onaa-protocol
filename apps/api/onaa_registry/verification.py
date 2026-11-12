"""Endpoint-control verification helpers: DNS TXT lookup and verification expiry (ENG-008)."""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .models import Listing, utcnow

TxtResolver = Callable[[str], list[str]]
DNS_LABEL = "_onaa-challenge"
EXPIRY_SWEEP_INTERVAL_SECONDS = 60


class DnsLookupError(Exception):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


def system_txt_resolver(name: str) -> list[str]:
    """Resolve TXT records with a short timeout. Values are untrusted strings."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout as exc:
        raise DnsLookupError("dns_timeout") from exc
    except dns.exception.DNSException as exc:
        raise DnsLookupError("dns_error") from exc
    out = []
    for rdata in answer:
        out.append(b"".join(rdata.strings).decode("utf-8", "replace")[:512])
    return out[:50]


def dns_record_name(host: str) -> str:
    return f"{DNS_LABEL}.{host}"


def is_currently_verified(listing: Listing) -> bool:
    if not listing.endpoint_control_verified:
        return False
    until = listing.endpoint_verified_until
    if until is None:
        return True  # legacy rows created before expiry existed
    if until.tzinfo is None:
        until = until.replace(tzinfo=dt.UTC)
    return until > utcnow()


def expire_verifications(session: Session) -> list[str]:
    """Clear endpoint-control flags whose proof has expired. Returns affected listing ids."""
    now = utcnow()
    ids = list(session.scalars(select(Listing.id).where(
        Listing.endpoint_control_verified.is_(True), Listing.endpoint_verified_until.is_not(None),
        Listing.endpoint_verified_until <= now)))
    if ids:
        session.execute(update(Listing).where(Listing.id.in_(ids)).values(endpoint_control_verified=False))
        session.execute(update(Listing).where(
            Listing.id.in_(ids), Listing.lifecycle_status.in_(("endpoint_verified", "certified")))
            .values(lifecycle_status="registered", status_reason="endpoint_verification_expired"))
    return ids


def maybe_sweep(app_state, session: Session) -> None:
    """Run the expiry sweep at most once per interval per process (cheap lazy cron)."""
    now = time.monotonic()
    if now - getattr(app_state, "last_expiry_sweep", 0.0) < EXPIRY_SWEEP_INTERVAL_SECONDS:
        return
    app_state.last_expiry_sweep = now
    ids = expire_verifications(session)
    if ids:
        session.commit()


def _future(ts: dt.datetime | None) -> bool:
    if ts is None:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.UTC)
    return ts > utcnow()


def in_founding_cohort(operator) -> bool:
    return _future(operator.founding_cohort_until)


def verification_entitlement(listing: Listing, operator) -> str | None:
    """Why this operator may run endpoint verification for this listing, or None.

    Founding Cohort covers agent listings only (service providers are not in the cohort).
    """
    if listing.listing_type == "agent" and in_founding_cohort(operator):
        return "founding_cohort"
    if _future(listing.verification_entitled_until):
        return "approved_application"
    return None
