"""Run the checkout checker inside the API server, continuously and gently.

The checker (checkout_checker.py) probes a store as an anonymous agent: list tools, search, create a one-item
checkout, cancel it. It never completes a checkout or sends payment data. Running it here, instead of in a
time-limited CI job, lets every listed store be checked within days instead of a month, on the machine the
registry already runs on.

Order: never-checked stores first, then the oldest check, and a store is re-checked only after
`recheck_days`. A few workers, each pausing between stores, keep the load on stores and on this server small.
Off unless ONAA_CHECKER_LOOP=1. Results are written straight to the database, exactly as the admin endpoint
`POST /v1/admin/listings/{id}/agent-checkout` records them.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import threading
import uuid
from collections.abc import Callable
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import Session

from .logic import PUBLIC_STATUSES, aware, set_facet_kind
from .models import Listing, ListingFacet, utcnow

log = logging.getLogger("onaa.checker")

# Bumped whenever the UCP agent profile changes: stores cache the profile by URL, so a new URL makes them read the
# new one at once (2026-11-16: the fulfillment extension, without which stores ignore the test address).
PROFILE_REV = "2026-11-16"

NOTE = ("Observed by ONAA's checker, which stops before payment. Not a verification or endorsement; the store's "
        "own terms apply.")


def apply_observation(session: Session, listing: Listing, obs: dict, actor: str = "admin") -> None:
    """Store one checkout observation on a marketplace listing (shared with the admin endpoint)."""
    from .logic import audit

    listing.agent_checkout = {**obs, "checked_at": aware(utcnow()).isoformat(), "note": NOTE}
    set_facet_kind(listing, "agent_checkout", {obs["status"]})
    listing.updated_at = utcnow()
    audit(session, actor, None, "listing.agent_checkout", listing.id, status=obs["status"])


def due_listing_ids(session: Session, limit: int, recheck_days: float) -> list[str]:
    """Stores to check next: never checked first, then the least recently updated whose check is old enough."""
    base = (Listing.service_type == "marketplace", Listing.lifecycle_status.in_(PUBLIC_STATUSES),
            Listing.endpoint_url.is_not(None))
    checked = select(ListingFacet.listing_id).where(ListingFacet.kind == "agent_checkout")
    ids = list(session.scalars(select(Listing.id).where(*base, Listing.id.not_in(checked))
                               .order_by(Listing.created_at, Listing.id).limit(limit)).all())
    if len(ids) >= limit:
        return ids
    cutoff = utcnow() - dt.timedelta(days=recheck_days)
    rows = session.execute(select(Listing.id, Listing.agent_checkout).where(*base, Listing.id.in_(checked),
                                                                            Listing.updated_at < cutoff)
                           .order_by(Listing.updated_at, Listing.id).limit(limit * 4)).all()
    old = []
    for lid, ac in rows:
        try:
            at = dt.datetime.fromisoformat((ac or {}).get("checked_at") or "")
        except ValueError:
            at = None
        if at is None or aware(at) < aware(cutoff):
            old.append(((ac or {}).get("checked_at") or "", lid))
    return ids + [lid for _, lid in sorted(old)[:limit - len(ids)]]


class CheckerLoop:
    def __init__(self, sessionmaker: Callable[[], Session], public_base_url: str, *, workers: int = 3,
                 delay_seconds: float = 3.0, recheck_days: float = 7.0, idle_seconds: float = 1800.0,
                 start_delay_seconds: float = 60.0, check_one: Callable | None = None,
                 client_factory: Callable | None = None):
        self.sessionmaker = sessionmaker
        self.base = public_base_url.rstrip("/")
        self.workers = max(1, min(workers, 8))
        self.delay = delay_seconds
        self.recheck_days = recheck_days
        self.idle = idle_seconds
        self.start_delay = start_delay_seconds
        self._check_one = check_one
        self._client_factory = client_factory
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._queue: list[str] = []
        self._claimed: set[str] = set()
        self.stats = {"checked": 0, "recorded": 0, "errors": 0}
        from .checkout_checker import SHIP_TEST

        self.args = SimpleNamespace(country="US", currency="USD", ship_countries=",".join(SHIP_TEST))

    # ----- queue -----
    def _next(self) -> str | None:
        with self._lock:
            while True:
                if self._queue:
                    lid = self._queue.pop(0)
                    if lid not in self._claimed:
                        self._claimed.add(lid)
                        return lid
                    continue
                with self.sessionmaker() as s:
                    fresh = [i for i in due_listing_ids(s, 50 * self.workers, self.recheck_days)
                             if i not in self._claimed]
                if not fresh:
                    return None
                self._queue = fresh

    def _done(self, lid: str) -> None:
        with self._lock:
            self._claimed.discard(lid)

    # ----- one store -----
    def check(self, http, lid: str) -> str | None:
        from . import checkout_checker

        with self.sessionmaker() as s:
            listing = s.get(Listing, lid)
            if listing is None or not listing.endpoint_url:
                return None
            info = {"id": listing.id, "endpoint_url": listing.endpoint_url,
                    "documentation_url": listing.documentation_url, "display_name": listing.display_name}
        check_one = self._check_one or checkout_checker.check_one
        obs = check_one(http, info, f"{self.base}/agent/ucp-profile.json?v={PROFILE_REV}", self.args)
        from .schemas import AgentCheckoutObservation

        body = AgentCheckoutObservation(**obs).model_dump(mode="json", exclude_none=True)
        with self.sessionmaker() as s:
            listing = s.get(Listing, lid)
            if listing is None or listing.service_type != "marketplace":
                return None
            apply_observation(s, listing, body, actor="system")
            s.commit()
        return body["status"]

    def _client(self):
        if self._client_factory is not None:
            return self._client_factory()
        import httpx

        run = uuid.uuid4().hex[:8]
        return httpx.Client(timeout=20.0, follow_redirects=False, headers={
            "user-agent": f"ONAA-Checkout-Checker/0.1 (+{self.base}/opt-out; run {run})"})

    def _worker(self, n: int) -> None:
        if self._stop.wait(self.start_delay + n * self.delay):
            return
        with self._client() as http:
            while not self._stop.is_set():
                try:
                    lid = self._next()
                except Exception:  # noqa: BLE001 - database hiccup: try again later
                    log.warning("checker queue failed", exc_info=True)
                    lid = None
                if lid is None:
                    self._stop.wait(self.idle)
                    continue
                try:
                    status = self.check(http, lid)
                    with self._lock:
                        self.stats["checked"] += 1
                        self.stats["recorded"] += status is not None
                except Exception:  # noqa: BLE001 - one store must never stop the loop
                    with self._lock:
                        self.stats["errors"] += 1
                    log.warning("checker failed on %s", lid, exc_info=True)
                finally:
                    self._done(lid)
                self._stop.wait(self.delay)

    def start(self) -> None:
        if self._threads:
            return
        for n in range(self.workers):
            t = threading.Thread(target=self._worker, args=(n,), name=f"onaa-checker-{n}", daemon=True)
            t.start()
            self._threads.append(t)
        log.info("checkout checker started with %d workers", self.workers)

    def stop(self) -> None:
        self._stop.set()


def from_env(sessionmaker: Callable[[], Session], public_base_url: str) -> CheckerLoop | None:
    if os.environ.get("ONAA_CHECKER_LOOP", "0") != "1":
        return None
    return CheckerLoop(sessionmaker, public_base_url,
                       workers=int(os.environ.get("ONAA_CHECKER_WORKERS", "3")),
                       delay_seconds=float(os.environ.get("ONAA_CHECKER_DELAY_SECONDS", "3")),
                       recheck_days=float(os.environ.get("ONAA_CHECKER_RECHECK_DAYS", "7")))
