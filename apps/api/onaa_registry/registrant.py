"""What registering gives a store or agent operator (founder decision 2026-11-17).

- A trust level that agents can see at a glance (`trust_level`): found by ONAA, registered by its operator,
  operator confirmed through the store's own published email, operator proved endpoint control, certified.
  Each level is a separate fact (design principle 8); none is a legal identity check.
- Store-stated details (`store_stated_view`): shipping countries, payment methods, returns, categories, always
  labelled as stated by the store and kept apart from what ONAA's test checkout observed.
- Optional ranking: when results are otherwise equal, listings registered by their operator come first
  (`rank_registered_first`; founder approved 2026-11-17, on by default, ONAA_RANK_REGISTERED_FIRST=0 turns it off).
- A weekly count of how often agents looked the listing up (`count_lookups`, `weekly_lookups`): external traffic
  only, per listing and door, no caller information at all. Counted for registered listings only.
- Free certification for early registrants: new operators join the Founding Cohort while seats last
  (`maybe_join_founding_cohort`).
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

LEVELS = ("discovered_unverified", "operator_registered", "operator_confirmed_by_email",
          "operator_endpoint_verified", "certified")
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
LEVEL_LABELS = {
    "discovered_unverified": "Found by ONAA on the public web; not registered by its operator (unverified)",
    "operator_registered": "Registered by its operator; not verified by ONAA",
    "operator_confirmed_by_email": "Registered by its operator, confirmed through the contact email the store "
                                   "publishes itself (not an identity check)",
    "operator_endpoint_verified": "Registered by its operator, who proved control of this endpoint (not an "
                                  "identity check)",
    "certified": "Operator proved control of this endpoint and holds an active ONAA certification",
}
STATED_NOTE = ("Stated by the store's registered operator. Not verified by ONAA; ONAA's own test results are under "
               "`shipping` and `checkout_probe`.")


def trust_level(*, operator_id: str | None, lifecycle_status: str | None, endpoint_verified: bool,
                certified: bool = False, owner_confirmed_via: str | None = None) -> str:
    """The highest level the listing has reached (see LEVELS)."""
    if operator_id is None or lifecycle_status in (None, "discovered", "claim_pending"):
        return "discovered_unverified"
    if endpoint_verified:
        return "certified" if certified else "operator_endpoint_verified"
    if owner_confirmed_via == "published_email":
        return "operator_confirmed_by_email"
    return "operator_registered"


def level_of(listing: Any) -> str:
    """trust_level for a Listing or a buying.StoreView."""
    from .verification import is_currently_verified

    verified = bool(getattr(listing, "endpoint_control_verified", False)) and is_currently_verified(listing)
    return trust_level(operator_id=listing.operator_id, lifecycle_status=listing.lifecycle_status,
                       endpoint_verified=verified, owner_confirmed_via=getattr(listing, "owner_confirmed_via", None),
                       certified=verified and listing.lifecycle_status == "certified")


def is_registered(listing: Any) -> bool:
    return level_of(listing) != "discovered_unverified"


def rank_registered_first() -> bool:
    """Registered listings ahead of unregistered ones when results are otherwise equal (founder approved
    2026-11-17). ONAA_RANK_REGISTERED_FIRST=0 turns it off."""
    return os.environ.get("ONAA_RANK_REGISTERED_FIRST", "1") == "1"


def store_stated_view(listing: Any) -> dict | str:
    stated = (getattr(listing, "profile", None) or {}).get("store_stated")
    if not stated:
        return "unknown"
    return {**stated, "source": "store_stated", "note": STATED_NOTE}


# ---------- lookups ----------
LOOKUP_KIND = "listing_lookup"
LOOKUP_DOORS = ("detail", "check", "search")
LOOKUP_NOTE = ("How often outside agents and apps looked this listing up through ONAA: detail = fetched its record, "
               "check = asked about checking out here, search = it was on a page of search results. Counts only; "
               "ONAA keeps nothing about who asked. ONAA's own traffic and directory checkers are not counted.")


def hit_registered_ids(usage, ids, door: str) -> None:
    """Count one lookup per listing id; the caller passes registered listings only. External origin only; never
    raises (measurement must never break serving)."""
    if usage is None or door not in LOOKUP_DOORS:
        return
    try:
        from .traffic import EXTERNAL, current_origin

        if current_origin.get() != EXTERNAL:
            return
        for lid in dict.fromkeys(i for i in ids if isinstance(i, str)):
            usage.hit(LOOKUP_KIND, f"{lid}|{door}", origin=EXTERNAL)
    except Exception:  # noqa: BLE001
        pass


def registered_ids(assessed_items) -> list[str]:
    """Listing ids of registered stores in buying.assess answers (their `store.trust_level`)."""
    out = []
    for it in assessed_items or []:
        store = it.get("store") if isinstance(it, dict) else None
        if isinstance(store, dict) and store.get("trust_level") not in (None, "discovered_unverified"):
            out.append(store.get("id"))
    return out


def count_lookups(usage, listings, door: str) -> None:
    """Count one lookup for each registered Listing or StoreView given."""
    try:
        ids = [x.id for x in listings if x is not None and is_registered(x)]
    except Exception:  # noqa: BLE001
        return
    hit_registered_ids(usage, ids, door)


def weekly_lookups(session: Session, listing_id: str, weeks: int = 8) -> dict:
    from .models import UsageCounter

    weeks = max(1, min(weeks, 26))
    today = dt.datetime.now(dt.UTC).date()
    monday = today - dt.timedelta(days=today.weekday())
    since = (monday - dt.timedelta(weeks=weeks - 1)).isoformat()
    rows = session.execute(select(UsageCounter.day, UsageCounter.key, func.sum(UsageCounter.count)).where(
        UsageCounter.kind == LOOKUP_KIND, UsageCounter.day >= since,
        UsageCounter.key.like(f"{listing_id}|%")).group_by(UsageCounter.day, UsageCounter.key)).all()
    by_week: dict[str, dict[str, int]] = {}
    for i in range(weeks):
        start = (monday - dt.timedelta(weeks=i)).isoformat()
        by_week[start] = {d: 0 for d in LOOKUP_DOORS}
    for day, key, n in rows:
        parts = key.split("|")
        if len(parts) != 3 or parts[0] != listing_id or parts[2] != "external" or parts[1] not in LOOKUP_DOORS:
            continue
        d = dt.date.fromisoformat(day)
        start = (d - dt.timedelta(days=d.weekday())).isoformat()
        if start in by_week:
            by_week[start][parts[1]] += int(n or 0)
    out = [{"week_starting": w, **c, "total": sum(c.values())} for w, c in sorted(by_week.items(), reverse=True)]
    return {"listing_id": listing_id, "weeks": out, "this_week": out[0], "note": LOOKUP_NOTE}


# ---------- free certification for early registrants ----------
def maybe_join_founding_cohort(session: Session, operator, settings, months: int = 12) -> bool:
    """Give a new operator a Founding Cohort seat (free verification and certification review) while seats last
    (founder decisions 2026-11-12 and 2026-11-17: early registrants get certification free)."""
    from .models import Operator, utcnow

    if operator.founding_cohort_until is not None:
        return False
    used = session.scalar(select(func.count()).select_from(Operator).where(
        Operator.founding_cohort_until.is_not(None))) or 0
    if used >= settings.founding_cohort_size:
        return False
    operator.founding_cohort_until = utcnow() + dt.timedelta(days=30 * months)
    return True


def carry_over_store_observations(discovered: Any, registered: Any) -> None:
    """When a store's operator registers it, keep what ONAA already observed about the discovered entry (checkout
    probe and its check record, endpoint health, the manifest link and first-seen time) on the new listing, so
    registering never loses the store's history."""
    if registered.agent_checkout is None and discovered.agent_checkout is not None:
        registered.agent_checkout = dict(discovered.agent_checkout)
        status = discovered.agent_checkout.get("status")
        if status:
            from .logic import set_facet_kind

            set_facet_kind(registered, "agent_checkout", {status})
    if not registered.documentation_url and discovered.documentation_url:
        registered.documentation_url = discovered.documentation_url
    for col in ("discovered_at", "reachability", "last_checked_at", "last_check_result",
                "consecutive_check_failures"):
        if getattr(discovered, col, None) is not None and getattr(registered, col, None) in (None, "unknown", 0):
            setattr(registered, col, getattr(discovered, col))
