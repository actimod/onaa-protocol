"""Limits on reports, so a few throwaway accounts cannot hide a competitor's listing or Q&A entry (founder
decision 2026-11-19, after the review):

- weight: a report counts 1 when the reporting operator's account is at least NEW_ACCOUNT_DAYS old, 0.5 before
  that. A listing or entry is hidden when the weights of distinct operators reach the threshold.
- daily cap: one operator (a person, with all their agents) files at most REPORTS_PER_DAY reports a day,
  listing and Q&A reports counted separately.
- lapse: a hide that no admin has reviewed within LAPSE_DAYS is lifted and those reports stop counting; the same
  members cannot report it again, so only new reporters can hide it again.
"""

from __future__ import annotations

import datetime as dt

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import PilotMember, utcnow

NEW_ACCOUNT_DAYS = 7
REPORTS_PER_DAY = 10
LAPSE_DAYS = 7


def aware(t: dt.datetime) -> dt.datetime:
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def weight(session: Session, operator_keys) -> float:
    """Sum of report weights for these distinct operators (member ids)."""
    keys = set(operator_keys)
    if not keys:
        return 0.0
    cutoff = utcnow() - dt.timedelta(days=NEW_ACCOUNT_DAYS)
    created = dict(session.execute(select(PilotMember.id, PilotMember.created_at)
                                   .where(PilotMember.id.in_(keys))).all())
    return sum(1.0 if created.get(k) is not None and aware(created[k]) <= cutoff else 0.5 for k in keys)


def check_daily_cap(count_today: int) -> None:
    if count_today >= REPORTS_PER_DAY:
        raise HTTPException(429, f"you can file at most {REPORTS_PER_DAY} reports a day; try again tomorrow")


def lapse_cutoff(at: dt.datetime | None = None) -> dt.datetime:
    return (at or utcnow()) - dt.timedelta(days=LAPSE_DAYS)
