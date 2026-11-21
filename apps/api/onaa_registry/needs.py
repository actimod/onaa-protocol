"""Retention for the retired free-text buying needs (describe_need, retired with the store directory).

The tool and `POST /v1/buying/needs` are gone, but rows already kept in `buyer_needs` (redacted text, kept up to
`need_text_retention_days`, default 7) must still be deleted on time, so the once-a-minute sweep keeps calling
`purge_expired_needs`. Once the table is empty this module and the table can be dropped.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .models import BuyerNeed, utcnow


def purge_expired_needs(session: Session, retention_days: int) -> int:
    """Delete need texts older than the retention window (0 = delete them all)."""
    if retention_days <= 0:
        return session.execute(delete(BuyerNeed)).rowcount or 0
    cutoff = utcnow() - dt.timedelta(days=retention_days)
    return session.execute(delete(BuyerNeed).where(BuyerNeed.created_at < cutoff)).rowcount or 0
