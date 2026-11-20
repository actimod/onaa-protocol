"""Removed listings and closed wants are deleted for good 30 days after removal (DP-PILOT-REMOVED-PURGE-01).

Removing still hides an item at once; until the purge the member can put it back. The purge deletes the item with
its Q&A (and their reports), its offers and agent mandates, or the want with its mandates. An item or want stays
while a report on it is still open (a member report not yet decided, a pending review, or a report made on one of
its deals) or a deal on it is unfinished; it goes on the first hourly run after that is resolved.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import (
    PilotA2ADeal,
    PilotItem,
    PilotItemQuestion,
    PilotListingReport,
    PilotMandate,
    PilotOffer,
    PilotQuestionReport,
    PilotWant,
)

log = logging.getLogger(__name__)

REMOVED_RETENTION_DAYS = 30
# Deals that are still going on: offer deals being arranged, A2A orders not yet decided.
_LIVE_DEAL = ("arranging", "arranged")
_LIVE_A2A = ("requested", "quoted", "order_pending", "approved", "awaiting_seller")
REMOVAL_NOTE = ("Removed now: nobody else sees it. ONAA permanently deletes it (with its Q&A) 30 days after removal; "
                "while a report or an unfinished deal on it is still open it is kept until that is resolved. Until "
                "then you can put it back.")


def _aware(t: dt.datetime) -> dt.datetime:
    return t.replace(tzinfo=dt.UTC) if t.tzinfo is None else t


def removal_notice(updated_at: dt.datetime) -> dict[str, Any]:
    """What the member is told when they remove a listing or close a want."""
    return {"deleted_after": (_aware(updated_at) + dt.timedelta(days=REMOVED_RETENTION_DAYS)).isoformat(),
            "retention_days": REMOVED_RETENTION_DAYS, "note": REMOVAL_NOTE}


def _report_open(session: Session, kind: str, target_id: str, review: dict | None) -> bool:
    if (review or {}).get("state") in ("reported", "under_review"):
        return True
    return session.scalar(select(PilotListingReport.id).where(
        PilotListingReport.target_type == kind, PilotListingReport.target_id == target_id,
        PilotListingReport.status == "open").limit(1)) is not None


def _item_held(session: Session, it: PilotItem) -> bool:
    if _report_open(session, "item", it.id, it.review):
        return True
    for o in session.scalars(select(PilotOffer).where(PilotOffer.item_id == it.id,
                                                      PilotOffer.status == "accepted")):
        if o.deal_state in _LIVE_DEAL or o.deal_state is None or o.reports:
            return True
    for d in session.scalars(select(PilotA2ADeal).where(PilotA2ADeal.member_id == it.seller_id,
                                                        PilotA2ADeal.role == "seller",
                                                        PilotA2ADeal.state.in_(_LIVE_A2A))):
        if it.id in (d.item_ids or []):
            return True
    return False


def _delete_item(session: Session, item_id: str) -> None:
    # Explicit deletes, children first (SQLite runs without foreign-key cascades).
    qids = select(PilotItemQuestion.id).where(PilotItemQuestion.item_id == item_id)
    session.execute(delete(PilotQuestionReport).where(PilotQuestionReport.question_id.in_(qids)))
    session.execute(delete(PilotItemQuestion).where(PilotItemQuestion.item_id == item_id,
                                                    PilotItemQuestion.parent_id.is_not(None)))
    session.execute(delete(PilotItemQuestion).where(PilotItemQuestion.item_id == item_id))
    session.execute(delete(PilotMandate).where(PilotMandate.item_id == item_id))
    session.execute(delete(PilotOffer).where(PilotOffer.item_id == item_id))
    session.execute(delete(PilotListingReport).where(PilotListingReport.target_type == "item",
                                                     PilotListingReport.target_id == item_id))
    session.execute(delete(PilotItem).where(PilotItem.id == item_id))


def _delete_want(session: Session, want_id: str) -> None:
    session.execute(delete(PilotMandate).where(PilotMandate.want_id == want_id))
    session.execute(delete(PilotListingReport).where(PilotListingReport.target_type == "want",
                                                     PilotListingReport.target_id == want_id))
    session.execute(delete(PilotWant).where(PilotWant.id == want_id))


def purge_removed(session: Session, at: dt.datetime, limit: int = 500) -> dict[str, int]:
    """Delete removed items and closed wants older than REMOVED_RETENTION_DAYS, except those still held."""
    cutoff = at - dt.timedelta(days=REMOVED_RETENTION_DAYS)
    out = {"items": 0, "wants": 0, "held": 0}
    session.flush()  # autoflush is off: see this request's own changes first
    for it in session.scalars(select(PilotItem).where(PilotItem.status == "removed", PilotItem.updated_at < cutoff)
                              .order_by(PilotItem.updated_at).limit(limit)).all():
        if _item_held(session, it):
            out["held"] += 1
            continue
        _delete_item(session, it.id)
        out["items"] += 1
    for w in session.scalars(select(PilotWant).where(PilotWant.status == "closed", PilotWant.updated_at < cutoff)
                             .order_by(PilotWant.updated_at).limit(limit)).all():
        if _report_open(session, "want", w.id, w.review):
            out["held"] += 1
            continue
        _delete_want(session, w.id)
        out["wants"] += 1
    if out["items"] or out["wants"]:
        log.info("pilot retention: deleted %d removed item(s) and %d closed want(s) (%d held)",
                 out["items"], out["wants"], out["held"])
    return out
