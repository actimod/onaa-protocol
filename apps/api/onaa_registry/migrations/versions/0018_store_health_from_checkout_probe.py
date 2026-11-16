"""store health from the checkout probe: stores the checker reached count as reachable

Discovered stores were never health-probed (the health job covers registered listings only), so every store showed
reachability "unknown" and reachable_only filtered nothing (developer evaluation 2026-11-16). The checkout checker
already contacts each store's endpoint; from now on each observation also records endpoint health. This backfills
the stores observed before: a probe that got an answer (any status except failed) marks the store reachable as of
the probe time. Failed probes are left as they are. Data only; no schema change.

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-16 13:00:00
"""
from __future__ import annotations

import datetime as dt
import json

import sqlalchemy as sa
from alembic import op

revision = '0018'
down_revision = '0017'
branch_labels = None
depends_on = None

BATCH = 500


def _when(raw: str | None) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(raw) if raw else None
    except ValueError:
        return None


def upgrade() -> None:
    conn = op.get_bind()
    listings = sa.table('listings', sa.column('id', sa.String), sa.column('agent_checkout', sa.JSON),
                        sa.column('reachability', sa.String), sa.column('last_check_result', sa.String),
                        sa.column('last_checked_at', sa.DateTime(timezone=True)),
                        sa.column('consecutive_check_failures', sa.Integer))
    rows = conn.execute(sa.select(listings.c.id, listings.c.agent_checkout)
                        .where(listings.c.agent_checkout.is_not(None),
                               sa.or_(listings.c.reachability.is_(None), listings.c.reachability == 'unknown'),
                               listings.c.last_check_result.is_(None))).all()
    updates = []
    for listing_id, ac in rows:
        if isinstance(ac, str):
            ac = json.loads(ac)
        if not isinstance(ac, dict) or not ac.get('status') or ac['status'] == 'failed':
            continue
        updates.append({'b_id': listing_id, 'b_at': _when(ac.get('checked_at'))})
    stmt = (sa.update(listings).where(listings.c.id == sa.bindparam('b_id'))
            .values(reachability='reachable', last_check_result='ok', consecutive_check_failures=0,
                    last_checked_at=sa.bindparam('b_at')))
    for i in range(0, len(updates), BATCH):
        conn.execute(stmt, updates[i:i + BATCH])


def downgrade() -> None:
    pass  # health fields are refreshed by later probes; nothing to undo
