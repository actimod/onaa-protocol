"""store check record: per-store probe count, checkout-reached count and recent checks

Each checkout observation now keeps a small check record inside listings.agent_checkout ("check_history": total,
reached, first day, newest 5 [day, status]) so store answers can show a success rate and recent checks (trust
signal). This backfills the record for stores probed before, from the audit log (action listing.agent_checkout).
Data only; no schema change. Streams the audit rows, then updates in batches.

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-17 00:30:00
"""
from __future__ import annotations

import datetime as dt
import json

import sqlalchemy as sa
from alembic import op

revision = '0019'
down_revision = '0018'
branch_labels = None
depends_on = None

BATCH = 500
RECENT = 5
REACHED = ('checkout_ready', 'buyer_step_required')


def _day(at) -> str:
    if isinstance(at, str):
        at = dt.datetime.fromisoformat(at)
    return at.date().isoformat()


def _flush(conn, listings, pending: dict[str, dict]) -> None:
    if not pending:
        return
    rows = conn.execute(sa.select(listings.c.id, listings.c.agent_checkout)
                        .where(listings.c.id.in_(list(pending)))).all()
    updates = []
    for listing_id, ac in rows:
        if isinstance(ac, str):
            ac = json.loads(ac)
        if not isinstance(ac, dict) or not ac.get('status') or ac.get('check_history'):
            continue
        updates.append({'b_id': listing_id, 'b_ac': {**ac, 'check_history': pending[listing_id]}})
    if updates:
        conn.execute(sa.update(listings).where(listings.c.id == sa.bindparam('b_id'))
                     .values(agent_checkout=sa.bindparam('b_ac', type_=sa.JSON)), updates)
    pending.clear()


def upgrade() -> None:
    conn = op.get_bind()
    listings = sa.table('listings', sa.column('id', sa.String), sa.column('agent_checkout', sa.JSON))
    events = sa.table('audit_events', sa.column('id', sa.String), sa.column('action', sa.String),
                      sa.column('subject_id', sa.String), sa.column('result', sa.String),
                      sa.column('detail', sa.JSON), sa.column('created_at', sa.DateTime(timezone=True)))
    q = (sa.select(events.c.subject_id, events.c.created_at, events.c.detail)
         .where(events.c.action == 'listing.agent_checkout', events.c.result == 'ok',
                events.c.subject_id.is_not(None))
         .order_by(events.c.subject_id, events.c.created_at, events.c.id))
    pending: dict[str, dict] = {}
    current, hist = None, None
    for subject_id, at, detail in conn.execute(q):
        if isinstance(detail, str):
            detail = json.loads(detail)
        status = (detail or {}).get('status')
        if not isinstance(status, str) or at is None:
            continue
        if subject_id != current:
            if current is not None and hist:
                pending[current] = hist
            current, hist = subject_id, {'total': 0, 'reached': 0, 'first': _day(at), 'recent': []}
        hist['total'] += 1
        hist['reached'] += status in REACHED
        hist['recent'] = ([[_day(at), status]] + hist['recent'])[:RECENT]
    if current is not None and hist:
        pending[current] = hist
    # Updates run after the read finishes (a few small dicts per store), not while the cursor is open.
    ids = list(pending)
    for i in range(0, len(ids), BATCH):
        _flush(conn, listings, {k: pending[k] for k in ids[i:i + BATCH]})


def downgrade() -> None:
    pass
