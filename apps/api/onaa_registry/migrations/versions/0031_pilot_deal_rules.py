"""pilot: per-member deal rules, and what happens after an offer is accepted (no automatic contact reveal)

Founder, 2026-11-19: each member decides what their assistant may do alone after negotiating (auto or ask, ask by
default); after acceptance the two sides arrange payment and handoff on the deal itself. ONAA no longer keeps any
contact detail: saved contacts are erased (members share one inside a deal message, by choice). Listings and wants
can be reported and taken down after review.

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-19 03:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0031'
down_revision = '0030'
branch_labels = None
depends_on = None

OFFER_COLUMNS = (
    ('deal_state', sa.String(length=20)), ('accepted_at', sa.DateTime(timezone=True)), ('arrangement', sa.JSON()),
    ('done_by', sa.JSON()), ('waiting', sa.JSON()), ('reports', sa.JSON()),
    ('cancelled_by', sa.String(length=10)),
)


def upgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.add_column(sa.Column('deal_rules', sa.JSON(), nullable=True))
    with op.batch_alter_table('pilot_offers', schema=None) as batch_op:
        for name, type_ in OFFER_COLUMNS:
            batch_op.add_column(sa.Column(name, type_, nullable=True))
    for table in ('pilot_items', 'pilot_wants'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column('review', sa.JSON(), nullable=True))
    op.create_table(
        'pilot_listing_reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_type', sa.String(length=10), nullable=False),
        sa.Column('target_id', sa.String(length=40), nullable=False),
        sa.Column('reporter_id', sa.String(length=40), nullable=False),
        sa.Column('operator_key', sa.String(length=40), nullable=False),
        sa.Column('reason', sa.String(length=20), nullable=False),
        sa.Column('note', sa.String(length=300), nullable=True),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['reporter_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_type', 'target_id', 'reporter_id', name='uq_pilot_listing_report'),
    )
    with op.batch_alter_table('pilot_listing_reports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_listing_reports_target_id'), ['target_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_listing_reports_status'), ['status'], unique=False)
    conn = op.get_bind()
    # Deals accepted before this: still reserved = in progress; sold = done; back on sale or removed = cancelled.
    for state, item_status in (("arranging", "'reserved'"), ("done", "'sold'"), ("cancelled", "'available', 'removed'")):
        conn.execute(sa.text(
            f"UPDATE pilot_offers SET deal_state = '{state}', accepted_at = updated_at WHERE status = 'accepted' "
            f"AND deal_state IS NULL AND item_id IN (SELECT id FROM pilot_items WHERE status IN ({item_status}))"))
    conn.execute(sa.text("UPDATE pilot_offers SET deal_state = 'arranging', accepted_at = updated_at "
                         "WHERE status = 'accepted' AND deal_state IS NULL"))
    conn.execute(sa.text("UPDATE pilot_members SET contact = '' WHERE contact != ''"))


def downgrade() -> None:
    op.drop_table('pilot_listing_reports')
    for table in ('pilot_wants', 'pilot_items'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column('review')
    with op.batch_alter_table('pilot_offers', schema=None) as batch_op:
        for name, _ in reversed(OFFER_COLUMNS):
            batch_op.drop_column(name)
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.drop_column('deal_rules')
