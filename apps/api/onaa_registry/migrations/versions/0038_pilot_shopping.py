"""pilot: shopping runs (offers to several sellers at once, buying several units across sellers)

Founder decisions 2026-11-20 (multi-listing search and comparison, step 2): a buyer's AI may negotiate with up to
5 sellers at once inside one shopping run, with a target quantity and an optional private per-unit limit (shipping
included) for the whole run. Offers may be for some units of a listing; once the target is filled the run's other
open offers are withdrawn.

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-20 05:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0038'
down_revision = '0037'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'pilot_shopping',
        sa.Column('id', sa.String(length=40), primary_key=True),
        sa.Column('member_id', sa.String(length=40), sa.ForeignKey('pilot_members.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('target_quantity', sa.Integer(), nullable=False),
        sa.Column('unit_limit', sa.Integer(), nullable=True),
        sa.Column('partial_ok', sa.Boolean(), nullable=True),
        sa.Column('ask_again_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_pilot_shopping_member_id', 'pilot_shopping', ['member_id'])
    op.create_index('ix_pilot_shopping_status', 'pilot_shopping', ['status'])
    with op.batch_alter_table('pilot_offers') as b:
        b.add_column(sa.Column('shopping_id', sa.String(length=40), nullable=True))
        b.add_column(sa.Column('units', sa.Integer(), nullable=True))
        b.add_column(sa.Column('includes_shipping', sa.Boolean(), nullable=True))
        b.add_column(sa.Column('split', sa.Boolean(), nullable=False, server_default=sa.false()))
        b.create_foreign_key('fk_pilot_offers_shopping_id', 'pilot_shopping', ['shopping_id'], ['id'],
                             ondelete='SET NULL')
        b.create_index('ix_pilot_offers_shopping_id', ['shopping_id'])


def downgrade() -> None:
    with op.batch_alter_table('pilot_offers') as b:
        b.drop_index('ix_pilot_offers_shopping_id')
        b.drop_constraint('fk_pilot_offers_shopping_id', type_='foreignkey')
        b.drop_column('split')
        b.drop_column('includes_shipping')
        b.drop_column('units')
        b.drop_column('shopping_id')
    op.drop_index('ix_pilot_shopping_status', table_name='pilot_shopping')
    op.drop_index('ix_pilot_shopping_member_id', table_name='pilot_shopping')
    op.drop_table('pilot_shopping')
