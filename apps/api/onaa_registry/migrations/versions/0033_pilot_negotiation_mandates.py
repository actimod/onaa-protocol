"""pilot: negotiation mandates and agent notes (the member's ONAA agent negotiates on its own)

Founder, 2026-11-19: people give one instruction ("sell it for $5, you can go down to $4") and their ONAA agent
negotiates with the other side's agent within that range, around the clock. Whether it confirms by itself is
decided only by the member's deal rules (confirm_deal auto/ask and its price limit). pilot_mandates holds the
range and acceptable terms; pilot_agent_notes tells the member what the agent did and what needs them.

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-19 13:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0033'
down_revision = '0032'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'pilot_mandates',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('side', sa.String(length=4), nullable=False),
        sa.Column('item_id', sa.String(length=40), nullable=True),
        sa.Column('want_id', sa.String(length=40), nullable=True),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('start_price', sa.Integer(), nullable=True),
        sa.Column('limit_price', sa.Integer(), nullable=False),
        sa.Column('terms', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('ended_reason', sa.String(length=40), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['item_id'], ['pilot_items.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['want_id'], ['pilot_wants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_mandates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_mandates_member_id'), ['member_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_mandates_item_id'), ['item_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_mandates_want_id'), ['want_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_mandates_status'), ['status'], unique=False)
    op.create_table(
        'pilot_agent_notes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('kind', sa.String(length=10), nullable=False),
        sa.Column('offer_id', sa.String(length=40), nullable=True),
        sa.Column('mandate_id', sa.String(length=40), nullable=True),
        sa.Column('text', sa.String(length=600), nullable=False),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_agent_notes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_agent_notes_member_id'), ['member_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_agent_notes_created_at'), ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_table('pilot_agent_notes')
    op.drop_table('pilot_mandates')
