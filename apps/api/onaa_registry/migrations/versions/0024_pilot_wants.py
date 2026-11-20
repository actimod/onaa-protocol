"""pilot wants: what members want to buy or hire (phase 2 matching)

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-18 08:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'pilot_wants',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('buyer_id', sa.String(length=40), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('max_price', sa.Integer(), nullable=True),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('category', sa.String(length=20), nullable=False),
        sa.Column('region', sa.String(length=80), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['buyer_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_wants', schema=None) as batch_op:
        batch_op.create_index('ix_pilot_wants_buyer_id', ['buyer_id'], unique=False)
        batch_op.create_index('ix_pilot_wants_category', ['category'], unique=False)
        batch_op.create_index('ix_pilot_wants_status', ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('pilot_wants')
