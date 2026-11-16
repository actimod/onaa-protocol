"""redacted free-text buying needs, kept 30 days (describe_need)

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-15 23:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'buyer_needs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('day', sa.String(length=10), nullable=False),
        sa.Column('text_hash', sa.String(length=64), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('origin', sa.String(length=10), nullable=False),
        sa.Column('matched', sa.Integer(), nullable=False),
        sa.Column('agent_platform', sa.String(length=20), nullable=True),
        sa.Column('themes', sa.JSON(), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('repeat_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('text_hash'),
    )
    with op.batch_alter_table('buyer_needs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_buyer_needs_day'), ['day'], unique=False)
        batch_op.create_index(batch_op.f('ix_buyer_needs_created_at'), ['created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('buyer_needs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_buyer_needs_created_at'))
        batch_op.drop_index(batch_op.f('ix_buyer_needs_day'))
    op.drop_table('buyer_needs')
