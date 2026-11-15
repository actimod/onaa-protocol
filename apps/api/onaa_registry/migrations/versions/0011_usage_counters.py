"""anonymous daily usage counters (agent traffic measurement)

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-14 11:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'usage_counters',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('day', sa.String(length=10), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('key', sa.String(length=160), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('day', 'kind', 'key'),
    )
    with op.batch_alter_table('usage_counters', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_usage_counters_day'), ['day'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('usage_counters', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_usage_counters_day'))
    op.drop_table('usage_counters')
