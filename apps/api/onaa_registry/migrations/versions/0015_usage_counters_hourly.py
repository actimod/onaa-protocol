"""hourly anonymous usage counters, kept 30 days

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-16 07:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'usage_counters_hourly',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('hour', sa.String(length=13), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('key', sa.String(length=160), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hour', 'kind', 'key'),
    )
    with op.batch_alter_table('usage_counters_hourly', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_usage_counters_hourly_hour'), ['hour'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('usage_counters_hourly', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_usage_counters_hourly_hour'))
    op.drop_table('usage_counters_hourly')
