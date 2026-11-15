"""buying channels: agent_checkout probe result

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-14 08:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('agent_checkout', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.drop_column('agent_checkout')
