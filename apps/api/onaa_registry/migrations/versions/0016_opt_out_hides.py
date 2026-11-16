"""opt-out requests that only offer proof: no second unproven hide for a host within 30 days

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-16 08:40:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('opt_out_claims', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hides', sa.Boolean(), server_default=sa.true(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('opt_out_claims', schema=None) as batch_op:
        batch_op.drop_column('hides')
