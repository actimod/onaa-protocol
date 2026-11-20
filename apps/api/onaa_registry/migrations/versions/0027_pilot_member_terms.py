"""pilot members: member terms acceptance (version, hash, time, method)

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-18 22:10:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0027'
down_revision = '0026'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.add_column(sa.Column('terms_version', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('terms_sha256', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('terms_accepted_via', sa.String(length=40), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.drop_column('terms_accepted_via')
        batch_op.drop_column('terms_accepted_at')
        batch_op.drop_column('terms_sha256')
        batch_op.drop_column('terms_version')
