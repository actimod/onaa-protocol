"""pilot: when the member's AI last ran a check, so a published schedule that stopped running is not trusted

Bookshelf retest 2026-11-19: the buyer's account kept a 5-minute schedule from an earlier test, so its counterparty
saw "next check in 1 min" and the buyer's AI was never asked to set up a check. last_check_at is set by check_inbox
and by publishing a schedule; a recurring schedule counts only while checks keep arriving.

Revision ID: 0036
Revises: 0035
Create Date: 2026-11-19 18:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0036'
down_revision = '0035'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('pilot_members', sa.Column('last_check_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('pilot_members', 'last_check_at')
