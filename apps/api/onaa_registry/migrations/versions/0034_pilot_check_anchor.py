"""pilot: remember when a member's recurring check runs, apart from one-off checks

Retest 2026-11-19: Claude pins an hourly task to the minute it was made (e.g. :28), and the founder wants the two
AIs of a negotiation to line up their checks. check_anchor_at is one real run of the recurring task (later runs
are counted from it); next_check_at stays a one-off check, such as an extra run at the other side's check time.

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-19 16:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0034'
down_revision = '0033'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('pilot_members', sa.Column('check_anchor_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('pilot_members', 'check_anchor_at')
