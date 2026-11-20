"""pilot: Q&A reports can lapse

Founder decision 2026-11-19 (review): a Q&A entry hidden by reports that no admin reviews within a week comes
back, and those reports stop counting (status lapsed), as listing reports already do.

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-19 18:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0035'
down_revision = '0034'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('pilot_question_reports',
                  sa.Column('status', sa.String(10), nullable=False, server_default='open'))


def downgrade() -> None:
    op.drop_column('pilot_question_reports', 'status')
