"""retire nickname-only sign-up: accounts made by POST /v1/pilot/join become kind=nickname (browse only)

Founder, 2026-11-18: nobody answers for these accounts (no email, no operator), so they keep their data but can only
browse listings and wants; their hosted address stops taking messages and their directory listing is withdrawn.
Identified by the audit event the join endpoint wrote (pilot.member_joined). Nothing is deleted.

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-18 23:40:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0030'
down_revision = '0029'
branch_labels = None
depends_on = None

JOINED = ("SELECT subject_id FROM audit_events WHERE action = 'pilot.member_joined' AND subject_id IS NOT NULL")


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text(
        "UPDATE listings SET lifecycle_status = 'deleted', status_reason = 'nickname sign-up retired' "
        f"WHERE id IN (SELECT listing_id FROM pilot_members WHERE listing_id IS NOT NULL AND id IN ({JOINED}) "
        "AND kind = 'person' AND email_hash IS NULL) AND lifecycle_status != 'deleted'"))
    conn.execute(sa.text(
        "UPDATE pilot_members SET kind = 'nickname', a2a_enabled = false "
        f"WHERE id IN ({JOINED}) AND kind = 'person' AND email_hash IS NULL"))


def downgrade() -> None:
    op.get_bind().execute(sa.text("UPDATE pilot_members SET kind = 'person' WHERE kind = 'nickname'"))
