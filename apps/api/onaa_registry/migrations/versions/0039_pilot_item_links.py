"""pilot: up to 3 links on a listing (photos or product pages), never opened by ONAA

Founder decision 2026-11-20: photos travel as https links only (no upload or storage by ONAA). Links are shown only
while the listing is on sale and cleared when it is sold or removed.

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-20 05:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0039'
down_revision = '0038'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('pilot_items', sa.Column('links', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('pilot_items', 'links')
