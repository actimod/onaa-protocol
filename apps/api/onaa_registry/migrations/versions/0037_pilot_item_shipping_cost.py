"""pilot: shipping cost on listings, so buyers' AIs can compare several listings on item price plus shipping

Founder decision 2026-11-20 (multi-listing search and comparison): shipped deals are compared on the total the
buyer pays. Sellers state the cost when listing (0 = free); NULL means not stated or it depends on the address,
and the buyer's AI asks the seller.

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-20 03:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0037'
down_revision = '0036'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('pilot_items', sa.Column('shipping_cost', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('pilot_items', 'shipping_cost')
