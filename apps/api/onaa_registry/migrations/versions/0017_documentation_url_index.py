"""index listings.documentation_url: store pages look stores up by their manifest URL

Without it every /stores/<domain> and /v1/stores/<domain> request scanned the whole listings table (twice), and a
crawler reading thousands of store pages saturated the database (production slowdown 2026-11-16).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-16 10:40:00
"""
from __future__ import annotations

from alembic import op

revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_listings_documentation_url'), ['documentation_url'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_listings_documentation_url'))
