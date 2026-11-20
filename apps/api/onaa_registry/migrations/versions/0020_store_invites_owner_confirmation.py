"""store invites and owner confirmation

Stores register with a one-time "verify my store" link sent to the contact address the store publishes itself
(founder decision 2026-11-17). Adds `store_invites` and two listing columns recording how an operator confirmed
they manage a listing without proving endpoint control (`owner_confirmed_via`, `owner_confirmed_at`).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-17 05:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('owner_confirmed_via', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('owner_confirmed_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'store_invites',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('listing_id', sa.String(length=40), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('email_source_url', sa.String(length=2048), nullable=False),
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('operator_id', sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(['listing_id'], ['listings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code_hash'),
    )
    with op.batch_alter_table('store_invites', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_store_invites_listing_id'), ['listing_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('store_invites', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_store_invites_listing_id'))
    op.drop_table('store_invites')
    with op.batch_alter_table('listings', schema=None) as batch_op:
        batch_op.drop_column('owner_confirmed_at')
        batch_op.drop_column('owner_confirmed_via')
