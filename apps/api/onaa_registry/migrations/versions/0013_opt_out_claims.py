"""pending opt-outs of discovered entries: hide now, erase after proof of host control or restore after 7 days

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-16 06:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'opt_out_claims',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('host', sa.String(length=253), nullable=False),
        sa.Column('scope', sa.String(length=10), nullable=False),
        sa.Column('key_hashes', sa.JSON(), nullable=False),
        sa.Column('listing_ids', sa.JSON(), nullable=False),
        sa.Column('nonce_hash', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=12), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('opt_out_claims', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_opt_out_claims_host'), ['host'], unique=False)
        batch_op.create_index(batch_op.f('ix_opt_out_claims_state'), ['state'], unique=False)
        batch_op.create_index(batch_op.f('ix_opt_out_claims_expires_at'), ['expires_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('opt_out_claims', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_opt_out_claims_expires_at'))
        batch_op.drop_index(batch_op.f('ix_opt_out_claims_state'))
        batch_op.drop_index(batch_op.f('ix_opt_out_claims_host'))
    op.drop_table('opt_out_claims')
