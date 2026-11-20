"""pilot listings and wants: quantity, condition, trade and payment methods (required for new ones)

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-18 21:40:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('quantity', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('trade_methods', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('payment_methods', sa.String(length=80), nullable=True))
    with op.batch_alter_table('pilot_wants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('quantity', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('conditions', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('trade_methods', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('payment_methods', sa.String(length=80), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('pilot_wants', schema=None) as batch_op:
        batch_op.drop_column('payment_methods')
        batch_op.drop_column('trade_methods')
        batch_op.drop_column('conditions')
        batch_op.drop_column('quantity')
    with op.batch_alter_table('pilot_items', schema=None) as batch_op:
        batch_op.drop_column('payment_methods')
        batch_op.drop_column('trade_methods')
        batch_op.drop_column('quantity')
