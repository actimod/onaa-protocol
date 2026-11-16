"""one-time links that hand a self-registered operator its API key outside the agent's conversation

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-16 06:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'key_claims',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('operator_id', sa.String(length=40), nullable=False),
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['operator_id'], ['operators.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code_hash'),
    )
    with op.batch_alter_table('key_claims', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_key_claims_operator_id'), ['operator_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('key_claims', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_key_claims_operator_id'))
    op.drop_table('key_claims')
