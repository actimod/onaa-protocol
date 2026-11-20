"""pilot members: kind (person | agent), operator claim and Google check, for one-call agent sign-up

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-18 23:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0028'
down_revision = '0027'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_members') as b:
        b.add_column(sa.Column('kind', sa.String(length=10), nullable=False, server_default='person'))
        b.add_column(sa.Column('operator_member_id', sa.String(length=40), nullable=True))
        b.add_column(sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column('claim_code_hash', sa.String(length=64), nullable=True))
        b.add_column(sa.Column('claim_expires_at', sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column('google_verified_at', sa.DateTime(timezone=True), nullable=True))
        b.create_index('ix_pilot_members_operator_member_id', ['operator_member_id'])
        b.create_unique_constraint('uq_pilot_members_claim_code_hash', ['claim_code_hash'])


def downgrade() -> None:
    with op.batch_alter_table('pilot_members') as b:
        b.drop_constraint('uq_pilot_members_claim_code_hash', type_='unique')
        b.drop_index('ix_pilot_members_operator_member_id')
        for col in ('google_verified_at', 'claim_expires_at', 'claim_code_hash', 'claimed_at', 'operator_member_id',
                    'kind'):
            b.drop_column(col)
