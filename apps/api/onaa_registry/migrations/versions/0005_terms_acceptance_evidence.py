"""terms acceptance evidence and operator authority

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-12 08:10:00

Adds acceptance evidence (terms text hash, time, method), a private operator notice contact, and the agent's
operator-authority confirmation for self-registration. Existing rows keep NULL/false: they accepted draft-0.1,
which had no published text; new registrations must accept the bundled draft-0.2 text.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('operators', schema=None) as batch_op:
        batch_op.add_column(sa.Column('terms_sha256', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('terms_acceptance_method', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('operator_contact', sa.String(length=320), nullable=True))

    with op.batch_alter_table('self_registrations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('terms_sha256', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('operator_authority_confirmed', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
        batch_op.add_column(sa.Column('operator_contact', sa.String(length=320), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('self_registrations', schema=None) as batch_op:
        batch_op.drop_column('operator_contact')
        batch_op.drop_column('operator_authority_confirmed')
        batch_op.drop_column('terms_sha256')

    with op.batch_alter_table('operators', schema=None) as batch_op:
        batch_op.drop_column('operator_contact')
        batch_op.drop_column('terms_acceptance_method')
        batch_op.drop_column('terms_accepted_at')
        batch_op.drop_column('terms_sha256')
