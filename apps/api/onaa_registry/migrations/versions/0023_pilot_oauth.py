"""pilot OAuth sign-in for MCP connectors, member email hash

Standard MCP remote-server authorization (OAuth 2.1 with PKCE, dynamic client registration). Members sign in with
an emailed one-time code; only hashes of emails, codes and tokens are stored.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-18 00:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0023'
down_revision = '0022'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('welcomed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_unique_constraint('uq_pilot_members_email_hash', ['email_hash'])
    op.create_table(
        'pilot_oauth_clients',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('secret_hash', sa.String(length=64), nullable=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('redirect_uris', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'pilot_oauth_logins',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('redirect_uri', sa.String(length=2048), nullable=False),
        sa.Column('state', sa.String(length=512), nullable=True),
        sa.Column('code_challenge', sa.String(length=128), nullable=False),
        sa.Column('scope', sa.String(length=100), nullable=False),
        sa.Column('email_hash', sa.String(length=64), nullable=True),
        sa.Column('nickname', sa.String(length=40), nullable=True),
        sa.Column('otp_hash', sa.String(length=64), nullable=True),
        sa.Column('otp_attempts', sa.Integer(), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=True),
        sa.Column('code_hash', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code_hash'),
    )
    with op.batch_alter_table('pilot_oauth_logins', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_oauth_logins_client_id'), ['client_id'], unique=False)
    op.create_table(
        'pilot_oauth_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=10), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('family', sa.String(length=40), nullable=False),
        sa.Column('scope', sa.String(length=100), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    with op.batch_alter_table('pilot_oauth_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_oauth_tokens_member_id'), ['member_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_oauth_tokens_family'), ['family'], unique=False)


def downgrade() -> None:
    op.drop_table('pilot_oauth_tokens')
    op.drop_table('pilot_oauth_logins')
    op.drop_table('pilot_oauth_clients')
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.drop_constraint('uq_pilot_members_email_hash', type_='unique')
        batch_op.drop_column('welcomed_at')
        batch_op.drop_column('email_hash')
