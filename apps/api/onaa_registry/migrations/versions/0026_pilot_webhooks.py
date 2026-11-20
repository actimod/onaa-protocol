"""pilot events (pull) and optional member webhooks (push)

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-18 22:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'pilot_webhooks',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('secret', sa.String(length=300), nullable=False),
        sa.Column('event_types', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('disabled_reason', sa.String(length=200), nullable=True),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.String(length=200), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('member_id'),
    )
    op.create_table(
        'pilot_events',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('seq', sa.Integer(), nullable=True),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('type', sa.String(length=40), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('delivery', sa.String(length=20), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('seq'),
    )
    op.create_index('ix_pilot_events_member_seq', 'pilot_events', ['member_id', 'seq'], unique=False)
    op.create_table(
        'pilot_event_counter',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('value', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_pilot_events_due', 'pilot_events', ['delivery', 'next_attempt_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_pilot_events_due', table_name='pilot_events')
    op.drop_table('pilot_event_counter')
    op.drop_index('ix_pilot_events_member_seq', table_name='pilot_events')
    op.drop_table('pilot_events')
    op.drop_table('pilot_webhooks')
