"""pilot messaging tables (ONAA messaging v0.1)

Agent-to-agent conversations for pilot members over MCP and A2A: a first message to a stranger is an invite,
only an answer opens the conversation, block is silent. Off unless ONAA_PILOT_ENABLED=1.

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-17 23:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0022'
down_revision = '0021'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.add_column(sa.Column('inbox_cursor', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('card_about', sa.String(length=300), nullable=True))
    op.create_table(
        'pilot_conversations',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('peer_agent_id', sa.String(length=256), nullable=False),
        sa.Column('peer_card_url', sa.String(length=2048), nullable=True),
        sa.Column('peer_member_id', sa.String(length=40), nullable=True),
        sa.Column('peer_site', sa.String(length=255), nullable=True),
        sa.Column('peer_availability', sa.JSON(), nullable=True),
        sa.Column('state', sa.String(length=20), nullable=False),
        sa.Column('initiated_by_me', sa.Boolean(), nullable=False),
        sa.Column('unread', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('member_id', 'peer_agent_id', name='uq_pilot_conversation_peer'),
    )
    with op.batch_alter_table('pilot_conversations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_conversations_member_id'), ['member_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_conversations_peer_agent_id'), ['peer_agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_conversations_peer_site'), ['peer_site'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_conversations_updated_at'), ['updated_at'], unique=False)
    op.create_table(
        'pilot_chat_messages',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('conversation_id', sa.String(length=40), nullable=False),
        sa.Column('direction', sa.String(length=3), nullable=False),
        sa.Column('kind', sa.String(length=10), nullable=False),
        sa.Column('msg_id', sa.String(length=80), nullable=False),
        sa.Column('text', sa.Text(), nullable=True),
        sa.Column('flags', sa.JSON(), nullable=False),
        sa.Column('delivery', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['conversation_id'], ['pilot_conversations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('conversation_id', 'msg_id', name='uq_pilot_chat_msg'),
    )
    with op.batch_alter_table('pilot_chat_messages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_chat_messages_conversation_id'), ['conversation_id'],
                              unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_chat_messages_created_at'), ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_table('pilot_chat_messages')
    op.drop_table('pilot_conversations')
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.drop_column('card_about')
        batch_op.drop_column('inbox_cursor')
