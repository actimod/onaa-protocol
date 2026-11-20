"""selling-agent pilot tables

Invite-only stage-1 pilot (founder decision 2026-11-17): members list items and make offers through a personal MCP
connector. Off unless ONAA_PILOT_ENABLED=1; all rows are wiped with DELETE /v1/admin/pilot when the pilot ends.

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-17 09:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'pilot_members',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('nickname', sa.String(length=40), nullable=False),
        sa.Column('region', sa.String(length=80), nullable=True),
        sa.Column('contact', sa.String(length=200), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('a2a_enabled', sa.Boolean(), nullable=False),
        sa.Column('auto_confirm', sa.Boolean(), nullable=False),
        sa.Column('country', sa.String(length=2), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('check_every_minutes', sa.Integer(), nullable=True),
        sa.Column('next_check_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('operator_id', sa.String(length=40), nullable=True),
        sa.Column('listing_id', sa.String(length=40), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_table(
        'pilot_items',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('seller_id', sa.String(length=40), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('price', sa.Integer(), nullable=False),
        sa.Column('floor_price', sa.Integer(), nullable=True),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('category', sa.String(length=20), nullable=False),
        sa.Column('condition', sa.String(length=20), nullable=True),
        sa.Column('region', sa.String(length=80), nullable=True),
        sa.Column('photo_url', sa.String(length=2048), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['seller_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_items_category'), ['category'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_items_seller_id'), ['seller_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_items_status'), ['status'], unique=False)
    op.create_table(
        'pilot_offers',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('item_id', sa.String(length=40), nullable=False),
        sa.Column('buyer_id', sa.String(length=40), nullable=False),
        sa.Column('seller_id', sa.String(length=40), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('turn', sa.String(length=10), nullable=False),
        sa.Column('rounds', sa.Integer(), nullable=False),
        sa.Column('history', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['item_id'], ['pilot_items.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['buyer_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['seller_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_offers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_offers_item_id'), ['item_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_offers_buyer_id'), ['buyer_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_offers_seller_id'), ['seller_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_offers_status'), ['status'], unique=False)


    op.create_table(
        'pilot_a2a_deals',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('rfq_id', sa.String(length=128), nullable=False),
        sa.Column('role', sa.String(length=10), nullable=False),
        sa.Column('counterparty_agent_id', sa.String(length=200), nullable=False),
        sa.Column('counterparty_card_url', sa.String(length=2048), nullable=True),
        sa.Column('item_ids', sa.JSON(), nullable=False),
        sa.Column('state', sa.String(length=20), nullable=False),
        sa.Column('currency', sa.String(length=3), nullable=True),
        sa.Column('total_minor', sa.Integer(), nullable=True),
        sa.Column('order_id', sa.String(length=128), nullable=True),
        sa.Column('pending_order', sa.JSON(), nullable=True),
        sa.Column('approved_quote_id', sa.String(length=128), nullable=True),
        sa.Column('unread', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('member_id', 'rfq_id', 'role'),
    )
    with op.batch_alter_table('pilot_a2a_deals', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_a2a_deals_member_id'), ['member_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_a2a_deals_order_id'), ['order_id'], unique=False)
    op.create_table(
        'pilot_a2a_messages',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('deal_id', sa.String(length=40), nullable=False),
        sa.Column('direction', sa.String(length=3), nullable=False),
        sa.Column('env_type', sa.String(length=40), nullable=False),
        sa.Column('env_id', sa.String(length=128), nullable=False),
        sa.Column('envelope', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['deal_id'], ['pilot_a2a_deals.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_a2a_messages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_a2a_messages_deal_id'), ['deal_id'], unique=False)


def downgrade() -> None:
    op.drop_table('pilot_a2a_messages')
    op.drop_table('pilot_a2a_deals')
    op.drop_table('pilot_offers')
    op.drop_table('pilot_items')
    op.drop_table('pilot_members')
