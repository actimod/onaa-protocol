"""pilot: delete the test accounts named "x" that an old deploy check made through the retired POST /v1/pilot/join

Founder, 2026-11-19 ("테스트용 계정은 삭제"): the nickname-only accounts named "x" (no email, no operator, made by
the retired join endpoint) are test leftovers, so they are deleted with everything they own. Guarded: only accounts
of kind nickname, named exactly "x" (any case), with no email and no operator, that the join endpoint made (audit
event pilot.member_joined), and only when 1 to 5 such accounts exist; otherwise nothing is deleted. It logs how
many accounts it deleted. Other members' conversations that mention them are theirs and are kept.

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-19 12:00:00
"""
from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op

revision = '0032'
down_revision = '0031'
branch_labels = None
depends_on = None

MAX_ACCOUNTS = 5
log = logging.getLogger("alembic.runtime.migration")

FIND = sa.text(
    "SELECT id, listing_id FROM pilot_members WHERE kind = 'nickname' AND email_hash IS NULL "
    "AND operator_member_id IS NULL AND lower(trim(nickname)) = 'x' AND id IN "
    "(SELECT subject_id FROM audit_events WHERE action = 'pilot.member_joined' AND subject_id IS NOT NULL)")

# Children first, so the result is the same with or without ON DELETE CASCADE on the server.
DELETES = (
    "DELETE FROM pilot_question_reports WHERE reporter_id IN :ids",
    "DELETE FROM pilot_listing_reports WHERE reporter_id IN :ids",
    "DELETE FROM pilot_listing_reports WHERE (target_type = 'item' AND target_id IN "
    "(SELECT id FROM pilot_items WHERE seller_id IN :ids)) OR (target_type = 'want' AND target_id IN "
    "(SELECT id FROM pilot_wants WHERE buyer_id IN :ids))",
    "DELETE FROM pilot_question_reports WHERE question_id IN (SELECT id FROM pilot_item_questions WHERE "
    "author_id IN :ids OR item_id IN (SELECT id FROM pilot_items WHERE seller_id IN :ids))",
    "DELETE FROM pilot_item_questions WHERE parent_id IS NOT NULL AND (author_id IN :ids OR item_id IN "
    "(SELECT id FROM pilot_items WHERE seller_id IN :ids))",
    "DELETE FROM pilot_item_questions WHERE author_id IN :ids OR item_id IN "
    "(SELECT id FROM pilot_items WHERE seller_id IN :ids)",
    "DELETE FROM pilot_offers WHERE buyer_id IN :ids OR seller_id IN :ids OR item_id IN "
    "(SELECT id FROM pilot_items WHERE seller_id IN :ids)",
    "DELETE FROM pilot_items WHERE seller_id IN :ids",
    "DELETE FROM pilot_wants WHERE buyer_id IN :ids",
    "DELETE FROM pilot_chat_messages WHERE conversation_id IN "
    "(SELECT id FROM pilot_conversations WHERE member_id IN :ids)",
    "DELETE FROM pilot_conversations WHERE member_id IN :ids",
    "DELETE FROM pilot_a2a_messages WHERE deal_id IN (SELECT id FROM pilot_a2a_deals WHERE member_id IN :ids)",
    "DELETE FROM pilot_a2a_deals WHERE member_id IN :ids",
    "DELETE FROM pilot_events WHERE member_id IN :ids",
    "DELETE FROM pilot_inbox_counters WHERE member_id IN :ids",
    "DELETE FROM pilot_oauth_tokens WHERE member_id IN :ids",
    "DELETE FROM pilot_webhooks WHERE member_id IN :ids",
    "DELETE FROM pilot_members WHERE id IN :ids",
)


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(FIND).all()
    if not 1 <= len(rows) <= MAX_ACCOUNTS:
        msg = f"0032: {len(rows)} test accounts named x found; deleting none (expected 1 to {MAX_ACCOUNTS})"
        log.info(msg)
        print(msg, flush=True)
        return
    ids = [r[0] for r in rows]
    listings = [r[1] for r in rows if r[1]]
    for sql in DELETES:
        conn.execute(sa.text(sql).bindparams(sa.bindparam("ids", expanding=True)), {"ids": ids})
    if listings:
        conn.execute(sa.text("DELETE FROM listings WHERE id IN :ids").bindparams(
            sa.bindparam("ids", expanding=True)), {"ids": listings})
    msg = f"0032: deleted {len(ids)} test accounts named x (and {len(listings)} directory listings)"
    log.info(msg)
    print(msg, flush=True)


def downgrade() -> None:
    """Deleted test accounts are not restored."""
