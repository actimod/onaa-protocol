"""pilot: gapless inbox sequence numbers, structured message data, public listing Q&A

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-18 23:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0029'
down_revision = '0028'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.add_column(sa.Column('inbox_seq', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('public_handle', sa.String(length=12), nullable=True))
        # a unique index, not a constraint: SQLite adds it without rebuilding pilot_members (a rebuild would
        # cascade-delete conversations there)
        batch_op.create_index(batch_op.f('ix_pilot_members_public_handle'), ['public_handle'], unique=True)
    with op.batch_alter_table('pilot_chat_messages', schema=None) as batch_op:
        batch_op.add_column(sa.Column('data', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('seq', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_pilot_chat_messages_seq'), ['seq'], unique=False)
    op.create_table(
        'pilot_inbox_counters',
        sa.Column('member_id', sa.String(length=40), nullable=False),
        sa.Column('last_seq', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['member_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('member_id'),
    )
    op.create_table(
        'pilot_item_questions',
        sa.Column('id', sa.String(length=40), nullable=False),
        sa.Column('item_id', sa.String(length=40), nullable=False),
        sa.Column('author_id', sa.String(length=40), nullable=False),
        sa.Column('parent_id', sa.String(length=40), nullable=True),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('flags', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('hidden_by', sa.String(length=10), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['item_id'], ['pilot_items.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['parent_id'], ['pilot_item_questions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pilot_item_questions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_item_questions_item_id'), ['item_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_item_questions_author_id'), ['author_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_item_questions_parent_id'), ['parent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pilot_item_questions_created_at'), ['created_at'], unique=False)
    op.create_table(
        'pilot_question_reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('question_id', sa.String(length=40), nullable=False),
        sa.Column('reporter_id', sa.String(length=40), nullable=False),
        sa.Column('reason', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['question_id'], ['pilot_item_questions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reporter_id'], ['pilot_members.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('question_id', 'reporter_id', name='uq_pilot_question_report'),
    )
    with op.batch_alter_table('pilot_question_reports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pilot_question_reports_question_id'), ['question_id'], unique=False)
    _backfill_seq()


def _backfill_seq() -> None:
    """Number every member's stored incoming messages 1..n in arrival order and start check_inbox's mark after the
    ones it already returned (those that arrived before the old time mark)."""
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT m.id, c.member_id, m.created_at FROM pilot_chat_messages m "
        "JOIN pilot_conversations c ON c.id = m.conversation_id WHERE m.direction = 'in' ORDER BY m.id")).all()
    marks = {r[0]: r[1] for r in conn.execute(sa.text("SELECT id, inbox_cursor FROM pilot_members")).all()}
    last: dict[str, int] = {}
    seen: dict[str, int] = {}
    for msg_id, member_id, created in rows:
        n = last.get(member_id, 0) + 1
        last[member_id] = n
        conn.execute(sa.text("UPDATE pilot_chat_messages SET seq = :n WHERE id = :id"), {"n": n, "id": msg_id})
        mark = marks.get(member_id)
        if mark is not None and _naive(created) <= _naive(mark):
            seen[member_id] = n
    for member_id, n in last.items():
        conn.execute(sa.text("INSERT INTO pilot_inbox_counters (member_id, last_seq) VALUES (:m, :n)"),
                     {"m": member_id, "n": n})
    for member_id, n in seen.items():
        conn.execute(sa.text("UPDATE pilot_members SET inbox_seq = :n WHERE id = :m"), {"n": n, "m": member_id})


def _naive(t):
    import datetime as dt

    if isinstance(t, str):  # SQLite returns text
        t = dt.datetime.fromisoformat(t)
    return t.astimezone(dt.UTC).replace(tzinfo=None) if t.tzinfo else t


def downgrade() -> None:
    op.drop_table('pilot_question_reports')
    op.drop_table('pilot_item_questions')
    op.drop_table('pilot_inbox_counters')
    with op.batch_alter_table('pilot_chat_messages', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pilot_chat_messages_seq'))
        batch_op.drop_column('seq')
        batch_op.drop_column('data')
    with op.batch_alter_table('pilot_members', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pilot_members_public_handle'))
        batch_op.drop_column('public_handle')
        batch_op.drop_column('inbox_seq')
