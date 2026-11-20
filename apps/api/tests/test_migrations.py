"""ENG-007: Alembic migrations produce exactly the ORM schema (SQLite always; PostgreSQL when configured)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from onaa_registry.db import Base, make_engine

API_DIR = Path(__file__).resolve().parents[1]


def _urls(tmp_path):
    urls = [f"sqlite:///{tmp_path / 'mig.db'}"]
    pg = os.environ.get("ONAA_TEST_DATABASE_URL", "")
    if pg.startswith("postgresql"):
        urls.append(pg)
    return urls


def _cfg(url: str) -> Config:
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "onaa_registry" / "migrations"))
    cfg.cmd_opts = type("o", (), {"x": [f"url={url}"]})()
    return cfg


@pytest.mark.parametrize("which", [0, 1])
def test_upgrade_matches_models_and_downgrades(tmp_path, which):
    urls = _urls(tmp_path)
    if which >= len(urls):
        pytest.skip("ONAA_TEST_DATABASE_URL (postgresql) not set")
    url = urls[which]
    engine = make_engine(url)
    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    cfg = _cfg(url)
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"migrations drift from models: {diff}"
    command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    engine.dispose()


def test_app_does_not_auto_create_on_server_db_by_default(monkeypatch):
    from onaa_registry.config import Settings
    monkeypatch.setenv("ONAA_DATABASE_URL", "postgresql+psycopg://u@h/db")
    monkeypatch.delenv("ONAA_AUTO_CREATE_SCHEMA", raising=False)
    assert Settings().auto_create_schema is False
    monkeypatch.setenv("ONAA_DATABASE_URL", "sqlite:///x.db")
    assert Settings().auto_create_schema is True


def test_0019_backfills_check_record_from_audit(tmp_path):
    import datetime as dt
    import json

    from sqlalchemy import text

    url = f"sqlite:///{tmp_path / 'bf.db'}"
    engine = make_engine(url)
    cfg = _cfg(url)
    command.upgrade(cfg, "0018")
    cols = {c["name"]: c for c in inspect(engine).get_columns("listings")}
    now = dt.datetime(2026, 11, 14, tzinfo=dt.UTC)
    with engine.begin() as conn:
        values = {"id": "svc_bf", "listing_type": "service", "service_type": "marketplace", "display_name": "bf",
                  "lifecycle_status": "discovered", "agent_checkout": '{"status": "checkout_ready"}',
                  "created_at": now, "updated_at": now}
        for name, col in cols.items():  # fill other NOT NULL columns with neutral values
            if name not in values and not col["nullable"] and col.get("default") is None:
                values[name] = 0 if "INT" in str(col["type"]).upper() or "BOOL" in str(col["type"]).upper() else (
                    "[]" if "JSON" in str(col["type"]).upper() else "x")
        conn.execute(text(f"INSERT INTO listings ({', '.join(values)}) VALUES ({', '.join(':' + k for k in values)})"),
                     values)
        for i, st in enumerate(["failed", "buyer_step_required", "checkout_ready"]):
            conn.execute(text("INSERT INTO audit_events (id, actor_type, action, subject_id, result, detail, "
                              "created_at) VALUES (:id, 'system', 'listing.agent_checkout', 'svc_bf', 'ok', :d, :at)"),
                         {"id": f"evt_{i}", "d": f'{{"status": "{st}"}}', "at": now + dt.timedelta(days=i)})
    command.upgrade(cfg, "0019")
    with engine.connect() as conn:
        ac = json.loads(conn.execute(text("SELECT agent_checkout FROM listings WHERE id='svc_bf'")).scalar())
    assert ac["check_history"] == {"total": 3, "reached": 2, "first": "2026-11-14",
                                   "recent": [["2026-11-16", "checkout_ready"], ["2026-11-15", "buyer_step_required"],
                                              ["2026-11-14", "failed"]]}
    engine.dispose()


def test_0029_numbers_existing_inbox_messages_and_keeps_check_inbox_mark(tmp_path):
    from sqlalchemy import text

    url = f"sqlite:///{tmp_path / 'seq.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "0028")
    engine = make_engine(url)
    with engine.begin() as c:
        c.execute(text("INSERT INTO pilot_members (id, nickname, contact, token_hash, status, a2a_enabled, "
                       "auto_confirm, inbox_cursor, created_at) VALUES ('pm_a', 'a', '', 'h', 'active', 1, 0, "
                       "'2026-11-18 10:30:00', '2026-11-18 09:00:00')"))
        c.execute(text("INSERT INTO pilot_conversations (id, member_id, peer_agent_id, state, initiated_by_me, "
                       "unread, created_at, updated_at) VALUES ('pc_1', 'pm_a', 'x', 'open', 0, 0, "
                       "'2026-11-18 09:00:00', '2026-11-18 09:00:00')"))
        for i, (d, at) in enumerate([("in", "10:00"), ("out", "10:10"), ("in", "10:20"), ("in", "11:00")]):
            c.execute(text("INSERT INTO pilot_chat_messages (conversation_id, direction, kind, msg_id, text, flags, "
                           "delivery, created_at) VALUES ('pc_1', :d, 'text', :mid, 't', '[]', 'stored', :at)"),
                      {"d": d, "mid": f"msg_{i:08d}", "at": f"2026-11-18 {at}:00"})
    command.upgrade(cfg, "head")
    with engine.connect() as c:
        seqs = c.execute(text("SELECT direction, seq FROM pilot_chat_messages ORDER BY id")).all()
        assert [tuple(r) for r in seqs] == [("in", 1), ("out", None), ("in", 2), ("in", 3)]
        assert c.execute(text("SELECT last_seq FROM pilot_inbox_counters WHERE member_id='pm_a'")).scalar() == 3
        assert c.execute(text("SELECT inbox_seq FROM pilot_members WHERE id='pm_a'")).scalar() == 2
    engine.dispose()


def test_0030_makes_nickname_join_accounts_browse_only(tmp_path):
    from sqlalchemy import text

    url = f"sqlite:///{tmp_path / 'nick.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "0029")
    engine = make_engine(url)
    with engine.begin() as c:
        for mid, email in (("pm_join", None), ("pm_invited", None), ("pm_mail", "eh")):
            c.execute(text("INSERT INTO pilot_members (id, nickname, contact, token_hash, status, a2a_enabled, "
                           "auto_confirm, email_hash, created_at) VALUES (:id, :id, '', :id, 'active', 1, 0, :e, "
                           "'2026-11-18 09:00:00')"), {"id": mid, "e": email})
        for mid, action in (("pm_join", "pilot.member_joined"), ("pm_invited", "pilot.member_created"),
                            ("pm_mail", "pilot.member_joined")):
            c.execute(text("INSERT INTO audit_events (id, actor_type, action, subject_id, result, detail, created_at) "
                           "VALUES (:e, 'pilot', :a, :id, 'ok', '{}', '2026-11-18 09:00:00')"),
                      {"e": "evt_" + mid, "a": action, "id": mid})
    command.upgrade(cfg, "head")
    with engine.connect() as c:
        rows = dict(c.execute(text("SELECT id, kind || ':' || a2a_enabled FROM pilot_members")).all())
    # only the nickname sign-up without an email changes; admin-invited and email members stay as they were
    assert rows == {"pm_join": "nickname:0", "pm_invited": "person:1", "pm_mail": "person:1"}
    engine.dispose()


def _seed_x_accounts(url, names):
    """Members as the retired /join made them (kind nickname, no email), plus one real member with an item."""
    from sqlalchemy.orm import Session

    from onaa_registry.models import (
        AuditEvent,
        PilotChatMessage,
        PilotConversation,
        PilotItem,
        PilotMember,
        PilotOffer,
        PilotWant,
    )
    engine = make_engine(url)
    with Session(engine) as s, s.begin():
        # Core inserts name only the columns given (plus defaults), so columns added after 0031 are not needed
        members = PilotMember.__table__
        s.execute(members.insert().values(id="pm_real", nickname="Actimod", contact="", token_hash="t_real",
                                          email_hash="eh"))
        for i, (name, kind, email, joined) in enumerate(names):
            mid = f"pm_{i}"
            s.execute(members.insert().values(id=mid, nickname=name, contact="", token_hash=f"t_{i}", kind=kind,
                                              email_hash=email))
            if joined:
                s.add(AuditEvent(actor_type="pilot", action="pilot.member_joined", subject_id=mid))
        s.flush()  # no ORM relationships here, so parents are flushed first by hand
        items = PilotItem.__table__  # core insert too: pilot_items gained columns after 0031 (shipping_cost)
        s.execute(items.insert().values(id="it_real", seller_id="pm_real", title="lamp", description="", price=10,
                                        currency="USD", category="for_sale", status="available"))
        s.execute(items.insert().values(id="it_x", seller_id="pm_0", title="test", description="", price=1,
                                        currency="USD", category="for_sale", status="available"))
        s.add(PilotWant(id="wt_x", buyer_id="pm_0", title="test"))
        s.flush()
        # pilot_offers gained columns after 0031 (shopping runs) and some have Python defaults: insert through a
        # copy of the table without them
        later = {"shopping_id", "units", "includes_shipping", "split"}
        offers = sa.Table("pilot_offers", sa.MetaData(),
                          *[c._copy() for c in PilotOffer.__table__.c if c.name not in later])
        s.execute(offers.insert().values(id="of_x", item_id="it_real", buyer_id="pm_0", seller_id="pm_real", amount=5))
        s.add(PilotConversation(id="cv_x", member_id="pm_0", peer_agent_id="peer", state="open"))
        s.flush()
        s.add(PilotChatMessage(conversation_id="cv_x", direction="in", kind="text", msg_id="m1"))
    return engine


def test_0032_deletes_only_the_test_x_accounts(tmp_path):
    from sqlalchemy import text

    url = f"sqlite:///{tmp_path / 'x.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "0031")
    engine = _seed_x_accounts(url, [("x", "nickname", None, True), ("X", "nickname", None, True),
                                    ("x", "nickname", "eh2", True), ("x", "person", None, True),
                                    ("x", "nickname", None, False), ("xy", "nickname", None, True)])
    command.upgrade(cfg, "head")
    with engine.connect() as c:
        members = {r[0] for r in c.execute(text("SELECT id FROM pilot_members"))}
        left = [c.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in
                ("pilot_items", "pilot_wants", "pilot_offers", "pilot_conversations", "pilot_chat_messages")]
    # gone: the two joined nickname accounts named x/X with no email, and all they owned
    assert members == {"pm_real", "pm_2", "pm_3", "pm_4", "pm_5"}
    assert left == [1, 0, 0, 0, 0]
    engine.dispose()


def test_0032_deletes_nothing_when_more_than_five_match(tmp_path):
    from sqlalchemy import text

    url = f"sqlite:///{tmp_path / 'x6.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "0031")
    engine = _seed_x_accounts(url, [("x", "nickname", None, True)] * 6)
    command.upgrade(cfg, "head")
    with engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM pilot_members")).scalar() == 7
        assert c.execute(text("SELECT count(*) FROM pilot_items")).scalar() == 2
    engine.dispose()
