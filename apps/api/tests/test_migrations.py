"""ENG-007: Alembic migrations produce exactly the ORM schema (SQLite always; PostgreSQL when configured)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
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
