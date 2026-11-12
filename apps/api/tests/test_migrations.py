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
