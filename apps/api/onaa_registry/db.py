from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
    elif url.startswith("postgresql"):
        # Neon closes idle connections and can pause; without these a dead pooled connection makes a query hang
        # until the kernel gives up, while the request (and its pool slot) waits. Check connections before use,
        # recycle them, detect a dead peer with TCP keepalives and cap any single statement.
        kwargs.update(pool_pre_ping=True, pool_recycle=300, pool_timeout=10, connect_args={
            "connect_timeout": 10, "keepalives": 1, "keepalives_idle": 30, "keepalives_interval": 10,
            "keepalives_count": 3, "options": "-c statement_timeout=60000"})
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.sessionmaker()
    try:
        from .verification import maybe_sweep

        maybe_sweep(request.app.state, session)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
