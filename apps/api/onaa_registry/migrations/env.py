"""Alembic environment. Database URL comes from ONAA_DATABASE_URL (or -x url=...), never from a file."""

from __future__ import annotations

import os

from alembic import context

from onaa_registry import models  # noqa: F401  (register tables)
from onaa_registry.db import Base, make_engine

config = context.config
url = context.get_x_argument(as_dictionary=True).get("url") or os.environ.get(
    "ONAA_DATABASE_URL", "sqlite:///./onaa_dev.db")
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is not None:
        context.configure(connection=connectable, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = make_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
