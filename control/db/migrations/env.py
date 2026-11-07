"""Alembic environment for the control-plane database.

URL resolution, in order: a connection passed in ``config.attributes["connection"]``
(for callers that already hold one), ``sqlalchemy.url`` set on the config, then
``$DATABASE_URL``. ``target_metadata`` is :data:`control.db.tables.Base.metadata`, so
``alembic revision --autogenerate`` diffs against the declared tables.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool

from control.db.engine import create_db_engine, database_url
from control.db.tables import Base

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return database_url(config.get_main_option("sqlalchemy.url") or None)


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL to stdout (``alembic upgrade head --sql``) without a database."""
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    engine = create_db_engine(_url(), poolclass=pool.NullPool)
    try:
        with engine.connect() as conn:
            _configure(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
