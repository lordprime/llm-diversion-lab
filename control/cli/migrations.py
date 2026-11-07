"""Alembic helpers that need no ``alembic.ini``: head and current revisions, upgrade.

The migration scripts are found next to :mod:`control.db.migrations`, so this works
from a source checkout and from the control-plane image alike. Alembic's logger
configuration is switched off (``configure_logger = False``): the caller has already
run :func:`~control.core.logging.configure_logging`, and Alembic's ``fileConfig``
would replace that redacting JSON handler with plain text.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

import control.db.migrations as _migrations

__all__ = [
    "MIGRATIONS_DIR",
    "alembic_config",
    "current_revisions",
    "head_revisions",
    "upgrade_head",
]

MIGRATIONS_DIR = Path(_migrations.__file__).resolve().parent


def alembic_config() -> Config:
    """An in-memory Alembic config for :data:`MIGRATIONS_DIR` (no URL: pass a connection)."""
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["configure_logger"] = False
    return cfg


def head_revisions() -> frozenset[str]:
    """The head revision(s) of the migration scripts."""
    return frozenset(ScriptDirectory.from_config(alembic_config()).get_heads())


def current_revisions(engine: Engine) -> frozenset[str]:
    """The revision(s) the database is at (empty if it was never migrated)."""
    with engine.connect() as conn:
        return frozenset(MigrationContext.configure(conn).get_current_heads())


def upgrade_head(engine: Engine) -> None:
    """``alembic upgrade head`` on ``engine``, in one transaction."""
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
