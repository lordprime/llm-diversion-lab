"""Engine and session helpers for the control-plane Postgres database.

The database URL comes from the ``DATABASE_URL`` environment variable (twelve-factor),
unless passed explicitly. Plain ``postgresql://`` / ``postgres://`` URLs are pinned to
the psycopg 3 driver. Only PostgreSQL is accepted: the run queue relies on
``SELECT ... FOR UPDATE SKIP LOCKED`` and the event tables on ``ON CONFLICT``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from typing import Any, Final

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

__all__ = [
    "DATABASE_URL_ENV",
    "create_db_engine",
    "database_url",
    "get_engine",
    "session_scope",
]

#: Environment variable holding the database URL.
DATABASE_URL_ENV: Final = "DATABASE_URL"

_DRIVER: Final = "postgresql+psycopg"


def database_url(url: str | None = None) -> str:
    """Return ``url`` (or ``$DATABASE_URL``) normalised to the psycopg 3 driver.

    Raises ``RuntimeError`` if no URL is configured and ``ValueError`` if it is not a
    PostgreSQL URL.
    """
    raw = url if url is not None else os.environ.get(DATABASE_URL_ENV)
    if not raw:
        raise RuntimeError(f"no database URL: set {DATABASE_URL_ENV}")
    parsed = make_url(raw)
    backend, _, driver = parsed.drivername.partition("+")
    if backend not in ("postgresql", "postgres"):
        raise ValueError(f"unsupported database backend {backend!r}: PostgreSQL is required")
    if driver not in ("", "psycopg"):
        raise ValueError(f"unsupported PostgreSQL driver {driver!r}: use psycopg (v3)")
    return parsed.set(drivername=_DRIVER).render_as_string(hide_password=False)


def create_db_engine(url: str | None = None, **kwargs: Any) -> Engine:
    """Create an engine for ``url`` (default ``$DATABASE_URL``).

    ``pool_pre_ping`` is on so a worker survives a Postgres restart between claims.
    Extra keyword arguments go to :func:`sqlalchemy.create_engine`.
    """
    kwargs.setdefault("pool_pre_ping", True)
    return create_engine(database_url(url), **kwargs)


@lru_cache(maxsize=1)
def _default_engine(url: str) -> Engine:
    return create_db_engine(url)


def get_engine() -> Engine:
    """Return the process-wide engine for ``$DATABASE_URL`` (created on first use)."""
    return _default_engine(database_url())


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """Yield a session inside one transaction: commit on success, roll back on error.

    ``engine`` defaults to :func:`get_engine`. Objects stay loaded after the commit
    (``expire_on_commit=False``), so a returned row can be used outside the scope.
    """
    with Session(engine or get_engine(), expire_on_commit=False) as session, session.begin():
        yield session
