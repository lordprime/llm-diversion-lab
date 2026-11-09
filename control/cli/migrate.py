"""The control-plane ``migrate`` one-shot: ``python -m control.cli.migrate``.

``alembic upgrade head`` with the redacted JSON logging configured first. The
database comes from ``$DATABASE_URL`` (else the host's lab.env, see
:mod:`control.cli.settings`). Exit 0 at head, 1 on any failure.

Deliberately **not** a labctl subcommand: on the host, migrations run only through
``release.sh``, which takes a ``pg_dump`` first and rolls back on failure.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence

from sqlalchemy import pool
from sqlalchemy.exc import ArgumentError, SQLAlchemyError

from control.cli.migrations import current_revisions, head_revisions, upgrade_head
from control.cli.settings import ConfigError, LabSettings
from control.core.logging import configure_logging
from control.db.engine import create_db_engine

__all__ = ["main"]

log = logging.getLogger("control.cli.migrate")


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(prog="python -m control.cli.migrate", description=__doc__).parse_args(
        argv
    )
    configure_logging()
    try:
        engine = create_db_engine(
            LabSettings.from_environ().database_url(), poolclass=pool.NullPool
        )
    except ArgumentError:
        log.error("migrate: DATABASE_URL is not a valid database URL")
        return 1
    except (ConfigError, ValueError) as exc:
        log.error("migrate: %s", exc)
        return 1
    try:
        before = sorted(current_revisions(engine))
        upgrade_head(engine)
        after = current_revisions(engine)
    except SQLAlchemyError as exc:
        reason = getattr(exc, "orig", None) or exc
        log.error("migrate: failed: %s: %s", type(reason).__name__, str(reason).strip())
        return 1
    finally:
        engine.dispose()
    if after != head_revisions():
        log.error(
            "migrate: database at %s, expected head %s", sorted(after), sorted(head_revisions())
        )
        return 1
    log.info("migrate: database at head %s (was %s)", sorted(after), before or "empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
