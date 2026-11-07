from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from control.db.engine import create_db_engine
from control.db.tables import Base
from tests.conftest import alembic_config

EXPECTED_TABLES = {
    "experiments",
    "arms",
    "targets",
    "agents",
    "models",
    "runs",
    "placements",
    "placement_serves",
    "target_access",
    "llm_calls",
    "agent_events",
    "callbacks",
    "oracle_polls",
    "labels",
    "event_keys",
    "artifacts",
    "run_heartbeats",
    "rejected_batches",
}

EVENT_TABLES = {
    "placement_serves",
    "target_access",
    "llm_calls",
    "agent_events",
    "callbacks",
    "oracle_polls",
}


def _tables(url: str) -> set[str]:
    eng = create_db_engine(url)
    try:
        return set(inspect(eng).get_table_names())
    finally:
        eng.dispose()


def test_upgrade_downgrade(db_url: str) -> None:
    """`alembic upgrade head` then `downgrade base` runs clean on an empty DB."""
    cfg = alembic_config(db_url)
    assert _tables(db_url) == set()

    command.upgrade(cfg, "head")
    assert _tables(db_url) == EXPECTED_TABLES | {"alembic_version"}

    command.downgrade(cfg, "base")
    assert _tables(db_url) == {"alembic_version"}

    # and back up again: the downgrade left nothing behind that blocks a re-upgrade
    command.upgrade(cfg, "head")
    assert _tables(db_url) == EXPECTED_TABLES | {"alembic_version"}


def test_metadata_covers_planned_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_migrations_match_metadata(db_url: str) -> None:
    """No drift: the migrated schema is exactly what `tables.py` declares."""
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        with eng.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": True})
            diff = compare_metadata(ctx, Base.metadata)
    finally:
        eng.dispose()
    assert diff == []


def test_event_tables_have_stream_idempotency_key(db_url: str) -> None:
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        insp = inspect(eng)
        for table in EVENT_TABLES:
            uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints(table)}
            assert ("run_id", "stream", "seq") in uniques, table
            assert not any(set(u) == {"run_id", "kind", "seq"} for u in uniques), table
    finally:
        eng.dispose()
