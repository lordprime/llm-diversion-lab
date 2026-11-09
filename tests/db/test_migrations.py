import re
import uuid
from typing import Any

import psycopg
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from psycopg import sql
from sqlalchemy import inspect

from control.core.models import EventKind, InvalidReason
from control.db.engine import create_db_engine
from control.db.tables import Base
from tests.conftest import _libpq_url, alembic_config

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
    "cellguard_decisions",
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
    "cellguard_decisions",
}


def test_runs_invalid_reason_check_is_exactly_the_models_reasons(db_url: str) -> None:
    """The migrated CHECK on runs.invalid_reason lists InvalidReason, no more, no less."""
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        checks = inspect(eng).get_check_constraints("runs")
    finally:
        eng.dispose()
    (check,) = [c for c in checks if c["name"] == "ck_runs_invalid_reason"]
    assert set(re.findall(r"'([a-z_]+)'", check["sqltext"])) == {r.value for r in InvalidReason}


def test_event_keys_kind_check_accepts_every_event_kind(db_url: str) -> None:
    """The migrated CHECK on event_keys.kind lists exactly the model's kinds."""
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        checks = inspect(eng).get_check_constraints("event_keys")
    finally:
        eng.dispose()
    (kind_check,) = [c for c in checks if c["name"] == "ck_event_keys_kind"]
    for kind in EventKind:
        assert f"'{kind.value}'" in kind_check["sqltext"]


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


def _constraints(url: str) -> dict[tuple[str, str], Any]:
    """Every CHECK (normalised text), unique constraint, index and foreign key by name."""
    eng = create_db_engine(url)
    try:
        insp = inspect(eng)
        found: dict[tuple[str, str], Any] = {}
        for table in insp.get_table_names():
            if table == "alembic_version":
                continue
            for c in insp.get_check_constraints(table):
                found[(table, f"CK:{c['name']}")] = " ".join(c["sqltext"].split())
            for c in insp.get_unique_constraints(table):
                found[(table, f"UQ:{c['name']}")] = tuple(c["column_names"])
            for c in insp.get_indexes(table):
                found[(table, f"IX:{c['name']}")] = (
                    tuple(c["column_names"]),
                    bool(c.get("unique")),
                    str(c.get("dialect_options")),
                )
            for c in insp.get_foreign_keys(table):
                found[(table, f"FK:{c['name']}")] = (
                    tuple(c["constrained_columns"]),
                    c["referred_table"],
                    tuple(c["referred_columns"]),
                )
        return found
    finally:
        eng.dispose()


def test_migrated_constraints_match_create_all(db_url: str, pg_server_url: str) -> None:
    """The migrated schema's CHECKs (by text), uniques, indexes and FKs are exactly what
    ``Base.metadata.create_all`` builds: ``compare_metadata`` does not compare CHECK
    text, so a migration that forgot a CHECK change would otherwise pass."""
    command.upgrade(alembic_config(db_url), "head")
    migrated = _constraints(db_url)
    name = f"test_{uuid.uuid4().hex}"
    with psycopg.connect(pg_server_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        eng = create_db_engine(_libpq_url(pg_server_url, database=name))
        try:
            Base.metadata.create_all(eng)
        finally:
            eng.dispose()
        created = _constraints(_libpq_url(pg_server_url, database=name))
    finally:
        with psycopg.connect(pg_server_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
    assert any(key.startswith("CK:") for _, key in migrated)  # the comparison sees CHECKs
    only_migrated = {k: v for k, v in migrated.items() if created.get(k) != v}
    only_created = {k: v for k, v in created.items() if migrated.get(k) != v}
    assert only_migrated == {}
    assert only_created == {}
