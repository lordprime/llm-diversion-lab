import re
import uuid
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from psycopg import sql
from sqlalchemy import Engine, inspect, text, update
from sqlalchemy.exc import IntegrityError

from control.core.models import Arm, EventKind, InvalidReason
from control.db import tables as t
from control.db.engine import create_db_engine, session_scope
from control.db.tables import Base
from tests.conftest import _libpq_url, alembic_config
from tests.db.test_repo import add_run, seed_experiment

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
    "run_telemetry",
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


def _runs(url: str) -> dict[str, dict[str, Any]]:
    eng = create_db_engine(url)
    try:
        with eng.connect() as conn:
            rows = conn.exec_driver_sql("SELECT * FROM runs").mappings().all()
    finally:
        eng.dispose()
    return {row["run_id"]: dict(row) for row in rows}


def test_dual_verdict_columns_and_check(db_url: str) -> None:
    """runs.effect and runs.mechanism are nullable booleans (NULL until the verdict is
    stored); effect is set exactly when outcome is."""
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        insp = inspect(eng)
        columns = {c["name"]: c for c in insp.get_columns("runs")}
        checks = {c["name"]: c["sqltext"] for c in insp.get_check_constraints("runs")}
    finally:
        eng.dispose()
    for name in ("effect", "mechanism"):
        assert columns[name]["nullable"] is True
        assert str(columns[name]["type"]) == "BOOLEAN"
    assert "outcome IS NULL" in checks["ck_runs_outcome_has_effect"]
    assert "effect IS NULL" in checks["ck_runs_outcome_has_effect"]


def test_dual_verdict_check_refuses_an_outcome_without_an_effect(engine: Engine) -> None:
    ids = seed_experiment(engine)
    run_id = add_run(engine, ids, schedule_index=0)
    for lopsided in ({"outcome": True}, {"effect": False}):
        with (
            pytest.raises(IntegrityError, match="ck_runs_outcome_has_effect"),
            session_scope(engine) as s,
        ):
            s.execute(update(t.Run).where(t.Run.run_id == run_id).values(**lopsided))
    with session_scope(engine) as s:  # both together, with the mechanism unknown, is fine
        s.execute(update(t.Run).where(t.Run.run_id == run_id).values(outcome=False, effect=False))


def test_dual_verdict_migration_backfills_effect_and_downgrades(db_url: str) -> None:
    """Existing rows: effect = outcome (NULL stays NULL), mechanism NULL; the downgrade
    drops the columns and the upgrade can run again."""
    cfg = alembic_config(db_url)
    command.upgrade(cfg, "head")
    eng = create_db_engine(db_url)
    try:
        ids = seed_experiment(eng)
        done_true = add_run(eng, ids, schedule_index=0)
        done_false = add_run(eng, ids, schedule_index=1)
        queued = add_run(eng, ids, schedule_index=2)
    finally:
        eng.dispose()
    command.downgrade(cfg, "0006")
    old = create_db_engine(db_url)
    try:
        with old.begin() as conn:
            for run_id, outcome in ((done_true, True), (done_false, False)):
                conn.execute(
                    text(
                        "UPDATE runs SET status = 'valid', end_status = 'completed', "
                        "outcome = :outcome WHERE run_id = :run_id"
                    ),
                    {"outcome": outcome, "run_id": run_id},
                )
        assert "effect" not in {c["name"] for c in inspect(old).get_columns("runs")}
    finally:
        old.dispose()

    command.upgrade(cfg, "head")
    rows = _runs(db_url)
    assert (rows[done_true]["outcome"], rows[done_true]["effect"]) == (True, True)
    assert (rows[done_false]["outcome"], rows[done_false]["effect"]) == (False, False)
    assert (rows[queued]["outcome"], rows[queued]["effect"]) == (None, None)
    assert {r["mechanism"] for r in rows.values()} == {None}


def test_run_telemetry_holds_a_summary_or_an_error_never_both_or_neither(db_url: str) -> None:
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        run_id = add_run(eng, seed_experiment(eng), schedule_index=0)
        summary = dict.fromkeys(t.TELEMETRY_FIELDS, 1) | {"agents_source": "inferred"}
        summary["telemetry_version"] = "4"
        bad = [
            {"run_id": run_id},  # neither
            {"run_id": run_id, **summary, "telemetry_error": "and an error"},  # both
            {"run_id": run_id, **summary, "calls": None},  # an incomplete summary
        ]
        for row in bad:
            with pytest.raises(IntegrityError), session_scope(eng) as s:
                s.add(t.RunTelemetryRow(**row))
        with session_scope(eng) as s:
            s.add(t.RunTelemetryRow(run_id=run_id, **(summary | {"peak_input_tokens": None})))
    finally:
        eng.dispose()


def test_telemetry_migration_downgrades_to_its_parent(db_url: str) -> None:
    cfg = alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0009")
    assert "run_telemetry" not in _tables(db_url)
    command.upgrade(cfg, "head")
    assert "run_telemetry" in _tables(db_url)


# --------------------------------------------------------------------------- three arms (0011)


def _arms(url: str) -> list[tuple[str, str]]:
    eng = create_db_engine(url)
    try:
        with eng.connect() as conn:
            return sorted(
                (row.name, row.arm) for row in conn.execute(text("SELECT name, arm FROM arms"))
            )
    finally:
        eng.dispose()


def test_the_arm_checks_list_exactly_the_three_arms(db_url: str) -> None:
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        insp = inspect(eng)
        for table in ("arms", "runs"):
            (check,) = [
                c for c in insp.get_check_constraints(table) if c["name"] == f"ck_{table}_arm"
            ]
            assert set(re.findall(r"'([a-z_]+)'", check["sqltext"])) == {a.value for a in Arm}
        columns = {c["name"] for c in insp.get_columns("runs")}
        assert "block_id" in columns and "pair_id" not in columns
    finally:
        eng.dispose()


def test_the_three_arm_migration_keeps_two_arm_rows_readable(db_url: str) -> None:
    """Rows stored before 0011 (``injected``, ``pair_id``) come back as instruction runs
    of a block with the same id; the downgrade restores them exactly."""
    cfg = alembic_config(db_url)
    command.upgrade(cfg, "head")
    eng = create_db_engine(db_url)
    try:
        ids = seed_experiment(eng)
        control = add_run(eng, ids, schedule_index=0, block_id="pair_old")
        treated = add_run(eng, ids, schedule_index=1, arm=Arm.INSTRUCTION, block_id="pair_old")
    finally:
        eng.dispose()

    command.downgrade(cfg, "0010")  # the M1a schema, as M0 and M1a self-tests wrote it
    old = _runs(db_url)
    assert (old[control]["arm"], old[control]["pair_id"]) == ("control", "pair_old")
    assert (old[treated]["arm"], old[treated]["pair_id"]) == ("injected", "pair_old")
    assert "block_id" not in old[treated]
    assert _arms(db_url) == [("control", "control"), ("p1-p7-derail", "injected")]
    eng = create_db_engine(db_url)
    try:  # an M1a-era arm and run, named as M1a named them
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO arms (arm_id, experiment_id, name, arm, surfaces, "
                    "payload_family, payload_style, payload_version) VALUES "
                    "('arm_m1a', :exp, 'injected', 'injected', '{P1}', 'decoy', 'neutral', '1')"
                ),
                {"exp": ids["experiment_id"]},
            )
            conn.execute(
                text(
                    "INSERT INTO runs (run_id, experiment_id, arm_id, arm, target_id, agent_id, "
                    "model_id, pair_id, schedule_index, tag) VALUES ('run_m1a', :exp, 'arm_m1a', "
                    "'injected', :tgt, :agt, :mdl, 'pair_m1a', 2, '0123456789abcdef')"
                ),
                {
                    "exp": ids["experiment_id"],
                    "tgt": ids["target_id"],
                    "agt": ids["agent_id"],
                    "mdl": ids["model_id"],
                },
            )
    finally:
        eng.dispose()

    command.upgrade(cfg, "head")
    new = _runs(db_url)
    assert (new[treated]["arm"], new[treated]["block_id"]) == ("instruction", "pair_old")
    assert (new["run_m1a"]["arm"], new["run_m1a"]["block_id"]) == ("instruction", "pair_m1a")
    assert (new[control]["arm"], new[control]["block_id"]) == ("control", "pair_old")
    assert ("instruction", "instruction") in _arms(db_url)
    eng = create_db_engine(db_url)
    try:  # and the ORM reads them as the instruction arm
        with session_scope(eng) as s:
            assert s.get(t.Run, "run_m1a").arm is Arm.INSTRUCTION  # type: ignore[union-attr]
        # the old value is refused from now on
        with pytest.raises(IntegrityError, match="ck_runs_arm"), eng.begin() as conn:
            conn.execute(text("UPDATE runs SET arm = 'injected' WHERE run_id = 'run_m1a'"))
    finally:
        eng.dispose()


def test_a_block_holds_one_run_per_arm_and_attempt(db_url: str) -> None:
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        ids = seed_experiment(eng)
        add_run(eng, ids, schedule_index=0, block_id="block_a")
        add_run(eng, ids, schedule_index=1, arm=Arm.INSTRUCTION, block_id="block_a")
        with pytest.raises(IntegrityError, match="uq_runs_block_id_arm_attempt"):
            add_run(eng, ids, schedule_index=2, arm=Arm.INSTRUCTION, block_id="block_a")
    finally:
        eng.dispose()


def test_the_three_arm_migration_refuses_to_downgrade_over_neutral_runs(db_url: str) -> None:
    cfg = alembic_config(db_url)
    command.upgrade(cfg, "head")
    eng = create_db_engine(db_url)
    try:
        ids = seed_experiment(eng)
        with session_scope(eng) as s:
            s.add(
                t.ExperimentArm(
                    arm_id="arm_neutral",
                    experiment_id=ids["experiment_id"],
                    name="neutral",
                    arm=Arm.NEUTRAL,
                    surfaces=["P1"],
                    payload_family="derail",
                    payload_style="neutral",
                    payload_version="1",
                )
            )
    finally:
        eng.dispose()
    with pytest.raises(RuntimeError, match="neutral run\\(s\\) or arm\\(s\\) are stored"):
        command.downgrade(cfg, "0010")
    assert "block_id" in {c for c in _runs_columns(db_url)}  # nothing was half-done


def _runs_columns(url: str) -> set[str]:
    eng = create_db_engine(url)
    try:
        return {c["name"] for c in inspect(eng).get_columns("runs")}
    finally:
        eng.dispose()
