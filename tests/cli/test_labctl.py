"""``labctl``: status, runs ls, run show, exit codes, logging (selftest: tests/runner).

The database commands run against a fresh migrated Postgres (``engine`` / ``db_url``
fixtures) through ``DATABASE_URL``; they only read.
"""

from __future__ import annotations

import json
import re
import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, update

from control.cli import main as cli
from control.cli.main import main
from control.core.ids import new_id
from control.core.models import Arm, EndStatus, InvalidReason, RunStatus
from control.core.selftest_status import SelftestResult, record_selftest_result
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import insert_events
from control.runner.store import RunStore
from control.telemetry.model import RunTelemetry
from tests.db.test_repo import _events, _seed_instruction_run, add_run, seed_experiment

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAB_ROOT", str(tmp_path / "lab"))
    monkeypatch.setenv("LAB_SELFTEST_STATUS_FILE", str(tmp_path / "lab" / "state" / "st.json"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(cli, "configure_logging", lambda **kw: None)


@pytest.fixture
def lab_db(db_url: str, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Engine:
    monkeypatch.setenv("DATABASE_URL", db_url)
    return engine


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    rc = main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


# --------------------------------------------------------------------- entry point


def test_console_script_is_declared() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"]["labctl"] == "control.cli.main:main"


def test_configures_logging_before_any_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    order: list[str] = []
    monkeypatch.setattr(cli, "configure_logging", lambda **kw: order.append("logging"))
    monkeypatch.setattr(cli, "_dispatch", lambda args: order.append("command") or 0)
    assert main(["status"]) == 0
    assert order == ["logging", "command"]


@pytest.mark.parametrize(
    "argv", [[], ["bogus"], ["runs"], ["run", "show"], ["runs", "ls", "-n", "x"]]
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 2


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    for word in ("doctor", "status", "runs", "run", "selftest"):
        assert word in out


# --------------------------------------------------------------------- database errors


def test_database_commands_fail_cleanly_without_a_database(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for argv in (["status"], ["runs", "ls"], ["run", "show", "run_x"]):
        rc, _, err = _run(capsys, *argv)
        assert rc == 1, argv
        assert "DATABASE_URL" in err


def test_unreachable_database_fails_without_leaking_the_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://lab:hunter2-secret@127.0.0.1:9/lab")
    rc, out, err = _run(capsys, "runs", "ls")
    assert rc == 1
    assert "hunter2" not in out + err


# --------------------------------------------------------------------- runs ls


def test_runs_ls_lists_newest_first(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    ids = seed_experiment(lab_db)
    first = add_run(lab_db, ids, schedule_index=0, arm=Arm.CONTROL)
    second = add_run(lab_db, ids, schedule_index=1, arm=Arm.INSTRUCTION, status=RunStatus.VALID)

    rc, out, _ = _run(capsys, "runs", "ls")

    assert rc == 0
    assert out.index(second) < out.index(first)
    assert "queued" in out and "valid" in out


def _second_experiment(engine: Engine, ids: dict[str, str]) -> dict[str, str]:
    """Another experiment on the same target, agent and model."""
    other = {
        **ids,
        "experiment_id": new_id("exp"),
        "control_arm_id": new_id("arm"),
        "instruction_arm_id": new_id("arm"),
    }
    with session_scope(engine) as s:
        s.add(
            t.Experiment(
                experiment_id=other["experiment_id"],
                name="second",
                definition_yaml="name: second\n",
                definition_sha256="b" * 64,
                schedule_seed=8,
            )
        )
        s.add_all(
            [
                t.ExperimentArm(
                    arm_id=other["control_arm_id"],
                    experiment_id=other["experiment_id"],
                    name="control",
                    arm=Arm.CONTROL,
                    surfaces=[],
                ),
                t.ExperimentArm(
                    arm_id=other["instruction_arm_id"],
                    experiment_id=other["experiment_id"],
                    name="instruction",
                    arm=Arm.INSTRUCTION,
                    surfaces=["P1"],
                    payload_family="derail",
                    payload_style="override",
                    payload_version="1",
                ),
            ]
        )
    return other


def test_runs_ls_filters_and_limits(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    ids = seed_experiment(lab_db)
    queued = add_run(lab_db, ids, schedule_index=0)
    valid = add_run(lab_db, ids, schedule_index=1, status=RunStatus.VALID)
    other = _second_experiment(lab_db, ids)
    elsewhere = add_run(lab_db, other, schedule_index=0, status=RunStatus.VALID)

    rc, out, _ = _run(
        capsys, "runs", "ls", "--status", "valid", "--experiment", ids["experiment_id"]
    )
    assert rc == 0
    assert valid in out and queued not in out and elsewhere not in out

    rc, out, _ = _run(capsys, "runs", "ls", "--json", "-n", "1")
    rows = json.loads(out)
    assert len(rows) == 1
    assert rows[0]["run_id"] == elsewhere


def test_runs_ls_rejects_an_unknown_status(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["runs", "ls", "--status", "exploded"]) == 2


def test_runs_ls_empty(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = _run(capsys, "runs", "ls")
    assert rc == 0
    assert "no runs" in out


# --------------------------------------------------------------------- run show


def test_run_show_details_and_evidence_counts(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    run_id, placement_id = _seed_instruction_run(lab_db)
    with session_scope(lab_db) as s:
        insert_events(s, _events(run_id, placement_id))
        s.execute(
            update(t.Run)
            .where(t.Run.run_id == run_id)
            .values(
                status=RunStatus.VALID,
                end_status=EndStatus.COMPLETED,
                outcome=True,
                effect=True,
                mechanism=False,
            )
        )
        kinds = dict(
            s.execute(
                select(t.EventKeyEntry.kind, func.count())
                .where(t.EventKeyEntry.run_id == run_id)
                .group_by(t.EventKeyEntry.kind)
            ).all()
        )

    rc, out, _ = _run(capsys, "run", "show", run_id)
    assert rc == 0
    assert run_id in out
    assert "valid" in out and "completed" in out
    for kind in kinds:
        assert str(kind) in out

    rc, out, _ = _run(capsys, "run", "show", run_id, "--json")
    data: dict[str, Any] = json.loads(out)
    assert data["run_id"] == run_id
    assert data["status"] == "valid"
    assert data["outcome"] is True
    assert (data["effect"], data["mechanism"]) == (True, False)
    assert data["placements"] == 1
    assert data["events"] == {str(k): v for k, v in kinds.items()}
    # block_id, and pair_id as its deprecated alias for one release, in both outputs
    with session_scope(lab_db) as s:
        block_id = s.scalar(select(t.Run.block_id).where(t.Run.run_id == run_id))
    assert data["arm"] == "instruction"
    assert data["block_id"] == data["pair_id"] == block_id
    rc, out, _ = _run(capsys, "run", "show", run_id)
    assert {line.split()[0] for line in out.splitlines() if block_id in line} == {
        "block_id",
        "pair_id",
    }


def test_runs_ls_and_run_show_say_why_a_run_is_invalid(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    """invalid_reason and dev in both; invalid_detail (redacted, also for rows stored
    before the runner redacted it) in run show."""
    ids = seed_experiment(lab_db)
    run_id = add_run(lab_db, ids, schedule_index=0, status=RunStatus.INVALID)
    with session_scope(lab_db) as s:
        s.execute(
            update(t.Run)
            .where(t.Run.run_id == run_id)
            .values(
                invalid_reason=InvalidReason.RECORDING_FAILED,
                invalid_detail="tap exited 137; db at postgresql://lab:hunter2secret@db/lab",
                dev=True,
            )
        )

    rc, out, _ = _run(capsys, "runs", "ls")
    assert rc == 0 and "recording_failed" in out and "invalid_reason" in out
    rc, out, _ = _run(capsys, "runs", "ls", "--json")
    (row,) = json.loads(out)
    assert (row["invalid_reason"], row["dev"]) == ("recording_failed", True)
    assert "invalid_detail" not in row  # the list stays short

    rc, out, _ = _run(capsys, "run", "show", run_id)
    assert rc == 0 and "recording_failed" in out and "tap exited 137" in out
    assert "hunter2secret" not in out
    rc, out, _ = _run(capsys, "run", "show", run_id, "--json")
    data = json.loads(out)
    assert data["invalid_reason"] == "recording_failed" and data["dev"] is True
    assert "tap exited 137" in data["invalid_detail"]
    assert "hunter2secret" not in data["invalid_detail"]


def test_run_show_unknown_run(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    rc, _, err = _run(capsys, "run", "show", "run_doesnotexist")
    assert rc == 1
    assert "no such run" in err


def test_commands_never_write(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    """The read path runs in a READ ONLY transaction."""
    from control.cli.queries import read_only_session

    with pytest.raises(Exception, match="read-only"), read_only_session(lab_db) as s:
        s.execute(update(t.Run).values(attempt=2))


# --------------------------------------------------------------------- status


def test_status_summarises_queue_and_selftest(
    lab_db: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ids = seed_experiment(lab_db)
    add_run(lab_db, ids, schedule_index=0)
    add_run(lab_db, ids, schedule_index=1, status=RunStatus.RUNNING)
    add_run(lab_db, ids, schedule_index=2, status=RunStatus.INVALID)
    record_selftest_result(
        SelftestResult(passed=True, finished_at=1_800_000_000.0, quick=True),
        tmp_path / "lab" / "state" / "st.json",
    )
    release = tmp_path / "lab" / "current"
    release.mkdir(parents=True)
    (release / "RELEASE").write_text("tag=v0.1.0\ncommit=abc\n", encoding="utf-8")

    rc, out, _ = _run(capsys, "status")
    assert rc == 0
    assert "v0.1.0" in out
    assert "queued 1" in out and "running 1" in out and "invalid 1" in out
    assert "2027-01-15" in out  # 1_800_000_000 is 2027-01-15T08:00:00Z

    rc, out, _ = _run(capsys, "status", "--json")
    data = json.loads(out)
    assert data["release"] == "v0.1.0"
    assert data["runs"]["queued"] == 1
    assert data["runs"]["running"] == 1
    assert data["experiments"] == 1
    assert data["selftest"]["last_success"]["finished_at"] == 1_800_000_000.0


def test_status_without_release_or_selftest(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, _ = _run(capsys, "status")
    assert rc == 0
    assert "release: none" in out
    assert "self-test: never run" in out


def test_status_shows_why_the_last_self_test_failed(
    lab_db: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = tmp_path / "lab" / "state" / "st.json"
    record_selftest_result(SelftestResult(True, 1_800_000_000.0, True, "passed: 9 checks"), status)
    record_selftest_result(
        SelftestResult(False, 1_800_000_500.0, True, "in progress since ... (aborted)"), status
    )
    rc, out, _ = _run(capsys, "status")
    assert rc == 0
    assert "FAILED" in out and "in progress since ... (aborted)" in out
    assert "last success at 2027-01-15" in out


def test_unparsable_database_url_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", "not a url")
    rc, out, err = _run(capsys, "runs", "ls")
    assert rc == 2
    assert "DATABASE_URL" in err
    assert "Traceback" not in out + err


def test_status_finds_the_selftest_under_lab_root(
    lab_db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("LAB_SELFTEST_STATUS_FILE")
    record_selftest_result(
        SelftestResult(passed=True, finished_at=1_800_000_000.0, quick=True),
        tmp_path / "lab" / "state" / "selftest.json",
    )
    rc, out, _ = _run(capsys, "status", "--json")
    assert rc == 0
    assert json.loads(out)["selftest"]["last_success"]["finished_at"] == 1_800_000_000.0


def test_build_backend_is_pinned() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    (requirement,) = project["build-system"]["requires"]
    assert re.fullmatch(r"hatchling==\d+\.\d+\.\d+", requirement)


# --------------------------------------------------------------------- telemetry

EXPORT_HEADER = (
    "run_id,arm,target,agent,model,end_status,status,invalid_reason,effect,mechanism,calls,"
    "agents,agents_source,peak_input_tokens,input_tokens,output_tokens,reasoning_chars,"
    "calls_with_reasoning,single_call_threads,largest_thread_calls,branch_points,"
    "persona_splits,telemetry_version,telemetry_status"
)


def _summary(run_id: str, **changes: Any) -> RunTelemetry:
    return RunTelemetry.from_calls(run_id, []).model_copy(update=changes)


def _telemetry_runs(engine: Engine) -> tuple[dict[str, str], list[str]]:
    """Three runs stored in reverse schedule order, with telemetry; plus one queued run."""
    ids = seed_experiment(engine)
    run_ids = [
        add_run(engine, ids, schedule_index=i, arm=arm, status=RunStatus.VALID)
        for i, arm in ((2, Arm.INSTRUCTION), (1, Arm.CONTROL), (0, Arm.INSTRUCTION))
    ]
    ids["queued_run_id"] = add_run(engine, ids, schedule_index=3)  # nothing derived yet
    with session_scope(engine) as s:
        for run_id in run_ids:
            s.execute(
                update(t.Run)
                .where(t.Run.run_id == run_id)
                .values(end_status=EndStatus.COMPLETED, effect=True, outcome=True, mechanism=None)
            )
    store = RunStore(engine)
    for n, run_id in enumerate(run_ids):
        store.record_telemetry(
            _summary(run_id, calls=10 + n, agents=2, peak_input_tokens=None if n == 1 else 900)
        )
    return ids, run_ids


def test_run_telemetry_prints_the_stored_summary(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    _, run_ids = _telemetry_runs(lab_db)
    rc, out, _ = _run(capsys, "run", "telemetry", run_ids[0])
    assert rc == 0
    assert re.search(r"^calls\s+10$", out, re.M) and re.search(r"^agents\s+2$", out, re.M)
    rc, out, _ = _run(capsys, "run", "telemetry", run_ids[0], "--json")
    data = json.loads(out)
    assert (rc, data["calls"], data["run_id"], data["telemetry_error"]) == (0, 10, run_ids[0], None)


def test_run_telemetry_shows_a_recorded_error(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    run_id = add_run(lab_db, seed_experiment(lab_db), schedule_index=0)
    RunStore(lab_db).record_telemetry_error(run_id, "the tap folder is a symlink")
    rc, out, _ = _run(capsys, "run", "telemetry", run_id)
    assert rc == 0 and "telemetry_error" in out and "the tap folder is a symlink" in out


def test_run_telemetry_for_an_unknown_run_or_one_without_it(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _, err = _run(capsys, "run", "telemetry", "run_doesnotexist")
    assert rc == 1 and "no such run" in err
    run_id = add_run(lab_db, seed_experiment(lab_db), schedule_index=0)
    rc, _, err = _run(capsys, "run", "telemetry", run_id)
    assert rc == 1 and "no telemetry" in err


def test_export_csv_has_one_row_per_run_in_schedule_order(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    ids, run_ids = _telemetry_runs(lab_db)
    experiment = ids["experiment_id"]
    rc, out, _ = _run(capsys, "export", "telemetry", "--experiment", experiment, "--format", "csv")
    assert rc == 0
    lines = out.splitlines()
    assert lines[0] == EXPORT_HEADER
    # schedule index 0, 1, 2, then the queued run: every run of the experiment is a row
    assert [line.split(",")[0] for line in lines[1:]] == [*run_ids[::-1], ids["queued_run_id"]]
    first = lines[1].split(",")
    assert first[1:11] == [
        "instruction", ids["target_id"], ids["agent_id"], ids["model_id"],
        "completed", "valid", "", "true", "", "12",
    ]  # fmt: skip
    assert first[-1] == "ok"
    assert lines[2].split(",")[13] == ""  # no peak input tokens reported: an empty cell
    queued = lines[4].split(",")
    assert queued[6] == "queued" and queued[10:23] == [""] * 13 and queued[-1] == "missing"
    again = _run(capsys, "export", "telemetry", "--experiment", experiment, "--format", "csv")
    assert again[1] == out  # deterministic


def test_export_markdown_is_a_table(lab_db: Engine, capsys: pytest.CaptureFixture[str]) -> None:
    ids, run_ids = _telemetry_runs(lab_db)
    rc, out, _ = _run(
        capsys, "export", "telemetry", "--experiment", ids["experiment_id"], "--format", "md"
    )
    lines = out.splitlines()
    assert rc == 0 and len(lines) == 2 + len(run_ids) + 1
    assert lines[0].startswith("| run_id | arm | target |") and set(lines[1]) <= set("|- ")
    assert lines[2].split("|")[1].strip() == run_ids[-1]
    assert all(line.count("|") == lines[0].count("|") for line in lines)


def test_export_refuses_to_mix_telemetry_versions_without_the_flag(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    ids, run_ids = _telemetry_runs(lab_db)
    with session_scope(lab_db) as s:
        s.execute(
            update(t.RunTelemetryRow)
            .where(t.RunTelemetryRow.run_id == run_ids[0])
            .values(telemetry_version="3")
        )
    args = ("export", "telemetry", "--experiment", ids["experiment_id"], "--format", "csv")
    rc, out, err = _run(capsys, *args)
    assert rc == 1 and out == "" and "3" in err and "--allow-mixed-versions" in err
    rc, out, _ = _run(capsys, *args, "--allow-mixed-versions")
    assert rc == 0 and len(out.splitlines()) == 5


def test_export_keeps_a_run_whose_telemetry_failed_as_an_empty_row(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    ids = seed_experiment(lab_db)
    ok = add_run(lab_db, ids, schedule_index=0)
    failed = add_run(lab_db, ids, schedule_index=1)
    RunStore(lab_db).record_telemetry(_summary(ok))
    RunStore(lab_db).record_telemetry_error(failed, "boom")
    rc, out, err = _run(
        capsys, "export", "telemetry", "--experiment", ids["experiment_id"], "--format", "csv"
    )
    assert rc == 0 and "1 run" in err and failed in err
    row = out.splitlines()[2].split(",")
    assert row[0] == failed and row[10:23] == [""] * 13 and row[23] == "error"


def test_export_with_no_telemetry_is_just_the_header(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    ids = seed_experiment(lab_db)
    rc, out, _ = _run(
        capsys, "export", "telemetry", "--experiment", ids["experiment_id"], "--format", "csv"
    )
    assert (rc, out.strip()) == (0, EXPORT_HEADER)


def test_export_for_an_unknown_experiment_fails(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, err = _run(capsys, "export", "telemetry", "--experiment", "exp_nope", "--format", "md")
    assert rc == 1 and out == "" and "no such experiment" in err


@pytest.mark.parametrize(
    "argv",
    [
        ["export"],
        ["export", "telemetry"],
        ["export", "telemetry", "--experiment", "e"],
        ["export", "telemetry", "--experiment", "e", "--format", "xlsx"],
        ["run", "telemetry"],
    ],
)
def test_telemetry_usage_errors_exit_2(argv: list[str]) -> None:
    assert main(argv) == 2


def test_export_counts_every_status_and_every_non_valid_run_on_stderr(
    lab_db: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    ids = seed_experiment(lab_db)
    ok = add_run(lab_db, ids, schedule_index=0, status=RunStatus.VALID)
    bad = add_run(lab_db, ids, schedule_index=1, status=RunStatus.INVALID)
    failed = add_run(lab_db, ids, schedule_index=2, status=RunStatus.VALID)
    add_run(lab_db, ids, schedule_index=3)  # queued, no telemetry record
    RunStore(lab_db).record_telemetry(_summary(ok))
    RunStore(lab_db).record_telemetry_error(failed, "boom")
    rc, out, err = _run(
        capsys, "export", "telemetry", "--experiment", ids["experiment_id"], "--format", "csv"
    )
    assert rc == 0 and len(out.splitlines()) == 5
    assert "telemetry: ok 1, error 1, missing 2" in err
    assert "2 of 4 run(s) are not valid" in err
    row = next(line for line in out.splitlines() if line.startswith(bad)).split(",")
    assert row[6:8] == ["invalid", "internal"] and row[-1] == "missing"


def test_a_summary_replacing_an_error_gets_a_fresh_derived_time(engine: Engine) -> None:
    run_id = add_run(engine, seed_experiment(engine), schedule_index=0)
    store = RunStore(engine)
    store.record_telemetry_error(run_id, "first try")
    with session_scope(engine) as s:
        before = s.get(t.RunTelemetryRow, run_id).created_at  # type: ignore[union-attr]
        s.execute(update(t.RunTelemetryRow).values(created_at=before - timedelta(days=1)))
        stale = s.get(t.RunTelemetryRow, run_id).created_at  # type: ignore[union-attr]
    store.record_telemetry(_summary(run_id))
    with session_scope(engine) as s:
        assert s.get(t.RunTelemetryRow, run_id).created_at > stale  # type: ignore[union-attr]
