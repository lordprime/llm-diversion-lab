"""``labctl``: status, runs ls, run show, the selftest stub, exit codes, logging.

The database commands run against a fresh migrated Postgres (``engine`` / ``db_url``
fixtures) through ``DATABASE_URL``; they only read.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, update

from control.cli import main as cli
from control.cli.main import main
from control.core.ids import new_id
from control.core.models import Arm, EndStatus, RunStatus
from control.core.selftest_status import SelftestResult, record_selftest_result
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import insert_events
from tests.db.test_repo import _events, _seed_injected_run, add_run, seed_experiment

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


@pytest.mark.parametrize("argv", [["selftest"], ["selftest", "--quick"]])
def test_selftest_is_a_stub_that_exits_2(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _, err = _run(capsys, *argv)
    assert rc == 2
    assert "not built yet (Task 15b-2)" in err


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
    second = add_run(lab_db, ids, schedule_index=1, arm=Arm.INJECTED, status=RunStatus.VALID)

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
        "injected_arm_id": new_id("arm"),
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
                    arm_id=other["injected_arm_id"],
                    experiment_id=other["experiment_id"],
                    name="injected",
                    arm=Arm.INJECTED,
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
    run_id, placement_id = _seed_injected_run(lab_db)
    with session_scope(lab_db) as s:
        insert_events(s, _events(run_id, placement_id))
        s.execute(
            update(t.Run)
            .where(t.Run.run_id == run_id)
            .values(status=RunStatus.VALID, end_status=EndStatus.COMPLETED, outcome=True)
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
    assert data["placements"] == 1
    assert data["events"] == {str(k): v for k, v in kinds.items()}


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

