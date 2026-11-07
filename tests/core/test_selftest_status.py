"""The persisted self-test status file (control.core.selftest_status).

The self-test (Task 15b-2) records each result here; ``/metrics`` and ``labctl status``
read it, so the last success survives a restart of any process.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from control.core.selftest_status import (
    DEFAULT_SELFTEST_STATUS_FILE,
    SELFTEST_STATUS_ENV,
    SelftestResult,
    SelftestStatus,
    SelftestStatusError,
    read_selftest_status,
    record_selftest_result,
    selftest_status_path,
)


def test_missing_file_means_no_selftest_yet(tmp_path: Path) -> None:
    status = read_selftest_status(tmp_path / "nope.json")
    assert status == SelftestStatus(last_run=None, last_success=None)
    assert status.last_success_timestamp is None


def test_roundtrip_of_a_passing_result(tmp_path: Path) -> None:
    path = tmp_path / "state" / "selftest.json"
    result = SelftestResult(passed=True, finished_at=1_800_000_000.5, quick=True, summary="ok")

    written = record_selftest_result(result, path)

    assert path.is_file()
    assert written == read_selftest_status(path)
    assert written.last_run == result
    assert written.last_success == result
    assert written.last_success_timestamp == 1_800_000_000.5


def test_a_failure_keeps_the_last_success(tmp_path: Path) -> None:
    path = tmp_path / "selftest.json"
    good = SelftestResult(passed=True, finished_at=100.0, quick=False)
    bad = SelftestResult(passed=False, finished_at=200.0, quick=True, summary="control leaked")

    record_selftest_result(good, path)
    status = record_selftest_result(bad, path)

    assert status.last_run == bad
    assert status.last_success == good
    assert read_selftest_status(path).last_success_timestamp == 100.0


def test_file_is_world_readable_and_written_atomically(tmp_path: Path) -> None:
    path = tmp_path / "selftest.json"
    record_selftest_result(SelftestResult(passed=True, finished_at=1.0, quick=True), path)

    # the collector container reads it as an unprivileged user through a read-only mount
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    # no temporary file left behind
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.startswith(".")) == [
        "selftest.json"
    ]
    json.loads(path.read_text(encoding="utf-8"))


def test_corrupt_file_raises_a_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "selftest.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SelftestStatusError, match=r"selftest\.json"):
        read_selftest_status(path)


def test_wrong_shape_raises(tmp_path: Path) -> None:
    path = tmp_path / "selftest.json"
    path.write_text(json.dumps({"last_run": {"passed": "yes"}}), encoding="utf-8")
    with pytest.raises(SelftestStatusError):
        read_selftest_status(path)


def test_summary_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "selftest.json"
    status = record_selftest_result(
        SelftestResult(passed=False, finished_at=1.0, quick=True, summary="x" * 10_000), path
    )
    assert status.last_run is not None
    assert len(status.last_run.summary) <= 1000


def test_path_comes_from_the_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SELFTEST_STATUS_ENV, raising=False)
    assert selftest_status_path() == DEFAULT_SELFTEST_STATUS_FILE
    assert Path("/srv/lab/state/selftest.json") == DEFAULT_SELFTEST_STATUS_FILE
    monkeypatch.setenv(SELFTEST_STATUS_ENV, str(tmp_path / "x.json"))
    assert selftest_status_path() == tmp_path / "x.json"
    assert selftest_status_path(tmp_path / "y.json") == tmp_path / "y.json"
