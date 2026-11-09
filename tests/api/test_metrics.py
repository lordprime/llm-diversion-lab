"""Prometheus ``/metrics`` on the Collector app (docs/TRACKING.md §3.2).

Process model: the run metrics are **derived from the runs table at scrape time**, and
the self-test timestamp from the persisted self-test status file, so every value
survives a restart of the Collector (or of whatever process recorded it).

Tests marked with the ``engine`` fixture run against a fresh migrated Postgres
database; the others need no database.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import Engine

from control.api.app import create_app
from control.api.metrics import METRIC_NAMES, UNRECORDED_REASON, LabMetrics
from control.core.models import Arm, EndStatus, RunStatus
from control.core.selftest_status import SelftestResult, record_selftest_result
from control.db import tables as t
from control.db.engine import create_db_engine, session_scope
from tests.db.test_repo import add_run, seed_experiment

Samples = dict[tuple[str, frozenset[tuple[str, str]]], float]


def _samples(text: str) -> Samples:
    return {
        (s.name, frozenset(s.labels.items())): s.value
        for fam in text_string_to_metric_families(text)
        for s in fam.samples
    }


@pytest.fixture
def status_file(tmp_path: Path) -> Path:
    return tmp_path / "state" / "selftest.json"


# --------------------------------------------------------------------- no database


@pytest.fixture
def client(status_file: Path) -> Iterator[TestClient]:
    with TestClient(create_app(metrics=LabMetrics(selftest_status_file=status_file))) as c:
        yield c


def test_metrics_route_serves_text_exposition_format(client: TestClient) -> None:
    r = client.get("/metrics")

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    families = {f.name for f in text_string_to_metric_families(r.text)}
    # Counter families are named without the ``_total`` suffix by the parser.
    assert {
        "lab_runs",
        "lab_invalid_runs",
        "lab_runs_in_flight",
        "lab_selftest_last_success_timestamp",
        "lab_metrics_database_up",
    } <= families
    for name in METRIC_NAMES:
        assert f"# TYPE {name} " in r.text


def test_metric_names_match_tracking_doc() -> None:
    assert {
        "lab_runs_total",
        "lab_invalid_runs_total",
        "lab_runs_in_flight",
        "lab_selftest_last_success_timestamp",
    } <= set(METRIC_NAMES)


def test_without_a_database_run_metrics_are_absent_and_flagged(client: TestClient) -> None:
    samples = _samples(client.get("/metrics").text)
    assert samples[("lab_metrics_database_up", frozenset())] == 0.0
    # absent, never a misleading zero
    assert not [k for k in samples if k[0] in {"lab_runs_total", "lab_invalid_runs_total"}]


def test_default_app_exposes_metrics_without_a_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with TestClient(create_app()) as c:
        r = c.get("/metrics")
    assert r.status_code == 200
    assert "# TYPE lab_runs_total counter" in r.text
    assert "lab_metrics_database_up 0.0" in r.text


def test_unreachable_database_still_answers_quickly() -> None:
    dead = create_db_engine(
        "postgresql://lab:x@127.0.0.1:9/lab", connect_args={"connect_timeout": 2}
    )
    try:
        text = LabMetrics(dead).exposition().decode()
    finally:
        dead.dispose()
    assert _samples(text)[("lab_metrics_database_up", frozenset())] == 0.0


def test_selftest_timestamp_is_zero_until_a_selftest_passes(
    client: TestClient, status_file: Path
) -> None:
    key = ("lab_selftest_last_success_timestamp", frozenset())
    assert _samples(client.get("/metrics").text)[key] == 0.0

    record_selftest_result(
        SelftestResult(passed=True, finished_at=1_800_000_000.0, quick=True), status_file
    )
    record_selftest_result(
        SelftestResult(passed=False, finished_at=1_800_000_500.0, quick=True), status_file
    )

    assert _samples(client.get("/metrics").text)[key] == 1_800_000_000.0


def test_corrupt_selftest_file_reads_as_never_passed(client: TestClient, status_file: Path) -> None:
    status_file.parent.mkdir(parents=True)
    status_file.write_text("garbage", encoding="utf-8")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert _samples(r.text)[("lab_selftest_last_success_timestamp", frozenset())] == 0.0


def test_separate_registries_do_not_share_state(status_file: Path) -> None:
    a, b = (
        LabMetrics(selftest_status_file=status_file),
        LabMetrics(selftest_status_file=status_file),
    )
    assert a.registry is not b.registry


def test_metrics_route_is_not_in_the_openapi_schema(client: TestClient) -> None:
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]


# --------------------------------------------------------------------- with a database


def _seed_runs(engine: Engine) -> dict[str, str]:
    ids = seed_experiment(engine)
    add_run(engine, ids, schedule_index=0, arm=Arm.INJECTED, status=RunStatus.VALID)
    add_run(engine, ids, schedule_index=1, arm=Arm.INJECTED, status=RunStatus.VALID)
    add_run(engine, ids, schedule_index=2, arm=Arm.CONTROL, status=RunStatus.INVALID)
    add_run(engine, ids, schedule_index=3, arm=Arm.CONTROL, status=RunStatus.RUNNING)
    add_run(engine, ids, schedule_index=4, arm=Arm.CONTROL, status=RunStatus.QUEUED)
    with session_scope(engine) as s:
        for run in s.query(t.Run).filter(t.Run.status == RunStatus.VALID):
            run.end_status = EndStatus.COMPLETED
    return ids


def test_run_metrics_derive_from_the_runs_table(engine: Engine, status_file: Path) -> None:
    ids = _seed_runs(engine)

    samples = _samples(LabMetrics(engine, selftest_status_file=status_file).exposition().decode())

    valid = {
        "status": "valid",
        "end_status": "completed",
        "agent": ids["agent_id"],
        "target": ids["target_id"],
        "arm": "injected",
    }
    assert samples[("lab_runs_total", frozenset(valid.items()))] == 2.0
    invalid = {**valid, "status": "invalid", "end_status": "none", "arm": "control"}
    assert samples[("lab_runs_total", frozenset(invalid.items()))] == 1.0
    # queued and running runs are not finished: not counted
    assert sum(v for (n, _), v in samples.items() if n == "lab_runs_total") == 3.0
    # by the run's recorded runs.invalid_reason (the seeded run is 'internal')
    assert samples[("lab_invalid_runs_total", frozenset({("reason", "internal")}))] == 1.0
    assert ("lab_invalid_runs_total", frozenset({("reason", UNRECORDED_REASON)})) not in samples
    assert samples[("lab_runs_in_flight", frozenset({("agent", ids["agent_id"])}))] == 1.0
    assert samples[("lab_metrics_database_up", frozenset())] == 1.0


def test_values_survive_a_collector_restart(engine: Engine, status_file: Path) -> None:
    """Two independent processes (fresh LabMetrics) report the same values."""
    _seed_runs(engine)
    record_selftest_result(
        SelftestResult(passed=True, finished_at=1_800_000_000.0, quick=True), status_file
    )

    with TestClient(
        create_app(engine, metrics=LabMetrics(engine, selftest_status_file=status_file))
    ) as c:
        before = _samples(c.get("/metrics").text)
    with TestClient(
        create_app(engine, metrics=LabMetrics(engine, selftest_status_file=status_file))
    ) as c:
        after = _samples(c.get("/metrics").text)

    lab = {k: v for k, v in before.items() if k[0].startswith("lab_")}
    assert lab == {k: v for k, v in after.items() if k[0].startswith("lab_")}
    assert lab[("lab_selftest_last_success_timestamp", frozenset())] == 1_800_000_000.0


def test_in_flight_gauge_is_zero_for_idle_agents(engine: Engine, status_file: Path) -> None:
    ids = seed_experiment(engine)
    samples = _samples(LabMetrics(engine, selftest_status_file=status_file).exposition().decode())
    assert samples[("lab_runs_in_flight", frozenset({("agent", ids["agent_id"])}))] == 0.0


def test_default_app_metrics_use_the_app_engine(engine: Engine) -> None:
    ids = _seed_runs(engine)
    with TestClient(create_app(engine)) as c:
        samples = _samples(c.get("/metrics").text)
    assert samples[("lab_runs_in_flight", frozenset({("agent", ids["agent_id"])}))] == 1.0


def test_concurrent_scrapes_run_one_query_at_a_time(
    monkeypatch: pytest.MonkeyPatch, status_file: Path
) -> None:
    """A slow database must not pile scrapes onto the pool: one query in flight.

    Deterministic: the first scrape's query blocks until released; every scrape that
    arrives meanwhile must return the cached result without querying.
    """
    import threading

    from control.api import metrics as metrics_mod

    entered = threading.Event()
    release = threading.Event()
    calls = 0
    in_flight = 2  # agt_x's sample in the result the next query returns

    def blocking_query(engine: object) -> object:
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(5), "the test never released the query"
        return metrics_mod._RunCounts([], [], [("agt_x", in_flight)])

    monkeypatch.setattr(metrics_mod, "_query", blocking_query)
    lab = LabMetrics(object(), selftest_status_file=status_file)  # type: ignore[arg-type]
    release.set()
    lab.exposition()  # warm: agt_x=2 cached
    release.clear()
    entered.clear()
    calls = 0
    in_flight = 3  # the blocked query's own result

    def sample(text: str) -> float:
        return _samples(text)[("lab_runs_in_flight", frozenset({("agent", "agt_x")}))]

    first: list[str] = []
    others: list[str] = []
    slow = threading.Thread(target=lambda: first.append(lab.exposition().decode()))
    slow.start()
    assert entered.wait(5), "the first scrape never reached the database"
    waiting = [
        threading.Thread(target=lambda: others.append(lab.exposition().decode())) for _ in range(5)
    ]
    for th in waiting:
        th.start()
    for th in waiting:
        th.join(5)
    assert not any(th.is_alive() for th in waiting), "a scrape waited for the query"
    assert calls == 1, "scrapes that found a query in flight did not query"
    assert [sample(t) for t in others] == [2.0] * 5, "they served the cached result"

    release.set()
    slow.join(5)
    assert not slow.is_alive()
    assert calls == 1
    assert [sample(t) for t in first] == [3.0]
