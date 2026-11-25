"""Results API: ``GET /v1/runs/{id}/telemetry`` (read-only, derived data)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from control.api.app import create_app
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.store import RunStore
from tests.db.test_repo import add_run, seed_experiment
from tests.runner.test_derive import _stored_run_summary


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as c:
        yield c


def test_a_stored_summary_is_returned_with_every_field(
    client: TestClient, engine: Engine, tmp_path: Path
) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    RunStore(engine).record_telemetry(summary)
    response = client.get(f"/v1/runs/{summary.run_id}/telemetry")
    assert response.status_code == 200
    body = response.json()
    assert body["telemetry_error"] is None
    for field in (
        "run_id", "telemetry_version", "calls", "agents", "agents_source",
        "peak_input_tokens", "input_tokens", "output_tokens", "reasoning_chars",
        "calls_with_reasoning", "single_call_threads", "largest_thread_calls",
        "branch_points", "persona_splits",
    ):  # fmt: skip
        assert body[field] == getattr(summary, field), field


def test_a_failed_derivation_is_reported_not_hidden(client: TestClient, engine: Engine) -> None:
    run_id = add_run(engine, seed_experiment(engine), schedule_index=0)
    RunStore(engine).record_telemetry_error(run_id, "the tap folder is a symlink")
    response = client.get(f"/v1/runs/{run_id}/telemetry")
    assert response.status_code == 200
    body = response.json()
    assert body["telemetry_error"] == "the tap folder is a symlink"
    assert body["calls"] is None and body["telemetry_version"] is None


def test_a_run_without_telemetry_is_404(client: TestClient, engine: Engine) -> None:
    run_id = add_run(engine, seed_experiment(engine), schedule_index=0)
    response = client.get(f"/v1/runs/{run_id}/telemetry")
    assert (response.status_code, response.json()["reason"]) == (404, "no_telemetry")


@pytest.mark.parametrize("run_id", ["run_missing", "x" * 300, "bad id", "..%2f..", "%00"])
def test_an_unknown_or_odd_run_id_is_404_and_stores_nothing(
    client: TestClient, engine: Engine, run_id: str
) -> None:
    response = client.get(f"/v1/runs/{run_id}/telemetry")
    assert response.status_code in (404, 422)
    with session_scope(engine) as s:
        assert s.query(t.RejectedBatch).count() == 0


def test_only_get_is_allowed(client: TestClient, engine: Engine) -> None:
    run_id = add_run(engine, seed_experiment(engine), schedule_index=0)
    for method in ("post", "put", "delete"):
        assert getattr(client, method)(f"/v1/runs/{run_id}/telemetry").status_code == 405
