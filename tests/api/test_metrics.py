"""Prometheus ``/metrics`` on the Collector app (docs/TRACKING.md §3.2).

No database: ``create_app()`` without an engine never connects until a route needs it,
and ``/metrics`` does not.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from control.api.app import create_app
from control.api.metrics import METRIC_NAMES, LabMetrics
from control.core.models import Arm, EndStatus, RunStatus


@pytest.fixture
def metrics() -> LabMetrics:
    return LabMetrics()


@pytest.fixture
def client(metrics: LabMetrics) -> Iterator[TestClient]:
    with TestClient(create_app(metrics=metrics)) as c:
        yield c


def _samples(text: str) -> dict[tuple[str, frozenset[tuple[str, str]]], float]:
    return {
        (s.name, frozenset(s.labels.items())): s.value
        for fam in text_string_to_metric_families(text)
        for s in fam.samples
    }


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


def test_run_counter_increment_shows_up(client: TestClient, metrics: LabMetrics) -> None:
    metrics.record_run(
        status=RunStatus.VALID,
        end_status=EndStatus.COMPLETED,
        agent="scripted",
        target="dvga",
        arm=Arm.INJECTED,
    )
    metrics.record_run(
        status=RunStatus.VALID,
        end_status=EndStatus.COMPLETED,
        agent="scripted",
        target="dvga",
        arm=Arm.INJECTED,
    )
    metrics.record_run(
        status=RunStatus.INVALID, end_status=None, agent="scripted", target="dvga", arm=Arm.CONTROL
    )

    samples = _samples(client.get("/metrics").text)
    labels = {
        "status": "valid",
        "end_status": "completed",
        "agent": "scripted",
        "target": "dvga",
        "arm": "injected",
    }
    assert samples[("lab_runs_total", frozenset(labels.items()))] == 2.0
    invalid = {**labels, "status": "invalid", "end_status": "none", "arm": "control"}
    assert samples[("lab_runs_total", frozenset(invalid.items()))] == 1.0


def test_invalid_counter_in_flight_gauge_and_selftest_timestamp(
    client: TestClient, metrics: LabMetrics
) -> None:
    metrics.record_invalid_run("containment_breach")
    with metrics.track_in_flight("scripted"):
        during = _samples(client.get("/metrics").text)
    after = _samples(client.get("/metrics").text)
    metrics.record_selftest_success(1_700_000_000.0)
    final = _samples(client.get("/metrics").text)

    reason = frozenset({("reason", "containment_breach")})
    assert final[("lab_invalid_runs_total", reason)] == 1.0
    agent = frozenset({("agent", "scripted")})
    assert during[("lab_runs_in_flight", agent)] == 1.0
    assert after[("lab_runs_in_flight", agent)] == 0.0
    assert final[("lab_selftest_last_success_timestamp", frozenset())] == 1_700_000_000.0


def test_in_flight_gauge_decrements_on_error(metrics: LabMetrics) -> None:
    with pytest.raises(RuntimeError), metrics.track_in_flight("scripted"):
        raise RuntimeError("cell crashed")
    assert (
        _samples(metrics.exposition().decode())[
            ("lab_runs_in_flight", frozenset({("agent", "scripted")}))
        ]
        == 0.0
    )


def test_selftest_timestamp_defaults_to_now(metrics: LabMetrics) -> None:
    metrics.record_selftest_success()
    value = _samples(metrics.exposition().decode())[
        ("lab_selftest_last_success_timestamp", frozenset())
    ]
    assert value > 1_700_000_000.0


def test_separate_registries_do_not_share_state() -> None:
    a, b = LabMetrics(), LabMetrics()
    a.record_invalid_run("x")
    assert 'reason="x"' in a.exposition().decode()
    assert 'reason="x"' not in b.exposition().decode()


def test_default_app_exposes_metrics_without_a_database() -> None:
    with TestClient(create_app()) as c:
        r = c.get("/metrics")
    assert r.status_code == 200
    assert "# TYPE lab_runs_total counter" in r.text


def test_metrics_route_is_not_in_the_openapi_schema(client: TestClient) -> None:
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]
