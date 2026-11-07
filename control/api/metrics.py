"""Prometheus metrics for the lab services (docs/TRACKING.md §3.2).

:class:`LabMetrics` owns its own :class:`~prometheus_client.CollectorRegistry` (never
the process-global one), so apps and tests can each have an isolated set. The
Collector app exposes one at ``GET /metrics`` (:func:`metrics_router`) in the
Prometheus text exposition format.

Metrics:

* ``lab_runs_total`` (counter; ``status``, ``end_status``, ``agent``, ``target``,
  ``arm``): finished runs. ``end_status`` is ``none`` when the run has none (e.g. an
  invalid run that never ended normally).
* ``lab_invalid_runs_total`` (counter; ``reason``): runs marked invalid, by reason.
* ``lab_runs_in_flight`` (gauge; ``agent``): runs currently executing.
* ``lab_selftest_last_success_timestamp`` (gauge): Unix time of the last passing
  self-test.

Plus the standard ``process_*``, ``python_gc_*`` and ``python_info`` collectors.

Counters live in the memory of the process that increments them: a process that
records runs must be the one scraped (or expose its own ``/metrics``).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum

from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    GC_COLLECTOR,
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    CollectorRegistry,
    Counter,
    Gauge,
    generate_latest,
)

__all__ = [
    "METRIC_NAMES",
    "NONE_LABEL",
    "LabMetrics",
    "metrics_router",
]

#: The lab's own metric names, as they appear in the exposition.
METRIC_NAMES: tuple[str, ...] = (
    "lab_runs_total",
    "lab_invalid_runs_total",
    "lab_runs_in_flight",
    "lab_selftest_last_success_timestamp",
)

#: Label value used for an absent ``end_status``.
NONE_LABEL = "none"


def _label(value: str | Enum | None) -> str:
    if value is None:
        return NONE_LABEL
    if isinstance(value, Enum):
        return str(value.value)
    return value


class LabMetrics:
    """The lab's service metrics, registered on their own registry."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        if registry is None:
            registry = CollectorRegistry()
            for collector in (PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR):
                registry.register(collector)
        self.registry = registry
        self.runs_total = Counter(
            "lab_runs",
            "Finished runs.",
            ["status", "end_status", "agent", "target", "arm"],
            registry=registry,
        )
        self.invalid_runs_total = Counter(
            "lab_invalid_runs", "Runs marked invalid, by reason.", ["reason"], registry=registry
        )
        self.runs_in_flight = Gauge(
            "lab_runs_in_flight",
            "Runs currently executing.",
            ["agent"],
            registry=registry,
        )
        self.selftest_last_success_timestamp = Gauge(
            "lab_selftest_last_success_timestamp",
            "Unix time of the last passing self-test.",
            registry=registry,
        )

    # ----------------------------------------------------------------- recording

    def record_run(
        self,
        *,
        status: str | Enum,
        end_status: str | Enum | None,
        agent: str,
        target: str,
        arm: str | Enum,
    ) -> None:
        """Count one finished run."""
        self.runs_total.labels(
            status=_label(status),
            end_status=_label(end_status),
            agent=agent,
            target=target,
            arm=_label(arm),
        ).inc()

    def record_invalid_run(self, reason: str | Enum) -> None:
        """Count one run marked invalid for ``reason``."""
        self.invalid_runs_total.labels(reason=_label(reason)).inc()

    @contextmanager
    def track_in_flight(self, agent: str) -> Iterator[None]:
        """Count a run as in flight for the duration of the block, even if it raises."""
        gauge = self.runs_in_flight.labels(agent=agent)
        gauge.inc()
        try:
            yield
        finally:
            gauge.dec()

    def record_selftest_success(self, timestamp: float | None = None) -> None:
        """Record a passing self-test at ``timestamp`` (default: now)."""
        self.selftest_last_success_timestamp.set(time.time() if timestamp is None else timestamp)

    # ----------------------------------------------------------------- exposition

    def exposition(self) -> bytes:
        """The registry in the Prometheus text exposition format."""
        return generate_latest(self.registry)


def metrics_router() -> APIRouter:
    """``GET /metrics`` serving ``request.app.state.metrics`` (a :class:`LabMetrics`)."""
    router = APIRouter()

    @router.get("/metrics", include_in_schema=False)
    def metrics(request: Request) -> Response:
        lab_metrics: LabMetrics = request.app.state.metrics
        return Response(content=lab_metrics.exposition(), media_type=CONTENT_TYPE_LATEST)

    return router
