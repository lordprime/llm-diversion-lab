"""Prometheus metrics for the lab services (docs/TRACKING.md §3.2).

Process model
-------------
**Every lab metric is derived at scrape time from persistent state**, never counted
in a process's memory, so a restart of the Collector (or of the runner, or of the
self-test) loses nothing and two Collector processes report the same values:

* ``lab_runs_total`` (counter; ``status``, ``end_status``, ``agent``, ``target``,
  ``arm``): finished runs, i.e. rows of ``runs`` with ``status`` ``valid`` or
  ``invalid``. ``agent`` / ``target`` are the run's ``agent_id`` / ``target_id``;
  ``end_status`` is ``none`` when the run has none.
* ``lab_invalid_runs_total`` (counter; ``reason``): runs with ``status = 'invalid'``,
  by ``runs.invalid_reason`` (the bounded :class:`~control.core.models.InvalidReason`
  set the runner records). A database CHECK makes every invalid run carry one;
  :data:`UNRECORDED_REASON` would only label a row that somehow had none.
* ``lab_runs_in_flight`` (gauge; ``agent``): runs with ``status = 'running'``; ``0``
  for every registered agent with none.
* ``lab_selftest_last_success_timestamp`` (gauge): Unix time of the last passing
  self-test, from the self-test status file (:mod:`control.core.selftest_status`);
  ``0`` when no self-test has passed (or the file is unreadable), so a staleness
  alert fires rather than going quiet.
* ``lab_metrics_database_up`` (gauge): ``1`` if the run metrics above could be read
  from the database during this scrape, else ``0``; the run families are then
  **absent** (never reported as a misleading ``0``).

The counters are monotonic because runs are never deleted (an invalid run is retried
as a new row); restoring a pre-migration dump can lower them, which Prometheus reads
as a counter reset.

The alternative, the runner incrementing counters through the Collector API, was
rejected: in-memory counters reset on every Collector restart, and persisting them
would duplicate what the runs table already records.

Each scrape runs a few ``GROUP BY`` queries in one ``READ ONLY`` transaction with a
:data:`QUERY_TIMEOUT_MS` statement timeout. **One query at a time:** a scrape that
finds another one's query in flight reuses the last result instead of opening another
connection (none yet: the database reads as down), so a slow or hung database cannot
pile scrapes onto the connection pool. The Collector's engine also has a connect
timeout (:mod:`control.api.__main__`).

:class:`LabMetrics` owns its own :class:`~prometheus_client.CollectorRegistry` (never
the process-global one), plus the standard ``process_*``, ``python_gc_*`` and
``python_info`` collectors. The Collector app exposes it at ``GET /metrics``
(:func:`metrics_router`).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Iterator
from enum import Enum
from pathlib import Path
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    GC_COLLECTOR,
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    CollectorRegistry,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from prometheus_client.registry import Collector
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import SQLAlchemyError

from control.core.models import RunStatus
from control.core.selftest_status import SelftestStatusError, read_selftest_status
from control.db.tables import Agent, Run

__all__ = [
    "METRIC_NAMES",
    "NONE_LABEL",
    "QUERY_TIMEOUT_MS",
    "UNRECORDED_REASON",
    "LabMetrics",
    "metrics_router",
]

log = logging.getLogger(__name__)

#: The lab's own metric names, as they appear in the exposition.
METRIC_NAMES: tuple[str, ...] = (
    "lab_runs_total",
    "lab_invalid_runs_total",
    "lab_runs_in_flight",
    "lab_selftest_last_success_timestamp",
    "lab_metrics_database_up",
)

#: Label value used for an absent ``end_status``.
NONE_LABEL: Final = "none"
#: ``reason`` label of ``lab_invalid_runs_total`` for an invalid run without a reason.
UNRECORDED_REASON: Final = "unrecorded"
#: Statement timeout of the scrape queries.
QUERY_TIMEOUT_MS: Final = 5_000

EngineSource = Engine | Callable[[], Engine]


def _label(value: str | Enum | None) -> str:
    if value is None:
        return NONE_LABEL
    if isinstance(value, Enum):
        return str(value.value)
    return value


class _RunTableCollector(Collector):
    """Builds the lab metric families from the database and the self-test file."""

    def __init__(self, engine: EngineSource | None, selftest_status_file: Path | None) -> None:
        self._engine = engine
        self._selftest_status_file = selftest_status_file
        self._query_lock = threading.Lock()
        self._last: _RunCounts | None = None

    def describe(self) -> Iterable[Metric]:
        # Families without samples: registering never touches the database.
        return list(self._families(db=None))

    def collect(self) -> Iterable[Metric]:
        return list(self._families(db=self._read_database()))

    def _read_database(self) -> _RunCounts | None:
        if self._engine is None:
            return None
        if not self._query_lock.acquire(blocking=False):
            return self._last  # another scrape's query is in flight
        try:
            engine = self._engine() if callable(self._engine) else self._engine
            self._last = _query(engine)
        except (SQLAlchemyError, RuntimeError, ValueError) as exc:
            log.warning("metrics: database unavailable: %s", type(exc).__name__)
            self._last = None
        finally:
            self._query_lock.release()
        return self._last

    def _families(self, db: _RunCounts | None) -> Iterator[Metric]:
        runs = CounterMetricFamily(
            "lab_runs",
            "Finished runs.",
            labels=["status", "end_status", "agent", "target", "arm"],
        )
        invalid = CounterMetricFamily(
            "lab_invalid_runs", "Runs marked invalid, by reason.", labels=["reason"]
        )
        in_flight = GaugeMetricFamily(
            "lab_runs_in_flight", "Runs currently executing.", labels=["agent"]
        )
        if db is not None:
            for labels, count in db.finished:
                runs.add_metric(list(labels), count)
            for reason, count in db.invalid:
                invalid.add_metric([reason], count)
            for agent, count in db.in_flight:
                in_flight.add_metric([agent], count)
        yield runs
        yield invalid
        yield in_flight

        selftest = GaugeMetricFamily(
            "lab_selftest_last_success_timestamp", "Unix time of the last passing self-test."
        )
        selftest.add_metric([], self._selftest_timestamp())
        yield selftest

        up = GaugeMetricFamily(
            "lab_metrics_database_up",
            "1 if the latest database read for the run metrics succeeded, else 0.",
        )
        up.add_metric([], 0.0 if db is None else 1.0)
        yield up

    def _selftest_timestamp(self) -> float:
        try:
            ts = read_selftest_status(self._selftest_status_file).last_success_timestamp
        except SelftestStatusError as exc:
            log.warning("metrics: unreadable self-test status: %s", exc)
            return 0.0
        return 0.0 if ts is None else ts


class _RunCounts:
    __slots__ = ("finished", "in_flight", "invalid")

    def __init__(
        self,
        finished: list[tuple[tuple[str, str, str, str, str], int]],
        invalid: list[tuple[str, int]],
        in_flight: list[tuple[str, int]],
    ) -> None:
        self.finished = finished
        self.invalid = invalid
        self.in_flight = in_flight


def _query(engine: Engine) -> _RunCounts:
    finished_q = (
        select(Run.status, Run.end_status, Run.agent_id, Run.target_id, Run.arm, func.count())
        .where(Run.status.in_([RunStatus.VALID, RunStatus.INVALID]))
        .group_by(Run.status, Run.end_status, Run.agent_id, Run.target_id, Run.arm)
    )
    invalid_q = (
        select(Run.invalid_reason, func.count())
        .where(Run.status == RunStatus.INVALID)
        .group_by(Run.invalid_reason)
    )
    in_flight_q = (
        select(Agent.agent_id, func.count(Run.run_id))
        .select_from(Agent)
        .outerjoin(Run, (Run.agent_id == Agent.agent_id) & (Run.status == RunStatus.RUNNING))
        .group_by(Agent.agent_id)
    )
    with engine.connect() as conn, conn.begin():
        conn.execute(text("SET TRANSACTION READ ONLY"))
        conn.execute(text(f"SET LOCAL statement_timeout = {int(QUERY_TIMEOUT_MS)}"))
        finished = [
            (
                (
                    _label(status),
                    _label(end_status),
                    agent,
                    target,
                    _label(arm),
                ),
                int(count),
            )
            for status, end_status, agent, target, arm, count in conn.execute(finished_q)
        ]
        invalid = [
            (UNRECORDED_REASON if reason is None else _label(reason), int(count))
            for reason, count in conn.execute(invalid_q)
        ]
        in_flight = [(agent, int(count)) for agent, count in conn.execute(in_flight_q)]
    return _RunCounts(finished, invalid, in_flight)


class LabMetrics:
    """The lab's service metrics, on their own registry, derived at scrape time.

    ``engine`` is the database to read (an :class:`~sqlalchemy.Engine` or a callable
    returning one, resolved at each scrape); ``None`` reports the database as down.
    ``selftest_status_file`` defaults to ``$LAB_SELFTEST_STATUS_FILE`` / the default
    location of :mod:`control.core.selftest_status`.
    """

    def __init__(
        self,
        engine: EngineSource | None = None,
        *,
        selftest_status_file: Path | None = None,
        registry: CollectorRegistry | None = None,
    ) -> None:
        if registry is None:
            registry = CollectorRegistry()
            for collector in (PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR):
                registry.register(collector)
        self.registry = registry
        registry.register(_RunTableCollector(engine, selftest_status_file))

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
