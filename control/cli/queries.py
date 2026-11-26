"""Read-only queries behind ``labctl status``, ``runs ls``, ``run show`` and the
telemetry commands.

Everything runs in :func:`read_only_session`: one ``SET TRANSACTION READ ONLY``
transaction (Postgres refuses any write in it) with a statement timeout, on the
tables of :mod:`control.db.tables`. labctl never writes to the database.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from control.core.logging import redact_text
from control.core.models import RunStatus
from control.db.tables import (
    TELEMETRY_FIELDS,
    Artifact,
    EventKeyEntry,
    Experiment,
    Label,
    Placement,
    RejectedBatch,
    Run,
    RunHeartbeatRow,
    RunTelemetryRow,
)

__all__ = [
    "EXPORT_COLUMNS",
    "QUERY_TIMEOUT_MS",
    "RunDetail",
    "RunSummary",
    "experiment_count",
    "get_run",
    "get_run_telemetry",
    "list_runs",
    "read_only_session",
    "run_exists",
    "run_status_counts",
    "telemetry_export_rows",
]

QUERY_TIMEOUT_MS: Final = 15_000

#: The columns of ``labctl export telemetry``, in order: the run's identity and verdict,
#: then the summary (``telemetry_version`` last).
EXPORT_COLUMNS: Final = (
    "run_id",
    "block_id",
    "arm",
    "target",
    "agent",
    "model",
    "end_status",
    "status",
    "invalid_reason",
    "effect",
    "mechanism",
    *(f for f in TELEMETRY_FIELDS if f != "telemetry_version"),
    "telemetry_version",
    "telemetry_status",
)


@contextmanager
def read_only_session(engine: Engine) -> Iterator[Session]:
    """A session in one ``READ ONLY`` transaction, rolled back at the end."""
    with Session(engine) as session:
        try:
            session.execute(text("SET TRANSACTION READ ONLY"))
            session.execute(text(f"SET LOCAL statement_timeout = {int(QUERY_TIMEOUT_MS)}"))
            yield session
        finally:
            session.rollback()


@dataclass(frozen=True, slots=True)
class RunSummary:
    run_id: str
    experiment_id: str
    arm: str
    target_id: str
    agent_id: str
    model_id: str
    status: str
    end_status: str | None
    outcome: bool | None
    created_at: datetime
    #: why the run is invalid (a bounded set), else None
    invalid_reason: str | None
    #: the run ran on a development host (LAB_DEV=1)
    dev: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "arm": self.arm,
            "target_id": self.target_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "status": self.status,
            "end_status": self.end_status,
            "outcome": self.outcome,
            "created_at": self.created_at.isoformat(),
            "invalid_reason": self.invalid_reason,
            "dev": self.dev,
        }


def _value(v: Any) -> Any:
    return getattr(v, "value", v)


def _summary(run: Run) -> RunSummary:
    return RunSummary(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        arm=_value(run.arm),
        target_id=run.target_id,
        agent_id=run.agent_id,
        model_id=run.model_id,
        status=_value(run.status),
        end_status=_value(run.end_status),
        outcome=run.outcome,
        created_at=run.created_at,
        invalid_reason=_value(run.invalid_reason),
        dev=run.dev,
    )


def run_status_counts(session: Session) -> dict[str, int]:
    """Number of runs per status (every :class:`RunStatus`, zero included)."""
    counts = dict.fromkeys((s.value for s in RunStatus), 0)
    for status, count in session.execute(select(Run.status, func.count()).group_by(Run.status)):
        counts[_value(status)] = int(count)
    return counts


def experiment_count(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(Experiment)) or 0)


def list_runs(
    session: Session,
    *,
    limit: int,
    status: RunStatus | None = None,
    experiment_id: str | None = None,
) -> list[RunSummary]:
    """Runs, newest first (``created_at``, then ``run_id``, descending)."""
    stmt = select(Run).order_by(Run.created_at.desc(), Run.run_id.desc()).limit(limit)
    if status is not None:
        stmt = stmt.where(Run.status == status)
    if experiment_id is not None:
        stmt = stmt.where(Run.experiment_id == experiment_id)
    return [_summary(run) for run in session.scalars(stmt)]


@dataclass(frozen=True, slots=True)
class RunDetail:
    """One run in full. ``to_json`` also prints ``block_id`` as ``pair_id``, the name it
    had before the three-arm design: a deprecated alias kept for one release."""

    run: RunSummary
    block_id: str
    schedule_index: int
    attempt: int
    tag: str | None
    effect: bool | None
    mechanism: bool | None
    oracle_message: str | None
    #: everything that went wrong, redacted (again: rows stored before the runner
    #: redacted it may hold secrets)
    invalid_detail: str | None
    started_at: datetime | None
    finished_at: datetime | None
    decided_at: datetime | None
    manifest_sha256: str | None
    placements: int
    events: dict[str, int]
    labels: list[dict[str, Any]]
    artifacts: int
    rejected_batches: int
    last_heartbeat: dict[str, Any] | None

    def to_json(self) -> dict[str, Any]:
        def ts(v: datetime | None) -> str | None:
            return None if v is None else v.isoformat()

        return {
            **self.run.to_json(),
            "block_id": self.block_id,
            "pair_id": self.block_id,  # deprecated alias of block_id, for one release
            "schedule_index": self.schedule_index,
            "attempt": self.attempt,
            "tag": self.tag,
            "effect": self.effect,
            "mechanism": self.mechanism,
            "oracle_message": self.oracle_message,
            "invalid_detail": self.invalid_detail,
            "started_at": ts(self.started_at),
            "finished_at": ts(self.finished_at),
            "decided_at": ts(self.decided_at),
            "manifest_sha256": self.manifest_sha256,
            "placements": self.placements,
            "events": self.events,
            "labels": self.labels,
            "artifacts": self.artifacts,
            "rejected_batches": self.rejected_batches,
            "last_heartbeat": self.last_heartbeat,
        }


def get_run(session: Session, run_id: str) -> RunDetail | None:
    """Everything ``labctl run show`` prints, or ``None`` for an unknown run."""
    run = session.get(Run, run_id)
    if run is None:
        return None

    def count(model: Any, *where: Any) -> int:
        return int(session.scalar(select(func.count()).select_from(model).where(*where)) or 0)

    events = {
        _value(kind): int(n)
        for kind, n in session.execute(
            select(EventKeyEntry.kind, func.count())
            .where(EventKeyEntry.run_id == run_id)
            .group_by(EventKeyEntry.kind)
            .order_by(EventKeyEntry.kind)
        )
    }
    labels = [
        {
            "stage": _value(label.stage),
            "value": label.value,
            "labeler": label.labeler,
            "labeler_version": label.labeler_version,
        }
        for label in session.scalars(
            select(Label).where(Label.run_id == run_id).order_by(Label.stage, Label.id)
        )
    ]
    heartbeat = session.scalars(
        select(RunHeartbeatRow)
        .where(RunHeartbeatRow.run_id == run_id)
        .order_by(RunHeartbeatRow.seq.desc())
        .limit(1)
    ).first()
    return RunDetail(
        run=_summary(run),
        block_id=run.block_id,
        schedule_index=run.schedule_index,
        attempt=run.attempt,
        tag=run.tag,
        effect=run.effect,
        mechanism=run.mechanism,
        oracle_message=run.oracle_message,
        invalid_detail=None if run.invalid_detail is None else redact_text(run.invalid_detail),
        started_at=run.started_at,
        finished_at=run.finished_at,
        decided_at=run.decided_at,
        manifest_sha256=run.manifest_sha256,
        placements=count(Placement, Placement.run_id == run_id),
        events=events,
        labels=labels,
        artifacts=count(Artifact, Artifact.run_id == run_id),
        rejected_batches=count(RejectedBatch, RejectedBatch.run_id == run_id),
        last_heartbeat=None
        if heartbeat is None
        else {
            "seq": heartbeat.seq,
            "phase": _value(heartbeat.phase),
            "ts": heartbeat.ts.isoformat(),
        },
    )


def run_exists(session: Session, run_id: str) -> bool:
    return session.get(Run, run_id) is not None


def get_run_telemetry(session: Session, run_id: str) -> dict[str, Any] | None:
    """A run's stored telemetry (summary fields plus ``telemetry_error``), or ``None``
    when none was derived (or the run is unknown)."""
    row = session.get(RunTelemetryRow, run_id)
    if row is None:
        return None
    return {
        "run_id": run_id,
        **row.summary(),
        "telemetry_error": row.telemetry_error,
        "derived_at": row.created_at.isoformat(),
    }


def telemetry_export_rows(session: Session, experiment_id: str) -> list[dict[str, Any]] | None:
    """One row for every run of the experiment, keyed by :data:`EXPORT_COLUMNS` plus
    ``telemetry_error``; ordered by schedule index, attempt and run id. Nothing is left
    out: a run without a telemetry record has ``telemetry_status`` ``missing`` and empty
    summary cells. ``None`` for an unknown experiment."""
    if session.get(Experiment, experiment_id) is None:
        return None
    stmt = (
        select(Run, RunTelemetryRow)
        .outerjoin(RunTelemetryRow, RunTelemetryRow.run_id == Run.run_id)
        .where(Run.experiment_id == experiment_id)
        .order_by(Run.schedule_index, Run.attempt, Run.run_id)
    )
    return [
        {
            "run_id": run.run_id,
            "block_id": run.block_id,
            "arm": _value(run.arm),
            "target": run.target_id,
            "agent": run.agent_id,
            "model": run.model_id,
            "end_status": _value(run.end_status),
            "status": _value(run.status),
            "invalid_reason": _value(run.invalid_reason),
            "effect": run.effect,
            "mechanism": run.mechanism,
            **(tel.summary() if tel else dict.fromkeys(TELEMETRY_FIELDS)),
            "telemetry_status": tel.status if tel else "missing",
            "telemetry_error": tel.telemetry_error if tel else None,
        }
        for run, tel in session.execute(stmt)
    ]
