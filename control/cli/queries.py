"""Read-only queries behind ``labctl status``, ``runs ls`` and ``run show``.

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

from control.core.models import RunStatus
from control.db.tables import (
    Artifact,
    EventKeyEntry,
    Experiment,
    Label,
    Placement,
    RejectedBatch,
    Run,
    RunHeartbeatRow,
)

__all__ = [
    "QUERY_TIMEOUT_MS",
    "RunDetail",
    "RunSummary",
    "experiment_count",
    "get_run",
    "list_runs",
    "read_only_session",
    "run_status_counts",
]

QUERY_TIMEOUT_MS: Final = 15_000


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
    run: RunSummary
    pair_id: str
    schedule_index: int
    attempt: int
    tag: str | None
    oracle_message: str | None
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
            "pair_id": self.pair_id,
            "schedule_index": self.schedule_index,
            "attempt": self.attempt,
            "tag": self.tag,
            "oracle_message": self.oracle_message,
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
        pair_id=run.pair_id,
        schedule_index=run.schedule_index,
        attempt=run.attempt,
        tag=run.tag,
        oracle_message=run.oracle_message,
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
