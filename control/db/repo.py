"""Queue and evidence-write operations on the control-plane database.

Functions take an open :class:`~sqlalchemy.orm.Session` and never commit; the caller
owns the transaction (normally :func:`control.db.engine.session_scope`).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, JsonValue
from sqlalchemy import (
    BigInteger,
    ColumnElement,
    Connection,
    String,
    column,
    func,
    select,
    update,
    values,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from control.core import models as m
from control.core.models import (
    CollectorEndpoint,
    Event,
    EventKind,
    RejectReason,
    RunStatus,
)
from control.core.selftest_status import SELFTEST_EXPERIMENT_PREFIX
from control.db.tables import (
    EVENT_TABLES,
    Artifact,
    EventKeyEntry,
    EventRow,
    Placement,
    RejectedBatch,
    Run,
    RunHeartbeatRow,
)

__all__ = [
    "BULK_CHUNK_ROWS",
    "UNRECORDED_REASON",
    "ArtifactResult",
    "EventKey",
    "InsertResult",
    "WriteOutcome",
    "WriteResult",
    "claim_next_run",
    "event_content_sha256",
    "foreign_placements",
    "insert_events",
    "invalid_runs_by_reason",
    "model_sha256",
    "not_selftest",
    "record_heartbeat",
    "record_manifest",
    "record_rejected",
    "record_verdict",
    "register_artifacts",
    "run_exists",
]


#: Rows per multi-row statement. Postgres allows at most 65,535 bind parameters in one
#: statement; the widest event table binds about 20 per row, so 1,000 rows stay far
#: below the limit. Chunks of one call all run in the caller's transaction.
BULK_CHUNK_ROWS: Final = 1_000


def _chunks[T](items: Sequence[T], size: int = BULK_CHUNK_ROWS) -> Iterator[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


#: ``reason`` of an invalid run without a recorded one (a CHECK makes that impossible).
UNRECORDED_REASON: Final = "unrecorded"


def not_selftest() -> ColumnElement[bool]:
    """Runs of study experiments only: not of a self-test (``exp_selftest_*``)."""
    return ~Run.experiment_id.startswith(SELFTEST_EXPERIMENT_PREFIX, autoescape=True)


def invalid_runs_by_reason(conn: Session | Connection) -> dict[str, int]:
    """Invalid study runs counted by ``runs.invalid_reason`` (``lab_invalid_runs_total``);
    self-test runs are left out (:func:`not_selftest`)."""
    rows = conn.execute(
        select(Run.invalid_reason, func.count())
        .where(Run.status == RunStatus.INVALID, not_selftest())
        .group_by(Run.invalid_reason)
    )
    return {
        (reason.value if reason is not None else UNRECORDED_REASON): int(n) for reason, n in rows
    }


def claim_next_run(session: Session, *, experiment_id: str | None = None) -> Run | None:
    """Claim the next queued run (of ``experiment_id`` if given), or ``None``.

    The oldest queued run (by ``created_at``, then ``schedule_index``) is selected with
    ``SELECT ... FOR UPDATE SKIP LOCKED`` and, in the same statement, moved to
    ``running`` with ``started_at = now()``. A run whose row another open transaction
    holds is skipped rather than waited for, so concurrent workers never claim the
    same run. If the caller's transaction rolls back, the run is queued again.
    """
    queued = Run.status == RunStatus.QUEUED
    if experiment_id is not None:
        queued = queued & (Run.experiment_id == experiment_id)
    next_queued = (
        select(Run.run_id)
        .where(queued)
        .order_by(Run.created_at, Run.schedule_index, Run.run_id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    stmt = (
        update(Run)
        .where(Run.run_id == next_queued)
        .values(status=RunStatus.RUNNING, started_at=func.now())
        .returning(Run)
        .execution_options(populate_existing=True)
    )
    return session.scalars(stmt).one_or_none()


# --------------------------------------------------------------------------- events


@dataclass(frozen=True, slots=True)
class EventKey:
    """An event's idempotency key ``(run_id, stream, seq)`` plus the kind it came as."""

    run_id: str
    stream: str
    seq: int
    kind: EventKind


@dataclass(slots=True)
class InsertResult:
    """Outcome of :func:`insert_events`.

    * ``inserted``: events stored now (their key was new).
    * ``duplicates``: events whose key was already stored with the same kind and the
      same content hash; a harmless re-ship, nothing written.
    * ``conflicts``: events whose key was already stored with a different kind or
      different content; nothing written. ``kind`` is the kind of the *rejected*
      event. The caller must not drop these silently.
    """

    inserted: int = 0
    duplicates: int = 0
    conflicts: list[EventKey] = field(default_factory=list)


def model_sha256(model: BaseModel) -> str:
    """SHA-256 of a model's canonical JSON (every field, sorted keys, compact, UTF-8)."""
    canonical = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def event_content_sha256(event: Event) -> str:
    """SHA-256 of the event's canonical JSON (every field, kind included, sorted keys)."""
    return model_sha256(event)


def insert_events(session: Session, events: Iterable[Event]) -> InsertResult:
    """Store evidence events idempotently on ``(run_id, stream, seq)``, across kinds.

    1. Every key is claimed in ``event_keys`` with
       ``INSERT ... ON CONFLICT DO NOTHING RETURNING``.
    2. Only events whose key was newly claimed are written to their kind table.
    3. A key that already existed is a *duplicate* if the stored kind and content hash
       match, otherwise a *conflict*. Neither writes anything.

    Within one call the first event for a key wins; later ones are classified against
    it the same way. Everything happens in the caller's transaction.
    """
    result = InsertResult()
    first: dict[tuple[str, str, int], tuple[Event, str]] = {}
    for event in events:
        key = (event.run_id, event.stream, event.seq)
        digest = event_content_sha256(event)
        if key in first:
            _classify(result, event, first[key][0].kind, first[key][1], digest)
        else:
            first[key] = (event, digest)
    if not first:
        return result

    claimed: set[tuple[str, str, int]] = set()
    for chunk in _chunks(list(first.values())):
        claim = (
            pg_insert(EventKeyEntry)
            .values(
                [
                    {
                        "run_id": ev.run_id,
                        "stream": ev.stream,
                        "seq": ev.seq,
                        "kind": ev.kind,
                        "content_sha256": digest,
                    }
                    for ev, digest in chunk
                ]
            )
            .on_conflict_do_nothing()
            .returning(EventKeyEntry.run_id, EventKeyEntry.stream, EventKeyEntry.seq)
        )
        claimed.update((r.run_id, r.stream, r.seq) for r in session.execute(claim))

    existing_keys = [k for k in first if k not in claimed]
    for chunk_keys in _chunks(existing_keys):
        # join against a VALUES list (hash join) rather than a row-value IN list, which
        # Postgres plans as one OR branch per key
        keys = values(
            column("run_id", String),
            column("stream", String),
            column("seq", BigInteger),
            name="k",
        ).data(list(chunk_keys))
        stored = session.execute(
            select(
                EventKeyEntry.run_id,
                EventKeyEntry.stream,
                EventKeyEntry.seq,
                EventKeyEntry.kind,
                EventKeyEntry.content_sha256,
            ).join(
                keys,
                (EventKeyEntry.run_id == keys.c.run_id)
                & (EventKeyEntry.stream == keys.c.stream)
                & (EventKeyEntry.seq == keys.c.seq),
            )
        )
        for row in stored:
            event, digest = first[(row.run_id, row.stream, row.seq)]
            _classify(result, event, row.kind, row.content_sha256, digest)

    rows: defaultdict[type[EventRow], list[dict[str, Any]]] = defaultdict(list)
    for key, (event, _) in first.items():  # batch order, not set order
        if key in claimed:
            rows[EVENT_TABLES[event.kind]].append(event.model_dump(exclude={"kind"}))
    # Plain INSERT: the per-table unique (run_id, stream, seq) constraint raises if a
    # row exists without its ledger entry, which would be a bug, not a re-ship.
    for table, table_rows in rows.items():
        for chunk_rows in _chunks(table_rows):
            session.execute(pg_insert(table).values(list(chunk_rows)))
    result.inserted = len(claimed)
    return result


def _classify(
    result: InsertResult,
    event: Event,
    stored_kind: EventKind,
    stored_sha256: str,
    digest: str,
) -> None:
    if stored_kind == event.kind and stored_sha256 == digest:
        result.duplicates += 1
    else:
        result.conflicts.append(EventKey(event.run_id, event.stream, event.seq, event.kind))


# --------------------------------------------------------------------------- collector


class WriteOutcome(StrEnum):
    """Outcome of a write-once record (manifest, verdict, heartbeat)."""

    #: written now
    STORED = "stored"
    #: identical to what is already stored; nothing written
    DUPLICATE = "duplicate"
    #: contradicts what is already stored (or the run row); nothing written
    CONFLICT = "conflict"
    #: no such run; nothing written
    UNKNOWN_RUN = "unknown_run"


@dataclass(frozen=True, slots=True)
class WriteResult:
    """A :class:`WriteOutcome` plus, for a conflict, the fields that disagree."""

    outcome: WriteOutcome
    fields: tuple[str, ...] = ()


def run_exists(session: Session, run_id: str) -> bool:
    return session.scalar(select(Run.run_id).where(Run.run_id == run_id)) is not None


def foreign_placements(session: Session, run_id: str, placement_ids: Iterable[str]) -> list[str]:
    """The ``placement_ids`` that are not planned placements of ``run_id``, sorted."""
    wanted = set(placement_ids)
    if not wanted:
        return []
    found = set(
        session.scalars(
            select(Placement.placement_id).where(
                Placement.run_id == run_id, Placement.placement_id.in_(wanted)
            )
        )
    )
    return sorted(wanted - found)


#: Manifest fields that must agree with the queued run row.
MANIFEST_RUN_FIELDS = ("experiment_id", "pair_id", "arm", "schedule_index", "attempt", "tag")


def record_manifest(session: Session, manifest: m.RunManifest) -> WriteResult:
    """Store a run's manifest once: its placements plus ``runs.manifest_sha256``.

    The manifest must agree with the run row on :data:`MANIFEST_RUN_FIELDS`. The hash
    (:func:`model_sha256`) is set with ``UPDATE ... WHERE manifest_sha256 IS NULL``, so
    of two concurrent posts exactly one writes the placements; a later identical
    manifest is a duplicate and a different one a conflict.
    """
    row = session.execute(
        select(*(getattr(Run, f) for f in MANIFEST_RUN_FIELDS)).where(Run.run_id == manifest.run_id)
    ).one_or_none()
    if row is None:
        return WriteResult(WriteOutcome.UNKNOWN_RUN)
    mismatched = tuple(f for f in MANIFEST_RUN_FIELDS if getattr(row, f) != getattr(manifest, f))
    if mismatched:
        return WriteResult(WriteOutcome.CONFLICT, mismatched)

    digest = model_sha256(manifest)
    claimed = session.execute(
        update(Run)
        .where(Run.run_id == manifest.run_id, Run.manifest_sha256.is_(None))
        .values(manifest_sha256=digest)
        .returning(Run.run_id)
        .execution_options(synchronize_session=False)
    ).first()
    if claimed is None:
        stored = session.scalar(select(Run.manifest_sha256).where(Run.run_id == manifest.run_id))
        if stored == digest:
            return WriteResult(WriteOutcome.DUPLICATE)
        return WriteResult(WriteOutcome.CONFLICT, ("manifest_sha256",))
    if manifest.placements:
        session.execute(pg_insert(Placement).values([p.model_dump() for p in manifest.placements]))
    return WriteResult(WriteOutcome.STORED)


def record_verdict(session: Session, verdict: m.Verdict) -> WriteResult:
    """Set the run's oracle verdict and end status, write-once.

    ``UPDATE runs ... WHERE outcome IS NULL AND end_status IS NULL``: the first verdict
    wins; re-posting the same verdict is a duplicate and a different one a conflict
    (the stored verdict is never overwritten).
    """
    values: dict[str, Any] = {
        "end_status": verdict.end_status,
        "outcome": verdict.outcome,
        "oracle_message": verdict.oracle_message,
        "decided_at": verdict.decided_at,
    }
    claimed = session.execute(
        update(Run)
        .where(Run.run_id == verdict.run_id, Run.outcome.is_(None), Run.end_status.is_(None))
        .values(**values)
        .returning(Run.run_id)
        .execution_options(synchronize_session=False)
    ).first()
    if claimed is not None:
        return WriteResult(WriteOutcome.STORED)
    stored = session.execute(
        select(Run.end_status, Run.outcome, Run.oracle_message, Run.decided_at).where(
            Run.run_id == verdict.run_id
        )
    ).one_or_none()
    if stored is None:
        return WriteResult(WriteOutcome.UNKNOWN_RUN)
    differing = tuple(k for k, v in values.items() if getattr(stored, k) != v)
    if differing:
        return WriteResult(WriteOutcome.CONFLICT, differing)
    return WriteResult(WriteOutcome.DUPLICATE)


@dataclass(slots=True)
class ArtifactResult:
    """Outcome of :func:`register_artifacts`; ``conflicts`` lists rejected paths."""

    inserted: int = 0
    duplicates: int = 0
    conflicts: list[str] = field(default_factory=list)


def register_artifacts(session: Session, batch: m.ArtifactBatch) -> ArtifactResult:
    """Register artifact files idempotently on ``(run_id, path)``.

    A path already registered with the same sha256, size and media type is a
    duplicate; with any difference it is a conflict and the stored row is kept.
    """
    result = ArtifactResult()
    if not batch.artifacts:
        return result
    files = {a.path: a for a in batch.artifacts}
    claimed: set[str] = set()
    for chunk in _chunks(batch.artifacts):
        claimed.update(
            session.scalars(
                pg_insert(Artifact)
                .values([{"run_id": batch.run_id, **a.model_dump()} for a in chunk])
                .on_conflict_do_nothing()
                .returning(Artifact.path)
            )
        )
    existing = [p for p in files if p not in claimed]
    stored: dict[str, tuple[str, int, str | None]] = {}
    for chunk_paths in _chunks(existing):
        stored.update(
            (row.path, (row.sha256, row.size_bytes, row.media_type))
            for row in session.execute(
                select(
                    Artifact.path, Artifact.sha256, Artifact.size_bytes, Artifact.media_type
                ).where(Artifact.run_id == batch.run_id, Artifact.path.in_(chunk_paths))
            )
        )
    for path in existing:
        a = files[path]
        if stored.get(path) == (a.sha256, a.size_bytes, a.media_type):
            result.duplicates += 1
        else:
            result.conflicts.append(path)
    result.inserted = len(claimed)
    return result


def record_heartbeat(session: Session, heartbeat: m.RunHeartbeat) -> WriteResult:
    """Store a lifecycle heartbeat idempotently on ``(run_id, seq)``.

    The run must exist (checked by the caller; the foreign key enforces it).
    """
    values: dict[str, Any] = {
        "phase": heartbeat.phase,
        "ts": heartbeat.ts,
        "message": heartbeat.message,
    }
    claimed = session.scalar(
        pg_insert(RunHeartbeatRow)
        .values(run_id=heartbeat.run_id, seq=heartbeat.seq, **values)
        .on_conflict_do_nothing()
        .returning(RunHeartbeatRow.seq)
    )
    if claimed is not None:
        return WriteResult(WriteOutcome.STORED)
    stored = session.execute(
        select(RunHeartbeatRow.phase, RunHeartbeatRow.ts, RunHeartbeatRow.message).where(
            RunHeartbeatRow.run_id == heartbeat.run_id, RunHeartbeatRow.seq == heartbeat.seq
        )
    ).one()
    differing = tuple(k for k, v in values.items() if getattr(stored, k) != v)
    if differing:
        return WriteResult(WriteOutcome.CONFLICT, differing)
    return WriteResult(WriteOutcome.DUPLICATE)


def record_rejected(
    session: Session,
    *,
    run_id: str,
    endpoint: CollectorEndpoint,
    reason: RejectReason,
    body: bytes,
    detail: JsonValue,
) -> int:
    """Keep a refused request body verbatim in ``rejected_batches``; return its id.

    ``body`` is stored byte for byte. NUL characters (which Postgres text and JSONB
    cannot hold) are replaced by U+FFFD in ``run_id`` and ``detail`` only.
    """
    row = RejectedBatch(
        run_id=run_id.replace("\x00", "\ufffd"),
        endpoint=endpoint,
        reason=reason,
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        detail=_without_nul(detail),
    )
    session.add(row)
    session.flush()
    return row.id


def _without_nul(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, list):
        return [_without_nul(v) for v in value]
    if isinstance(value, dict):
        return {k.replace("\x00", "\ufffd"): _without_nul(v) for k, v in value.items()}
    return value
