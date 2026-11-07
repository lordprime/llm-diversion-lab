"""Queue and evidence-write operations on the control-plane database.

Functions take an open :class:`~sqlalchemy.orm.Session` and never commit; the caller
owns the transaction (normally :func:`control.db.engine.session_scope`).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from control.core.models import Event, EventKind, RunStatus
from control.db.tables import EVENT_TABLES, EventKeyEntry, EventRow, Run

__all__ = [
    "EventKey",
    "InsertResult",
    "claim_next_run",
    "event_content_sha256",
    "insert_events",
]


def claim_next_run(session: Session) -> Run | None:
    """Claim the next queued run, or return ``None`` if none is claimable.

    The oldest queued run (by ``created_at``, then ``schedule_index``) is selected with
    ``SELECT ... FOR UPDATE SKIP LOCKED`` and, in the same statement, moved to
    ``running`` with ``started_at = now()``. A run whose row another open transaction
    holds is skipped rather than waited for, so concurrent workers never claim the
    same run. If the caller's transaction rolls back, the run is queued again.
    """
    next_queued = (
        select(Run.run_id)
        .where(Run.status == RunStatus.QUEUED)
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


def event_content_sha256(event: Event) -> str:
    """SHA-256 of the event's canonical JSON (every field, kind included, sorted keys)."""
    canonical = json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
                for ev, digest in first.values()
            ]
        )
        .on_conflict_do_nothing()
        .returning(EventKeyEntry.run_id, EventKeyEntry.stream, EventKeyEntry.seq)
    )
    claimed = {(r.run_id, r.stream, r.seq) for r in session.execute(claim)}

    existing_keys = [k for k in first if k not in claimed]
    if existing_keys:
        stored = session.execute(
            select(
                EventKeyEntry.run_id,
                EventKeyEntry.stream,
                EventKeyEntry.seq,
                EventKeyEntry.kind,
                EventKeyEntry.content_sha256,
            ).where(
                tuple_(EventKeyEntry.run_id, EventKeyEntry.stream, EventKeyEntry.seq).in_(
                    existing_keys
                )
            )
        )
        for row in stored:
            event, digest = first[(row.run_id, row.stream, row.seq)]
            _classify(result, event, row.kind, row.content_sha256, digest)

    rows: defaultdict[type[EventRow], list[dict[str, Any]]] = defaultdict(list)
    for key in claimed:
        event = first[key][0]
        rows[EVENT_TABLES[event.kind]].append(event.model_dump(exclude={"kind"}))
    # Plain INSERT: the per-table unique (run_id, stream, seq) constraint raises if a
    # row exists without its ledger entry, which would be a bug, not a re-ship.
    for table, values in rows.items():
        session.execute(pg_insert(table).values(values))
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
