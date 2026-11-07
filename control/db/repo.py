"""Queue and evidence-write operations on the control-plane database.

Functions take an open :class:`~sqlalchemy.orm.Session` and never commit; the caller
owns the transaction (normally :func:`control.db.engine.session_scope`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from control.core.models import Event, RunStatus
from control.db.tables import EVENT_KEY, EVENT_TABLES, EventRow, Run

__all__ = ["claim_next_run", "insert_events"]


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


def insert_events(session: Session, events: Iterable[Event]) -> int:
    """Store evidence events idempotently; return how many rows were new.

    Each event goes to its kind's table with
    ``INSERT ... ON CONFLICT (run_id, stream, seq) DO NOTHING``, so re-shipping a batch
    (or part of one) never duplicates a row.
    """
    rows: defaultdict[type[EventRow], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        rows[EVENT_TABLES[event.kind]].append(event.model_dump(exclude={"kind"}))

    inserted = 0
    for table, values in rows.items():
        stmt = (
            pg_insert(table)
            .values(values)
            .on_conflict_do_nothing(index_elements=list(EVENT_KEY))
            .returning(table.id)
        )
        inserted += len(session.execute(stmt).all())
    return inserted
