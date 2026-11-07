"""Collector API routes: the only write path for run evidence into Postgres.

Called by the runner after a run, never by anything inside a run cell. Every route
reads the raw request body, validates it against its envelope model in
:mod:`control.core.models` (the source of the JSON Schemas in ``schemas/``), checks
that the ``run_id`` in the URL equals the one in the payload, and writes through
:mod:`control.db.repo`.

Guarantees
----------
* **Idempotent.** Re-posting the same body never duplicates anything: events are keyed
  on ``(run_id, stream, seq)``, artifacts on ``(run_id, path)``, heartbeats on
  ``(run_id, seq)``; the manifest and the verdict are write-once per run.
* **Never silently lost, never silently accepted.** Every refused body is kept byte
  for byte in ``rejected_batches`` with the endpoint, a :class:`RejectReason` and a JSON
  detail, and its id is returned as ``rejected_id``.
* **Write-once.** There is no route that updates or deletes evidence.

Status codes
------------
* ``200``: stored, or an exact duplicate of what is stored (``result`` / counts say which).
* ``404`` ``unknown_run``: no such run.
* ``409`` ``conflict``: contradicts stored evidence (or, for a manifest, the run row).
  For events and artifacts, every non-conflicting item in the body **was stored**; the
  response lists only the conflicting keys.
* ``422``: ``invalid`` (not JSON / fails the schema), ``run_id_mismatch``,
  ``unknown_placement`` (an event names a placement not planned for this run) or
  ``constraint`` (schema-valid but refused by the database; nothing stored).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, JsonValue, ValidationError
from sqlalchemy import Engine
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from control.core import models as m
from control.core.models import CollectorEndpoint, EventKind, RejectReason
from control.db import repo
from control.db.engine import get_engine, session_scope
from control.db.repo import WriteOutcome, WriteResult

__all__ = [
    "ArtifactAck",
    "EventBatchAck",
    "EventKeyOut",
    "Rejection",
    "WriteAck",
    "get_db_engine",
    "router",
]

router = APIRouter(prefix="/v1/runs/{run_id}", tags=["collector"])

#: Database errors that mean "this schema-valid body cannot be stored" (too long for a
#: column, NUL in text, a uniqueness or foreign-key violation...). The transaction is
#: rolled back and the body is kept as a ``constraint`` rejection.
_STORAGE_ERRORS = (IntegrityError, DataError)


# --------------------------------------------------------------------- dependencies


def get_db_engine(request: Request) -> Engine:
    """The app's engine (``create_app(engine)``), else the ``$DATABASE_URL`` engine."""
    engine: Engine | None = request.app.state.engine
    return engine if engine is not None else get_engine()


async def _raw_body(request: Request) -> bytes:
    return await request.body()


EngineDep = Annotated[Engine, Depends(get_db_engine)]
BodyDep = Annotated[bytes, Depends(_raw_body)]


# --------------------------------------------------------------------- responses


class WriteAck(BaseModel):
    """``200`` for a write-once record (manifest, verdict, status)."""

    run_id: str
    result: Literal["stored", "duplicate"]


class EventKeyOut(BaseModel):
    stream: str
    seq: int
    kind: EventKind


class EventBatchAck(BaseModel):
    """``200`` for ``events:batch`` (``conflicts`` is empty; see ``409`` otherwise)."""

    run_id: str
    inserted: int
    duplicates: int
    conflicts: list[EventKeyOut]


class ArtifactAck(BaseModel):
    """``200`` for ``artifacts`` (``conflicts`` is empty; see ``409`` otherwise)."""

    run_id: str
    inserted: int
    duplicates: int
    conflicts: list[str]


class Rejection(BaseModel):
    """Body of every ``404``/``409``/``422``; extra fields depend on ``reason``."""

    detail: str
    reason: RejectReason
    rejected_id: int


_REJECTIONS: dict[int | str, dict[str, Any]] = {
    404: {"model": Rejection, "description": "Unknown run (body kept)."},
    409: {"model": Rejection, "description": "Conflicts with stored evidence (body kept)."},
    422: {"model": Rejection, "description": "Invalid or unstorable body (body kept)."},
}

_MESSAGES: dict[RejectReason, str] = {
    RejectReason.INVALID: "body is not a valid envelope",
    RejectReason.RUN_ID_MISMATCH: "run_id in the URL differs from run_id in the body",
    RejectReason.UNKNOWN_RUN: "no such run",
    RejectReason.UNKNOWN_PLACEMENT: "event references a placement not planned for this run",
    RejectReason.CONFLICT: "conflicts with evidence already stored",
    RejectReason.CONSTRAINT: "the database refused the body",
}

_STATUS: dict[RejectReason, int] = {
    RejectReason.INVALID: 422,
    RejectReason.RUN_ID_MISMATCH: 422,
    RejectReason.UNKNOWN_RUN: 404,
    RejectReason.UNKNOWN_PLACEMENT: 422,
    RejectReason.CONFLICT: 409,
    RejectReason.CONSTRAINT: 422,
}


# --------------------------------------------------------------------- rejection


class _Intake:
    """One request: its endpoint, URL run_id and raw body, for keeping rejections."""

    def __init__(self, endpoint: CollectorEndpoint, run_id: str, body: bytes) -> None:
        self.endpoint = endpoint
        self.run_id = run_id
        self.body = body

    def reject_in(
        self,
        session: Session,
        reason: RejectReason,
        detail: JsonValue,
        **extra: JsonValue,
    ) -> JSONResponse:
        """Keep the body in ``session``'s transaction and build the rejection response."""
        rejected_id = repo.record_rejected(
            session,
            run_id=self.run_id,
            endpoint=self.endpoint,
            reason=reason,
            body=self.body,
            detail=detail,
        )
        content: dict[str, Any] = {
            "detail": _MESSAGES[reason],
            "reason": reason.value,
            "rejected_id": rejected_id,
            **extra,
        }
        return JSONResponse(status_code=_STATUS[reason], content=content)

    def reject(
        self, engine: Engine, reason: RejectReason, detail: JsonValue, **extra: JsonValue
    ) -> JSONResponse:
        """Keep the body in a transaction of its own."""
        with session_scope(engine) as session:
            return self.reject_in(session, reason, detail, **extra)

    def parse[M: BaseModel](self, model: type[M], engine: Engine) -> M | JSONResponse:
        """Validate the body against ``model``; reject it if invalid or for another run."""
        try:
            payload = model.model_validate_json(self.body)
        except ValidationError as exc:
            errors: list[JsonValue] = [
                {"type": e["type"], "loc": list(e["loc"]), "msg": e["msg"]}
                for e in exc.errors(include_url=False, include_context=False, include_input=False)
            ]
            return self.reject(engine, RejectReason.INVALID, errors, errors=errors)
        payload_run_id = getattr(payload, "run_id", None)
        if payload_run_id != self.run_id:
            ids: dict[str, JsonValue] = {
                "url_run_id": self.run_id,
                "payload_run_id": payload_run_id,
            }
            return self.reject(engine, RejectReason.RUN_ID_MISMATCH, ids, **ids)
        return payload

    def storage_error(self, engine: Engine, exc: IntegrityError | DataError) -> JSONResponse:
        error = str(exc.orig) if exc.orig is not None else str(exc)
        return self.reject(engine, RejectReason.CONSTRAINT, {"error": error}, error=error)

    def write_result(self, session: Session, result: WriteResult) -> WriteAck | JSONResponse:
        """Map a write-once :class:`WriteResult` to a response."""
        if result.outcome is WriteOutcome.UNKNOWN_RUN:
            return self.reject_in(session, RejectReason.UNKNOWN_RUN, {"run_id": self.run_id})
        if result.outcome is WriteOutcome.CONFLICT:
            fields: list[JsonValue] = list(result.fields)
            return self.reject_in(session, RejectReason.CONFLICT, {"fields": fields}, fields=fields)
        result_value: Literal["stored", "duplicate"] = (
            "stored" if result.outcome is WriteOutcome.STORED else "duplicate"
        )
        return WriteAck(run_id=self.run_id, result=result_value)


# --------------------------------------------------------------------- routes


@router.post("/manifest", response_model=WriteAck, responses=_REJECTIONS)
def post_manifest(run_id: str, body: BodyDep, engine: EngineDep) -> WriteAck | JSONResponse:
    """Store the run's planned placements and manifest hash (write-once)."""
    intake = _Intake(CollectorEndpoint.MANIFEST, run_id, body)
    manifest = intake.parse(m.RunManifest, engine)
    if isinstance(manifest, JSONResponse):
        return manifest
    try:
        with session_scope(engine) as session:
            return intake.write_result(session, repo.record_manifest(session, manifest))
    except _STORAGE_ERRORS as exc:
        return intake.storage_error(engine, exc)


@router.post("/events:batch", response_model=EventBatchAck, responses=_REJECTIONS)
def post_events(run_id: str, body: BodyDep, engine: EngineDep) -> EventBatchAck | JSONResponse:
    """Store an :class:`~control.core.models.EventBatch` idempotently.

    Non-conflicting events are stored even when others conflict; the conflicts are
    answered with ``409`` and the whole body is kept in ``rejected_batches``.
    """
    intake = _Intake(CollectorEndpoint.EVENTS, run_id, body)
    batch = intake.parse(m.EventBatch, engine)
    if isinstance(batch, JSONResponse):
        return batch
    try:
        with session_scope(engine) as session:
            if not repo.run_exists(session, run_id):
                return intake.reject_in(session, RejectReason.UNKNOWN_RUN, {"run_id": run_id})
            referenced = [
                ev.placement_id
                for ev in batch.events
                if isinstance(ev, m.PlacementServe | m.Callback) and ev.placement_id is not None
            ]
            missing = repo.foreign_placements(session, run_id, referenced)
            if missing:
                ids: list[JsonValue] = list(missing)
                return intake.reject_in(
                    session,
                    RejectReason.UNKNOWN_PLACEMENT,
                    {"placement_ids": ids},
                    placement_ids=ids,
                )
            result = repo.insert_events(session, batch.events)
            conflicts: list[JsonValue] = [
                {"stream": k.stream, "seq": k.seq, "kind": k.kind.value} for k in result.conflicts
            ]
            if conflicts:
                return intake.reject_in(
                    session,
                    RejectReason.CONFLICT,
                    conflicts,
                    run_id=run_id,
                    inserted=result.inserted,
                    duplicates=result.duplicates,
                    conflicts=conflicts,
                )
            return EventBatchAck(
                run_id=run_id,
                inserted=result.inserted,
                duplicates=result.duplicates,
                conflicts=[],
            )
    except _STORAGE_ERRORS as exc:
        return intake.storage_error(engine, exc)


@router.post("/artifacts", response_model=ArtifactAck, responses=_REJECTIONS)
def post_artifacts(run_id: str, body: BodyDep, engine: EngineDep) -> ArtifactAck | JSONResponse:
    """Register raw artifact files (path relative to ``runs/<run_id>/`` plus sha256)."""
    intake = _Intake(CollectorEndpoint.ARTIFACTS, run_id, body)
    batch = intake.parse(m.ArtifactBatch, engine)
    if isinstance(batch, JSONResponse):
        return batch
    try:
        with session_scope(engine) as session:
            if not repo.run_exists(session, run_id):
                return intake.reject_in(session, RejectReason.UNKNOWN_RUN, {"run_id": run_id})
            result = repo.register_artifacts(session, batch)
            if result.conflicts:
                paths: list[JsonValue] = list(result.conflicts)
                return intake.reject_in(
                    session,
                    RejectReason.CONFLICT,
                    paths,
                    run_id=run_id,
                    inserted=result.inserted,
                    duplicates=result.duplicates,
                    conflicts=paths,
                )
            return ArtifactAck(
                run_id=run_id,
                inserted=result.inserted,
                duplicates=result.duplicates,
                conflicts=[],
            )
    except _STORAGE_ERRORS as exc:
        return intake.storage_error(engine, exc)


@router.post("/verdict", response_model=WriteAck, responses=_REJECTIONS)
def post_verdict(run_id: str, body: BodyDep, engine: EngineDep) -> WriteAck | JSONResponse:
    """Set the run's oracle outcome and end status (write-once)."""
    intake = _Intake(CollectorEndpoint.VERDICT, run_id, body)
    verdict = intake.parse(m.Verdict, engine)
    if isinstance(verdict, JSONResponse):
        return verdict
    try:
        with session_scope(engine) as session:
            return intake.write_result(session, repo.record_verdict(session, verdict))
    except _STORAGE_ERRORS as exc:
        return intake.storage_error(engine, exc)


@router.post("/status", response_model=WriteAck, responses=_REJECTIONS)
def post_status(run_id: str, body: BodyDep, engine: EngineDep) -> WriteAck | JSONResponse:
    """Record a runner lifecycle heartbeat (idempotent on ``(run_id, seq)``)."""
    intake = _Intake(CollectorEndpoint.STATUS, run_id, body)
    heartbeat = intake.parse(m.RunHeartbeat, engine)
    if isinstance(heartbeat, JSONResponse):
        return heartbeat
    try:
        with session_scope(engine) as session:
            if not repo.run_exists(session, run_id):
                return intake.reject_in(session, RejectReason.UNKNOWN_RUN, {"run_id": run_id})
            return intake.write_result(session, repo.record_heartbeat(session, heartbeat))
    except _STORAGE_ERRORS as exc:
        return intake.storage_error(engine, exc)
