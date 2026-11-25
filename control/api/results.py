"""Results API routes: read-only views of derived run data.

Unlike the collector routes these never write, and nothing here is evidence: it is
derived from the evidence and can be worked out again.

* ``GET /v1/runs/{run_id}/telemetry``: the run's telemetry summary, or the
  ``telemetry_error`` that says why none could be derived (``200`` either way);
  ``404`` ``unknown_run`` / ``no_telemetry`` (not derived yet); ``422`` for an id that
  is not shaped like a run id.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Engine

from control.api.collector import get_db_engine
from control.core.ids import ID_PATTERN
from control.db import tables as t
from control.db.engine import session_scope

__all__ = ["TelemetryOut", "router"]

router = APIRouter(prefix="/v1/runs/{run_id}", tags=["results"])

EngineDep = Annotated[Engine, Depends(get_db_engine)]
#: A run id that is not shaped like one is refused (422) before it reaches the database.
RunIdPath = Annotated[str, Path(pattern=ID_PATTERN, max_length=128)]


class TelemetryOut(BaseModel):
    """A run's stored telemetry; every summary field is ``None`` when it failed."""

    run_id: str
    telemetry_version: str | None
    calls: int | None
    agents: int | None
    agents_source: str | None
    peak_input_tokens: int | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_chars: int | None
    calls_with_reasoning: int | None
    single_call_threads: int | None
    largest_thread_calls: int | None
    branch_points: int | None
    persona_splits: int | None
    telemetry_error: str | None
    derived_at: datetime


class NotFound(BaseModel):
    detail: str
    reason: str


@router.get(
    "/telemetry",
    response_model=TelemetryOut,
    responses={404: {"model": NotFound, "description": "Unknown run, or no telemetry yet."}},
)
def get_telemetry(run_id: RunIdPath, engine: EngineDep) -> TelemetryOut | JSONResponse:
    with session_scope(engine) as session:
        row = session.get(t.RunTelemetryRow, run_id)
        if row is None:
            known = session.get(t.Run, run_id) is not None
            reason = "no_telemetry" if known else "unknown_run"
            detail = "no telemetry derived for this run" if known else "no such run"
            return JSONResponse(status_code=404, content={"detail": detail, "reason": reason})
        return TelemetryOut(
            **{
                name: getattr(row, name)
                for name in TelemetryOut.model_fields
                if name != "derived_at"
            },
            derived_at=row.created_at,
        )
