"""FastAPI application for the Collector API.

Build an app bound to a specific engine with :func:`create_app` (tests do this); the
module-level :data:`app` uses ``$DATABASE_URL``.

* ``GET /healthz``: liveness; never touches the database.
* ``GET /readyz``: readiness; ``200`` if ``SELECT 1`` succeeds, else ``503``.
* ``GET /metrics``: Prometheus metrics (:mod:`control.api.metrics`), read from the
  database at each scrape; still ``200`` (with ``lab_metrics_database_up 0``) without one.

Run the Collector process with ``python -m control.api`` (:mod:`control.api.__main__`),
which configures the structured logging first.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from control.api import collector
from control.api.metrics import LabMetrics, metrics_router
from control.db.engine import get_engine

__all__ = ["app", "create_app"]

log = logging.getLogger(__name__)


def create_app(engine: Engine | None = None, *, metrics: LabMetrics | None = None) -> FastAPI:
    """Build the Collector API app.

    ``engine`` defaults to the ``$DATABASE_URL`` one (resolved on first use);
    ``metrics`` defaults to a fresh :class:`LabMetrics` with its own registry that
    reads the same database at each scrape.
    """
    if metrics is None:
        metrics = LabMetrics(lambda: engine if engine is not None else get_engine())
    app = FastAPI(
        title="LLM Diversion Lab Collector API",
        version="1",
        summary="The only write path for run evidence into Postgres.",
    )
    app.state.engine = engine
    app.state.metrics = metrics
    app.include_router(collector.router)
    app.include_router(metrics_router())

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get(
        "/readyz",
        tags=["health"],
        responses={503: {"description": "Database unreachable."}},
    )
    def readyz(request: Request) -> JSONResponse:
        try:
            with collector.get_db_engine(request).connect() as conn:
                conn.execute(text("SELECT 1"))
        except (SQLAlchemyError, RuntimeError, ValueError) as exc:
            log.warning("readyz: database unavailable: %s", type(exc).__name__)
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(content={"status": "ready"})

    return app


app = create_app()
