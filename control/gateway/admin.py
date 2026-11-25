"""The gateway's admin API, on its control-plane listener only.

``POST /admin/grants`` registers a run's key hash, models and expiry;
``DELETE /admin/grants/{run_id}`` revokes it (idempotent); ``GET /healthz`` answers
the container's health check. Every grant call needs ``Authorization: Bearer
<LAB_GATEWAY_ADMIN_SECRET>``, compared in constant time.
"""

from __future__ import annotations

import hmac
import logging
import re
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from control.core.ids import ID_PATTERN
from control.gateway.asgi import BodyReader, Refused
from control.gateway.config import GatewayConfig
from control.gateway.keys import GrantConflict, GrantInvalid, RunKeys

__all__ = ["MAX_ADMIN_BODY_BYTES", "AdminApi", "GrantRequest"]

log = logging.getLogger(__name__)

#: The most an admin request body may weigh.
MAX_ADMIN_BODY_BYTES: Final = 64 << 10
_RUN_ID: Final = re.compile(ID_PATTERN)


class GrantRequest(BaseModel):
    """``POST /admin/grants``: a run's key hash, its models and when it lapses."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: str
    key_sha256: str
    models: list[str]
    expires_at: AwareDatetime
    embeddings: bool = False


class AdminApi:
    """The control-plane ASGI app: register and revoke run grants."""

    def __init__(self, config: GatewayConfig, keys: RunKeys) -> None:
        self._expected = f"Bearer {config.admin_secret}".encode()
        self._keys = keys
        self._bodies = BodyReader(MAX_ADMIN_BODY_BYTES, config.body_timeout_s)
        self._app = Starlette(
            routes=[
                Route("/admin/grants", self._grant, methods=["POST"]),
                Route("/admin/grants/{run_id}", self._revoke, methods=["DELETE"]),
                Route("/healthz", self._health, methods=["GET"]),
            ]
        )

    def __repr__(self) -> str:  # the secret never appears in a repr or traceback local
        return "AdminApi()"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)

    def _authorise(self, request: Request) -> None:
        values = request.headers.getlist("authorization")
        if len(values) != 1 or not hmac.compare_digest(values[0].encode(), self._expected):
            raise Refused(401, "admin secret missing or wrong")

    async def _health(self, request: Request) -> Response:
        return JSONResponse({"ok": True})

    async def _grant(self, request: Request) -> Response:
        try:
            self._authorise(request)
            body = await self._bodies.read(request)
            try:
                grant = GrantRequest.model_validate_json(body)
            except ValidationError as exc:
                bad_json = any(e["type"] == "json_invalid" for e in exc.errors())
                raise Refused(400 if bad_json else 422, "malformed grant") from None
            try:
                held = await run_in_threadpool(
                    self._keys.register,
                    grant.run_id,
                    grant.key_sha256,
                    grant.models,
                    grant.expires_at,
                    embeddings=grant.embeddings,
                )
            except GrantInvalid as exc:
                raise Refused(422, str(exc)) from None
            except GrantConflict as exc:
                raise Refused(409, str(exc)) from None
            except Exception:
                log.exception("gateway: cannot store the grant of run %s", grant.run_id)
                raise Refused(503, "the grant store is unavailable") from None
        except Refused as refused:
            log.warning("gateway: admin grant refused %d: %s", refused.status, refused.reason)
            return refused.response()
        log.info(
            "gateway: granted run %s models %s until %s",
            held.run_id,
            sorted(held.models),
            held.expires_at.isoformat(),
        )
        return JSONResponse(
            {"run_id": held.run_id, "expires_at": held.expires_at.isoformat()}, status_code=201
        )

    async def _revoke(self, request: Request) -> Response:
        run_id = request.path_params["run_id"]
        try:
            self._authorise(request)
            if not _RUN_ID.fullmatch(run_id):
                raise Refused(404, "not a run id")
            try:
                held = await run_in_threadpool(self._keys.revoke, run_id)
            except Exception:
                log.exception("gateway: revoked run %s in memory, not in the store", run_id)
                raise Refused(503, "revoked here, but the grant store is unavailable") from None
        except Refused as refused:
            log.warning("gateway: admin revoke refused %d: %s", refused.status, refused.reason)
            return refused.response()
        log.info("gateway: revoked run %s (%s)", run_id, "held" if held else "not held")
        return Response(status_code=204)
