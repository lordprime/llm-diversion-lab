"""The runner's side of the gateway's admin API: grant a run its key, then revoke it.

Only the key's SHA-256 crosses the wire; the key itself stays with the runner and the
run's agent. The admin secret is sent as a bearer token and never appears in a repr,
an exception message or a log line.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final

import httpx

from control.gateway.keys import key_sha256

__all__ = ["ADMIN_SECRET_ENV", "ADMIN_URL_ENV", "GatewayAdminError", "GrantClient"]

#: Where labctl finds the gateway's admin listener and its secret (lab.env).
ADMIN_URL_ENV: Final = "LAB_GATEWAY_ADMIN_URL"
ADMIN_SECRET_ENV: Final = "LAB_GATEWAY_ADMIN_SECRET"  # noqa: S105 -- a variable name
_TIMEOUT_S: Final = 10.0


class GatewayAdminError(RuntimeError):
    """The gateway did not take a grant or a revoke."""


class GrantClient:
    """Registers and revokes run grants at the gateway's admin listener."""

    def __init__(self, http: httpx.Client, secret: str) -> None:
        if not secret:
            raise ValueError(f"{ADMIN_SECRET_ENV} is empty")
        self._http = http
        self._auth = {"authorization": f"Bearer {secret}"}

    def __repr__(self) -> str:  # the secret never appears in a repr or traceback local
        return f"GrantClient(base_url={self._http.base_url!s})"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GrantClient | None:
        """A client for ``LAB_GATEWAY_ADMIN_URL``, or ``None`` when it is not set."""
        url = env.get(ADMIN_URL_ENV, "")
        if not url:
            return None
        return cls(httpx.Client(base_url=url, timeout=_TIMEOUT_S), env.get(ADMIN_SECRET_ENV, ""))

    def grant(self, run_id: str, key: str, models: Sequence[str], expires_at: datetime) -> None:
        """Let ``key`` use ``models`` until ``expires_at`` (idempotent)."""
        body = {
            "run_id": run_id,
            "key_sha256": key_sha256(key),
            "models": list(models),
            "expires_at": expires_at.isoformat(),
        }
        self._call("POST", "/admin/grants", body, expect=201)

    def revoke(self, run_id: str) -> None:
        """Withdraw ``run_id``'s grant (idempotent)."""
        self._call("DELETE", f"/admin/grants/{run_id}", None, expect=204)

    def _call(self, method: str, path: str, body: object, *, expect: int) -> None:
        try:
            response = self._http.request(method, path, json=body, headers=self._auth)
        except httpx.HTTPError as exc:
            raise GatewayAdminError(f"gateway admin unreachable: {type(exc).__name__}") from None
        if response.status_code != expect:
            raise GatewayAdminError(
                f"gateway admin answered {response.status_code} to {method} {path}: "
                f"{response.text[:200]}"
            )
