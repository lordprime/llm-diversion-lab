"""Where labctl finds the lab: paths, the Collector URL and the database URL.

On the lab host labctl runs as root with nothing configured: everything defaults to
the layout of docs/DEPLOYMENT.md §3 and the control-plane compose file
(``deploy/compose/control-plane.yml``), which publishes Postgres on
``127.0.0.1:`` :data:`DB_PORT` and the Collector on ``127.0.0.1:`` :data:`COLLECTOR_PORT`.

Environment overrides (tests and development):

* ``LAB_ROOT``: the lab tree (default ``/srv/lab``);
* ``LAB_COLLECTOR_URL``: the Collector's base URL;
* ``LAB_SELFTEST_STATUS_FILE``: the self-test status (default
  ``<LAB_ROOT>/state/selftest.json``);
* ``DATABASE_URL``: the database. Without it, labctl builds the URL from
  :data:`DB_PASSWORD_VAR` in ``<LAB_ROOT>/secrets/lab.env`` (the same file compose
  reads with ``--env-file``). The password never appears in argv or in output.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sqlalchemy.engine import URL

from control.core.selftest_status import SELFTEST_STATUS_ENV
from control.db.engine import DATABASE_URL_ENV, database_url

__all__ = [
    "COLLECTOR_PORT",
    "DB_NAME",
    "DB_PASSWORD_VAR",
    "DB_PORT",
    "DB_USER",
    "DEFAULT_COLLECTOR_URL",
    "DEFAULT_LAB_ROOT",
    "ConfigError",
    "LabSettings",
    "read_env_file",
]

LAB_ROOT_ENV: Final = "LAB_ROOT"
COLLECTOR_URL_ENV: Final = "LAB_COLLECTOR_URL"
DEFAULT_LAB_ROOT: Final = Path("/srv/lab")

#: Postgres role and database of the control plane (POSTGRES_USER / POSTGRES_DB).
DB_USER: Final = "lab"
DB_NAME: Final = "lab"
#: Host port (on 127.0.0.1) the control-plane compose file publishes Postgres on.
DB_PORT: Final = 5432
#: lab.env variable holding the Postgres password.
DB_PASSWORD_VAR: Final = "LAB_DB_PASSWORD"  # noqa: S105 -- a variable name, not a value
#: Host port (on 127.0.0.1) the control-plane compose file publishes the Collector on.
COLLECTOR_PORT: Final = 8100
DEFAULT_COLLECTOR_URL: Final = f"http://127.0.0.1:{COLLECTOR_PORT}"

_ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


class ConfigError(RuntimeError):
    """labctl cannot work out how to reach something (no secret in the message)."""


def read_env_file(path: Path) -> dict[str, str]:
    """Parse ``NAME=value`` lines (``#`` comments and blank lines skipped).

    Values are taken literally (stripped of surrounding whitespace): no quoting, no
    ``$`` expansion, never executed. Lines that are not assignments are ignored.
    """
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


@dataclass(frozen=True, slots=True)
class LabSettings:
    lab_root: Path
    collector_url: str
    environ: Mapping[str, str]

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> LabSettings:
        env = dict(os.environ if environ is None else environ)
        root = env.get(LAB_ROOT_ENV) or str(DEFAULT_LAB_ROOT)
        url = (env.get(COLLECTOR_URL_ENV) or DEFAULT_COLLECTOR_URL).rstrip("/")
        return cls(lab_root=Path(root), collector_url=url, environ=env)

    @property
    def host_env_file(self) -> Path:
        return self.lab_root / "host.env"

    @property
    def secrets_env_file(self) -> Path:
        return self.lab_root / "secrets" / "lab.env"

    @property
    def release_file(self) -> Path:
        return self.lab_root / "current" / "RELEASE"

    @property
    def selftest_status_file(self) -> Path:
        """``$LAB_SELFTEST_STATUS_FILE``, else ``<LAB_ROOT>/state/selftest.json``."""
        if env := self.environ.get(SELFTEST_STATUS_ENV):
            return Path(env)
        return self.lab_root / "state" / "selftest.json"

    def database_url(self) -> str:
        """``$DATABASE_URL``, else the host's control-plane database from lab.env.

        Raises :class:`ConfigError` when neither is available.
        """
        if raw := self.environ.get(DATABASE_URL_ENV):
            return database_url(raw)
        try:
            password = read_env_file(self.secrets_env_file).get(DB_PASSWORD_VAR, "")
        except FileNotFoundError:
            password = ""
        except OSError as exc:
            raise ConfigError(
                f"cannot read {self.secrets_env_file} ({exc.strerror}); "
                f"set {DATABASE_URL_ENV} or run labctl as root on the lab host"
            ) from exc
        if not password:
            raise ConfigError(
                f"no database configured: set {DATABASE_URL_ENV}, or {DB_PASSWORD_VAR} "
                f"in {self.secrets_env_file} (deploy/secrets.sh)"
            )
        url = URL.create(
            "postgresql+psycopg",
            username=DB_USER,
            password=password,
            host="127.0.0.1",
            port=DB_PORT,
            database=DB_NAME,
        )
        return url.render_as_string(hide_password=False)
