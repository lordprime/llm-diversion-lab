"""``labctl doctor``: is this host ready to run the lab?

One check per prerequisite, in :data:`CHECK_NAMES` order. Each yields ``ok``,
``fail`` or ``skip`` with a one-line detail; a check never raises (an unexpected
exception is a ``fail`` naming the exception type). Exit status: 0 when nothing
failed (skips allowed), 1 when any check failed, 2 for a usage error.

* ``database``: Postgres reachable and the schema at the Alembic head.
* ``collector``: ``GET <collector>/healthz`` answers ``{"status": "ok"}``.
* ``metrics``: ``GET <collector>/metrics`` serves the lab metrics.
* ``docker``: the Docker API answers ``/_ping`` on its Unix socket
  (``$DOCKER_HOST`` if it is ``unix://``, else ``/var/run/docker.sock``).
* ``host_env``: ``/srv/lab/host.env`` exists and ``LAB_CELL_NETWORKS`` is a
  comma-separated list of IPv4 networks, each written strictly (no host bits),
  inside :data:`DEFAULT_CELL_RANGE` (``--cell-range``), not overlapping.
* ``firewall``: on the lab host, ``lab-cell-egress check`` (both firewall layers
  loaded and as expected) must pass. Off the host (neither host.env nor the tool
  present) it is skipped with a message. On the host a missing tool is a failure.

Error details pass through :func:`~control.core.logging.redact_text`, so a database
URL in an exception never prints its password.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network
from pathlib import Path
from typing import Final

import httpx
from sqlalchemy import pool
from sqlalchemy.exc import SQLAlchemyError

from control.cli.migrations import current_revisions, head_revisions
from control.cli.settings import ConfigError, LabSettings, read_env_file
from control.core.logging import redact_text
from control.db.engine import create_db_engine

__all__ = [
    "CHECK_NAMES",
    "DEFAULT_CELL_RANGE",
    "DEFAULT_DOCKER_SOCKET",
    "DEFAULT_EGRESS_COMMAND",
    "CheckResult",
    "DoctorConfig",
    "Status",
    "exit_code",
    "parse_cell_networks",
    "render_json",
    "render_text",
    "run_doctor",
]

DEFAULT_CELL_RANGE: Final = IPv4Network("10.231.0.0/16")
DEFAULT_DOCKER_SOCKET: Final = Path("/var/run/docker.sock")
DEFAULT_EGRESS_COMMAND: Final = Path("/usr/local/sbin/lab-cell-egress")
TIMEOUT_S: Final = 10.0
_DETAIL_CHARS: Final = 400


class Status(StrEnum):
    OK = "ok"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: Status
    detail: str


@dataclass
class DoctorConfig:
    settings: LabSettings
    #: the cell networks must lie inside this range
    cell_range: IPv4Network = DEFAULT_CELL_RANGE
    #: ``unix:///path``; ``None`` means ``$DOCKER_HOST`` or the default socket
    docker_host: str | None = None
    egress_command: Path = DEFAULT_EGRESS_COMMAND
    #: client for the Collector checks (its own timeout applies); ``None`` creates one
    http_client: httpx.Client | None = None
    #: the database to check; ``None`` resolves it from :attr:`settings`
    database_url: str | None = None
    timeout: float = TIMEOUT_S

    @property
    def on_lab_host(self) -> bool:
        return self.settings.host_env_file.exists() or self.egress_command.exists()


def _detail(text: str) -> str:
    text = redact_text(" ".join(text.split()))
    return text if len(text) <= _DETAIL_CHARS else text[: _DETAIL_CHARS - 3] + "..."


def _error(exc: BaseException) -> str:
    message = str(exc)
    return _detail(f"{type(exc).__name__}: {message}" if message else type(exc).__name__)


# --------------------------------------------------------------------- database


def check_database(cfg: DoctorConfig) -> CheckResult:
    name = "database"
    try:
        url = cfg.database_url or cfg.settings.database_url()
        engine = create_db_engine(
            url, poolclass=pool.NullPool, connect_args={"connect_timeout": int(cfg.timeout)}
        )
    except (ConfigError, ValueError) as exc:
        return CheckResult(name, Status.FAIL, _detail(str(exc)))
    try:
        current = current_revisions(engine)
    except SQLAlchemyError as exc:
        return CheckResult(
            name, Status.FAIL, "unreachable: " + _error(getattr(exc, "orig", None) or exc)
        )
    finally:
        engine.dispose()
    heads = head_revisions()
    if current != heads:
        have = ", ".join(sorted(current)) or "never migrated"
        return CheckResult(
            name,
            Status.FAIL,
            f"reachable, but schema not at head: at {have}, head is {', '.join(sorted(heads))}",
        )
    return CheckResult(name, Status.OK, f"reachable, schema at head ({', '.join(sorted(heads))})")


# --------------------------------------------------------------------- collector


def _get(cfg: DoctorConfig, path: str) -> httpx.Response:
    url = cfg.settings.collector_url + path
    if cfg.http_client is not None:
        return cfg.http_client.get(url)
    with httpx.Client(timeout=cfg.timeout, trust_env=False) as client:
        return client.get(url)


def check_collector(cfg: DoctorConfig) -> CheckResult:
    name = "collector"
    where = cfg.settings.collector_url
    try:
        r = _get(cfg, "/healthz")
    except httpx.HTTPError as exc:
        return CheckResult(name, Status.FAIL, f"{where}/healthz unreachable: " + _error(exc))
    try:
        body = r.json()
    except ValueError:
        body = None
    if r.status_code != 200 or body != {"status": "ok"}:
        return CheckResult(name, Status.FAIL, f"{where}/healthz answered HTTP {r.status_code}")
    return CheckResult(name, Status.OK, f"{where}/healthz ok")


def check_metrics(cfg: DoctorConfig) -> CheckResult:
    name = "metrics"
    where = cfg.settings.collector_url + "/metrics"
    try:
        r = _get(cfg, "/metrics")
    except httpx.HTTPError as exc:
        return CheckResult(name, Status.FAIL, f"{where} unreachable: " + _error(exc))
    if r.status_code != 200:
        return CheckResult(name, Status.FAIL, f"{where} answered HTTP {r.status_code}")
    if "# TYPE lab_runs_total counter" not in r.text:
        return CheckResult(name, Status.FAIL, f"{where} does not serve lab_runs_total")
    if "lab_metrics_database_up 0" in r.text:
        return CheckResult(
            name,
            Status.FAIL,
            f"{where} is up but cannot read the database (lab_metrics_database_up 0)",
        )
    return CheckResult(name, Status.OK, f"{where} serves the lab metrics")


# --------------------------------------------------------------------- docker


def _docker_socket(cfg: DoctorConfig) -> Path:
    host = cfg.docker_host or os.environ.get("DOCKER_HOST") or f"unix://{DEFAULT_DOCKER_SOCKET}"
    if not host.startswith("unix://"):
        raise ValueError(f"DOCKER_HOST {host!r} is not a unix:// socket; only unix:// is checked")
    return Path(host.removeprefix("unix://"))


def check_docker(cfg: DoctorConfig) -> CheckResult:
    name = "docker"
    try:
        socket = _docker_socket(cfg)
    except ValueError as exc:
        return CheckResult(name, Status.FAIL, _detail(str(exc)))
    transport = httpx.HTTPTransport(uds=str(socket))
    try:
        with httpx.Client(
            transport=transport, base_url="http://docker", timeout=cfg.timeout, trust_env=False
        ) as c:
            ping = c.get("/_ping")
            if ping.status_code != 200 or ping.text.strip() != "OK":
                return CheckResult(
                    name, Status.FAIL, f"{socket}: /_ping answered HTTP {ping.status_code}"
                )
            version = c.get("/version")
            server = (
                version.json().get("Version", "unknown")
                if version.status_code == 200
                else "unknown"
            )
    except (httpx.HTTPError, ValueError) as exc:
        return CheckResult(name, Status.FAIL, f"{socket} unreachable: " + _error(exc))
    return CheckResult(name, Status.OK, f"{socket}: server {server}")


# --------------------------------------------------------------------- host.env


def parse_cell_networks(
    value: str, cell_range: IPv4Network = DEFAULT_CELL_RANGE
) -> list[IPv4Network]:
    """Parse ``LAB_CELL_NETWORKS`` strictly; raises ``ValueError`` saying why."""
    if not value:
        raise ValueError("empty")
    networks: list[IPv4Network] = []
    for item in value.split(","):
        if not item:
            raise ValueError(f"empty entry in {value!r}")
        if item != item.strip():
            raise ValueError(f"whitespace around {item!r}")
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"{item!r} is not a network") from None
        if "/" not in item:
            raise ValueError(f"{item!r} has no prefix length")
        if not isinstance(net, IPv4Network):
            raise ValueError(f"{item!r} is not IPv4")
        if str(net) != item:
            raise ValueError(f"{item!r} has host bits set (did you mean {net}?)")
        if not net.subnet_of(cell_range):
            raise ValueError(f"{item} is outside the cell range {cell_range}")
        for other in networks:
            if net.overlaps(other):
                raise ValueError(f"{item} and {other} overlap")
        networks.append(net)
    return networks


def check_host_env(cfg: DoctorConfig) -> CheckResult:
    name = "host_env"
    path = cfg.settings.host_env_file
    try:
        values = read_env_file(path)
    except FileNotFoundError:
        return CheckResult(name, Status.FAIL, f"{path} is missing (run deploy/bootstrap.sh)")
    except (OSError, UnicodeDecodeError) as exc:
        return CheckResult(name, Status.FAIL, f"{path} unreadable: " + _error(exc))
    raw = values.get("LAB_CELL_NETWORKS")
    if raw is None:
        return CheckResult(name, Status.FAIL, f"{path} does not set LAB_CELL_NETWORKS")
    try:
        nets = parse_cell_networks(raw, cfg.cell_range)
    except ValueError as exc:
        return CheckResult(name, Status.FAIL, _detail(f"LAB_CELL_NETWORKS invalid: {exc}"))
    return CheckResult(
        name,
        Status.OK,
        f"{path}: LAB_CELL_NETWORKS={','.join(map(str, nets))} (inside {cfg.cell_range})",
    )


# --------------------------------------------------------------------- firewall


def check_firewall(cfg: DoctorConfig) -> CheckResult:
    name = "firewall"
    tool = cfg.egress_command
    if not cfg.on_lab_host:
        return CheckResult(
            name, Status.SKIP, f"not on the lab host (no {cfg.settings.host_env_file}, no {tool})"
        )
    if not (tool.is_file() and os.access(tool, os.X_OK)):
        return CheckResult(name, Status.FAIL, f"{tool} is missing on the lab host (firewall role)")
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, absolute path, no shell
            [str(tool), "check"],
            capture_output=True,
            text=True,
            timeout=cfg.timeout * 3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(name, Status.FAIL, f"{tool} check: " + _error(exc))
    output = _detail((proc.stdout + " " + proc.stderr).strip())
    if proc.returncode != 0:
        return CheckResult(name, Status.FAIL, f"{tool} check exited {proc.returncode}: {output}")
    return CheckResult(name, Status.OK, f"{tool} check passed" + (f": {output}" if output else ""))


# --------------------------------------------------------------------- the whole run

_CHECKS: Final[tuple[tuple[str, str], ...]] = (
    ("database", "check_database"),
    ("collector", "check_collector"),
    ("metrics", "check_metrics"),
    ("docker", "check_docker"),
    ("host_env", "check_host_env"),
    ("firewall", "check_firewall"),
)
CHECK_NAMES: Final[tuple[str, ...]] = tuple(name for name, _ in _CHECKS)


def run_doctor(cfg: DoctorConfig) -> list[CheckResult]:
    """Run every check in order; never raises."""
    results = []
    for name, attr in _CHECKS:
        check: Callable[[DoctorConfig], CheckResult] = globals()[attr]
        try:
            result = check(cfg)
        except Exception as exc:  # a check must never abort the others
            result = CheckResult(name, Status.FAIL, "unexpected error: " + _error(exc))
        results.append(result)
    return results


def exit_code(results: Sequence[CheckResult]) -> int:
    return 1 if any(r.status is Status.FAIL for r in results) else 0


_MARK: Final = {Status.OK: "[ OK ]", Status.FAIL: "[FAIL]", Status.SKIP: "[SKIP]"}


def render_text(results: Sequence[CheckResult]) -> str:
    lines = [f"{_MARK[r.status]} {r.name}: {r.detail}" for r in results]
    failed = sum(r.status is Status.FAIL for r in results)
    skipped = sum(r.status is Status.SKIP for r in results)
    verdict = "doctor: FAILED" if failed else "doctor: OK"
    lines.append(f"{verdict} ({len(results)} checks, {failed} failed, {skipped} skipped)")
    return "\n".join(lines)


def render_json(results: Sequence[CheckResult]) -> str:
    return json.dumps(
        {
            "ok": exit_code(results) == 0,
            "checks": [
                {"name": r.name, "status": r.status.value, "detail": r.detail} for r in results
            ],
        },
        indent=2,
    )
