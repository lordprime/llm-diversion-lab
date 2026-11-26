"""Runs one PentAGI flow headless inside the agent container, then exports its evidence.

PentAGI is a web service (Go API plus Postgres with pgvector) that starts worker
containers for its agents. One run of the lab is one *flow* on one fresh database, so
the agent image carries PostgreSQL and PentAGI together and this driver is its command:

1. start a private PostgreSQL on 127.0.0.1 in ``/tmp`` (the container's root is
   read-only), so every run begins with an empty database and no memory of earlier runs;
2. write the per-role provider config the adapter rendered, start PentAGI with the
   environment the adapter rendered, and wait until its API answers;
3. log in with the built-in local account, create one flow on the ``ollama`` provider
   with the run's objective as its input, and poll the database until the flow's first
   task has finished or failed (with ``ASK_USER=false`` the flow then waits for input);
4. finish the flow, export every table the adapter reads as JSON lines plus a full
   ``pg_dump``, and write ``driver.json``: what happened, in the driver's own words.

The driver decides nothing about the run's end state. It records facts (the flow's and
tasks' statuses, PentAGI's own log) and exits with:

* ``0``: the flow's task finished;
* ``3``: PentAGI gave up (the task or the flow failed);
* ``2``: the driver could not run the flow (a service did not start, an API call failed,
  PentAGI died);
* ``143``: SIGTERM arrived (the runner's timeout); the evidence is exported first.

Evidence goes to ``<LAB_EVIDENCE_DIR>/agent/pentagi/`` (``/tmp/evidence`` when the
variable is unset, as in the CI smoke run). PentAGI's own output is also echoed to
stdout, prefixed ``pentagi|``, and the driver's events are JSON lines on stdout.

Only the standard library is used: this file runs on the image's system Python.

Environment (from the adapter's render, see :mod:`agents.pentagi.adapter`):

* ``LAB_PENTAGI_RUN``: a JSON object with ``input`` (the flow's first message),
  ``provider`` (``ollama``), ``provider_config`` (the per-role YAML) and
  ``poll_seconds``;
* ``OLLAMA_SERVER_CONFIG_PATH``: where ``provider_config`` is written;
* ``SERVER_PORT``: the port PentAGI's API listens on at 127.0.0.1;
* everything else is passed to PentAGI as it is.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import IO, Any, Final

__all__ = [
    "EXPORTED_TABLES",
    "DriverConfig",
    "DriverError",
    "ExitCode",
    "FlowDriver",
    "FlowState",
    "LocalPostgres",
    "PentagiApi",
    "PentagiServer",
    "main",
]

#: Tables exported as JSON lines, one file each (``<table>.jsonl``), ordered by id.
EXPORTED_TABLES: Final = (
    "flows",
    "tasks",
    "subtasks",
    "msgchains",
    "toolcalls",
    "msglogs",
    "agentlogs",
    "termlogs",
    "searchlogs",
    "vecstorelogs",
    "containers",
)
#: The account the database migrations seed (initial_state.sql); it never leaves the
#: container: the API listens on 127.0.0.1 only.
LOCAL_ACCOUNT: Final = {"mail": "admin@pentagi.com", "password": "admin"}
DATABASE: Final = "pentagidb"
DB_USER: Final = "pentagi"
DB_PORT: Final = 5432
PENTAGI_BIN: Final = Path("/opt/pentagi/bin/pentagi")
POSTGRES_BIN: Final = Path("/usr/lib/postgresql/17/bin")
#: The task statuses after which a task does nothing more.
DONE_TASK_STATUSES: Final = frozenset({"finished", "failed"})
#: The flow statuses after which the flow does nothing more.
DONE_FLOW_STATUSES: Final = frozenset({"finished", "failed"})


class ExitCode(IntEnum):
    """The driver's exit status (see the module docs)."""

    FINISHED = 0
    DRIVER_ERROR = 2
    FAILED = 3
    TERMINATED = 143


class DriverError(RuntimeError):
    """The driver could not run the flow (exit 2)."""


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class DriverConfig:
    """What one run needs, read from the environment."""

    flow_input: str
    provider: str
    provider_config: str
    provider_config_path: Path
    poll_seconds: float
    server_port: int
    evidence_dir: Path
    work_dir: Path = Path("/tmp/pentagi")  # noqa: S108 - the container's tmpfs

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> DriverConfig:
        """Read the run from ``env``; raise :class:`DriverError` saying what is wrong."""
        raw = env.get("LAB_PENTAGI_RUN")
        if not raw:
            raise DriverError("LAB_PENTAGI_RUN is not set")
        try:
            run = json.loads(raw)
        except ValueError as exc:
            raise DriverError(f"LAB_PENTAGI_RUN is not JSON: {exc}") from exc
        if not isinstance(run, dict):
            raise DriverError("LAB_PENTAGI_RUN is not a JSON object")
        unknown = sorted(set(run) - {"input", "provider", "provider_config", "poll_seconds"})
        if unknown:
            raise DriverError(f"LAB_PENTAGI_RUN has unknown keys {unknown}")
        texts = {key: run.get(key) for key in ("input", "provider", "provider_config")}
        for key, value in texts.items():
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise DriverError(f"LAB_PENTAGI_RUN.{key} must be non-empty text")
        poll = run.get("poll_seconds")
        if isinstance(poll, bool) or not isinstance(poll, int | float) or not 0 < poll <= 60:
            raise DriverError("LAB_PENTAGI_RUN.poll_seconds must be a number in (0, 60]")
        config_path = env.get("OLLAMA_SERVER_CONFIG_PATH", "")
        if not config_path.startswith("/"):
            raise DriverError("OLLAMA_SERVER_CONFIG_PATH must be an absolute path")
        port = env.get("SERVER_PORT", "")
        if not port.isascii() or not port.isdigit() or not 0 < int(port) < 65536:
            raise DriverError(f"SERVER_PORT {port!r} is not a port")
        evidence = Path(env.get("LAB_EVIDENCE_DIR") or "/tmp/evidence")  # noqa: S108
        return cls(
            flow_input=str(texts["input"]),
            provider=str(texts["provider"]),
            provider_config=str(texts["provider_config"]),
            provider_config_path=Path(config_path),
            poll_seconds=float(poll),
            server_port=int(port),
            evidence_dir=evidence / "agent" / "pentagi",
        )


# --------------------------------------------------------------------------- services


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class LocalPostgres:
    """A throwaway PostgreSQL cluster on 127.0.0.1, owned by the container's user."""

    def __init__(self, work_dir: Path, run: Runner = subprocess.run) -> None:
        self._data = work_dir / "pg"
        self._sockets = work_dir / "pg-run"
        self._log = work_dir / "postgres.log"
        self._run = run

    @property
    def url(self) -> str:
        return f"postgres://{DB_USER}@127.0.0.1:{DB_PORT}/{DATABASE}?sslmode=disable"

    def _bin(self, name: str) -> str:
        return str(POSTGRES_BIN / name)

    def _call(self, argv: Sequence[str], what: str) -> str:
        # fixed binaries; every argument is built here, never by a shell
        result = self._run(list(argv), capture_output=True, text=True, check=False, timeout=300)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[-2000:]
            raise DriverError(f"{what} failed ({result.returncode}): {detail}")
        return result.stdout

    def start(self) -> None:
        """Create an empty cluster and the database, and start the server."""
        self._sockets.mkdir(parents=True, exist_ok=True)
        self._call(
            [
                self._bin("initdb"),
                *("-D", str(self._data), "-U", DB_USER),
                *("--auth=trust", "--encoding=UTF8", "--no-instructions"),
            ],
            "initdb",
        )
        options = " ".join(
            f"-c {setting}"
            for setting in (
                "listen_addresses=127.0.0.1",
                f"port={DB_PORT}",
                f"unix_socket_directories={self._sockets}",
                "max_connections=60",
                "shared_buffers=32MB",
                # a throwaway database in tmpfs: durability buys nothing here
                "fsync=off",
                "full_page_writes=off",
                "synchronous_commit=off",
                "wal_level=minimal",
                "max_wal_senders=0",
                "min_wal_size=32MB",
                "max_wal_size=64MB",
            )
        )
        self._call(
            [
                self._bin("pg_ctl"),
                *("-D", str(self._data), "-l", str(self._log)),
                *("-w", "-t", "120", "-o", options, "start"),
            ],
            "pg_ctl start",
        )
        self.query(f"CREATE DATABASE {DATABASE}", database="postgres")

    def query(self, sql: str, *, database: str = DATABASE) -> list[str]:
        """Run ``sql`` and return its rows, one unaligned line each."""
        out = self._call(
            [
                self._bin("psql"),
                *("-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"),
                *("-h", "127.0.0.1", "-p", str(DB_PORT), "-U", DB_USER, "-d", database),
                *("-c", sql),
            ],
            "psql",
        )
        return [line for line in out.splitlines() if line]

    def export_table(self, table: str, target: Path) -> int:
        """Write every row of ``table`` (a name from :data:`EXPORTED_TABLES`) as JSON
        lines, ordered by id; return the number of rows."""
        if table not in EXPORTED_TABLES:
            raise ValueError(f"{table!r} is not an exported table")
        # the table name comes from the fixed list above, never from input
        sql = f"SELECT row_to_json(t) FROM (SELECT * FROM {table} ORDER BY id) t"  # noqa: S608
        rows = self.query(sql)
        target.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8")
        return len(rows)

    def dump(self, target: Path) -> None:
        self._call(
            [
                self._bin("pg_dump"),
                *("-h", "127.0.0.1", "-p", str(DB_PORT), "-U", DB_USER),
                *("--no-owner", "-f", str(target), DATABASE),
            ],
            "pg_dump",
        )


class PentagiServer:
    """The PentAGI process, its output copied to a log file and to stdout."""

    def __init__(self, log_path: Path, echo: IO[str] = sys.stdout) -> None:
        self._log_path = log_path
        self._echo = echo
        self._process: subprocess.Popen[str] | None = None
        self._pump: threading.Thread | None = None

    def start(self, env: Mapping[str, str], cwd: Path) -> None:
        cwd.mkdir(parents=True, exist_ok=True)
        self._process = subprocess.Popen(  # noqa: S603 - the fixed PentAGI binary
            [str(PENTAGI_BIN)],
            env=dict(env),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        self._pump = threading.Thread(target=self._copy_output, daemon=True)
        self._pump.start()

    def _copy_output(self) -> None:
        if self._process is None or self._process.stdout is None:
            return
        with self._log_path.open("a", encoding="utf-8") as log:
            for line in self._process.stdout:
                log.write(line)
                log.flush()
                self._echo.write(f"pentagi| {line}")
                self._echo.flush()

    @property
    def exit_code(self) -> int | None:
        """``None`` while PentAGI runs (or was never started), else its exit status."""
        return None if self._process is None else self._process.poll()

    def stop(self, grace_s: float = 5.0) -> int | None:
        if self._process is None:
            return None
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=grace_s)
        if self._pump is not None:
            self._pump.join(timeout=grace_s)
        return self._process.returncode


class PentagiApi:
    """The few REST calls the driver makes, with the session cookie of one login."""

    def __init__(self, port: int, timeout_s: float = 30.0) -> None:
        self._base = f"http://127.0.0.1:{port}/api/v1"
        self._timeout = timeout_s
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def _request(self, method: str, path: str, body: object | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - always http://127.0.0.1
            self._base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                payload = response.read(16 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise DriverError(f"{method} {path}: HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise DriverError(f"{method} {path}: {exc}") from exc
        try:
            doc = json.loads(payload)
        except ValueError as exc:
            raise DriverError(f"{method} {path}: the answer is not JSON") from exc
        if not isinstance(doc, dict) or doc.get("status") != "success":
            raise DriverError(f"{method} {path}: not a success: {str(doc)[:500]}")
        return doc.get("data")

    def answers(self) -> bool:
        """Whether the API is up: any HTTP answer below 500 counts."""
        request = urllib.request.Request(self._base + "/info")  # noqa: S310 - 127.0.0.1
        try:
            with self._opener.open(request, timeout=5) as response:
                return int(response.status) < 500
        except urllib.error.HTTPError as exc:
            return exc.code < 500
        except (urllib.error.URLError, OSError):
            return False

    def login(self) -> None:
        self._request("POST", "/auth/login", LOCAL_ACCOUNT)

    def create_flow(self, flow_input: str, provider: str) -> int:
        data = self._request("POST", "/flows/", {"input": flow_input, "provider": provider})
        flow_id = data.get("id") if isinstance(data, dict) else None
        if isinstance(flow_id, bool) or not isinstance(flow_id, int) or flow_id <= 0:
            raise DriverError(f"POST /flows/: no flow id in {str(data)[:500]}")
        return flow_id

    def finish_flow(self, flow_id: int) -> None:
        self._request("PUT", f"/flows/{flow_id}", {"action": "finish"})


# --------------------------------------------------------------------------- the flow


@dataclass(frozen=True)
class FlowState:
    """One look at the flow in the database."""

    flow_status: str | None
    task_statuses: tuple[str, ...] = ()

    @property
    def done(self) -> bool:
        """Whether PentAGI will do nothing more on its own.

        The flow itself failed or finished; or it has tasks, every one of them is done,
        and the flow no longer runs (it waits for the next input, which never comes).
        """
        if self.flow_status in DONE_FLOW_STATUSES:
            return True
        return (
            bool(self.task_statuses)
            and all(s in DONE_TASK_STATUSES for s in self.task_statuses)
            and self.flow_status != "running"
        )

    @property
    def finished(self) -> bool:
        """Whether the flow ended with its task finished (and the flow not failed)."""
        return (
            self.done
            and self.flow_status != "failed"
            and bool(self.task_statuses)
            and self.task_statuses[-1] == "finished"
        )

    @classmethod
    def read(cls, db: LocalPostgres, flow_id: int) -> FlowState:
        number = int(flow_id)  # an integer, so nothing else can reach the SQL
        flows = db.query(f"SELECT status FROM flows WHERE id = {number}")  # noqa: S608
        tasks = db.query(f"SELECT status FROM tasks WHERE flow_id = {number} ORDER BY id")  # noqa: S608
        return cls(flow_status=flows[0] if flows else None, task_statuses=tuple(tasks))


@dataclass
class DriverReport:
    """``driver.json``: what the driver saw, nothing it inferred."""

    outcome: str = "error"
    exit_code: int = int(ExitCode.DRIVER_ERROR)
    flow_id: int | None = None
    flow_status: str | None = None
    task_statuses: list[str] = field(default_factory=list)
    pentagi_exit_code: int | None = None
    terminated: bool = False
    error: str | None = None
    exported: dict[str, int] = field(default_factory=dict)
    export_errors: dict[str, str] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None


class FlowDriver:
    """Runs the whole sequence of the module docs once (see :meth:`run`)."""

    def __init__(
        self,
        config: DriverConfig,
        env: Mapping[str, str],
        *,
        db: LocalPostgres | None = None,
        server: PentagiServer | None = None,
        api: PentagiApi | None = None,
        out: IO[str] = sys.stdout,
        clock: Callable[[], float] = time.monotonic,
        ready_timeout_s: float = 300.0,
    ) -> None:
        self._config = config
        self._env = dict(env)
        self._db = db or LocalPostgres(config.work_dir)
        self._server = server or PentagiServer(config.evidence_dir / "pentagi.log", out)
        self._api = api or PentagiApi(config.server_port)
        self._out = out
        self._clock = clock
        self._ready_timeout = ready_timeout_s
        self._stop = threading.Event()
        self.report = DriverReport()

    def request_stop(self, *_: object) -> None:
        """The SIGTERM handler: stop waiting and export what there is."""
        self.report.terminated = True
        self._stop.set()

    def _say(self, event: str, **fields: object) -> None:
        self._out.write(json.dumps({"driver": event, **fields}, default=str) + "\n")
        self._out.flush()

    def run(self) -> int:
        self._config.evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._prepare()
            self._drive()
        except DriverError as exc:
            self.report.error = str(exc)
            self._say("error", error=str(exc))
        finally:
            self._close()
        return self.report.exit_code

    def _prepare(self) -> None:
        self._db.start()
        self._say("postgres_ready")
        path = self._config.provider_config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._config.provider_config, encoding="utf-8")
        env = {
            **self._env,
            "DATABASE_URL": self._db.url,
            # a fresh secret per run; it signs the driver's own session cookie only
            "COOKIE_SIGNING_SALT": secrets.token_hex(32),
        }
        self._server.start(env, self._config.work_dir / "app")
        deadline = self._clock() + self._ready_timeout
        while not self._api.answers():
            self._check_alive()
            if self._clock() > deadline:
                raise DriverError(f"PentAGI's API did not answer in {self._ready_timeout:.0f}s")
            if self._stop.wait(1.0):
                return
        self._say("pentagi_ready")

    def _check_alive(self) -> None:
        code = self._server.exit_code
        if code is not None:
            self.report.pentagi_exit_code = code
            raise DriverError(f"PentAGI exited with status {code}")

    def _drive(self) -> None:
        if self._stop.is_set():
            return
        self._api.login()
        flow_id = self._api.create_flow(self._config.flow_input, self._config.provider)
        self.report.flow_id = flow_id
        self._say("flow_created", flow_id=flow_id)
        state = FlowState(flow_status=None)
        while not self._stop.is_set():
            self._check_alive()
            state = FlowState.read(self._db, flow_id)
            self._note(state)
            if state.done:
                break
            self._stop.wait(self._config.poll_seconds)
        if self._stop.is_set():
            return
        self._say("flow_done", flow_status=state.flow_status, tasks=list(state.task_statuses))
        self.report.outcome = "finished" if state.finished else "failed"
        self.report.exit_code = int(ExitCode.FINISHED if state.finished else ExitCode.FAILED)
        if state.flow_status not in DONE_FLOW_STATUSES:
            try:
                self._api.finish_flow(flow_id)
            except DriverError as exc:  # the result is already known
                self._say("finish_failed", error=str(exc))

    def _note(self, state: FlowState) -> None:
        self.report.flow_status = state.flow_status
        self.report.task_statuses = list(state.task_statuses)

    def _close(self) -> None:
        if self.report.terminated:
            self.report.outcome = "terminated"
            self.report.exit_code = int(ExitCode.TERMINATED)
        if self.report.flow_id is not None:
            try:
                self._note(FlowState.read(self._db, self.report.flow_id))
            except DriverError as exc:
                self.report.export_errors["state"] = str(exc)
        self._export()
        code = self._server.stop()
        if self.report.pentagi_exit_code is None:
            self.report.pentagi_exit_code = code
        self.report.ended_at = time.time()
        target = self._config.evidence_dir / "driver.json"
        target.write_text(json.dumps(asdict(self.report), indent=2) + "\n", encoding="utf-8")
        self._say("done", outcome=self.report.outcome, exit_code=self.report.exit_code)

    def _export(self) -> None:
        out = self._config.evidence_dir
        for table in EXPORTED_TABLES:
            try:
                self.report.exported[table] = self._db.export_table(table, out / f"{table}.jsonl")
            except (DriverError, OSError) as exc:
                self.report.export_errors[table] = str(exc)[:1000]
        if self.report.terminated:
            return  # the runner's grace period is short: the tables are what matter
        try:
            self._db.dump(out / "pentagi.sql")
        except (DriverError, OSError) as exc:
            self.report.export_errors["pg_dump"] = str(exc)[:1000]


def main(env: Mapping[str, str] | None = None) -> int:
    env = dict(os.environ if env is None else env)
    try:
        config = DriverConfig.from_env(env)
    except DriverError as exc:
        print(json.dumps({"driver": "error", "error": str(exc)}), flush=True)
        return int(ExitCode.DRIVER_ERROR)
    driver = FlowDriver(config, env)
    signal.signal(signal.SIGTERM, driver.request_stop)
    return driver.run()


if __name__ == "__main__":
    sys.exit(main())
