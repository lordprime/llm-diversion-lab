"""The RedAmon driver: runs one RedAmon session inside a cell, with no human.

It is the cell's ``agent`` service (``needs_docker``; its only Docker socket is the
cell-guard's). For one :class:`~agents.redamon.plan.RunPlan` it:

1. starts the five RedAmon services as siblings through cell-guard, in order, each
   waited for before the next (postgres, neo4j, kali, agent, webapp). Their
   secrets are made here and never written anywhere; their names carry the cell
   prefix cell-guard adds, which the driver reads back from the first container;
2. seeds the webapp the way AUTOMATION_FEASIBILITY §2.1 describes: an admin made
   with ``scripts/create-admin.mjs``, a login, one OpenAI-compatible provider row
   whose base URL is the tap, and one project carrying every gate and limit;
3. opens ``/ws/agent`` with a fresh ticket, sends ``init`` and the objective, and
   answers anything the agent asks with the plan's one canned reply (identical in
   every arm, and logged);
4. stops at the agent's own end (``task_complete``, a non-recoverable ``error`` or
   ``stopped``); on SIGTERM (the runner's timeout) it sends ``stop`` first;
5. copies RedAmon's per-session logs out of the agent container.

Evidence, under ``$LAB_EVIDENCE_DIR``: every frame in and out (``ws.jsonl``), the
driver's own steps (``driver.jsonl``), the ending (``outcome.json``) and the native
logs. The exit code is :attr:`EndingKind.exit_code`.

Run::

    python -m agents.redamon.driver --plan /etc/lab/agent/redamon-plan.json
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import secrets
import signal
import socket
import struct
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Final, Protocol
from urllib.parse import quote, urlsplit

import httpx

from agents.redamon.plan import (
    DRIVER_LOG_FILE,
    NATIVE_LOG_DIR,
    OUTCOME_FILE,
    WS_LOG_FILE,
    EndingKind,
    RunPlan,
    ServiceRole,
    ServiceSpec,
    SessionEnding,
)

__all__ = [
    "AgentSession",
    "DockerApi",
    "Driver",
    "DriverError",
    "EvidenceLog",
    "FrameSocket",
    "Stack",
    "StackSecrets",
    "Webapp",
    "main",
]

#: The Docker API version the driver speaks (cell-guard refuses anything below 1.40).
DOCKER_API: Final = "v1.43"
#: How long one service may take to answer (the webapp runs `prisma db push` first).
STARTUP_TIMEOUT_S: Final = 900.0
#: How long the driver waits for ``stopped`` after it sent ``stop``.
STOP_GRACE_S: Final = 20.0
#: An idle socket gets an application ping this often (the agent's heartbeat is 30 s).
PING_EVERY_S: Final = 25.0
#: The most bytes of one native log the driver copies out.
MAX_NATIVE_LOG: Final = 64 * 1024 * 1024
ADMIN_EMAIL: Final = "operator@lab.test"
ADMIN_NAME: Final = "Lab Operator"
#: Where upstream's images keep the agent's logs and the webapp's scripts.
AGENT_LOG_DIR: Final = "/app/logs"
WEBAPP_DIR: Final = "/app"


class DriverError(RuntimeError):
    """A step the session cannot start without failed (the ending is setup_failed)."""


# --------------------------------------------------------------------------- evidence


class EvidenceLog:
    """Append-only JSON lines under the evidence dir, flushed and fsynced per line."""

    def __init__(self, evidence_dir: Path, *, clock: Callable[[], datetime] | None = None):
        self._dir = evidence_dir
        self._clock = clock or (lambda: datetime.now(UTC))

    def _path(self, relative: str) -> Path:
        path = self._dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _append(self, relative: str, doc: Mapping[str, Any]) -> None:
        line = json.dumps({"at": self._clock().isoformat(), **doc}, sort_keys=True, default=str)
        with self._path(relative).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def frame(self, direction: str, frame: Any) -> None:
        """One WebSocket frame, ``in`` from the agent or ``out`` from the driver."""
        self._append(WS_LOG_FILE, {"dir": direction, "frame": frame})

    def step(self, event: str, **fields: Any) -> None:
        self._append(DRIVER_LOG_FILE, {"step": event, **fields})

    def ending(self, ending: SessionEnding) -> None:
        self._path(OUTCOME_FILE).write_text(ending.to_json() + "\n", encoding="utf-8")

    def native(self, name: str, data: bytes) -> None:
        self._path(f"{NATIVE_LOG_DIR}/{name}").write_bytes(data)


# --------------------------------------------------------------------------- docker


class DockerApi:
    """The few Docker Engine calls the driver needs, over the cell-guard socket."""

    def __init__(self, client: httpx.Client):
        self._http = client

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> DockerApi:
        host = env.get("DOCKER_HOST", "")
        if not host.startswith("unix://"):
            raise DriverError(f"DOCKER_HOST must be the cell-guard's unix socket, not {host!r}")
        transport = httpx.HTTPTransport(uds=host.removeprefix("unix://"))
        return cls(httpx.Client(transport=transport, base_url="http://docker", timeout=60.0))

    def _call(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = self._http.request(method, f"/{DOCKER_API}{path}", **kwargs)
        if response.status_code >= 300:
            raise DriverError(
                f"docker {method} {path}: HTTP {response.status_code} {response.text[:300]}"
            )
        return response

    def create(self, name: str, body: Mapping[str, Any]) -> str:
        response = self._call("POST", "/containers/create", params={"name": name}, json=body)
        container_id = response.json().get("Id")
        if not isinstance(container_id, str) or not container_id:
            raise DriverError(f"docker create {name}: no container id in the answer")
        return container_id

    def start(self, container_id: str) -> None:
        self._call("POST", f"/containers/{container_id}/start")

    def identity(self, container_id: str) -> tuple[str, str]:
        """A started container's name (with cell-guard's prefix) and its address on the
        cell network. The driver dials siblings by address: its own resolver may know
        only the cell's DNS (the smoke's canary), never Docker's container names."""
        doc = self._call("GET", f"/containers/{container_id}/json").json()
        name = doc.get("Name") if isinstance(doc, dict) else None
        if not isinstance(name, str) or not name.strip("/"):
            raise DriverError(f"docker inspect {container_id}: no name")
        networks = ((doc.get("NetworkSettings") or {}).get("Networks") or {}).values()
        addresses = [n.get("IPAddress") for n in networks if isinstance(n, dict)]
        address = next((a for a in addresses if isinstance(a, str) and a), None)
        if address is None:
            raise DriverError(f"docker inspect {container_id}: no address on the cell network")
        return name.strip("/"), address

    def exec(
        self, container_id: str, argv: Iterable[str], env: Mapping[str, str] | None = None
    ) -> tuple[int, bytes]:
        """Run ``argv`` in a container; its exit code and its stdout and stderr."""
        body: dict[str, Any] = {"AttachStdout": True, "AttachStderr": True, "Cmd": list(argv)}
        if env:
            body["Env"] = [f"{k}={v}" for k, v in env.items()]
        exec_id = self._call("POST", f"/containers/{container_id}/exec", json=body).json()["Id"]
        raw = self._call("POST", f"/exec/{exec_id}/start", json={"Detach": False}).content
        code = self._call("GET", f"/exec/{exec_id}/json").json().get("ExitCode")
        return (code if isinstance(code, int) else -1), self.demux(raw)

    @staticmethod
    def demux(raw: bytes) -> bytes:
        """Join the frames of Docker's multiplexed stdout/stderr stream (no TTY).

        Each frame is an 8-byte header (stream type, three zero bytes, a big-endian
        length) and its payload. A stream that does not start with a valid header is
        returned as it is; a truncated last frame keeps what arrived.
        """
        out, at = bytearray(), 0
        while at + 8 <= len(raw):
            kind, size = raw[at], struct.unpack(">I", raw[at + 4 : at + 8])[0]
            if kind not in (0, 1, 2) or raw[at + 1 : at + 4] != b"\0\0\0":
                return raw if at == 0 else bytes(out)
            out += raw[at + 8 : at + 8 + size]
            at += 8 + size
        return bytes(out) if at else raw


# --------------------------------------------------------------------------- the stack


@dataclass(frozen=True)
class StackSecrets:
    """The stack's credentials, made fresh for each run and never written down."""

    postgres_password: str
    neo4j_password: str
    ws_ticket_secret: str
    mcp_token: str
    internal_key: str
    auth_secret: str
    scanner_key: str
    orchestrator_key: str
    admin_password: str

    @classmethod
    def generate(cls) -> StackSecrets:
        return cls(**{name: secrets.token_hex(24) for name in cls.__dataclass_fields__})


class Waiter:
    """Waits until a service answers: an HTTP path with a 2xx, or an open TCP port."""

    def __init__(
        self,
        http: httpx.Client,
        *,
        connect: Callable[[str, int], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._http = http
        self._connect = connect or self._tcp
        self._clock = clock
        self._sleep = sleep

    @staticmethod
    def _tcp(host: str, port: int) -> None:
        socket.create_connection((host, port), timeout=5).close()

    def _ready(self, host: str, spec: ServiceSpec) -> bool:
        try:
            if spec.health_path is None:
                self._connect(host, spec.port)
                return True
            response = self._http.get(f"http://{host}:{spec.port}{spec.health_path}")
            return 200 <= response.status_code < 300
        except (OSError, httpx.HTTPError):
            return False

    def wait(self, host: str, spec: ServiceSpec, timeout_s: float = STARTUP_TIMEOUT_S) -> None:
        deadline = self._clock() + timeout_s
        while not self._ready(host, spec):
            if self._clock() >= deadline:
                raise DriverError(f"{spec.role.value} did not answer within {timeout_s:.0f} s")
            self._sleep(2.0)


class Stack:
    """The five sibling containers: their bodies, their names, and bringing them up."""

    def __init__(self, plan: RunPlan, docker: DockerApi, keys: StackSecrets, scratch_volume: str):
        self._plan = plan
        self._docker = docker
        self._keys = keys
        self._scratch = scratch_volume
        #: cell-guard's prefix, read back from the first container it created
        self.prefix: str | None = None
        self.ids: dict[ServiceRole, str] = {}
        self.addresses: dict[ServiceRole, str] = {}

    def host(self, role: ServiceRole) -> str:
        """The name siblings use for a service (Docker's DNS on the cell network)."""
        if self.prefix is None:
            raise DriverError("no container exists yet, so the cell prefix is unknown")
        return f"{self.prefix}{role.container_name}"

    def address(self, role: ServiceRole) -> str:
        """The address the driver itself dials."""
        if role not in self.addresses:
            raise DriverError(f"{role.value} has not been started")
        return self.addresses[role]

    def runtime_env(self, role: ServiceRole) -> dict[str, str]:
        """What only the run knows: the secrets and the other services' names."""
        k = self._keys
        # The databases name no other service, so they need no cell prefix yet.
        if role is ServiceRole.POSTGRES:
            return {
                "POSTGRES_USER": "redamon",
                "POSTGRES_PASSWORD": k.postgres_password,
                "POSTGRES_DB": "redamon",
            }
        if role is ServiceRole.NEO4J:
            return {"NEO4J_AUTH": f"neo4j/{k.neo4j_password}"}
        h = self.host
        database = (
            f"postgresql://redamon:{k.postgres_password}@{h(ServiceRole.POSTGRES)}:5432/redamon"
        )
        neo4j = {
            "NEO4J_URI": f"bolt://{h(ServiceRole.NEO4J)}:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": k.neo4j_password,
        }
        kali, agent, webapp = h(ServiceRole.KALI), h(ServiceRole.AGENT), h(ServiceRole.WEBAPP)
        if role is ServiceRole.KALI:
            return {
                "MCP_AUTH_TOKEN": k.mcp_token,
                "WEBAPP_API_URL": f"http://{webapp}:3000",
                "REDAMON_AGENT_URL": f"http://{agent}:8080",
            }
        if role is ServiceRole.AGENT:
            return {
                **neo4j,
                "DATABASE_URL": database,
                "MCP_NETWORK_RECON_URL": f"http://{kali}:8000/sse",
                "MCP_NUCLEI_URL": f"http://{kali}:8002/sse",
                "MCP_METASPLOIT_URL": f"http://{kali}:8003/sse",
                "MCP_NMAP_URL": f"http://{kali}:8004/sse",
                "MCP_PLAYWRIGHT_URL": f"http://{kali}:8005/sse",
                "MCP_METASPLOIT_PROGRESS_URL": f"http://{kali}:8013/progress",
                "MCP_HYDRA_PROGRESS_URL": f"http://{kali}:8014/progress",
                "KALI_TERMINAL_WS_URL": f"ws://{kali}:8016",
                "MCP_AUTH_TOKEN": k.mcp_token,
                "AGENT_WS_TICKET_SECRET": k.ws_ticket_secret,
                # api.py reads WEBAPP_URL, everything else WEBAPP_API_URL; both default
                # to http://webapp:3000, which is not this cell's webapp.
                "WEBAPP_API_URL": f"http://{webapp}:3000",
                "WEBAPP_URL": f"http://{webapp}:3000",
                "INTERNAL_API_KEY": k.internal_key,
                "SCANNER_API_KEY": k.scanner_key,
            }
        return {
            **neo4j,
            "DATABASE_URL": database,
            "AUTH_SECRET": k.auth_secret,
            "INTERNAL_API_KEY": k.internal_key,
            "SCANNER_API_KEY": k.scanner_key,
            "AGENT_WS_TICKET_SECRET": k.ws_ticket_secret,
            "ORCHESTRATOR_API_KEY": k.orchestrator_key,
            "AGENT_API_URL": f"http://{agent}:8080",
            "AGENT_WS_URL": f"ws://{agent}:8080/ws/agent",
            "WEBAPP_URL": f"http://{webapp}:3000",
        }

    def body(self, spec: ServiceSpec) -> dict[str, Any]:
        """The container create body. The plan's switches win over nothing: a runtime
        variable never overrides one, and a clash is a plan error."""
        runtime = self.runtime_env(spec.role)
        clash = sorted(set(runtime) & set(spec.env))
        if clash:
            raise DriverError(f"{spec.role.value}: the plan sets run-time variables {clash}")
        env = {**spec.env, **runtime}
        host: dict[str, Any] = {"Memory": spec.mem_bytes}
        if spec.cap_add:
            host["CapAdd"] = list(spec.cap_add)
        if spec.workspace:
            host["Binds"] = [f"{self._scratch}:/workspace"]
        return {
            "Image": spec.image,
            "Env": [f"{k}={v}" for k, v in sorted(env.items())],
            "HostConfig": host,
        }

    def up(self, waiter: Waiter, log: EvidenceLog) -> None:
        for spec in self._plan.services:
            # The first service (postgres, which names no other) is created before
            # the prefix is known; its name, read back, gives the prefix.
            container_id = self._docker.create(spec.role.container_name, self.body(spec))
            self.ids[spec.role] = container_id
            self._docker.start(container_id)
            name, address = self._docker.identity(container_id)
            if not name.endswith(spec.role.container_name):
                raise DriverError(f"cell-guard named the {spec.role.value} container {name!r}")
            prefix = name.removesuffix(spec.role.container_name)
            if self.prefix is None:
                self.prefix = prefix
            elif prefix != self.prefix:
                raise DriverError(f"{name!r} does not carry the cell prefix {self.prefix!r}")
            self.addresses[spec.role] = address
            log.step("service_started", role=spec.role.value, image=spec.image, id=container_id)
            waiter.wait(address, spec)
            log.step("service_ready", role=spec.role.value)


# --------------------------------------------------------------------------- the webapp


class Webapp:
    """The webapp's REST calls a session needs, as the signed-in admin (cookie session)."""

    def __init__(self, client: httpx.Client):
        self._http = client

    def _json(self, response: httpx.Response, what: str) -> dict[str, Any]:
        if response.status_code >= 300:
            raise DriverError(f"webapp {what}: HTTP {response.status_code} {response.text[:300]}")
        doc = response.json()
        if not isinstance(doc, dict):
            raise DriverError(f"webapp {what}: the answer is not an object")
        return doc

    @staticmethod
    def _id(doc: Mapping[str, Any], what: str) -> str:
        value = doc.get("id")
        if not isinstance(value, str) or not value:
            raise DriverError(f"webapp {what}: no id in the answer")
        return value

    def login(self, email: str, password: str) -> str:
        """Sign in (route.ts sets the ``redamon-auth`` cookie); the user's id."""
        doc = self._json(
            self._http.post("/api/auth/login", json={"email": email, "password": password}),
            "login",
        )
        return self._id(doc, "login")

    def create_provider(self, user_id: str, plan: RunPlan) -> str:
        """The run's one provider row: OpenAI-compatible, pointed at the tap."""
        body = {
            "providerType": "openai_compatible",
            "name": "lab-tap",
            "baseUrl": plan.llm.base_url,
            # the tap forwards to the gateway, which holds the real credentials
            "apiKey": "lab-tap",
            "modelIdentifier": plan.llm.model,
            "maxTokens": plan.llm.max_tokens,
            "timeout": plan.llm.timeout_s,
            "temperature": 0,
            "sslVerify": True,
            "reasoningEnabled": False,
        }
        path = f"/api/users/{quote(user_id, safe='')}/llm-providers"
        return self._id(self._json(self._http.post(path, json=body), "provider"), "provider")

    def create_project(self, plan: RunPlan, provider_id: str) -> str:
        body = {**plan.project, "agentOpenaiModel": f"custom/{provider_id}"}
        return self._id(
            self._json(self._http.post("/api/projects", json=body), "project"), "project"
        )

    def ws_ticket(self, project_id: str, session_id: str) -> str:
        doc = self._json(
            self._http.post(
                "/api/agent/ws-ticket",
                json={"projectId": project_id, "sessionId": session_id, "socket": "agent"},
            ),
            "ws ticket",
        )
        ticket = doc.get("ticket")
        if not isinstance(ticket, str) or not ticket:
            raise DriverError("webapp ws ticket: none minted (is AGENT_WS_TICKET_SECRET set?)")
        return ticket


# --------------------------------------------------------------------------- the session


class FrameSocket(Protocol):
    """The part of a WebSocket connection the session uses (``websockets.sync``)."""

    def send(self, message: str) -> None: ...
    def recv(self, timeout: float | None = None) -> str | bytes: ...
    def close(self) -> None: ...


@dataclass
class _StopFlag:
    requested: bool = False

    def set(self, _signum: int, _frame: FrameType | None) -> None:
        self.requested = True


class AgentSession:
    """One chat over ``/ws/agent``: init, the objective, canned replies, the end.

    Replies (all logged as ``out`` frames): an ``approval_request`` is approved, a
    ``question_request`` gets the plan's canned answer, a ``tool_confirmation_request``
    is approved, and so is a fireteam member waiting for confirmation. The gates are
    off in the project, so these are the fallback, not the plan.
    """

    def __init__(
        self,
        sock: FrameSocket,
        log: EvidenceLog,
        plan: RunPlan,
        stop: _StopFlag,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._sock = sock
        self._log = log
        self._plan = plan
        self._stop = stop
        self._clock = clock

    def _send(self, kind: str, payload: Mapping[str, Any]) -> None:
        frame = {"type": kind, "payload": dict(payload)}
        self._log.frame("out", frame)
        self._sock.send(json.dumps(frame))

    def _recv(self, timeout: float) -> dict[str, Any] | None:
        """The next frame, or None when none came in time. A frame that is not JSON
        or not an object is logged as it came and skipped."""
        try:
            raw = self._sock.recv(timeout=timeout)
        except TimeoutError:
            return None
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        try:
            frame = json.loads(text)
        except ValueError:
            self._log.frame("in", {"unparsed": text[:4000]})
            return {}
        self._log.frame("in", frame)
        return frame if isinstance(frame, dict) else {}

    def _reply(self, frame: Mapping[str, Any]) -> None:
        kind, payload = frame.get("type"), frame.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        if kind == "approval_request":
            self._send("approval", {"decision": "approve"})
        elif kind == "question_request":
            self._send("answer", {"answer": self._plan.canned_answer})
        elif kind == "tool_confirmation_request":
            self._send("tool_confirmation", {"decision": "approve"})
        elif kind == "fireteam_member_awaiting_confirmation":
            self._send(
                "fireteam_member_confirmation",
                {
                    "wave_id": payload.get("wave_id") or payload.get("fireteam_id"),
                    "member_id": payload.get("member_id"),
                    "decision": "approve",
                },
            )

    def run(self, user_id: str, project_id: str, ticket: str) -> SessionEnding:
        self._send(
            "init",
            {
                "user_id": user_id,
                "project_id": project_id,
                "session_id": self._plan.session_id,
                "ticket": ticket,
                "graph_view_cypher": None,
            },
        )
        connected = self._recv(timeout=60.0)
        if not connected or connected.get("type") != "connected":
            ending = SessionEnding.from_frame(connected, self._plan.max_iterations)
            return ending or SessionEnding(
                kind=EndingKind.SETUP_FAILED, message="the agent did not accept the session"
            )
        self._send("query", {"question": self._plan.objective})
        last_sent = self._clock()
        stop_sent_at: float | None = None
        while True:
            if self._stop.requested and stop_sent_at is None:
                self._send("stop", {})
                stop_sent_at = self._clock()
            if stop_sent_at is not None and self._clock() - stop_sent_at > STOP_GRACE_S:
                return SessionEnding(kind=EndingKind.STOPPED, message="stopped by the runner")
            try:
                frame = self._recv(timeout=1.0)
            except Exception as exc:
                # OSError, or the websockets library's ConnectionClosed family (which
                # the harness cannot name: the library lives in the driver image only)
                return SessionEnding(kind=EndingKind.CONNECTION_LOST, message=type(exc).__name__)
            if frame is None:
                if self._clock() - last_sent >= PING_EVERY_S:
                    self._send("ping", {})
                    last_sent = self._clock()
                continue
            ending = SessionEnding.from_frame(frame, self._plan.max_iterations)
            if ending is not None:
                return ending
            self._reply(frame)


# --------------------------------------------------------------------------- the driver


def _connect_ws(url: str) -> FrameSocket:
    # Imported here: websockets is in the driver image only, never in the harness.
    client = importlib.import_module("websockets.sync.client")
    sock: FrameSocket = client.connect(url, max_size=16 * 1024 * 1024, open_timeout=60)
    return sock


@dataclass
class Driver:
    """Wires the pieces together for one run; every collaborator can be replaced."""

    plan: RunPlan
    docker: DockerApi
    log: EvidenceLog
    scratch_volume: str
    keys: StackSecrets = field(default_factory=StackSecrets.generate)
    http: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=60.0, trust_env=False))
    connect_ws: Callable[[str], FrameSocket] = _connect_ws
    stop: _StopFlag = field(default_factory=_StopFlag)

    def _create_admin(self, stack: Stack) -> None:
        code, output = self.docker.exec(
            stack.ids[ServiceRole.WEBAPP],
            ["sh", "-c", f"cd {WEBAPP_DIR} && exec node scripts/create-admin.mjs"],
            env={
                "ADMIN_NAME": ADMIN_NAME,
                "ADMIN_EMAIL": ADMIN_EMAIL,
                "ADMIN_PASSWORD": self.keys.admin_password,
            },
        )
        # exit 0: created; 3: the address exists but was not promoted (a reused stack)
        if code != 0:
            raise DriverError(f"create-admin exited {code}: {output[-300:]!r}")

    def _copy_native_logs(self, stack: Stack) -> None:
        agent = stack.ids.get(ServiceRole.AGENT)
        if agent is None:
            return
        for suffix in ("events.jsonl", "log"):
            name = f"agent.{self.plan.session_id}.{suffix}"
            try:
                code, data = self.docker.exec(
                    agent, ["head", "-c", str(MAX_NATIVE_LOG), f"{AGENT_LOG_DIR}/{name}"]
                )
            except (DriverError, httpx.HTTPError) as exc:
                self.log.step("native_log_failed", name=name, error=str(exc)[:300])
                continue
            if code == 0:
                self.log.native(name, data)
            else:
                self.log.step("native_log_missing", name=name, exit_code=code)

    def run(self) -> SessionEnding:
        stack = Stack(self.plan, self.docker, self.keys, self.scratch_volume)
        try:
            stack.up(Waiter(self.http), self.log)
            self._create_admin(stack)
            webapp = Webapp(
                httpx.Client(
                    base_url=f"http://{stack.address(ServiceRole.WEBAPP)}:3000",
                    timeout=60.0,
                    trust_env=False,
                )
            )
            user_id = webapp.login(ADMIN_EMAIL, self.keys.admin_password)
            provider_id = webapp.create_provider(user_id, self.plan)
            project_id = webapp.create_project(self.plan, provider_id)
            self.log.step("seeded", user_id=user_id, provider_id=provider_id, project_id=project_id)
            ticket = webapp.ws_ticket(project_id, self.plan.session_id)
            sock = self.connect_ws(f"ws://{stack.address(ServiceRole.AGENT)}:8080/ws/agent")
        except Exception as exc:
            # Whatever failed before the session started (a step, the HTTP client, the
            # WebSocket handshake), the run still ends with an outcome on record.
            ending = SessionEnding(
                kind=EndingKind.SETUP_FAILED, message=f"{type(exc).__name__}: {exc}"[:4000]
            )
        else:
            try:
                ending = AgentSession(sock, self.log, self.plan, self.stop).run(
                    user_id, project_id, ticket
                )
            finally:
                sock.close()
        self._copy_native_logs(stack)
        return ending


def _scratch_volume(env: Mapping[str, str]) -> str:
    """The cell's scratch volume, which the runner (and the smoke) name in
    LAB_SCRATCH_VOLUME. There is no fallback: a second copy of the runner's naming rule
    would drift silently."""
    named = env.get("LAB_SCRATCH_VOLUME", "")
    if not named:
        raise DriverError("LAB_SCRATCH_VOLUME is not set: the cell's scratch volume is unknown")
    return named


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", type=Path, help="the plan file (a cell run)")
    source.add_argument("--plan-env", metavar="VAR", help="a variable holding the plan (smoke)")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    log = EvidenceLog(Path(env.get("LAB_EVIDENCE_DIR", "/evidence")))
    try:
        text = (
            args.plan.read_text(encoding="utf-8")
            if args.plan is not None
            else env.get(args.plan_env, "")
        )
        plan = RunPlan.from_json(text)
        run_id = env.get("LAB_RUN_ID")
        if not plan.smoke and run_id is not None and plan.run_id != run_id:
            raise DriverError(f"the plan is for run {plan.run_id}, not {run_id}")
        if urlsplit(plan.llm.base_url).hostname is None:
            raise DriverError("the plan's model endpoint has no host")
        driver = Driver(plan, DockerApi.from_env(env), log, _scratch_volume(env))
    except (OSError, ValueError, DriverError) as exc:
        return _finish(log, SessionEnding(kind=EndingKind.SETUP_FAILED, message=str(exc)[:4000]))
    signal.signal(signal.SIGTERM, driver.stop.set)
    return _finish(log, driver.run())


def _finish(log: EvidenceLog, ending: SessionEnding) -> int:
    """Record the ending, print it (the smoke keeps only stdout), return the exit code."""
    log.ending(ending)
    print(f"redamon-driver outcome: {ending.to_json()}", flush=True)
    return ending.kind.exit_code


if __name__ == "__main__":
    sys.exit(main())
