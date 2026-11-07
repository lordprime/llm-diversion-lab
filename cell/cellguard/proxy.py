"""cell-guard proxy: a Unix socket the agent sees as ``docker.sock``, in front of the real one.

Every connection carries exactly one request (the proxy answers with
``Connection: close``; Docker clients reconnect per request). For each request it:

1. parses the request strictly (one ``Content-Length`` or ``chunked``, never both;
   no obs-fold; bounded head and body) and answers ``400``/``413`` otherwise;
2. if the path names an existing object (a container, exec, network or volume),
   inspects that object on the real socket to learn its id and labels, which become
   :attr:`~cell.cellguard.policy.DockerRequest.target` (the forwarded path is then
   pinned to the full id, so the request acts on exactly what was checked);
3. decides with the pure :func:`~cell.cellguard.policy.evaluate`;
4. appends the decision to the run's evidence and fsyncs it (:class:`DecisionLog`)
   *before* anything is forwarded; if it cannot be recorded, nothing is forwarded;
5. answers a denial with ``403`` and a JSON ``message`` (the daemon never sees it), or
   forwards the decided path and body with ``Connection: close`` and relays the
   response byte-for-byte until the daemon closes. The body forwarded is the one the
   policy rebuilt (never the client's bytes); body-less operations forward none.

Names: container and volume names the agent chooses get the cell's prefix at create
time, so a lookup of an unprefixed name tries the prefixed name first.

Connection upgrades (attach, exec start): the client's ``Upgrade`` header is
forwarded. When the daemon answers ``101`` (or ``200`` with a Docker raw or
multiplexed stream content type, the pre-upgrade hijack), the proxy relays the
response head and then splices both directions until the daemon's side ends (the
client's half-close is passed on as a half-close). Otherwise the response is relayed
by its ``Content-Length`` and the connection closed, so the client can never speak
HTTP to the daemon on a kept-alive connection.

Evidence: ``<evidence>/cellguard/decisions.jsonl``, stream ``cellguard``: one
:class:`~control.core.models.CellGuardDecision` event per request, allowed or denied,
each line exactly its ``model_dump_json()`` so the runner ships it to the Collector
byte-for-byte. The same write-once discipline as the other cell components: append +
fsync, ``seq`` per stream from 0, resumed after a restart, a torn last line closed and
its ``seq`` never reused.
Request bodies are not stored (they may carry the agent's environment); their
SHA-256 and size are.

Configuration (:meth:`CellGuardConfig.from_env`):

* ``LAB_RUN_ID`` (required): the run the cell belongs to.
* ``LAB_CELLGUARD_NETWORK`` (required): the cell's internal network.
* ``LAB_CELLGUARD_IMAGES_LOCK`` (required): path of ``images.lock`` (YAML or JSON).
* ``LAB_CELLGUARD_DNS`` (required): IP address of the cell resolver (the catcher's
  DNS), forced as every created container's only nameserver.
* ``LAB_CELLGUARD_LISTEN`` (default ``/run/cellguard/docker.sock``): socket to serve.
* ``LAB_CELLGUARD_UPSTREAM`` (default ``/var/run/docker.sock``; ``unix://`` accepted).
* ``LAB_CELLGUARD_SCRATCH_VOLUME`` (optional): the cell's scratch named volume, the one
  persistent mount a created container may use. Host paths are never mounted, so the
  former ``LAB_CELLGUARD_SCRATCH_DIR`` is refused if set.
* ``LAB_CELLGUARD_NAME_PREFIX`` (default ``<run id lowercased>-``): prefix forced on
  container and volume names the agent chooses; ends with ``-``, holds no other ``-``.
* ``LAB_CELLGUARD_MEMORY`` (bytes), ``LAB_CELLGUARD_NANO_CPUS``, ``LAB_CELLGUARD_PIDS``
  (optional): limits forced on created containers.
* ``LAB_CELLGUARD_SOCKET_MODE`` (octal, default ``660``).
* ``LAB_CELLGUARD_MAX_CONNECTIONS`` (default 32): concurrent connections before ``503``.
* ``LAB_EVIDENCE_DIR`` (default ``./evidence``): the run's evidence volume.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cell.cellguard.policy import (
    DEFAULT_MEMORY_BYTES,
    DEFAULT_NANO_CPUS,
    DEFAULT_PIDS_LIMIT,
    RUN_ID_PATTERN,
    RUN_LABEL,
    CellContext,
    Decision,
    DockerRequest,
    Route,
    Target,
    evaluate,
    load_images_lock,
    route,
)
from control.core.models import CellGuardDecision

__all__ = [
    "CELLGUARD_DIR",
    "CELLGUARD_STREAM",
    "DECISIONS_FILE",
    "DEFAULT_EVIDENCE_DIR",
    "DEFAULT_MAX_CONNECTIONS",
    "MAX_BODY",
    "MAX_HEAD",
    "CellGuard",
    "CellGuardConfig",
    "DecisionLog",
    "main",
]

#: Producer stream name of cell-guard's decision records.
CELLGUARD_STREAM: Final = "cellguard"
DEFAULT_EVIDENCE_DIR: Final = "evidence"
CELLGUARD_DIR: Final = "cellguard"
#: The decision log, relative to the evidence dir.
DECISIONS_FILE: Final = f"{CELLGUARD_DIR}/decisions.jsonl"
#: Largest accepted request head (request line and headers).
MAX_HEAD: Final = 64 * 1024
#: Largest accepted request body; every allowed request has a small JSON body.
MAX_BODY: Final = 4 * 1024 * 1024
#: Largest response accepted from an ownership lookup on the real socket.
_MAX_LOOKUP: Final = 16 * 1024 * 1024
#: Time a client has to send its whole request, and a lookup has to complete.
_REQUEST_TIMEOUT_S: Final = 60.0
#: Concurrent client connections served before new ones are refused with ``503``.
DEFAULT_MAX_CONNECTIONS: Final = 32
_LOOKUP_TIMEOUT_S: Final = 30.0

_RUN_ID_RE = re.compile(RUN_ID_PATTERN)
_DECIMAL_RE = re.compile(r"[0-9]{1,12}")
_METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HOP_BY_HOP: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "transfer-encoding",
        "content-length",
        "expect",
        "te",
        "trailer",
        "upgrade",
        "host",
    }
)
_HIJACK_TYPES: Final = (
    "application/vnd.docker.raw-stream",
    "application/vnd.docker.multiplexed-stream",
)


# --------------------------------------------------------------------------- evidence


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class DecisionLog:
    """Appends one JSON record per decision; safe to call from several threads."""

    def __init__(self, run_id: str, path: Path) -> None:
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ValueError(f"malformed run id {run_id!r}")
        self._run_id = run_id
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._next_seq = self._resume()

    @property
    def path(self) -> Path:
        return self._path

    def _resume(self) -> int:
        """Next ``seq`` after the highest one stored; closes a torn last line."""
        if not self._path.is_file():
            return 0
        top = -1
        with self._path.open("rb") as fh:
            for line in fh:
                try:
                    seq = json.loads(line)["seq"]
                except (ValueError, KeyError, TypeError):
                    continue  # a torn line: its seq was never committed
                if isinstance(seq, int) and seq > top:
                    top = seq
            torn = fh.tell() > 0 and fh.seek(-1, os.SEEK_END) >= 0 and fh.read(1) != b"\n"
        if torn:
            _append(self._path, b"\n")
        return top + 1

    def record(
        self, request: DockerRequest, decision: Decision, ts: datetime | None = None
    ) -> dict[str, Any]:
        """Append and fsync the record of one decision; return it.

        A failed append raises and still consumes its ``seq``.
        """
        target = request.target
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            event = CellGuardDecision(
                run_id=self._run_id,
                stream=CELLGUARD_STREAM,
                seq=seq,
                ts=ts or datetime.now(UTC),
                allowed=decision.allowed,
                op=decision.op,
                rule=decision.rule,
                reason=decision.reason,
                method=request.method,
                path=request.path,
                forwarded_path=decision.path if decision.allowed else None,
                forced=list(decision.forced),
                target_kind=target.kind if target else None,
                target=target.id if target else None,
                target_run=target.labels.get(RUN_LABEL) if target else None,
                body_bytes=len(request.body),
                body_sha256=hashlib.sha256(request.body).hexdigest(),
            )
            _append(self._path, event.model_dump_json().encode() + b"\n")
        record: dict[str, Any] = event.model_dump(mode="json")
        return record


# --------------------------------------------------------------------------- config


def _positive_int(env: Mapping[str, str], name: str, default: int, base: int = 10) -> int:
    raw = env.get(name)
    if not raw:
        return default
    try:
        value = int(raw.strip(), base)
    except ValueError:
        raise ValueError(f"{name}: not an integer: {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{name}: must be positive, got {value}")
    return value


@dataclass(frozen=True, slots=True)
class CellGuardConfig:
    """One cell-guard instance: the cell it guards, its sockets and its evidence dir."""

    context: CellContext
    listen: Path
    upstream: str
    evidence_dir: Path
    socket_mode: int = 0o660
    max_connections: int = DEFAULT_MAX_CONNECTIONS

    @property
    def log_path(self) -> Path:
        return self.evidence_dir / DECISIONS_FILE

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> CellGuardConfig:
        for required in (
            "LAB_RUN_ID",
            "LAB_CELLGUARD_NETWORK",
            "LAB_CELLGUARD_IMAGES_LOCK",
            "LAB_CELLGUARD_DNS",
        ):
            if not env.get(required):
                raise ValueError(f"{required}: not set")
        if env.get("LAB_CELLGUARD_SCRATCH_DIR"):
            raise ValueError(
                "LAB_CELLGUARD_SCRATCH_DIR: host-path mounts were removed; "
                "use LAB_CELLGUARD_SCRATCH_VOLUME"
            )
        context = CellContext(
            run_id=env["LAB_RUN_ID"],
            network=env["LAB_CELLGUARD_NETWORK"],
            dns=env["LAB_CELLGUARD_DNS"].strip(),
            images=load_images_lock(Path(env["LAB_CELLGUARD_IMAGES_LOCK"])),
            scratch_volume=env.get("LAB_CELLGUARD_SCRATCH_VOLUME") or None,
            name_prefix=env.get("LAB_CELLGUARD_NAME_PREFIX") or None,
            memory_bytes=_positive_int(env, "LAB_CELLGUARD_MEMORY", DEFAULT_MEMORY_BYTES),
            nano_cpus=_positive_int(env, "LAB_CELLGUARD_NANO_CPUS", DEFAULT_NANO_CPUS),
            pids_limit=_positive_int(env, "LAB_CELLGUARD_PIDS", DEFAULT_PIDS_LIMIT),
        )
        upstream = env.get("LAB_CELLGUARD_UPSTREAM") or "/var/run/docker.sock"
        return cls(
            context=context,
            listen=Path(env.get("LAB_CELLGUARD_LISTEN") or "/run/cellguard/docker.sock"),
            upstream=upstream.removeprefix("unix://"),
            evidence_dir=Path(env.get("LAB_EVIDENCE_DIR") or DEFAULT_EVIDENCE_DIR),
            socket_mode=_positive_int(env, "LAB_CELLGUARD_SOCKET_MODE", 0o660, base=8),
            max_connections=_positive_int(
                env, "LAB_CELLGUARD_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS
            ),
        )


# --------------------------------------------------------------------------- HTTP helpers


class _BadRequest(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True, slots=True)
class _Head:
    method: str
    target: str
    headers: list[tuple[str, str]]

    def get(self, name: str) -> list[str]:
        return [v for n, v in self.headers if n.lower() == name]


def _parse_head(raw: bytes) -> _Head:
    lines = raw.decode("latin-1").removesuffix("\r\n\r\n").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _METHOD_RE.fullmatch(parts[0]) or not parts[1].startswith("/"):
        raise _BadRequest(400, "malformed request line")
    if parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise _BadRequest(400, "unsupported HTTP version")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not _TOKEN_RE.fullmatch(name):
            raise _BadRequest(400, "malformed header line")
        if "\n" in value or "\r" in value:
            raise _BadRequest(400, "malformed header value")
        headers.append((name, value.strip()))
    return _Head(parts[0], parts[1], headers)


def _status_of(head: bytes) -> int:
    parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
        raise ValueError("malformed response status line")
    return int(parts[1])


def _header(head: bytes, name: str) -> str | None:
    for line in head.decode("latin-1").split("\r\n")[1:]:
        key, colon, value = line.partition(":")
        if colon and key.strip().lower() == name:
            return value.strip()
    return None


async def _read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    body = bytearray()
    while True:
        size_line = await reader.readuntil(b"\r\n")
        size_text = size_line[:-2].split(b";", 1)[0].strip()
        if not size_text or not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_text):
            raise _BadRequest(400, "malformed chunk size")
        size = int(size_text, 16)
        if size == 0:
            while (await reader.readuntil(b"\r\n")) != b"\r\n":
                pass  # trailers are dropped
            return bytes(body)
        if len(body) + size > limit:
            raise _BadRequest(413, "request body too large")
        body += await reader.readexactly(size)
        if await reader.readexactly(2) != b"\r\n":
            raise _BadRequest(400, "malformed chunk")


async def _read_body(
    head: _Head, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> bytes:
    lengths = set(head.get("content-length"))
    encodings = head.get("transfer-encoding")
    if lengths and encodings:
        raise _BadRequest(400, "both Content-Length and Transfer-Encoding")
    if len(lengths) > 1:
        raise _BadRequest(400, "conflicting Content-Length")
    if encodings and [e.lower() for e in encodings] != ["chunked"]:
        raise _BadRequest(400, "unsupported Transfer-Encoding")
    length = 0
    if lengths:
        text = lengths.pop()
        if not _DECIMAL_RE.fullmatch(text):
            raise _BadRequest(400, "malformed Content-Length")
        length = int(text)
        if length > MAX_BODY:
            raise _BadRequest(413, "request body too large")
    if (encodings or length) and any(v.lower() == "100-continue" for v in head.get("expect")):
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()
    if encodings:
        return await _read_chunked(reader, MAX_BODY)
    return await reader.readexactly(length) if length else b""


def _response(status: int, reason: str, message: str) -> bytes:
    body = json.dumps({"message": f"cell-guard: {message}"}).encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


_REASONS: Final = {
    400: "Bad Request",
    413: "Content Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


@dataclass(slots=True)
class _State:
    """What is known about a connection's request, for the fail-closed error path."""

    method: str = ""
    path: str = ""
    op: str = "malformed"
    recorded: bool = False


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy ``reader`` to ``writer`` until EOF, then half-close ``writer``."""
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        with contextlib.suppress(OSError):
            writer.write_eof()


async def _copy_exact(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, n: int) -> None:
    while n > 0:
        data = await reader.read(min(n, 65536))
        if not data:
            return
        writer.write(data)
        await writer.drain()
        n -= len(data)


async def _read_to_eof(reader: asyncio.StreamReader, limit: int) -> bytes:
    data = bytearray()
    while chunk := await reader.read(65536):
        data += chunk
        if len(data) > limit:
            raise ValueError("response too large")
    return bytes(data)


def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()


# --------------------------------------------------------------------------- proxy


class CellGuard:
    """The proxy for one cell: decides, records, then forwards or denies each request."""

    def __init__(
        self,
        context: CellContext,
        upstream: str,
        log: DecisionLog,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        self._ctx = context
        self._upstream = upstream
        self._log = log
        self._max_connections = max_connections
        self._active = 0

    async def serve(self, path: Path, mode: int = 0o660) -> asyncio.Server:
        """Listen on Unix socket ``path`` (a stale socket there is replaced)."""
        if path.is_socket():
            path.unlink()
        elif path.exists() or path.is_symlink():
            raise FileExistsError(f"{path} exists and is not a socket")
        path.parent.mkdir(parents=True, exist_ok=True)
        server = await asyncio.start_unix_server(self.handle, path=str(path), limit=MAX_HEAD)
        os.chmod(path, stat.S_IMODE(mode))
        return server

    async def _record(self, request: DockerRequest, decision: Decision) -> bool:
        try:
            await asyncio.to_thread(self._log.record, request, decision)
        except OSError as exc:
            print(f"cell-guard: cannot record decision: {exc}", file=sys.stderr)
            return False
        return True

    async def _refuse(
        self, writer: asyncio.StreamWriter, decision: Decision, status: int, method: str = ""
    ) -> None:
        await self._record(DockerRequest(method, decision.path), decision)
        with contextlib.suppress(Exception):
            writer.write(_response(status, _REASONS[status], decision.reason))
            await writer.drain()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one client connection: one request, then close.

        Over :attr:`max_connections` concurrent connections, a connection is refused
        with a recorded ``503``. Any unexpected error before the request's decision is
        recorded is itself recorded as an ``http.500`` denial (fail closed).
        """
        if self._active >= self._max_connections:
            reason = f"more than {self._max_connections} concurrent connections"
            await self._refuse(
                writer, Decision(False, "connection", "http.503", reason, "", b""), 503
            )
            _close(writer)
            return
        self._active += 1
        state = _State()
        try:
            await self._handle(reader, writer, state)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        except Exception as exc:
            if state.recorded:
                print(f"cell-guard: error after the decision: {exc!r}", file=sys.stderr)
            else:
                reason = f"internal error: {type(exc).__name__}"
                decision = Decision(False, state.op, "http.500", reason, state.path, b"")
                await self._refuse(writer, decision, 500, state.method)
        finally:
            self._active -= 1
            _close(writer)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, state: _State
    ) -> None:
        head: _Head | None = None
        try:
            async with asyncio.timeout(_REQUEST_TIMEOUT_S):
                try:
                    raw = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError as exc:
                    if not exc.partial:
                        return  # the client connected and left
                    raise _BadRequest(400, "incomplete request head") from None
                except asyncio.LimitOverrunError:
                    raise _BadRequest(400, "request head too large") from None
                head = _parse_head(raw)
                state.method, state.path = head.method, head.target
                state.op = route(head.method, head.target).op
                body = await _read_body(head, reader, writer)
        except _BadRequest as bad:
            method, path = (head.method, head.target) if head else ("", "")
            op = route(method, path).op if head else "malformed"
            request = DockerRequest(method, path)
            decision = Decision(False, op, f"http.{bad.status}", bad.message, path, b"")
            state.recorded = await self._record(request, decision)
            writer.write(_response(bad.status, _REASONS.get(bad.status, "Error"), bad.message))
            await writer.drain()
            return

        request = DockerRequest(head.method, head.target, body)
        r = route(request.method, request.path)
        if r.target_kind is not None:
            request = replace(request, target=await self._resolve(r))
        decision = evaluate(request, self._ctx)
        state.recorded = await self._record(request, decision)
        if not state.recorded:
            writer.write(_response(500, _REASONS[500], "decision could not be recorded"))
            await writer.drain()
            return
        if not decision.allowed:
            message = f"denied {decision.op}: {decision.rule}: {decision.reason}"
            writer.write(_response(403, "Forbidden", message))
            await writer.drain()
            return
        await self._forward(head, decision, reader, writer)

    async def _forward(
        self,
        head: _Head,
        decision: Decision,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            up_reader, up_writer = await asyncio.open_unix_connection(
                self._upstream, limit=MAX_HEAD
            )
        except OSError as exc:
            writer.write(_response(502, "Bad Gateway", f"upstream unavailable: {exc}"))
            await writer.drain()
            return
        try:
            lines = [f"{head.method} {decision.path} HTTP/1.1", "Host: docker"]
            dropped = _HOP_BY_HOP | {"content-type"} if decision.body else _HOP_BY_HOP
            lines += [f"{n}: {v}" for n, v in head.headers if n.lower() not in dropped]
            if decision.body:
                # The body is the policy's own JSON, whatever the client declared.
                lines.append("Content-Type: application/json")
            if decision.body or head.method in ("POST", "PUT"):
                lines.append(f"Content-Length: {len(decision.body)}")
            upgrade = head.get("upgrade")
            if decision.upgrade and upgrade:
                lines += ["Connection: Upgrade", f"Upgrade: {upgrade[0]}"]
            else:
                lines.append("Connection: close")
            up_writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + decision.body)
            await up_writer.drain()
            if not decision.upgrade:
                await _pump(up_reader, writer)
                return
            response_head = await up_reader.readuntil(b"\r\n\r\n")
            writer.write(response_head)
            await writer.drain()
            status = _status_of(response_head)
            content_type = (_header(response_head, "content-type") or "").lower()
            if status == 101 or (status == 200 and content_type.startswith(_HIJACK_TYPES)):
                await self._splice(reader, writer, up_reader, up_writer)
                return
            length = _header(response_head, "content-length")
            if length is not None and _DECIMAL_RE.fullmatch(length):
                await _copy_exact(up_reader, writer, int(length))
            else:
                await _pump(up_reader, writer)
        finally:
            _close(up_writer)

    async def _splice(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
    ) -> None:
        """Relay a hijacked stream both ways until the daemon's side ends."""
        inbound = asyncio.create_task(_pump(reader, up_writer))
        try:
            await _pump(up_reader, writer)
        finally:
            inbound.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError, OSError):
                await inbound

    # ----------------------------------------------------------------- ownership lookups

    async def _get(self, path: str) -> Any:
        """``GET path`` on the real socket; the parsed JSON body, or ``None`` if not 200."""
        async with asyncio.timeout(_LOOKUP_TIMEOUT_S):
            up_reader, up_writer = await asyncio.open_unix_connection(
                self._upstream, limit=MAX_HEAD
            )
            try:
                up_writer.write(
                    f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode()
                )
                await up_writer.drain()
                response_head = await up_reader.readuntil(b"\r\n\r\n")
                if _status_of(response_head) != 200:
                    return None
                if (_header(response_head, "transfer-encoding") or "").lower() == "chunked":
                    try:
                        body = await _read_chunked(up_reader, _MAX_LOOKUP)
                    except _BadRequest:
                        return None
                else:
                    body = await _read_to_eof(up_reader, _MAX_LOOKUP)
                    length = _header(response_head, "content-length")
                    if length is not None and (
                        not _DECIMAL_RE.fullmatch(length) or int(length) != len(body)
                    ):
                        return None
            finally:
                _close(up_writer)
        try:
            return json.loads(body)
        except ValueError:
            return None

    async def _lookup(self, prefix: str, kind: str, ref: str) -> Target | None:
        if kind == "container":
            doc = await self._get(f"{prefix}/containers/{ref}/json")
            if not isinstance(doc, dict):
                return None
            config = doc.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            name = doc.get("Name")
            return _target(
                kind, doc.get("Id"), name.lstrip("/") if isinstance(name, str) else None, labels
            )
        if kind == "exec":
            doc = await self._get(f"{prefix}/exec/{ref}/json")
            if not isinstance(doc, dict) or not isinstance(doc.get("ContainerID"), str):
                return None
            if not re.fullmatch(r"[A-Za-z0-9]+", doc["ContainerID"]):
                return None
            container = await self._lookup(prefix, "container", doc["ContainerID"])
            if container is None:
                return None
            return _target(kind, doc.get("ID"), None, dict(container.labels))
        if kind == "network":
            doc = await self._get(f"{prefix}/networks/{ref}")
            if not isinstance(doc, dict):
                return None
            return _target(kind, doc.get("Id"), doc.get("Name"), doc.get("Labels"))
        if kind == "volume":
            doc = await self._get(f"{prefix}/volumes/{ref}")
            if not isinstance(doc, dict):
                return None
            return _target(kind, doc.get("Name"), doc.get("Name"), doc.get("Labels"))
        return None

    async def _resolve(self, r: Route) -> Target | None:
        """The object ``r`` names, as the daemon reports it; ``None`` if unknown."""
        if r.target_kind is None or r.ref is None:  # pragma: no cover
            return None
        prefix = f"/v{r.version}" if r.version else ""
        refs = [r.ref]
        if r.target_kind in ("container", "volume") and not r.ref.startswith(self._ctx.prefix):
            # Names the agent chose were given the cell prefix at create time.
            refs.insert(0, self._ctx.scoped(r.ref))
        try:
            for ref in refs:
                found = await self._lookup(prefix, r.target_kind, ref)
                if found is not None:
                    return found
            return None
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
            return None
        except asyncio.LimitOverrunError:
            return None


def _target(kind: str, ident: Any, name: Any, labels: Any) -> Target | None:
    if not isinstance(ident, str) or not ident:
        return None
    clean = (
        {k: v for k, v in labels.items() if isinstance(k, str) and isinstance(v, str)}
        if isinstance(labels, dict)
        else {}
    )
    return Target(kind, ident, name if isinstance(name, str) else None, clean)


# --------------------------------------------------------------------------- entry point


async def _serve_forever(config: CellGuardConfig) -> None:
    log = DecisionLog(config.context.run_id, config.log_path)
    guard = CellGuard(config.context, config.upstream, log, config.max_connections)
    server = await guard.serve(config.listen, config.socket_mode)
    print(
        f"cell-guard: run {config.context.run_id} on {config.listen} -> {config.upstream}",
        file=sys.stderr,
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    """Run cell-guard from the environment (``python -m cell.cellguard.proxy``)."""
    try:
        config = CellGuardConfig.from_env(os.environ)
    except ValueError as exc:
        print(f"cell-guard: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    asyncio.run(_serve_forever(config))


if __name__ == "__main__":
    main()
