"""Surface injector evidence: configuration and the serve log (no mitmproxy dependency).

:mod:`cell.injector.addon` is the mitmproxy shell; this module holds what it reads at
startup (:class:`InjectorConfig`) and what it writes (:class:`ServeLog`). Classes live
here, not in the addon script, because ``mitmdump -s`` loads the script as a module
outside ``sys.modules``, where dataclasses cannot be defined.

Configuration (:meth:`InjectorConfig.from_env`):

* ``LAB_MANIFEST`` (required): path of the run's :class:`RunManifest` JSON. It decides
  the arm and every placement.
* ``LAB_PAYLOADS`` (required for an injected run, optional for a control run): path of
  a JSON object mapping each ``placement_id`` to its rendered text. Each text must hash
  (UTF-8, sha256) to the placement's ``content_sha256`` and contain the run's tag; a
  control run must have none (checked by :func:`~cell.injector.placement.build_plan`).
* ``LAB_PROBE_SECRET`` (optional): the per-run probe secret. A request is a pre-flight
  probe only if its single ``x-lab-probe`` header equals it. It is never written to
  evidence and is hidden from ``repr``.
* ``LAB_EVIDENCE_DIR`` (optional, default ``./evidence``): the run's evidence volume.
* ``LAB_RUN_ID`` (optional): if set, must equal the manifest's ``run_id``.
* ``LAB_SYNTHESIZE_ROBOTS`` (optional, ``0`` or ``1``, default ``0``): ``1`` in every run
  of an experiment that plants P1, in both arms, so a control run serves the same
  synthesized robots.txt base as a treated run when the app has none.

Evidence (:class:`ServeLog`):

* ``<evidence>/injector/events.jsonl``: per request one :class:`TargetAccessEvent`,
  followed, if the request was one the injector plants on (``GET`` robots.txt or a P7
  path in an injected run), by one :class:`PlacementServe` per placement, whether or
  not the plant succeeded (``insert_ok``). Both kinds share the ``injector`` stream
  and one ``seq`` counter, which resumes after a restart. Each line is exactly
  ``model_dump_json()`` of its event; producers re-ship stored lines byte-for-byte.
  A flow's lines are appended in one write and fsynced. A torn last line left by a
  crash is closed with a newline so new lines never join it, and its ``seq`` is never
  reused; shippers must skip lines that do not parse.
* ``<evidence>/injector/NNNN.body``: the exact wire bytes served for each such
  request, and ``NNNN.meta.json`` beside it: the action, the app's status, the served
  status, the expected status (P7), whether the robots.txt base was synthesized because
  the app had none, the served Content-Encoding, a note on why nothing was planted, and
  each placement's offset and ``insert_ok``. Both are write-once (``NNNN`` = the access
  event's ``seq``, zero-padded to four digits).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final

from pydantic import JsonValue, ValidationError

from cell.injector.placement import INJECTOR_STREAM, Planted
from control.core.models import Arm, PlacementServe, RunManifest, TargetAccessEvent

__all__ = [
    "DEFAULT_EVIDENCE_DIR",
    "EVENTS_FILE",
    "INJECTOR_DIR",
    "AccessRecord",
    "InjectorConfig",
    "ServeLog",
    "ServedBody",
]

DEFAULT_EVIDENCE_DIR: Final = "evidence"
#: Directory (relative to the evidence dir) holding the injector's files.
INJECTOR_DIR: Final = "injector"
#: The injector's JSONL events file, relative to the evidence dir.
EVENTS_FILE: Final = f"{INJECTOR_DIR}/events.jsonl"

_EVIDENCE_NAME = re.compile(r"^(\d{4,})\.(?:body|meta\.json)$")


# --------------------------------------------------------------------------- config


def _read(env: Mapping[str, str], name: str) -> bytes:
    path = env.get(name, "")
    if not path:
        raise ValueError(f"{name}: not set")
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ValueError(f"{name}: cannot read {path!r}: {exc}") from exc


def _load_contents(raw: bytes) -> dict[str, str]:
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"LAB_PAYLOADS: not JSON: {exc}") from exc
    if not isinstance(doc, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in doc.items()
    ):
        raise ValueError("LAB_PAYLOADS: expected an object of placement_id -> text")
    return dict(doc)


@dataclass(frozen=True, slots=True)
class InjectorConfig:
    """One injector instance: the run's manifest, its rendered texts, where evidence goes."""

    manifest: RunManifest
    contents: Mapping[str, str]
    probe_secret: str = field(repr=False)
    evidence_dir: Path
    #: Serve :data:`~cell.injector.placement.DEFAULT_ROBOTS_BASE` for an app 404 on
    #: ``/robots.txt`` even without a P1 placement (arm parity; ``LAB_SYNTHESIZE_ROBOTS``).
    synthesize_robots: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> InjectorConfig:
        try:
            manifest = RunManifest.model_validate_json(_read(env, "LAB_MANIFEST"))
        except ValidationError as exc:
            raise ValueError(f"LAB_MANIFEST: invalid manifest: {exc}") from exc
        run_id = env.get("LAB_RUN_ID")
        if run_id and run_id != manifest.run_id:
            raise ValueError(f"LAB_RUN_ID {run_id!r} differs from manifest {manifest.run_id!r}")
        contents: dict[str, str] = {}
        if env.get("LAB_PAYLOADS") or manifest.arm is Arm.INJECTED:
            contents = _load_contents(_read(env, "LAB_PAYLOADS"))
        synthesize = env.get("LAB_SYNTHESIZE_ROBOTS", "")
        if synthesize not in ("", "0", "1"):
            raise ValueError(f"LAB_SYNTHESIZE_ROBOTS: expected 0 or 1, got {synthesize!r}")
        return cls(
            manifest=manifest,
            contents=contents,
            probe_secret=env.get("LAB_PROBE_SECRET", ""),
            evidence_dir=Path(env.get("LAB_EVIDENCE_DIR") or DEFAULT_EVIDENCE_DIR),
            synthesize_robots=synthesize == "1",
        )


# --------------------------------------------------------------------------- evidence


@dataclass(frozen=True, slots=True)
class AccessRecord:
    """What the injector saw of one request and the status the client got."""

    flow_id: str
    method: str
    url: str
    ts: datetime
    probe: bool
    status: int | None
    source_ip: str | None = None


@dataclass(frozen=True, slots=True)
class ServedBody:
    """The response to a request the injector plants on, as sent on the wire."""

    wire: bytes
    decoded: bytes
    status: int
    ts: datetime
    plants: tuple[Planted, ...]
    #: Extra facts for ``NNNN.meta.json`` (action, app/expected status, ...).
    meta: Mapping[str, JsonValue] = field(default_factory=dict)

    def meta_json(self, seq: int) -> bytes:
        doc: dict[str, JsonValue] = {
            **self.meta,
            "seq": seq,
            "served_status": self.status,
            "placements": [
                {
                    "placement_id": p.plant.placement.placement_id,
                    "byte_offset": p.offset if p.insert_ok else None,
                    "insert_ok": p.insert_ok,
                }
                for p in self.plants
            ],
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _write_once(path: Path, data: bytes) -> None:
    """Create ``path`` with ``data`` and fsync it; raise if it already exists."""
    with path.open("xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class ServeLog:
    """The injector's evidence for one run; safe to call from several threads.

    On construction it resumes from an existing evidence directory: numbering
    continues after the highest ``seq`` in the events file or ``NNNN.*`` name, and
    a torn last line is closed with a newline so new lines never join it.
    """

    def __init__(self, run_id: str, evidence_dir: Path) -> None:
        self._run_id = run_id
        self._dir = evidence_dir / INJECTOR_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._events = evidence_dir / EVENTS_FILE
        self._lock = threading.Lock()
        self._next_seq = self._resume()

    def _resume(self) -> int:
        seqs: set[int] = set()
        for entry in self._dir.iterdir():
            match = _EVIDENCE_NAME.fullmatch(entry.name)
            if match:
                seqs.add(int(match.group(1)))
        if self._events.is_file():
            data = self._events.read_bytes()
            for line in data.splitlines():
                try:
                    seq = json.loads(line)["seq"]
                except (ValueError, KeyError, TypeError):
                    continue  # a torn line: its seq was never committed
                if isinstance(seq, int) and seq >= 0:
                    seqs.add(seq)
            if data and not data.endswith(b"\n"):
                _append(self._events, b"\n")
        return max(seqs) + 1 if seqs else 0

    def record(
        self, access: AccessRecord, served: ServedBody | None = None
    ) -> list[TargetAccessEvent | PlacementServe]:
        """Log one request (and what was planted, if anything); return the events written.

        If the served body or its meta cannot be stored, the request is logged as answered ``502``
        with no serve events, and the storage error is raised afterwards so the caller
        withholds the planted response. A failed write still consumes its ``seq``s.
        """
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1 + (len(served.plants) if served else 0)
            failure: OSError | None = None
            status = access.status
            if served is not None:
                try:
                    _write_once(self._dir / f"{seq:04d}.body", served.wire)
                    _write_once(self._dir / f"{seq:04d}.meta.json", served.meta_json(seq))
                except OSError as exc:
                    failure, served, status = exc, None, 502
            events: list[TargetAccessEvent | PlacementServe] = [
                TargetAccessEvent(
                    run_id=self._run_id,
                    stream=INJECTOR_STREAM,
                    seq=seq,
                    ts=access.ts,
                    flow_id=access.flow_id,
                    method=access.method,
                    url=access.url,
                    status=status,
                    probe=access.probe,
                    source_ip=access.source_ip,
                )
            ]
            if served is not None:
                decoded_sha256 = hashlib.sha256(served.decoded).hexdigest()
                wire_sha256 = hashlib.sha256(served.wire).hexdigest()
                for i, planted in enumerate(served.plants, start=1):
                    events.append(
                        PlacementServe(
                            run_id=self._run_id,
                            stream=INJECTOR_STREAM,
                            seq=seq + i,
                            ts=served.ts,
                            placement_id=planted.plant.placement.placement_id,
                            surface=planted.plant.placement.surface,
                            flow_id=access.flow_id,
                            url=access.url,
                            status=served.status,
                            decoded_sha256=decoded_sha256,
                            wire_sha256=wire_sha256,
                            byte_offset=planted.offset if planted.insert_ok else None,
                            insert_ok=planted.insert_ok,
                            probe=access.probe,
                        )
                    )
            _append(self._events, b"".join(e.model_dump_json().encode() + b"\n" for e in events))
        if failure is not None:
            raise failure
        return events
