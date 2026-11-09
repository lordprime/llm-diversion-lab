"""Shipping a torn-down cell's evidence to the Collector API.

* Events: every producer's JSONL file (:data:`SHIP_FILES`: the labeller's
  :data:`~control.labeler.funnel.EVENT_FILES` plus cell-guard's decisions) is re-shipped
  **byte for byte**: each stored line is embedded verbatim in an ``events:batch`` body,
  never rebuilt, so an honest re-ship is a duplicate, not a conflict. A line that is not
  JSON is a torn line left by a crash: it is skipped and listed. A line that is JSON but
  not a valid event of that file's producer and run makes the evidence unusable
  (:class:`EvidenceError`). Batches stay under ``MAX_EVENTS_PER_BATCH``.
* Artifacts: every regular file below the evidence directory, with its sha256 and
  size, in batches under ``MAX_ARTIFACTS_PER_BATCH``. A symlink, special file or a
  path the Collector would refuse is an :class:`EvidenceError`.
* :class:`CollectorClient`: every non-200 answer is terminal (:class:`CollectorError`,
  with the Collector's ``reason``): 409 means stored minus conflicts, 422 refused, 500
  body kept; never retried blindly. A Collector that cannot be reached (connection,
  timeout or protocol error) is a :class:`CollectorError` too, with status ``0``.

The manifest is posted before any event batch (a batch naming an unplanned placement is
refused whole).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import httpx
from pydantic import TypeAdapter, ValidationError

from control.core.models import (
    ARTIFACT_PATH_PATTERN,
    MAX_ARTIFACTS_PER_BATCH,
    MAX_EVENTS_PER_BATCH,
    ArtifactBatch,
    ArtifactFile,
    Event,
    EventKind,
    RunHeartbeat,
    RunManifest,
    Verdict,
)
from control.labeler.funnel import EVENT_FILES, EventSource

__all__ = [
    "SHIP_FILES",
    "CollectorClient",
    "CollectorError",
    "EvidenceError",
    "ShipReport",
    "read_event_lines",
    "scan_artifacts",
]

SHIP_FILES: Final = {
    **EVENT_FILES,
    "cellguard/decisions.jsonl": EventSource(
        "cellguard", frozenset({EventKind.CELLGUARD_DECISION})
    ),
}
_EVENT: TypeAdapter[Event] = TypeAdapter(Event)
_ARTIFACT_RE = re.compile(ARTIFACT_PATH_PATTERN)


class EvidenceError(ValueError):
    """The run's evidence cannot be shipped as is (invalid event, unsafe file)."""


class CollectorError(RuntimeError):
    """The Collector API did not store what was posted (terminal; the body is kept).

    ``status`` is the HTTP status, ``0`` if the Collector could not be reached;
    ``reason`` the rejection's ``reason`` (``unknown_placement``, ``conflict``...)
    when the body names one.
    """

    def __init__(self, what: str, status: int, body: str) -> None:
        self.status = status
        self.body = body
        self.reason = _reject_reason(body)
        where = f"HTTP {status}" if status else "unreachable"
        super().__init__(f"Collector {what}: {where}: {body[:500]}")


def _reject_reason(body: str) -> str | None:
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    reason = doc.get("reason") if isinstance(doc, dict) else None
    return reason if isinstance(reason, str) else None


@dataclass(slots=True)
class ShipReport:
    events: int = 0
    artifacts: int = 0
    skipped_lines: list[str] = field(default_factory=list)


def read_event_lines(evidence_dir: Path, run_id: str, skipped: list[str]) -> list[bytes]:
    """Every stored event line of the run, verbatim, checked against its producer."""
    lines: list[bytes] = []
    for rel, source in SHIP_FILES.items():
        path = evidence_dir / rel
        if not path.exists() and not path.is_symlink():
            continue
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise EvidenceError(f"{rel}: not a regular file")
        for lineno, raw in enumerate(path.read_bytes().split(b"\n"), start=1):
            if not raw.strip():
                continue
            try:
                json.loads(raw)
            except ValueError:
                skipped.append(f"{rel}:{lineno}")
                continue
            try:
                event = _EVENT.validate_json(raw)
            except ValidationError as exc:
                raise EvidenceError(f"{rel}:{lineno}: not a valid event: {exc}") from exc
            if (
                event.kind not in source.kinds
                or event.stream != source.stream
                or event.run_id != run_id
            ):
                raise EvidenceError(
                    f"{rel}:{lineno}: {event.kind.value} on {event.stream!r} for "
                    f"{event.run_id} does not belong in this file of run {run_id}"
                )
            lines.append(raw)
    return lines


def _walk(root: Path) -> Iterator[Path]:
    for entry in sorted(os.scandir(root), key=lambda e: e.name):
        mode = entry.stat(follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            yield from _walk(Path(entry.path))
        elif stat.S_ISREG(mode):
            yield Path(entry.path)
        else:
            raise EvidenceError(f"{entry.path}: not a regular file or directory")


def scan_artifacts(evidence_dir: Path) -> list[ArtifactFile]:
    """Every regular file of the evidence directory as an :class:`ArtifactFile`."""
    files: list[ArtifactFile] = []
    for path in _walk(evidence_dir):
        rel = path.relative_to(evidence_dir).as_posix()
        if not _ARTIFACT_RE.fullmatch(rel) or len(rel) > 512:
            raise EvidenceError(f"{rel}: not a valid artifact path")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as fh:
            while chunk := fh.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        files.append(ArtifactFile(path=rel, sha256=digest.hexdigest(), size_bytes=size))
    return files


class CollectorClient:
    """The runner's side of the Collector API (an :class:`httpx.Client` on its base URL)."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def _post(self, what: str, url: str, content: bytes) -> None:
        try:
            response = self._http.post(
                url, content=content, headers={"content-type": "application/json"}
            )
        except httpx.TransportError as exc:  # never posted, or no answer: not stored
            raise CollectorError(what, 0, f"{type(exc).__name__}: {exc}") from exc
        if response.status_code != 200:
            raise CollectorError(what, response.status_code, response.text)

    def post_manifest(self, manifest: RunManifest) -> None:
        self._post(
            "manifest",
            f"/v1/runs/{manifest.run_id}/manifest",
            manifest.model_dump_json().encode(),
        )

    def post_events(self, run_id: str, lines: Sequence[bytes]) -> int:
        """Post stored event lines verbatim, in batches; return how many were sent."""
        for start in range(0, len(lines), MAX_EVENTS_PER_BATCH):
            chunk = lines[start : start + MAX_EVENTS_PER_BATCH]
            body = (
                b'{"schema_version":1,"run_id":'
                + json.dumps(run_id).encode()
                + b',"events":['
                + b",".join(chunk)
                + b"]}"
            )
            self._post("events", f"/v1/runs/{run_id}/events:batch", body)
        return len(lines)

    def post_artifacts(self, run_id: str, files: Sequence[ArtifactFile]) -> int:
        for start in range(0, len(files), MAX_ARTIFACTS_PER_BATCH):
            batch = ArtifactBatch(
                run_id=run_id, artifacts=list(files[start : start + MAX_ARTIFACTS_PER_BATCH])
            )
            self._post(
                "artifacts", f"/v1/runs/{run_id}/artifacts", batch.model_dump_json().encode()
            )
        return len(files)

    def post_verdict(self, verdict: Verdict) -> None:
        self._post(
            "verdict", f"/v1/runs/{verdict.run_id}/verdict", verdict.model_dump_json().encode()
        )

    def post_status(self, heartbeat: RunHeartbeat) -> None:
        self._post(
            "status", f"/v1/runs/{heartbeat.run_id}/status", heartbeat.model_dump_json().encode()
        )
