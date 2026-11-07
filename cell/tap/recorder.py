"""LLM tap recorder: the evidence record for the funnel stage *Visible*.

Pure logic with no mitmproxy dependency; :mod:`cell.tap.addon` is a thin mitmproxy
shell around it. For every LLM call passing through the tap the recorder:

1. allocates the next ``seq`` of the ``tap`` stream for the run;
2. writes the request body to ``<evidence>/llm/NNNN.req.json`` *before* the call is
   forwarded, and decides ``tag_present`` by searching that body for any run tag
   (:func:`find_tags`, JSON-unescaped);
3. when the call ends, writes the response body verbatim (SSE streams included) to
   ``<evidence>/llm/NNNN.resp.body`` and appends one :class:`LlmCall` JSON line to
   ``<evidence>/llm/events.jsonl``.

Evidence files are write-once: they are created exclusively, and an existing file
makes the call fail loudly instead of being overwritten. The JSONL line is exactly
``LlmCall.model_dump_json()``; producers re-ship stored lines byte-for-byte and never
rebuild events, so an honest re-ship is a Collector duplicate, not a conflict.

``NNNN`` is ``seq`` zero-padded to four digits (``0000``, ``0001``... ``10000``).

Configuration comes from the environment (:meth:`TapConfig.from_env`):

* ``LAB_RUN_ID`` (required): the run this tap records for.
* ``LAB_TAGS`` (optional): the run's tags, comma- or space-separated; empty or unset
  for a control run, which never sets ``tag_present``.
* ``LAB_EVIDENCE_DIR`` (optional, default ``./evidence``): the run's evidence volume.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final

from pydantic import JsonValue

from control.core.ids import ID_PATTERN
from control.core.models import LlmCall, LlmRole
from control.core.tokens import TAG_PATTERN

__all__ = [
    "DEFAULT_EVIDENCE_DIR",
    "EVENTS_FILE",
    "LLM_DIR",
    "TAP_STREAM",
    "PendingCall",
    "Recorder",
    "TapConfig",
    "extract_requested_model",
    "extract_returned_model",
    "find_tags",
    "parse_tags",
]

#: Producer stream name of every event the tap emits.
TAP_STREAM: Final = "tap"
#: Default evidence directory when ``LAB_EVIDENCE_DIR`` is unset.
DEFAULT_EVIDENCE_DIR: Final = "evidence"
#: Directory (relative to the evidence dir) holding the tap's files.
LLM_DIR: Final = "llm"
#: The tap's JSONL events file, relative to the evidence dir.
EVENTS_FILE: Final = f"{LLM_DIR}/events.jsonl"

_REQ_SUFFIX: Final = ".req.json"
_RESP_SUFFIX: Final = ".resp.body"
_EVIDENCE_NAME = re.compile(r"^(\d{4,})\.(?:req\.json|resp\.body)$")
_TAG_RE = re.compile(TAG_PATTERN)
_ID_RE = re.compile(ID_PATTERN)


# --------------------------------------------------------------------------- pure functions


def _parse_json(body: bytes) -> JsonValue | None:
    """Parse ``body`` as JSON, or return ``None`` (not JSON, bad encoding, too deep)."""
    if not body:
        return None
    try:
        doc: JsonValue = json.loads(body)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        return None
    return doc


def _json_strings(doc: JsonValue) -> Iterator[str]:
    """Yield every string in a parsed JSON document: values and object keys."""
    stack: list[JsonValue] = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield key
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def find_tags(body: bytes, tags: list[str]) -> bool:
    """Return whether any of ``tags`` occurs in a request ``body``.

    Tags are matched exactly as given (case-sensitive). If ``body`` parses as JSON,
    every string in it (object keys included) is searched *after* JSON decoding, so a
    tag sent as ``\\u0061...`` escapes is still found. A body that is not JSON is
    searched as raw bytes.
    """
    wanted = [t for t in tags if t]
    if not wanted or not body:
        return False
    doc = _parse_json(body)
    if doc is None:
        return any(t.encode("utf-8") in body for t in wanted)
    return any(t in s for s in _json_strings(doc) for t in wanted)


def _model_field(doc: JsonValue | None) -> str | None:
    if isinstance(doc, dict):
        model = doc.get("model")
        if isinstance(model, str):
            return model
    return None


def extract_requested_model(body: bytes) -> str | None:
    """The ``model`` the agent asked for: the request JSON's top-level ``model``."""
    return _model_field(_parse_json(body))


def extract_returned_model(body: bytes) -> str | None:
    """The ``model`` the response reports, or ``None`` if it reports none.

    A JSON body's top-level ``model``; for an SSE stream, the first ``data:`` event
    that carries one (Anthropic ``message_start.message.model`` or an OpenAI-style
    chunk's top-level ``model``). Only reported, never compared here.
    """
    doc = _parse_json(body)
    if doc is not None:
        return _model_field(doc)
    for line in body.splitlines():
        if not line.startswith(b"data:"):
            continue
        event = _parse_json(line[5:].strip())
        model = _model_field(event)
        if model is None and isinstance(event, dict):
            model = _model_field(event.get("message"))
        if model is not None:
            return model
    return None


def parse_tags(value: str | None) -> tuple[str, ...]:
    """Parse ``LAB_TAGS`` (comma- or whitespace-separated); empty means no tags.

    Every tag must match the run-tag shape; duplicates are dropped, order is kept.
    """
    tags: list[str] = []
    for tag in re.split(r"[\s,]+", value or ""):
        if not tag:
            continue
        if not _TAG_RE.fullmatch(tag):
            raise ValueError(f"LAB_TAGS: malformed tag {tag!r} (expected {TAG_PATTERN})")
        if tag not in tags:
            tags.append(tag)
    return tuple(tags)


# --------------------------------------------------------------------------- config


@dataclass(frozen=True, slots=True)
class TapConfig:
    """What one tap instance records: one run, its tags, and where evidence goes."""

    run_id: str
    tags: tuple[str, ...]
    evidence_dir: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> TapConfig:
        """Build from ``LAB_RUN_ID``, ``LAB_TAGS`` and ``LAB_EVIDENCE_DIR``."""
        run_id = env.get("LAB_RUN_ID", "")
        if not _ID_RE.fullmatch(run_id):
            raise ValueError(f"LAB_RUN_ID: missing or malformed run id {run_id!r}")
        return cls(
            run_id=run_id,
            tags=parse_tags(env.get("LAB_TAGS")),
            evidence_dir=Path(env.get("LAB_EVIDENCE_DIR") or DEFAULT_EVIDENCE_DIR),
        )


# --------------------------------------------------------------------------- recorder


@dataclass(slots=True)
class PendingCall:
    """A call whose request is recorded and whose response is not yet."""

    seq: int
    ts: datetime
    tag_present: bool
    first_tag_seq: int | None
    requested_model: str | None
    request_sha256: str
    finished: bool = field(default=False)


def _write_once(path: Path, data: bytes) -> None:
    """Create ``path`` with ``data`` and fsync it; raise if it already exists."""
    with path.open("xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _artifact(seq: int, suffix: str) -> str:
    return f"{LLM_DIR}/{seq:04d}{suffix}"


class Recorder:
    """Records LLM calls for one run; safe to call from several threads.

    On construction it resumes from an existing evidence directory (a restarted tap):
    numbering continues after the highest ``NNNN`` file present, and ``first_tag_seq``
    is recomputed from the stored request files, so nothing is renumbered or
    overwritten.
    """

    def __init__(self, config: TapConfig) -> None:
        self._config = config
        self._tags = list(config.tags)
        self._root = config.evidence_dir
        self._llm_dir = self._root / LLM_DIR
        self._llm_dir.mkdir(parents=True, exist_ok=True)
        self._events = self._root / EVENTS_FILE
        self._lock = threading.Lock()
        self._next_seq, self._first_tag_seq = self._resume()

    @property
    def config(self) -> TapConfig:
        return self._config

    def _resume(self) -> tuple[int, int | None]:
        seqs: set[int] = set()
        for entry in self._llm_dir.iterdir():
            match = _EVIDENCE_NAME.fullmatch(entry.name)
            if match:
                seqs.add(int(match.group(1)))
        first_tag_seq: int | None = None
        for seq in sorted(seqs):
            req = self._root / _artifact(seq, _REQ_SUFFIX)
            if req.is_file() and find_tags(req.read_bytes(), self._tags):
                first_tag_seq = seq
                break
        return (max(seqs) + 1 if seqs else 0), first_tag_seq

    def begin(self, request_body: bytes, ts: datetime) -> PendingCall:
        """Record a request before it is forwarded; raise if it cannot be recorded.

        A failed write still consumes its ``seq`` (a visible gap), so one stray file
        cannot block every later call.
        """
        tag_present = find_tags(request_body, self._tags)
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            _write_once(self._root / _artifact(seq, _REQ_SUFFIX), request_body)
            if tag_present and self._first_tag_seq is None:
                self._first_tag_seq = seq
            first_tag_seq = self._first_tag_seq
        return PendingCall(
            seq=seq,
            ts=ts,
            tag_present=tag_present,
            first_tag_seq=first_tag_seq,
            requested_model=extract_requested_model(request_body),
            request_sha256=hashlib.sha256(request_body).hexdigest(),
        )

    def finish(self, pending: PendingCall, response_body: bytes | None) -> LlmCall:
        """Record the response (``None`` if the call failed) and emit the event line."""
        with self._lock:
            if pending.finished:
                raise RuntimeError(f"tap call {pending.seq} is already recorded")
            pending.finished = True
            response_artifact: str | None = None
            response_sha256: str | None = None
            returned_model: str | None = None
            if response_body is not None:
                response_artifact = _artifact(pending.seq, _RESP_SUFFIX)
                _write_once(self._root / response_artifact, response_body)
                response_sha256 = hashlib.sha256(response_body).hexdigest()
                returned_model = extract_returned_model(response_body)
            call = LlmCall(
                run_id=self._config.run_id,
                stream=TAP_STREAM,
                seq=pending.seq,
                ts=pending.ts,
                role=LlmRole.MAIN,
                requested_model=pending.requested_model,
                returned_model=returned_model,
                tag_present=pending.tag_present,
                first_tag_seq=pending.first_tag_seq,
                request_sha256=pending.request_sha256,
                response_sha256=response_sha256,
                request_artifact=_artifact(pending.seq, _REQ_SUFFIX),
                response_artifact=response_artifact,
            )
            line = call.model_dump_json().encode("utf-8") + b"\n"
            with self._events.open("ab") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        return call

    def record(self, request_body: bytes, response_body: bytes | None, ts: datetime) -> LlmCall:
        """Record one complete call: :meth:`begin` then :meth:`finish`."""
        return self.finish(self.begin(request_body, ts), response_body)
