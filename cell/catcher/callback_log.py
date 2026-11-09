"""Callback catcher configuration and evidence log (shared by the HTTP and DNS catchers).

Configuration (:meth:`CatcherConfig.from_env`):

* ``LAB_TOKENS`` (what the runner sets): path of a token-only JSON file,
  ``{"run_id": ..., "callback_domain": ..., "tokens": [{"token": ...,
  "placement_id": ...}, ...]}`` (``control.runner.render.render_catcher_file``). These
  tokens are the only ones a callback can verify against; a control run has none, so
  its callbacks are recorded with ``token`` ``None``. The catcher never sees the
  manifest's tag, payload texts or anything else.
* ``LAB_MANIFEST`` (alternative, exclusive with ``LAB_TOKENS``; tests and tools): path
  of the run's :class:`RunManifest` JSON, from which only the tokens are taken.
* No key. Tokens are verified against the manifest's own placement tokens
  (:class:`~cell.catcher.classify.TokenIndex`); the lab-wide HMAC key never enters a
  run cell. The catcher refuses to start if a placement token is malformed or repeated.
* ``LAB_EVIDENCE_DIR`` (optional, default ``./evidence``): the run's evidence volume.
* ``LAB_RUN_ID`` (optional): if set, must equal the manifest's ``run_id``.

Evidence (:class:`CallbackLog`): one JSONL file per producer stream.

* ``<evidence>/catcher/http/events.jsonl``: stream ``catcher-http``;
* ``<evidence>/catcher/dns/events.jsonl``: stream ``catcher-dns``.

Each line is exactly ``Callback.model_dump_json()``; producers re-ship stored lines
byte-for-byte and never rebuild events. ``seq`` is numbered per stream from 0 and
resumes after a restart; a torn last line left by a crash is closed with a newline and
its ``seq`` is never reused (shippers skip lines that do not parse). Each line is
appended and fsynced before the contact is answered; a failed write raises (and still
consumes its ``seq``). One process per stream: two writers on one file would reuse
``seq`` values.

A catcher that cannot store an event first prints one line starting with
:data:`RECORD_FAILURE_PREFIX` (``catcher: cannot record ...``) to stderr
(:func:`report_record_failure`). The runner scans the catcher's log for
``catcher: cannot`` after the run and marks the run ``RECORDING_FAILED``, so a lost
callback never leaves a run ``VALID`` with Uptake false.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from cell.catcher.classify import TokenIndex
from control.core.ids import ID_PATTERN
from control.core.models import Callback, RunManifest

__all__ = [
    "CATCHER_DIR",
    "CATCHER_DNS_STREAM",
    "CATCHER_HTTP_STREAM",
    "DEFAULT_EVIDENCE_DIR",
    "DNS_EVENTS_FILE",
    "HTTP_EVENTS_FILE",
    "RECORD_FAILURE_PREFIX",
    "CallbackLog",
    "CatcherConfig",
    "parse_port",
    "report_record_failure",
]

#: Producer stream of the HTTP catcher.
CATCHER_HTTP_STREAM: Final = "catcher-http"
#: Producer stream of the DNS catcher (never shared with HTTP: the key is per stream).
CATCHER_DNS_STREAM: Final = "catcher-dns"
DEFAULT_EVIDENCE_DIR: Final = "evidence"
#: Directory (relative to the evidence dir) holding the catcher's files.
CATCHER_DIR: Final = "catcher"
HTTP_EVENTS_FILE: Final = f"{CATCHER_DIR}/http/events.jsonl"
DNS_EVENTS_FILE: Final = f"{CATCHER_DIR}/dns/events.jsonl"

#: Start of the stderr line a catcher prints when an event cannot be stored; the runner's
#: recording-failure scan matches ``catcher: cannot``.
RECORD_FAILURE_PREFIX: Final = "catcher: cannot record"
#: Most characters of the exception text kept on that line.
_FAILURE_DETAIL_CHARS: Final = 300

_ID_RE = re.compile(ID_PATTERN)
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_TOKENS_KEYS: Final = frozenset({"run_id", "callback_domain", "tokens"})


# --------------------------------------------------------------------------- config


def parse_port(value: str, name: str) -> int:
    """Parse one TCP/UDP port number from env var ``name``."""
    try:
        port = int(value.strip())
    except ValueError:
        raise ValueError(f"{name}: not a port number: {value!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}: port out of range: {port}")
    return port


def _read_tokens_file(path: str) -> tuple[TokenIndex, str]:
    """Parse a ``LAB_TOKENS`` file (see the module docstring for its exact shape)."""
    try:
        doc = json.loads(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"LAB_TOKENS: cannot read {path!r}: {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"LAB_TOKENS: not JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != _TOKENS_KEYS:
        keys = sorted(doc) if isinstance(doc, dict) else type(doc).__name__
        raise ValueError(f"LAB_TOKENS: unexpected document {keys}; expected {sorted(_TOKENS_KEYS)}")
    run_id, domain, entries = doc["run_id"], doc["callback_domain"], doc["tokens"]
    if not isinstance(run_id, str) or not _ID_RE.fullmatch(run_id):
        raise ValueError(f"LAB_TOKENS: malformed run_id {run_id!r}")
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"LAB_TOKENS: malformed callback_domain {domain!r}")
    if not isinstance(entries, list):
        raise ValueError("LAB_TOKENS: tokens must be a list")
    pairs: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"token", "placement_id"}:
            raise ValueError(f"LAB_TOKENS: unexpected token entry {entry!r}")
        pairs.append((entry["token"], entry["placement_id"]))
    try:
        return TokenIndex.from_pairs(run_id, pairs), domain
    except ValueError as exc:
        raise ValueError(f"LAB_TOKENS: {exc}") from exc


def _read_manifest(path: str) -> TokenIndex:
    try:
        manifest = RunManifest.model_validate_json(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"LAB_MANIFEST: cannot read {path!r}: {exc}") from exc
    except ValidationError as exc:
        raise ValueError(f"LAB_MANIFEST: invalid manifest: {exc}") from exc
    return TokenIndex.build(manifest)


@dataclass(frozen=True, slots=True)
class CatcherConfig:
    """One catcher instance: the run it records for, its verified tokens, evidence dir.

    ``callback_domain`` is the DNS zone the run's payloads name (``LAB_TOKENS`` only).
    The catcher answers every name, so it is recorded for the run, never used to filter.
    """

    run_id: str
    tokens: TokenIndex
    evidence_dir: Path
    callback_domain: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> CatcherConfig:
        tokens_path, manifest_path = env.get("LAB_TOKENS", ""), env.get("LAB_MANIFEST", "")
        if tokens_path and manifest_path:
            raise ValueError(
                "LAB_TOKENS and LAB_MANIFEST are exclusive; the runner sets LAB_TOKENS"
            )
        domain: str | None = None
        if tokens_path:
            tokens, domain = _read_tokens_file(tokens_path)
        elif manifest_path:
            tokens = _read_manifest(manifest_path)
        else:
            raise ValueError("LAB_TOKENS: not set (nor LAB_MANIFEST)")
        run_id = env.get("LAB_RUN_ID")
        if run_id and run_id != tokens.run_id:
            raise ValueError(f"LAB_RUN_ID {run_id!r} differs from the tokens' {tokens.run_id!r}")
        return cls(
            run_id=tokens.run_id,
            tokens=tokens,
            evidence_dir=Path(env.get("LAB_EVIDENCE_DIR") or DEFAULT_EVIDENCE_DIR),
            callback_domain=domain,
        )


# --------------------------------------------------------------------------- evidence


def report_record_failure(what: str, exc: BaseException) -> None:
    """Print the one-line recording-failure marker for ``what`` to stderr (flushed)."""
    detail = " ".join(str(exc).split())[:_FAILURE_DETAIL_CHARS]
    print(
        f"{RECORD_FAILURE_PREFIX} {what}: {type(exc).__name__}: {detail}",
        file=sys.stderr,
        flush=True,
    )


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class CallbackLog:
    """Appends one stream's :class:`Callback` events; safe to call from several threads."""

    def __init__(self, run_id: str, stream: str, path: Path) -> None:
        if not _ID_RE.fullmatch(run_id):
            raise ValueError(f"malformed run id {run_id!r}")
        self._run_id = run_id
        self._stream = stream
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._next_seq = self._resume()

    @property
    def path(self) -> Path:
        return self._path

    def _resume(self) -> int:
        """Next ``seq`` after the highest one stored; streams the file line by line."""
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

    def record(self, build: Callable[[int], Callback]) -> Callback:
        """Build the next event with ``build(seq)``, append it, fsync it, return it.

        The event must belong to this log's run and stream and carry the given
        ``seq``. A failed append raises and still consumes the ``seq``.
        """
        with self._lock:
            seq = self._next_seq
            callback = build(seq)
            if callback.run_id != self._run_id or callback.seq != seq:
                raise ValueError(f"callback {callback.stream}#{callback.seq} is not this log's")
            if callback.stream != self._stream:
                raise ValueError(f"callback stream {callback.stream!r} is not {self._stream!r}")
            self._next_seq += 1
            _append(self._path, callback.model_dump_json().encode("utf-8") + b"\n")
        return callback
