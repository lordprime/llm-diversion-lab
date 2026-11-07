"""Callback catcher configuration and evidence log (shared by the HTTP and DNS catchers).

Configuration (:meth:`CatcherConfig.from_env`):

* ``LAB_MANIFEST`` (required): path of the run's :class:`RunManifest` JSON. Its
  placements' tokens are the only ones a callback can verify against; a control run
  has none, so its callbacks are recorded with ``token`` ``None``.
* ``LAB_HMAC_KEY`` (hex; required when the manifest has placements): the lab key the
  tokens were derived with. It is used once at startup to build a
  :class:`~cell.catcher.classify.TokenIndex` (which fails loudly if the key does not
  reproduce the manifest's tokens) and is then dropped: it is never stored, logged or
  echoed in an error.
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
"""

from __future__ import annotations

import json
import os
import re
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
    "CallbackLog",
    "CatcherConfig",
    "parse_lab_key",
    "parse_port",
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

_ID_RE = re.compile(ID_PATTERN)


# --------------------------------------------------------------------------- config


def parse_lab_key(value: str | None) -> bytes:
    """Decode ``LAB_HMAC_KEY`` (hex). Errors never include the value."""
    if not value or not value.strip():
        raise ValueError("LAB_HMAC_KEY: not set")
    try:
        key = bytes.fromhex(value.strip())
    except ValueError:
        raise ValueError("LAB_HMAC_KEY: not valid hex") from None
    if not key:
        raise ValueError("LAB_HMAC_KEY: empty")
    return key


def parse_port(value: str, name: str) -> int:
    """Parse one TCP/UDP port number from env var ``name``."""
    try:
        port = int(value.strip())
    except ValueError:
        raise ValueError(f"{name}: not a port number: {value!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}: port out of range: {port}")
    return port


@dataclass(frozen=True, slots=True)
class CatcherConfig:
    """One catcher instance: the run it records for, its verified tokens, evidence dir."""

    run_id: str
    tokens: TokenIndex
    evidence_dir: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> CatcherConfig:
        path = env.get("LAB_MANIFEST", "")
        if not path:
            raise ValueError("LAB_MANIFEST: not set")
        try:
            manifest = RunManifest.model_validate_json(Path(path).read_bytes())
        except OSError as exc:
            raise ValueError(f"LAB_MANIFEST: cannot read {path!r}: {exc}") from exc
        except ValidationError as exc:
            raise ValueError(f"LAB_MANIFEST: invalid manifest: {exc}") from exc
        run_id = env.get("LAB_RUN_ID")
        if run_id and run_id != manifest.run_id:
            raise ValueError(f"LAB_RUN_ID {run_id!r} differs from manifest {manifest.run_id!r}")
        if manifest.placements or env.get("LAB_HMAC_KEY"):
            tokens = TokenIndex.build(manifest, parse_lab_key(env.get("LAB_HMAC_KEY")))
        else:
            tokens = TokenIndex(run_id=manifest.run_id)
        return cls(
            run_id=manifest.run_id,
            tokens=tokens,
            evidence_dir=Path(env.get("LAB_EVIDENCE_DIR") or DEFAULT_EVIDENCE_DIR),
        )


# --------------------------------------------------------------------------- evidence


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
        if not self._path.is_file():
            return 0
        data = self._path.read_bytes()
        seqs: set[int] = set()
        for line in data.splitlines():
            try:
                seq = json.loads(line)["seq"]
            except (ValueError, KeyError, TypeError):
                continue  # a torn line: its seq was never committed
            if isinstance(seq, int) and seq >= 0:
                seqs.add(seq)
        if data and not data.endswith(b"\n"):
            _append(self._path, b"\n")
        return max(seqs) + 1 if seqs else 0

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
