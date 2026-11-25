"""Run telemetry from the LLM tap's evidence: load, summarise, write derived files.

This is a derived layer, like the funnel labeller. It only reads the evidence and can
be rerun at any time; its output goes to a separate folder and never into the evidence.

* :func:`load_calls` is the only part that reads files. It reads the tap's
  ``llm/NNNN.req.json``, ``NNNN.resp.body`` and ``NNNN.meta.json`` (see
  :mod:`cell.tap.recorder`). The evidence is written by the run cell, so it is treated
  as untrusted: symlinks are never followed, only regular files are read, and no file
  over :data:`MAX_BODY_BYTES` is read. A body the tap stored raw (meta ``decoded``
  false) is decoded here with the recorded ``content_encoding``, bounded the same way.
  A problem with one call becomes that call's ``parse_error``; it never hides the rest.
* :func:`summarise` is pure: the same calls always give the same :class:`RunTelemetry`.
* :func:`write_derived` writes ``telemetry/summary.json``, ``telemetry/calls.jsonl``
  (one row per call, without the reasoning text or history hashes) and
  ``telemetry/reasoning.jsonl`` (the readable thought-process trace) under an output
  folder, as ASCII-only JSON (see
  :func:`_json_bytes`). Rows of both JSONL files carry ``agent``, the thread the call
  was linked to (:class:`ThreadLinker`; ``null`` for an unreadable request), next to the
  call's own ``thread_key``. Each file is replaced atomically. It refuses to write inside a
  run's evidence directory or through a symlink, so raw evidence can never be
  overwritten.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import JsonValue

from control.core.codecs import DecodedTooLargeError, decode_body_bounded
from control.core.tags import parse_json
from control.telemetry.model import TELEMETRY_VERSION, CallTelemetry, RunTelemetry, ThreadLinks
from control.telemetry.wire import MAX_BODY_BYTES, MessageDigests, parse_call, unparsed_call

__all__ = [
    "CALLS_FILE",
    "LLM_DIR",
    "MAX_BODY_BYTES",
    "REASONING_FILE",
    "SUMMARY_FILE",
    "TELEMETRY_DIR",
    "TELEMETRY_VERSION",
    "DerivedWriter",
    "TapEvidence",
    "TelemetryError",
    "load_calls",
    "summarise",
    "write_derived",
]

#: The tap's folder inside an evidence directory (``cell.tap.recorder.LLM_DIR``).
LLM_DIR: Final = "llm"
#: The tap's events file inside :data:`LLM_DIR`; its presence marks an evidence directory.
_TAP_EVENTS: Final = "events.jsonl"
_TAP_FILE = re.compile(r"^(\d{4,})\.(?:req\.json|resp\.body|meta\.json)$")
_REQ_SUFFIX: Final = ".req.json"
_RESP_SUFFIX: Final = ".resp.body"
_META_SUFFIX: Final = ".meta.json"

#: Folder (under the output folder) and file names :func:`write_derived` writes.
TELEMETRY_DIR: Final = "telemetry"
SUMMARY_FILE: Final = "summary.json"
CALLS_FILE: Final = "calls.jsonl"
REASONING_FILE: Final = "reasoning.jsonl"


class TelemetryError(ValueError):
    """The evidence cannot be read safely, or the output cannot be written safely."""


class _Unreadable(Exception):
    """One evidence file could not be read; the message says why."""


# --------------------------------------------------------------------------- tap meta


@dataclass(frozen=True, slots=True)
class _BodyMeta:
    """What the tap recorded about one stored body."""

    content_type: str | None = None
    content_encoding: str | None = None
    #: ``False`` when the tap stored the raw wire bytes because it could not decode them.
    decoded: bool = True

    @classmethod
    def from_json(cls, doc: JsonValue | None, label: str) -> _BodyMeta:
        if doc is None:
            return cls()
        if not isinstance(doc, dict):
            raise ValueError(f"{label} is not an object")
        content_type, encoding = doc.get("content_type"), doc.get("content_encoding")
        decoded = doc.get("decoded", True)
        if content_type is not None and not isinstance(content_type, str):
            raise ValueError(f"{label} content_type is not a string")
        if encoding is not None and not isinstance(encoding, str):
            raise ValueError(f"{label} content_encoding is not a string")
        if not isinstance(decoded, bool):
            raise ValueError(f"{label} decoded is not a boolean")
        return cls(content_type, encoding, decoded)


@dataclass(frozen=True, slots=True)
class _CallMeta:
    """The parts of ``NNNN.meta.json`` telemetry needs."""

    path: str | None
    request: _BodyMeta
    response: _BodyMeta

    @classmethod
    def from_json(cls, doc: JsonValue | None, seq: int) -> _CallMeta:
        """Parse a meta document; raise ``ValueError`` saying what is wrong with it."""
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
        if doc.get("seq") != seq:
            raise ValueError(f"its seq {doc.get('seq')!r} does not match the file name")
        request = doc.get("request")
        path: str | None = None
        if request is not None:
            if not isinstance(request, dict):
                raise ValueError("request is not an object")
            raw_path = request.get("path")
            if not isinstance(raw_path, str):
                raise ValueError("request path is missing")
            path = raw_path
        return cls(
            path=path,
            request=_BodyMeta.from_json(request, "request"),
            response=_BodyMeta.from_json(doc.get("response"), "response"),
        )


# --------------------------------------------------------------------------- reading


class TapEvidence:
    """The tap's files in one evidence directory, read without following symlinks."""

    def __init__(self, evidence_dir: Path) -> None:
        self._dir = evidence_dir / LLM_DIR

    def calls(self) -> list[CallTelemetry]:
        """Every call the tap recorded, in ``seq`` order.

        The message-digest cache lives for this one load only and is dropped with it.
        """
        digests = MessageDigests()
        return [self._call(seq, digests) for seq in self.seqs()]

    def seqs(self) -> list[int]:
        """The ``seq`` of every tap file present (any of the three kinds)."""
        try:
            info = os.lstat(self._dir)
        except FileNotFoundError:
            return []
        if stat.S_ISLNK(info.st_mode):
            raise TelemetryError(f"{self._dir}: symlinks are not followed in evidence")
        if not stat.S_ISDIR(info.st_mode):
            raise TelemetryError(f"{self._dir}: not a directory")
        found = (_TAP_FILE.fullmatch(name) for name in os.listdir(self._dir))
        return sorted({int(match.group(1)) for match in found if match})

    def _read(self, seq: int, suffix: str) -> bytes | None:
        """One tap file's bytes, ``None`` if absent; :class:`_Unreadable` if unsafe."""
        name = f"{seq:04d}{suffix}"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self._dir / name, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:  # ELOOP for a symlink, EACCES...
            raise _Unreadable(f"{name} cannot be opened ({exc.strerror})") from exc
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise _Unreadable(f"{name} is not a regular file")
            data = fh.read(MAX_BODY_BYTES + 1)
        if len(data) > MAX_BODY_BYTES:
            raise _Unreadable(f"{name} exceeds {MAX_BODY_BYTES} bytes")
        return data

    def _read_body(self, seq: int, suffix: str) -> tuple[bytes | None, str | None]:
        """A body and, if it could not be read, why (a plain absence needs no reason)."""
        try:
            return self._read(seq, suffix), None
        except _Unreadable as exc:
            return None, str(exc)

    @staticmethod
    def _decode(body: bytes, meta: _BodyMeta, label: str) -> tuple[bytes | None, str | None]:
        """Remove the content encoding from a body the tap stored raw."""
        if meta.decoded:
            return body, None
        try:
            decoded = decode_body_bounded(body, meta.content_encoding, max_size=MAX_BODY_BYTES)
        except DecodedTooLargeError:
            return None, f"stored {label} exceeds {MAX_BODY_BYTES} bytes once decoded"
        if decoded is None:
            return None, (
                f"cannot decode the stored {label} (content-encoding {meta.content_encoding!r})"
            )
        return decoded, None

    def _call(self, seq: int, digests: MessageDigests) -> CallTelemetry:
        request, request_problem = self._read_body(seq, _REQ_SUFFIX)
        response, response_problem = self._read_body(seq, _RESP_SUFFIX)
        try:
            raw_meta = self._read(seq, _META_SUFFIX)
        except _Unreadable as exc:
            return unparsed_call(seq, request, f"tap meta unreadable: {exc}")
        if raw_meta is None:
            return unparsed_call(seq, request, "tap meta missing")
        try:
            meta = _CallMeta.from_json(parse_json(raw_meta), seq)
        except ValueError as exc:
            return unparsed_call(seq, request, f"tap meta unreadable: {exc}")

        if request is not None:
            request, request_problem = self._decode(request, meta.request, "request")
        if response is not None:
            response, response_problem = self._decode(response, meta.response, "response")
        return parse_call(
            meta.path,
            request,
            response,
            meta.response.content_type,
            seq=seq,
            request_problem=request_problem,
            response_problem=response_problem,
            digests=digests,
        )


def load_calls(evidence_dir: Path) -> list[CallTelemetry]:
    """Read every LLM call the tap recorded under ``evidence_dir``, in ``seq`` order.

    No ``llm/`` folder means no calls. Raises :class:`TelemetryError` only when the
    ``llm/`` folder itself is a symlink or not a folder.
    """
    return TapEvidence(evidence_dir).calls()


def summarise(
    run_id: str,
    calls: Sequence[CallTelemetry],
    agent_ids: Mapping[int, str] | None = None,
) -> RunTelemetry:
    """Add up one run's calls (pure; see :meth:`RunTelemetry.from_calls`).

    ``agent_ids`` (call ``seq`` to agent id, from a framework adapter that knows which
    agent made each call) replaces the inferred agents; it must name every call.
    """
    return RunTelemetry.from_calls(run_id, calls, agent_ids)


# --------------------------------------------------------------------------- writing


def _json_bytes(doc: object, *, indent: int | None = None) -> bytes:
    """One JSON document as pure ASCII bytes, ending in a newline.

    The policy for every derived file: ``ensure_ascii`` writes each non-ASCII character
    as a ``\\uXXXX`` escape, so the bytes never depend on an encoding or locale, and
    text that is not valid UTF-8 (a lone surrogate, which JSON allows and a model can
    emit) is kept exactly and reads back as the same string. Documents come from
    pydantic's python-mode dump, because its JSON mode replaces such characters.
    """
    separators = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(doc, sort_keys=True, ensure_ascii=True, indent=indent, separators=separators)
    return text.encode("ascii") + b"\n"


class DerivedWriter:
    """Writes a run's telemetry files into ``<out_dir>/telemetry/``."""

    def __init__(self, out_dir: Path) -> None:
        self._out_dir = out_dir
        self._folder = out_dir / TELEMETRY_DIR

    def write(
        self,
        run: RunTelemetry,
        calls: Sequence[CallTelemetry],
        agent_ids: Mapping[int, str] | None = None,
    ) -> None:
        ordered = sorted(calls, key=lambda c: c.seq)
        if run.calls != len(ordered):
            raise ValueError(f"summary counts {run.calls} calls but {len(ordered)} were given")
        if (agent_ids is None) != (run.agents_source == "inferred"):
            raise ValueError(
                f"the summary's agents are {run.agents_source}; pass agent ids exactly when "
                "the summary was built from them"
            )
        self._check_destination()
        self._folder.mkdir(parents=True, exist_ok=True)
        # the agent each call belongs to (None for an unreadable request)
        agents = ThreadLinks.resolve(ordered, agent_ids).by_seq
        # the history hashes only serve the linking, whose result is the agent column;
        # they grow with every message, so they are left out of the file
        row_fields = {"reasoning", "history_hashes"}
        files = {
            CALLS_FILE: b"".join(
                _json_bytes({**c.model_dump(exclude=row_fields), "agent": agents.get(c.seq)})
                for c in ordered
            ),
            REASONING_FILE: b"".join(
                _json_bytes(
                    {
                        "seq": c.seq,
                        "agent": agents.get(c.seq),
                        "thread_key": c.thread_key,
                        "reasoning": c.reasoning,
                        "text": c.text,
                        "tool_calls": [t.model_dump() for t in c.tool_calls],
                    }
                )
                for c in ordered
            ),
            # the summary goes last: once it is there, the other two are complete
            SUMMARY_FILE: _json_bytes(run.model_dump(), indent=2),
        }
        for name, data in files.items():
            self._replace(self._folder / name, data)

    def _check_destination(self) -> None:
        """Refuse an output folder inside evidence, or one reached through a symlink."""
        real = self._out_dir.resolve()
        for folder in (real, *real.parents):
            if self._is_evidence(folder):
                raise TelemetryError(f"{self._out_dir} is inside the evidence directory {folder}")
        if self._folder.is_symlink():
            raise TelemetryError(f"{self._folder} is a symlink")
        if self._folder.exists() and not self._folder.is_dir():
            raise TelemetryError(f"{self._folder} is not a directory")
        for name in (CALLS_FILE, REASONING_FILE, SUMMARY_FILE):
            target = self._folder / name
            if target.is_symlink():
                raise TelemetryError(f"{target} is a symlink")
            if target.exists() and not target.is_file():
                raise TelemetryError(f"{target} is not a regular file")

    @staticmethod
    def _is_evidence(folder: Path) -> bool:
        """Whether ``folder`` is a run's evidence directory (it holds tap files)."""
        llm = folder / LLM_DIR
        if not llm.is_dir():
            return False
        if (llm / _TAP_EVENTS).exists():
            return True
        return any(_TAP_FILE.fullmatch(name) for name in os.listdir(llm))

    @staticmethod
    def _replace(target: Path, data: bytes) -> None:
        """Write ``data`` to a temporary file beside ``target``, then swap it in."""
        fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def write_derived(
    out_dir: Path,
    run: RunTelemetry,
    calls: Sequence[CallTelemetry],
    agent_ids: Mapping[int, str] | None = None,
) -> None:
    """Write ``run`` and ``calls`` under ``<out_dir>/telemetry/`` (see :class:`DerivedWriter`).

    Pass the same ``agent_ids`` the summary was built with (if any), so each row names
    the same agent. Rerunning replaces the previous files. Raises
    :class:`TelemetryError` if ``out_dir`` is, or lies inside, a run's evidence
    directory, or if the telemetry folder or one of its files is a symlink or not a
    regular file.
    """
    DerivedWriter(out_dir).write(run, calls, agent_ids)
