"""The persisted result of the instrumentation self-test (``labctl selftest``).

The self-test runs on the lab host and records every result here with
:func:`record_selftest_result`; the Collector's ``/metrics``
(``lab_selftest_last_success_timestamp``) and ``labctl status`` read it with
:func:`read_selftest_status`. Because it is a file, the last success survives a
restart of every process.

Location: ``$LAB_SELFTEST_STATUS_FILE``, default :data:`DEFAULT_SELFTEST_STATUS_FILE`
(``/srv/lab/state/selftest.json``). The control-plane compose file mounts
``/srv/lab/state`` read-only into the Collector, so the file is written ``0644`` and
replaced atomically (a temporary file in the same directory, then ``os.replace``):
a reader never sees a half-written file. Writers serialise on an ``flock`` of
``.selftest.lock`` next to it.

Format (JSON)::

    {"last_run": {"passed": false, "finished_at": 1800000500.0, "quick": true,
                  "summary": "control run carried a tag"},
     "last_success": {"passed": true, "finished_at": 1800000000.0, "quick": true,
                      "summary": ""}}

``finished_at`` is Unix time in seconds. ``summary`` is short free text (at most
:data:`MAX_SUMMARY_CHARS`); never put evidence or secrets in it.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

__all__ = [
    "DEFAULT_SELFTEST_STATUS_FILE",
    "MAX_SUMMARY_CHARS",
    "SELFTEST_EXPERIMENT_PREFIX",
    "SELFTEST_STATUS_ENV",
    "SelftestResult",
    "SelftestStatus",
    "SelftestStatusError",
    "read_selftest_status",
    "record_selftest_result",
    "selftest_status_path",
]

SELFTEST_STATUS_ENV: Final = "LAB_SELFTEST_STATUS_FILE"
DEFAULT_SELFTEST_STATUS_FILE: Final = Path("/srv/lab/state/selftest.json")
MAX_SUMMARY_CHARS: Final = 1000
#: Every self-test registers a fresh experiment ``exp_selftest_<ULID>``; study metrics
#: (``lab_runs_total``, ``lab_invalid_runs_total``) leave these experiments out.
SELFTEST_EXPERIMENT_PREFIX: Final = "exp_selftest_"


class SelftestStatusError(ValueError):
    """The status file exists but cannot be read as a self-test status."""


@dataclass(frozen=True, slots=True)
class SelftestResult:
    """One self-test result."""

    passed: bool
    #: Unix time (seconds) when the self-test finished
    finished_at: float
    #: ``--quick`` (one target) rather than the full self-test
    quick: bool
    summary: str = ""

    @classmethod
    def _from_json(cls, data: Any) -> SelftestResult:
        if not isinstance(data, dict):
            raise TypeError("a result must be an object")
        passed, finished_at = data.get("passed"), data.get("finished_at")
        quick, summary = data.get("quick"), data.get("summary", "")
        if not isinstance(passed, bool) or not isinstance(quick, bool):
            raise TypeError("passed and quick must be booleans")
        if isinstance(finished_at, bool) or not isinstance(finished_at, int | float):
            raise TypeError("finished_at must be a number")
        if not isinstance(summary, str):
            raise TypeError("summary must be a string")
        return cls(passed, float(finished_at), quick, summary[:MAX_SUMMARY_CHARS])


@dataclass(frozen=True, slots=True)
class SelftestStatus:
    """The latest self-test result and the latest passing one (either may be absent)."""

    last_run: SelftestResult | None
    last_success: SelftestResult | None

    @property
    def last_success_timestamp(self) -> float | None:
        return None if self.last_success is None else self.last_success.finished_at

    def to_json(self) -> dict[str, Any]:
        return {
            "last_run": None if self.last_run is None else asdict(self.last_run),
            "last_success": None if self.last_success is None else asdict(self.last_success),
        }


def selftest_status_path(path: Path | None = None) -> Path:
    """``path``, else ``$LAB_SELFTEST_STATUS_FILE``, else the default location."""
    if path is not None:
        return path
    env = os.environ.get(SELFTEST_STATUS_ENV)
    return Path(env) if env else DEFAULT_SELFTEST_STATUS_FILE


def read_selftest_status(path: Path | None = None) -> SelftestStatus:
    """Read the status; a missing file means no self-test has run yet.

    Raises :class:`SelftestStatusError` if the file exists but is not a valid status.
    """
    target = selftest_status_path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return SelftestStatus(last_run=None, last_success=None)
    except OSError as exc:
        raise SelftestStatusError(f"cannot read {target}: {exc.strerror}") from exc
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("not an object")
        return SelftestStatus(
            last_run=_optional(data.get("last_run")),
            last_success=_optional(data.get("last_success")),
        )
    except (ValueError, TypeError) as exc:
        raise SelftestStatusError(f"{target} is not a self-test status: {exc}") from exc


def _optional(value: Any) -> SelftestResult | None:
    return None if value is None else SelftestResult._from_json(value)


def record_selftest_result(result: SelftestResult, path: Path | None = None) -> SelftestStatus:
    """Record ``result`` as the last run (and, if it passed, the last success).

    A previous last success is kept when ``result`` failed. An unreadable previous
    file is replaced (its last success is lost, which reads as "never passed").
    Returns the status as written.
    """
    target = selftest_status_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    result = SelftestResult(
        result.passed, float(result.finished_at), result.quick, result.summary[:MAX_SUMMARY_CHARS]
    )
    with _locked(target.parent / ".selftest.lock"):
        try:
            previous = read_selftest_status(target).last_success
        except SelftestStatusError:
            previous = None
        status = SelftestStatus(last_run=result, last_success=result if result.passed else previous)
        _write_atomically(target, json.dumps(status.to_json(), indent=2, sort_keys=True) + "\n")
    return status


@contextlib.contextmanager
def _locked(lock_path: Path) -> Iterator[None]:
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write_atomically(target: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".selftest.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
