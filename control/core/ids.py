"""ULID-based identifiers: ``<prefix>_<ULID>``, unique and sortable by creation time."""

from __future__ import annotations

import re
import threading

from ulid import ULID

__all__ = ["ID_PATTERN", "new_id"]

#: Pattern every identifier field accepts. Restricted to characters that are safe in
#: file paths (``runs/<run_id>/...``), URLs and DNS-adjacent contexts.
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,127}$"

_PREFIX_RE = re.compile(r"^[a-z][a-z0-9]{0,15}$")
_MAX_ULID = (1 << 128) - 1

_lock = threading.Lock()
_last = 0


def _next_ulid() -> ULID:
    """Return a ULID strictly greater than the previous one from this process.

    Plain ULIDs generated within the same millisecond have random order; this keeps
    ids monotonic so that sorting by id equals sorting by creation order.
    """
    global _last
    with _lock:
        candidate = ULID()
        value = int(candidate)
        if value <= _last:
            if _last >= _MAX_ULID:
                raise OverflowError("ULID space exhausted")
            value = _last + 1
            candidate = ULID.from_int(value)
        _last = value
        return candidate


def new_id(prefix: str) -> str:
    """Return a new identifier such as ``run_01JC...`` (prefix, underscore, 26-char ULID).

    ``prefix`` must be a short lowercase word (``run``, ``exp``, ``pl``, ``pair``...).
    """
    if not _PREFIX_RE.fullmatch(prefix):
        raise ValueError(f"invalid id prefix {prefix!r}: expected [a-z][a-z0-9]{{0,15}}")
    return f"{prefix}_{_next_ulid()}"
