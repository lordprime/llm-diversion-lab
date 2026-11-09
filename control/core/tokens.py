"""Run tags and callback tokens.

* A **tag** is 16 random lowercase hex characters (64 bits) planted with every injected
  placement of a run. It must survive HTML escaping, JSON encoding and HTML stripping
  unchanged and match the same way case-sensitively and case-insensitively, so it is
  drawn from, and :data:`TAG_PATTERN` accepts, ``[0-9a-f]`` only.
* A **callback token** maps a callback to exactly one run and placement without a
  lookup table: the HMAC-SHA256 under the lab key of the two fields, each prefixed with
  its UTF-8 length as 8 big-endian bytes (``len(run_id) || run_id || len(placement_id)
  || placement_id``, so no concatenation is ambiguous), base32-encoded, cut to 12
  characters and lowercased so it is a valid DNS label (``<token>.cb.lab.test``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # models imports this module; the import is for annotations only
    from control.core.models import RunManifest

__all__ = [
    "TAG_LENGTH",
    "TAG_PATTERN",
    "TOKEN_LENGTH",
    "TOKEN_PATTERN",
    "derive_token",
    "new_tag",
    "token_to_run",
]

TOKEN_LENGTH = 12
TAG_LENGTH = 16

#: Accepted shape of a callback token (lowercase RFC 4648 base32 alphabet).
TOKEN_PATTERN = rf"^[a-z2-7]{{{TOKEN_LENGTH}}}$"
#: Accepted shape of a run tag.
TAG_PATTERN = rf"^[0-9a-f]{{{TAG_LENGTH}}}$"

_TOKEN_RE = re.compile(TOKEN_PATTERN)


def _field(value: str) -> bytes:
    """Length-prefix a field so concatenation is unambiguous (``ab|c`` != ``a|bc``)."""
    raw = value.encode("utf-8")
    return len(raw).to_bytes(8, "big") + raw


def derive_token(lab_key: bytes, run_id: str, placement_id: str) -> str:
    """Derive the 12-char lowercase base32 callback token for a run's placement.

    Deterministic for fixed inputs; unforgeable without ``lab_key``.
    """
    if not lab_key:
        raise ValueError("lab_key must be non-empty")
    mac = hmac.new(lab_key, _field(run_id) + _field(placement_id), hashlib.sha256).digest()
    return base64.b32encode(mac).decode("ascii")[:TOKEN_LENGTH].lower()


def new_tag() -> str:
    """Return a fresh 16-char random tag (``[0-9a-f]``, 64 bits from ``secrets``)."""
    return secrets.token_hex(TAG_LENGTH // 2)


def token_to_run(token: str, manifest: RunManifest) -> tuple[str, str] | None:
    """Map a token to ``(run_id, placement_id)`` of ``manifest``, or ``None``.

    Compares ``token`` in constant time against every placement's ``token`` in the
    run's manifest; no key is needed. A malformed token, a token not planted in this
    run, and any token of a control run (no placements) give ``None``.
    """
    if not _TOKEN_RE.fullmatch(token):
        return None
    match: tuple[str, str] | None = None
    for placement in manifest.placements:
        if hmac.compare_digest(placement.token, token) and match is None:
            match = (manifest.run_id, placement.placement_id)
    return match
