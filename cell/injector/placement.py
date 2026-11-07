"""Surface injector planting logic: pure helpers with no I/O and no mitmproxy dependency.

:mod:`cell.injector.addon` is the thin mitmproxy shell around this module. Here we
decide, from a run's :class:`~control.core.models.RunManifest` and the rendered text of
its placements, what the injector answers itself and with which bytes.

Arms (DEVELOPMENT_PLAN section 4.4):

* **injected**: ``GET``/``HEAD /robots.txt`` is answered with a synthetic file (a fixed
  allow-all base followed by every P1 placement's text, in manifest order); each P7
  placement's path is answered, for any method, with its configured 403/404 status
  and an error page carrying the placement's text; the decoy path ``/x-<tag>`` (and
  anything below ``/x-<tag>/``) is answered with a neutral HTML 200 page
  (:data:`DECOY_PAGE`). Everything else goes to the app untouched.
* **control**: nothing is planted and nothing is answered here; robots.txt, the P7
  paths and ``/x-...`` reach the unmodified app (control = the clean site).

Placement text never lives in this code. The runner renders each placement and pins
its UTF-8 bytes in the manifest as ``Placement.content_sha256``; the rendered text is
handed to the injector separately (see :mod:`cell.injector.addon`) and
:func:`build_plan` refuses any text whose hash differs or that lacks the run's tag.

Locators understood in M0:

* P1: ``robots.txt:append`` and a ``url`` whose path is ``/robots.txt``.
* P7: ``error:403`` or ``error:404`` and a ``url`` whose path is the probed path.

Any other surface or locator is rejected, so a manifest never silently plants less
than it promises.

:func:`plant_into_body` plants into an existing (possibly compressed) body. M0 builds
every planted body itself, so it is used for page surfaces (P3-P6) later on.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import importlib
import re
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from types import ModuleType
from typing import Final
from urllib.parse import urlsplit

from control.core.models import Arm, Placement, RunManifest, Surface

__all__ = [
    "DECOY_PAGE",
    "DECOY_PAGE_VERSION",
    "DEFAULT_ROBOTS_BASE",
    "INJECTOR_STREAM",
    "P7_LOCATOR_PATTERN",
    "PROBE_HEADER",
    "ROBOTS_LOCATOR",
    "ROBOTS_PATH",
    "InjectionPlan",
    "Plant",
    "SyntheticResponse",
    "build_plan",
    "is_probe",
    "plant_into_body",
    "render_decoy",
    "render_error",
    "render_robots",
    "request_path",
]

#: Producer stream name of every event the injector emits (``target_access`` and
#: ``placement_serve`` share it, and one ``seq`` counter).
INJECTOR_STREAM: Final = "injector"
#: Request header that marks a runner pre-flight probe; its value must equal the
#: per-run probe secret. Always removed before a request is forwarded.
PROBE_HEADER: Final = "x-lab-probe"
ROBOTS_PATH: Final = "/robots.txt"
ROBOTS_LOCATOR: Final = "robots.txt:append"
P7_LOCATOR_PATTERN: Final = r"^error:(403|404)$"
#: Lines of the synthetic robots.txt that precede the P1 text (allow everything).
DEFAULT_ROBOTS_BASE: Final = "User-agent: *\nDisallow:\n"
#: The neutral page served at the decoy path; versioned with the payload library.
DECOY_PAGE: Final = (
    "<!doctype html>\n<html><head><title>Index</title></head>\n"
    "<body><p>No content.</p></body></html>\n"
)
DECOY_PAGE_VERSION: Final = "1"

_P7_LOCATOR = re.compile(P7_LOCATOR_PATTERN)
_TEXT_PLAIN: Final = "text/plain; charset=utf-8"
_TEXT_HTML: Final = "text/html; charset=utf-8"
_ROBOTS_METHODS: Final = frozenset({"GET", "HEAD"})


# --------------------------------------------------------------------------- codecs


def _module(*names: str) -> ModuleType | None:
    for name in names:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


def _brotli() -> ModuleType:
    mod = _module("brotli")
    if mod is None:
        raise ValueError("brotli is not available")
    return mod


def _zstd() -> ModuleType:
    mod = _module("compression.zstd", "backports.zstd")
    if mod is None:
        raise ValueError("zstd is not available")
    return mod


def _identity(data: bytes) -> bytes:
    return data


def _gzip_encode(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _deflate_decode(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:  # some servers send raw deflate without the zlib wrapper
        return zlib.decompress(data, -zlib.MAX_WBITS)


def _br_decode(data: bytes) -> bytes:
    out: bytes = _brotli().decompress(data)
    return out


def _br_encode(data: bytes) -> bytes:
    out: bytes = _brotli().compress(data)
    return out


def _zstd_decode(data: bytes) -> bytes:
    out: bytes = _zstd().decompress(data)
    return out


def _zstd_encode(data: bytes) -> bytes:
    out: bytes = _zstd().compress(data)
    return out


_Codec = tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]]
_CODECS: Final[Mapping[str, _Codec]] = {
    "identity": (_identity, _identity),
    "gzip": (gzip.decompress, _gzip_encode),
    "x-gzip": (gzip.decompress, _gzip_encode),
    "deflate": (_deflate_decode, zlib.compress),
    "br": (_br_decode, _br_encode),
    "zstd": (_zstd_decode, _zstd_encode),
}


def _codec(encoding: str | None) -> _Codec | None:
    name = (encoding or "").strip().lower() or "identity"
    return _CODECS.get(name)


def _rfind_ci(haystack: bytes, needle: bytes) -> int:
    """Last index of ``needle`` in ``haystack``, ignoring ASCII case; -1 if absent."""
    return haystack.lower().rfind(needle.lower())


def plant_into_body(
    body: bytes, encoding: str | None, payload: bytes, *, before: bytes | None = None
) -> tuple[bytes, int, bool]:
    """Insert ``payload`` into a body sent with Content-Encoding ``encoding``.

    The body is decoded (``identity``/none, ``gzip``, ``deflate``, ``br``, ``zstd``),
    ``payload`` is inserted before the last occurrence of ``before`` (ASCII
    case-insensitive) or appended when ``before`` is ``None`` or absent, and the result
    is re-encoded with the same encoding and checked by decoding it again.

    Returns ``(new wire bytes, offset of payload in the decoded body, True)``. If the
    encoding is unsupported (including stacked encodings such as ``gzip, br``) or the
    body cannot be decoded or re-encoded, returns ``(body, -1, False)`` unchanged.
    The caller must fix Content-Length and drop a stale ETag.
    """
    if not payload:
        raise ValueError("payload must be non-empty")
    codec = _codec(encoding)
    if codec is None:
        return body, -1, False
    decode, encode = codec
    try:
        decoded = decode(body)
        offset = _rfind_ci(decoded, before) if before else -1
        if offset < 0:
            offset = len(decoded)
        planted = decoded[:offset] + payload + decoded[offset:]
        wire = encode(planted)
        ok = decode(wire)[offset : offset + len(payload)] == payload
    except Exception:  # any codec failure: leave the body alone
        return body, -1, False
    if not ok:
        return body, -1, False
    return wire, offset, True


# --------------------------------------------------------------------------- rendering


@dataclass(frozen=True, slots=True)
class Plant:
    """One placement's text inside a synthetic body, at ``offset`` (bytes)."""

    placement: Placement
    content: bytes
    offset: int


@dataclass(frozen=True, slots=True)
class SyntheticResponse:
    """A response the injector answers itself, never asking the app."""

    status: int
    body: bytes
    content_type: str
    plants: tuple[Plant, ...] = field(default=())


def _content(contents: Mapping[str, str], placement: Placement) -> bytes:
    try:
        return contents[placement.placement_id].encode("utf-8")
    except KeyError:
        raise ValueError(f"missing content for placement {placement.placement_id}") from None


def render_robots(
    manifest: RunManifest, contents: Mapping[str, str], base: str = DEFAULT_ROBOTS_BASE
) -> SyntheticResponse:
    """The synthetic ``/robots.txt``: ``base`` then each P1 placement's text, one per line.

    Text is inserted verbatim (a newline is added only if it does not end with one).
    """
    body = base.encode("utf-8")
    if body and not body.endswith(b"\n"):
        body += b"\n"
    plants: list[Plant] = []
    for placement in manifest.placements:
        if placement.surface is not Surface.P1:
            continue
        text = _content(contents, placement)
        plants.append(Plant(placement, text, len(body)))
        body += text if text.endswith(b"\n") else text + b"\n"
    return SyntheticResponse(200, body, _TEXT_PLAIN, tuple(plants))


def _error_status(placement: Placement) -> int:
    match = _P7_LOCATOR.fullmatch(placement.locator)
    if match is None:
        raise ValueError(
            f"placement {placement.placement_id}: P7 locator {placement.locator!r} "
            f"must match {P7_LOCATOR_PATTERN}"
        )
    return int(match.group(1))


def render_error(placement: Placement, content: str) -> SyntheticResponse:
    """The P7 error page: the configured 403/404 with the placement's text in the body."""
    status = _error_status(placement)
    reason = HTTPStatus(status).phrase
    head = (
        f"<!doctype html>\n<html><head><title>{status} {reason}</title></head>\n"
        f"<body><h1>{reason}</h1>\n<p>"
    ).encode()
    text = content.encode("utf-8")
    body = head + text + b"</p>\n</body></html>\n"
    return SyntheticResponse(status, body, _TEXT_HTML, (Plant(placement, text, len(head)),))


def render_decoy() -> SyntheticResponse:
    """The neutral decoy page (no placement text, no tag)."""
    return SyntheticResponse(200, DECOY_PAGE.encode("utf-8"), _TEXT_HTML)


# --------------------------------------------------------------------------- plan


def request_path(target: str) -> str:
    """The path of a request target or URL, without query string or fragment."""
    if target.startswith("/"):
        path = target.partition("?")[0].partition("#")[0]
    else:
        path = urlsplit(target).path
    return path or "/"


@dataclass(frozen=True, slots=True)
class InjectionPlan:
    """What one injector instance answers itself; empty for a control run."""

    arm: Arm
    robots: SyntheticResponse | None = None
    errors: Mapping[str, SyntheticResponse] = field(default_factory=dict)
    decoy_prefix: str | None = None
    decoy: SyntheticResponse | None = None

    def match(self, method: str, target: str) -> SyntheticResponse | None:
        """The synthetic answer for a request, or ``None`` to forward it to the app."""
        path = request_path(target)
        if self.robots is not None and path == ROBOTS_PATH and method.upper() in _ROBOTS_METHODS:
            return self.robots
        error = self.errors.get(path)
        if error is not None:
            return error
        prefix = self.decoy_prefix
        if prefix is not None and (path == prefix or path.startswith(prefix + "/")):
            return self.decoy
        return None


def _check_content(manifest: RunManifest, contents: Mapping[str, str]) -> None:
    planned = {p.placement_id for p in manifest.placements}
    unknown = sorted(set(contents) - planned)
    if unknown:
        raise ValueError(f"content for unknown placement(s): {', '.join(unknown)}")
    for placement in manifest.placements:
        text = _content(contents, placement)
        if hashlib.sha256(text).hexdigest() != placement.content_sha256:
            raise ValueError(
                f"placement {placement.placement_id}: content does not match content_sha256"
            )
        if placement.tag.encode() not in text:
            raise ValueError(f"placement {placement.placement_id}: content lacks the run tag")


def build_plan(
    manifest: RunManifest, contents: Mapping[str, str], robots_base: str = DEFAULT_ROBOTS_BASE
) -> InjectionPlan:
    """Validate a manifest and its rendered texts and decide what the injector serves.

    ``contents`` maps ``placement_id`` to the rendered text; it must cover exactly the
    manifest's placements (so it is empty for a control run). Raises ``ValueError`` on
    any mismatch, unsupported surface or malformed locator.
    """
    _check_content(manifest, contents)
    if manifest.arm is Arm.CONTROL:
        return InjectionPlan(arm=Arm.CONTROL)

    errors: dict[str, SyntheticResponse] = {}
    has_p1 = False
    for placement in manifest.placements:
        path = request_path(placement.url)
        if placement.surface is Surface.P1:
            if placement.locator != ROBOTS_LOCATOR:
                raise ValueError(
                    f"placement {placement.placement_id}: P1 locator {placement.locator!r} "
                    f"must be {ROBOTS_LOCATOR!r}"
                )
            if path != ROBOTS_PATH:
                raise ValueError(
                    f"placement {placement.placement_id}: P1 url must be {ROBOTS_PATH} (robots)"
                )
            has_p1 = True
        elif placement.surface is Surface.P7:
            page = render_error(placement, contents[placement.placement_id])
            if path == ROBOTS_PATH:
                raise ValueError(f"placement {placement.placement_id}: P7 cannot use robots.txt")
            if path in errors:
                raise ValueError(f"more than one P7 placement on path {path}")
            errors[path] = page
        else:
            raise ValueError(
                f"placement {placement.placement_id}: surface {placement.surface.value} "
                "is not supported by the M0 injector"
            )

    if manifest.tag is None:  # pragma: no cover - RunManifest forbids it for injected
        raise ValueError("injected manifest has no tag")
    prefix = f"/x-{manifest.tag}"
    if any(p == prefix or p.startswith(prefix + "/") for p in errors):
        raise ValueError("a P7 path lies under the decoy path")
    return InjectionPlan(
        arm=Arm.INJECTED,
        robots=render_robots(manifest, contents, robots_base) if has_p1 else None,
        errors=errors,
        decoy_prefix=prefix,
        decoy=render_decoy(),
    )


# --------------------------------------------------------------------------- probes


def is_probe(values: Sequence[str], secret: str) -> bool:
    """Whether a request's ``x-lab-probe`` header values mark a runner probe.

    True only for exactly one header whose value equals ``secret`` (compared in
    constant time). With no secret configured, nothing is a probe.
    """
    if not secret or len(values) != 1:
        return False
    given = values[0].encode("utf-8", "surrogateescape")
    return hmac.compare_digest(given, secret.encode("utf-8", "surrogateescape"))
