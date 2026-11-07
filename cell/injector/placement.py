"""Surface injector planting logic: pure helpers with no I/O and no mitmproxy dependency.

:mod:`cell.injector.addon` is the thin mitmproxy shell around this module. Here we
decide, from a run's :class:`~control.core.models.RunManifest` and the rendered text of
its placements, which requests to the target get an :class:`Action`, and we compute the
bytes the addon plants into the app's response.

The injector never fabricates a response. Every request goes to the app; in an
injected run the addon then transforms the app's *own* response for ``GET`` requests
only, keeping the app's status line and headers wherever the rules below allow, so
the arms differ only by the planted content (DEVELOPMENT_PLAN section 4.4):

* ``GET /robots.txt`` (P1): if the app answers 200, every P1 text is appended to its
  body as a line, in manifest order, in the body's own Content-Encoding. If the app
  answers 404 (it has no robots.txt), that response becomes a 200 ``text/plain`` whose
  body is :data:`DEFAULT_ROBOTS_BASE` followed by the P1 lines, keeping the app's other
  headers; the serve log records ``synthesized_base``. Any other status: nothing is
  planted (``insert_ok`` false).
* ``GET`` on a P7 path: if the app answers 4xx, the P7 text is planted into the app's
  own error body, before ``</body>`` if present, else appended; status and headers are
  kept. The locator's 403/404 is the *expected* status; the serve log records expected
  and actual. If the app does not answer 4xx, nothing is planted (``insert_ok`` false:
  a placement-map error the pre-flight probe catches).
* ``GET`` on the decoy path ``/x-<tag>`` or below ``/x-<tag>/``: the app's response
  becomes a 200 with :data:`DECOY_PAGE` as its body, keeping the app's other headers.
* control: no action at all; every response passes through untouched.

``HEAD`` and every other method are never planted. Placement text never lives in this
code. The runner renders each placement and pins its UTF-8 bytes in the manifest as
``Placement.content_sha256``; the rendered text is handed to the injector separately
(see :mod:`cell.injector.serve_log`) and :func:`build_plan` refuses any text whose hash
differs or that lacks the run's tag.

Locators understood in M0:

* P1: ``robots.txt:append`` and a ``url`` whose path is ``/robots.txt``.
* P7: ``error:403`` or ``error:404`` (the expected status) and a ``url`` whose path is
  the probed path.

Any other surface or locator is rejected, so a manifest never silently plants less
than it promises.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from control.core.codecs import decode_body, encode_body
from control.core.models import Arm, Placement, RunManifest, Surface
from control.core.tags import decoy_prefix, request_path, under_decoy

__all__ = [
    "DECOY_PAGE",
    "DECOY_PAGE_VERSION",
    "DEFAULT_ROBOTS_BASE",
    "INJECTOR_STREAM",
    "P7_LOCATOR_PATTERN",
    "PROBE_HEADER",
    "ROBOTS_LOCATOR",
    "ROBOTS_PATH",
    "Action",
    "ActionKind",
    "InjectionPlan",
    "Plant",
    "Planted",
    "build_plan",
    "decode_body",
    "encode_body",
    "is_probe",
    "plant_into_body",
    "recompute_etag",
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
#: robots.txt lines placed before the P1 text when the app has no robots.txt.
DEFAULT_ROBOTS_BASE: Final = "User-agent: *\nDisallow:\n"
#: The neutral page served at the decoy path; versioned with the payload library.
DECOY_PAGE: Final = (
    "<!doctype html>\n<html><head><title>Index</title></head>\n"
    "<body><p>No content.</p></body></html>\n"
)
DECOY_PAGE_VERSION: Final = "1"

_P7_LOCATOR = re.compile(P7_LOCATOR_PATTERN)


# --------------------------------------------------------------------------- codecs


def _rfind_ci(haystack: bytes, needle: bytes) -> int:
    """Last index of ``needle`` in ``haystack``, ignoring ASCII case; -1 if absent."""
    return haystack.lower().rfind(needle.lower())


def plant_into_body(
    body: bytes, encoding: str | None, payload: bytes, *, before: bytes | None = None
) -> tuple[bytes, int, bool]:
    """Insert ``payload`` into a body sent with Content-Encoding ``encoding``.

    The body is decoded (:func:`decode_body`), ``payload`` is inserted before the last
    occurrence of ``before`` (ASCII case-insensitive) or appended when ``before`` is
    ``None`` or absent, and the result is re-encoded with the same encoding.

    Returns ``(new wire bytes, offset of payload in the decoded body, True)``. If the
    encoding is unsupported or the body cannot be decoded or re-encoded, returns
    ``(body, -1, False)`` unchanged. The caller must fix the framing headers.
    """
    if not payload:
        raise ValueError("payload must be non-empty")
    decoded = decode_body(body, encoding)
    if decoded is None:
        return body, -1, False
    offset = _rfind_ci(decoded, before) if before else -1
    if offset < 0:
        offset = len(decoded)
    wire = encode_body(decoded[:offset] + payload + decoded[offset:], encoding)
    if wire is None:
        return body, -1, False
    return wire, offset, True


def recompute_etag(old: str, wire: bytes) -> str:
    """A new entity tag for a changed body: a quoted digest, keeping a ``W/`` prefix."""
    weak = old.strip().startswith("W/")
    return f'{"W/" if weak else ""}"{hashlib.sha256(wire).hexdigest()[:32]}"'


# --------------------------------------------------------------------------- plants


@dataclass(frozen=True, slots=True)
class Plant:
    """One placement and the exact bytes to plant for it."""

    placement: Placement
    content: bytes


@dataclass(frozen=True, slots=True)
class Planted:
    """Where one plant ended up in a decoded response body (``None`` if not planted)."""

    plant: Plant
    offset: int | None
    insert_ok: bool


def render_robots(existing: bytes, plants: Sequence[Plant]) -> tuple[bytes, tuple[int, ...]]:
    """Append each plant's text as a line of a decoded robots.txt body.

    A newline is added first if ``existing`` does not end with one, and after each text
    that does not end with one. Returns the new body and each text's offset in it.
    """
    body = existing
    if body and not body.endswith(b"\n"):
        body += b"\n"
    offsets: list[int] = []
    for plant in plants:
        offsets.append(len(body))
        body += plant.content if plant.content.endswith(b"\n") else plant.content + b"\n"
    return body, tuple(offsets)


# --------------------------------------------------------------------------- plan


class ActionKind(StrEnum):
    ROBOTS = "robots"
    ERROR = "error"
    DECOY = "decoy"


@dataclass(frozen=True, slots=True)
class Action:
    """What to do to the app's response for one request."""

    kind: ActionKind
    plants: tuple[Plant, ...] = ()
    #: P7 only: the status the placement map expects the app to answer with.
    expected_status: int | None = None


@dataclass(frozen=True, slots=True)
class InjectionPlan:
    """Which requests the injector acts on; empty for a control run."""

    arm: Arm
    robots: Action | None = None
    errors: Mapping[str, Action] = field(default_factory=dict)
    decoy_prefix: str | None = None

    def match(self, method: str, target: str) -> Action | None:
        """The action for a request, or ``None`` to leave its response untouched.

        Only ``GET`` is ever acted on.
        """
        if method.upper() != "GET":
            return None
        path = request_path(target)
        if self.robots is not None and path == ROBOTS_PATH:
            return self.robots
        error = self.errors.get(path)
        if error is not None:
            return error
        prefix = self.decoy_prefix
        if prefix is not None and under_decoy(path, prefix):
            return Action(ActionKind.DECOY)
        return None


def _content(contents: Mapping[str, str], placement: Placement) -> bytes:
    try:
        return contents[placement.placement_id].encode("utf-8")
    except KeyError:
        raise ValueError(f"missing content for placement {placement.placement_id}") from None


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


def _expected_status(placement: Placement) -> int:
    match = _P7_LOCATOR.fullmatch(placement.locator)
    if match is None:
        raise ValueError(
            f"placement {placement.placement_id}: P7 locator {placement.locator!r} "
            f"must match {P7_LOCATOR_PATTERN}"
        )
    return int(match.group(1))


def build_plan(manifest: RunManifest, contents: Mapping[str, str]) -> InjectionPlan:
    """Validate a manifest and its rendered texts and decide what the injector acts on.

    ``contents`` maps ``placement_id`` to the rendered text; it must cover exactly the
    manifest's placements (so it is empty for a control run). Raises ``ValueError`` on
    any mismatch, unsupported surface or malformed locator.
    """
    _check_content(manifest, contents)
    if manifest.arm is Arm.CONTROL:
        return InjectionPlan(arm=Arm.CONTROL)

    robots: list[Plant] = []
    errors: dict[str, Action] = {}
    for placement in manifest.placements:
        path = request_path(placement.url)
        plant = Plant(placement, _content(contents, placement))
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
            robots.append(plant)
        elif placement.surface is Surface.P7:
            expected = _expected_status(placement)
            if path == ROBOTS_PATH:
                raise ValueError(f"placement {placement.placement_id}: P7 cannot use robots.txt")
            if path in errors:
                raise ValueError(f"more than one P7 placement on path {path}")
            errors[path] = Action(ActionKind.ERROR, (plant,), expected)
        else:
            raise ValueError(
                f"placement {placement.placement_id}: surface {placement.surface.value} "
                "is not supported by the M0 injector"
            )

    if manifest.tag is None:  # pragma: no cover - RunManifest forbids it for injected
        raise ValueError("injected manifest has no tag")
    prefix = decoy_prefix(manifest.tag)
    if any(under_decoy(p, prefix) for p in errors):
        raise ValueError("a P7 path lies under the decoy path")
    return InjectionPlan(
        arm=Arm.INJECTED,
        robots=Action(ActionKind.ROBOTS, tuple(robots)) if robots else None,
        errors=errors,
        decoy_prefix=prefix,
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
