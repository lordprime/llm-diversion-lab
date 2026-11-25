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
* control: no planting at all; every response passes through untouched, except that
  in an experiment that plants P1 (``synthesize_robots``) a 404 for ``/robots.txt``
  becomes the same synthesized :data:`DEFAULT_ROBOTS_BASE` a treated run gets, so the
  arms' robots.txt differ by exactly the planted line (arm parity).

``HEAD`` and every other method are never planted. Placement text never lives in this
code. The runner renders each placement and pins its UTF-8 bytes in the manifest as
``Placement.content_sha256``; the rendered text is handed to the injector separately
(see :mod:`cell.injector.serve_log`) and :func:`build_plan` refuses any text whose hash
differs or that lacks the run's tag.

* ``GET`` on a page path (P2-P6, P8): if the app answers 200, the P2-P6 texts are
  planted into its own HTML body, each wrapped by :class:`SurfaceMarkup`. Every point
  is found once, on the body as the app sent it: the end of the first start or end tag
  ending at or after ``floor(len(body) * offset_fraction)`` between the real ``<body>``
  and the real last ``</body>``, found with a tokenizer (never inside a script, style,
  textarea, title, comment, tag, attribute value, svg, math, template or select), else
  just before ``</body>``. The texts go
  in from the end backwards, so none lands inside another; texts that share a point keep
  the surface order P2..P6. The serve's ``byte_offset`` is the point in the app's
  ORIGINAL body (see :func:`plant_many_into_body`). A P8 text only becomes the
  ``X-Security-Notice`` response header; the body, status and every other header stay
  the app's. A page that is not HTML, or not 200, is left alone (``insert_ok`` false).

Locators understood:

* P1: ``robots.txt:append`` and a ``url`` whose path is ``/robots.txt``.
* P2-P6, P8: the fixed strings in :data:`SURFACE_LOCATORS` and a ``url`` whose path is
  the page. P2-P6 also carry the manifest's ``offset_fraction``.
* P7: ``error:403`` or ``error:404`` (the expected status) and a ``url`` whose path is
  the probed path.

Any other surface or locator is rejected, so a manifest never silently plants less
than it promises.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from control.core.codecs import decode_body, encode_body
from control.core.models import Arm, Placement, RunManifest, Surface
from control.core.tags import decoy_prefix, request_path, under_decoy

__all__ = [
    "BODY_DIGEST_HEADER",
    "BODY_SURFACES",
    "DECOY_PAGE",
    "DECOY_PAGE_VERSION",
    "DEFAULT_ROBOTS_BASE",
    "INJECTOR_STREAM",
    "MAX_NOTICE_BYTES",
    "NOTICE_HEADER",
    "P7_LOCATOR_PATTERN",
    "PROBE_HEADER",
    "PROTECTED_HEADERS",
    "ROBOTS_LOCATOR",
    "ROBOTS_PATH",
    "SCANNER_PROBE",
    "SCANNER_PROBE_TAGS",
    "SURFACE_LOCATORS",
    "Action",
    "ActionKind",
    "InjectionPlan",
    "Plant",
    "Planted",
    "SurfaceMarkup",
    "build_plan",
    "check_scanner",
    "decode_body",
    "encode_body",
    "is_probe",
    "plant_into_body",
    "plant_many_into_body",
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
#: Response header added to *probe* responses on page paths only: the sha256 of the decoded
#: body after every body plant (P2-P6) and before P8, so the pre-flight can prove P8 left
#: the body alone.
BODY_DIGEST_HEADER: Final = "x-lab-body-sha256"
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

#: Surfaces whose text is planted into an HTML body at a relative offset.
BODY_SURFACES: Final = frozenset({Surface.P2, Surface.P3, Surface.P4, Surface.P5, Surface.P6})
#: The header P8 sets, and the longest value it may carry.
NOTICE_HEADER: Final = "x-security-notice"
MAX_NOTICE_BYTES: Final = 512
#: Fixed locator of each in-page surface (P1 and P7 have their own constants above).
SURFACE_LOCATORS: Final = {
    Surface.P2: "html:body",
    Surface.P3: "html:comment",
    Surface.P4: "html:offscreen",
    Surface.P5: "html:aria-hidden",
    Surface.P6: "jsonld:description",
    Surface.P8: f"header:{NOTICE_HEADER}",
}
#: Headers a P8 placement may never set or replace: they describe the body or the
#: caching and security of the page, so touching them would change more than the text.
PROTECTED_HEADERS: Final = frozenset(
    {
        "content-type",
        "content-security-policy",
        "set-cookie",
        "etag",
        "last-modified",
        "cache-control",
        "content-length",
        "content-encoding",
    }
)

_P7_LOCATOR = re.compile(P7_LOCATOR_PATTERN)
_HEADER_LOCATOR = re.compile(r"^header:([A-Za-z0-9-]+)$")


# --------------------------------------------------------------------------- codecs


def _rfind_ci(haystack: bytes, needle: bytes) -> int:
    """Last index of ``needle`` in ``haystack``, ignoring ASCII case; -1 if absent."""
    return haystack.lower().rfind(needle.lower())


class _TagScanner:
    """Records where each start and end tag of a page ends, in normal content only.

    A small tokenizer that follows the HTML parsing rules a browser applies, so it gives
    the same answer on every Python (the standard library parser changes between patch
    releases and differs from browsers in several corners). The page is read as Latin-1,
    so a character index is a byte index whatever the page's real charset. Each entry of
    :attr:`tags` is ``(start, end, tag, is_end_tag)``.

    * Comments (including ``<!-->`` and ``<!--->``, which close at once), doctypes,
      ``<?...>`` and ``</ ...>`` junk never count.
    * ``style``, ``xmp``, ``iframe``, ``noembed``, ``noframes`` and ``noscript`` (scripting
      on) hold raw text until their end tag; ``textarea`` and ``title`` likewise.
      The end of those start tags lies inside their content and is not recorded;
      ``plaintext`` swallows the rest of the page.
    * ``script`` follows the script data escape states: after ``<!--`` a ``<script``
      opens a double-escaped section that only a later ``</script>`` followed by ``-->``
      and a final ``</script>`` can end.
    * Tag ends honour quoted attribute values, so a ``>`` inside one is not a tag end.
    * Nothing is recorded from an ``svg`` or ``math`` start tag up to and including its
      matching end tag (foreign content, where CDATA sections are real and ``style``,
      ``title`` and ``script`` are not raw text), nor from ``template`` or ``select`` to
      their matching end tag: text there never renders as normal content.

    Anything unterminated (a comment, a quote, a script, a raw element, foreign content)
    swallows the rest of the page: no later boundary is recorded, which fails closed. So
    does foreign content or a ``select`` holding markup that only a full tree builder
    could follow (a tag that leaves foreign content, HTML inside an integration point,
    or anything old and new browsers read differently inside a ``select``).
    """

    _RAWTEXT: Final = frozenset({"style", "xmp", "iframe", "noembed", "noframes", "noscript"})
    _RCDATA: Final = frozenset({"textarea", "title"})
    #: Roots of foreign content, each with the elements of its namespace inside which a
    #: browser reads start tags as HTML again (integration points).
    _FOREIGN: Final = {
        "svg": frozenset({"foreignobject", "desc", "title"}),
        "math": frozenset({"mi", "mo", "mn", "ms", "mtext", "annotation-xml"}),
    }
    #: Start tags that make a browser leave foreign content ("font" only with some
    #: attributes, but any font is treated so here).
    _BREAKOUT: Final = frozenset(
        {
            "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt",
            "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li",
            "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span",
            "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var", "font",
        }
    )  # fmt: skip
    #: Elements whose content is inert until their matching end tag.
    _INERT: Final = frozenset({"template"})
    #: Start tags inside a ``select`` that change how the rest is read, or that old and
    #: new parsers (before and after the 2025 select change) treat differently.
    _SELECT_UNSAFE: Final = frozenset(
        {
            "plaintext", "svg", "math", "template", "select", "input", "keygen", "textarea",
            "table", "caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td",
            "th", "applet", "marquee", "object", "html",
        }
    )  # fmt: skip
    _SPACE: Final = "\t\n\f\r "
    _NAME_END: Final = re.compile(r"[^\t\n\f\r />]*")
    _ATTR_NAME: Final = re.compile(r"=?[^\t\n\f\r />=]*")
    _UNQUOTED: Final = re.compile(r"[^\t\n\f\r >]*")
    _SPACES: Final = re.compile(r"[\t\n\f\r ]*")
    _COMMENT_END: Final = re.compile(r"--!?>")
    _SCRIPT_TOKEN: Final = re.compile(
        r"<!--(-*>)?|-->|<script(?=[\t\n\f\r />])|</script(?=[\t\n\f\r />])", re.IGNORECASE
    )

    def __init__(self, decoded: bytes) -> None:
        self._text = decoded.decode("latin-1")
        self.tags: list[tuple[int, int, str, bool]] = []
        self._scan()

    def _tag_end(self, j: int) -> tuple[int, bool]:
        """``(index just after the tag's ">", self-closing)`` for the tag whose name ends at
        ``j``; ``(-1, False)`` if unterminated. Self-closing means ``/>`` that is not the
        end of an unquoted attribute value."""
        text, n = self._text, len(self._text)
        while j < n:
            c = text[j]
            if c == ">":
                return j + 1, False
            if c == "/" and text.startswith(">", j + 1):
                return j + 2, True
            if c in self._SPACE or c == "/":
                j += 1
                continue
            j = self._ATTR_NAME.match(text, j).end()  # type: ignore[union-attr]
            k = self._SPACES.match(text, j).end()  # type: ignore[union-attr]
            if text[k : k + 1] != "=":
                continue
            k = self._SPACES.match(text, k + 1).end()  # type: ignore[union-attr]
            quote = text[k : k + 1]
            if quote in ('"', "'"):
                close = text.find(quote, k + 1)
                if close < 0:
                    return -1, False
                j = close + 1
            else:
                j = self._UNQUOTED.match(text, k).end()  # type: ignore[union-attr]
        return -1, False

    def _next_tag(self, i: int, *, cdata: bool = False) -> tuple[int, int, str, bool, bool] | None:
        """The next start or end tag from ``i``, read in the data state.

        Returns ``(start, end, name, is_end_tag, self_closing)``. Comments, doctypes and
        bogus comments are stepped over, and so are CDATA sections when ``cdata`` is set
        (they only exist in foreign content). ``None`` at the end of the page or at
        anything unterminated.
        """
        text = self._text
        while (i := text.find("<", i)) >= 0:
            nxt = text[i + 1 : i + 2]
            if nxt == "!":
                if cdata and text.startswith("[CDATA[", i + 2):
                    close = text.find("]]>", i + 9)
                    if close < 0:
                        return None
                    i = close + 3
                elif text.startswith("<!--", i):
                    if text.startswith(">", i + 4):
                        i += 5
                    elif text.startswith("->", i + 4):
                        i += 6
                    else:
                        found = self._COMMENT_END.search(text, i + 4)
                        if found is None:
                            return None
                        i = found.end()
                else:  # a doctype or a bogus comment, up to the next ">"
                    close = text.find(">", i + 2)
                    if close < 0:
                        return None
                    i = close + 1
            elif nxt == "?" or (nxt == "/" and not self._letter(i + 2)):
                # "<?..>" and junk end tags are bogus comments; "</>" is dropped
                close = text.find(">", i + 2)
                if close < 0:
                    return None
                i = close + 1
            elif nxt == "/" or self._letter(i + 1):
                first = i + 2 if nxt == "/" else i + 1
                name_end = self._NAME_END.match(text, first).end()  # type: ignore[union-attr]
                end, closing = self._tag_end(name_end)
                if end < 0:
                    return None
                return i, end, text[first:name_end].lower(), nxt == "/", closing
            else:
                i += 1
        return None

    def _letter(self, j: int) -> bool:
        c = self._text[j : j + 1]
        return c.isascii() and c.isalpha()

    def _raw_end(self, name: str, start: int) -> tuple[int, int] | None:
        """``(start, end)`` of the end tag that closes raw text from ``start``; ``None`` if none."""
        pattern = re.compile(rf"</{name}(?=[\t\n\f\r />])", re.IGNORECASE)
        found = pattern.search(self._text, start)
        if found is None:
            return None
        end = self._tag_end(found.end())[0]
        return None if end < 0 else (found.start(), end)

    def _script_end(self, start: int) -> tuple[int, int] | None:
        """``(start, end)`` of the ``</script>`` that really ends the script from ``start``."""
        text = self._text
        state, pos = "data", start
        while (m := self._SCRIPT_TOKEN.search(text, pos)) is not None:
            piece = m.group(0).lower()
            pos = m.end()
            if piece.startswith("<!--"):
                if m.group(1) is not None:  # "<!-->", "<!--->": back to plain script data
                    state = "data"
                elif state == "data":
                    state = "escaped"
            elif piece == "-->":
                if state != "data":
                    state = "data"
            elif piece == "<script":
                if state == "escaped":
                    state = "double"
            elif state == "double":  # "</script" inside a double-escaped section
                state = "escaped"
            else:
                end = self._tag_end(m.end())[0]
                return None if end < 0 else (m.start(), end)
        return None

    def _foreign_end(self, start: int, root: str) -> int | None:
        """Index just after the end tag that closes the ``svg`` or ``math`` opened before
        ``start``; ``None`` if nothing does.

        Open elements are tracked as a browser does in foreign content: an end tag closes
        the nearest open element of its name (and everything inside it), a self-closing
        start tag opens nothing. ``None`` too where a browser would leave foreign content
        (a breakout tag, ``</p>``, ``</br>``, an end tag with no open element of its name,
        or a start tag inside an integration point), since only a full tree builder could
        say where normal content resumes.
        """
        points = self._FOREIGN[root]
        open_ = [root]
        i = start
        while (tag := self._next_tag(i, cdata=True)) is not None:
            _start, end, name, is_end, closing = tag
            i = end
            if is_end:
                if name in ("p", "br") or name not in open_:
                    return None
                del open_[len(open_) - 1 - open_[::-1].index(name) :]
                if not open_:
                    return end
            elif open_[-1] in points or name in self._BREAKOUT:
                return None
            elif not closing:
                open_.append(name)
        return None

    def _select_end(self, start: int) -> int | None:
        """Index just after the ``</select>`` that closes the select opened before ``start``;
        ``None`` if nothing does or the select holds a tag in :attr:`_SELECT_UNSAFE`."""
        i = start
        while (tag := self._next_tag(i)) is not None:
            _start, end, name, is_end, _closing = tag
            i = end
            if is_end:
                if name == "select":
                    return end
                if name in self._INERT:
                    return None
            elif name == "script":
                closing = self._script_end(end)
                if closing is None:
                    return None
                i = closing[1]
            elif name in self._SELECT_UNSAFE or name in self._RAWTEXT or name in self._RCDATA:
                return None
        return None

    def _scan(self) -> None:
        i, inert = 0, 0  # inert: how many templates are open
        while (tag := self._next_tag(i)) is not None:
            start, end, name, is_end, closing = tag
            i = end
            if is_end:
                if name in self._INERT and inert:
                    inert -= 1
                elif not inert:
                    self.tags.append((start, end, name, True))
                continue
            if name == "plaintext":
                return
            if name in self._FOREIGN or name == "select":
                if closing and name != "select":  # "<svg/>" holds nothing
                    continue
                after = self._select_end(end) if name == "select" else self._foreign_end(end, name)
                if after is None:
                    return
                i = after
            elif name in self._INERT:
                inert += 1
            elif name == "script" or name in self._RAWTEXT or name in self._RCDATA:
                raw = self._script_end(end) if name == "script" else self._raw_end(name, end)
                if raw is None:
                    return
                if not inert:
                    self.tags.append((raw[0], raw[1], name, True))
                i = raw[1]
            elif not inert:
                self.tags.append((start, end, name, False))


#: A page whose tag ends are known, for :func:`check_scanner`: an abrupt comment, a
#: quoted ``>``, a bad character reference, a ``--!>`` comment end, a noscript holding
#: ``<!--``, a double-escaped script, a style holding ``>``, an svg with a CDATA section
#: and a template.
SCANNER_PROBE: Final = (
    b'<html><body><!--> x --><p class="a>b">R&#D</p><!-- <i> --!><b>q</b>'
    b"<noscript><!--</noscript><i>n</i><script><!--\n"
    b'document.write("<script></script>");\n//--></script><style>a>b{}</style>'
    b"<svg><![CDATA[ <p>c</p> ]]><rect/></svg><template><p>t</p></template>"
    b"<p>z</p></body></html>"
)
#: Every ``(start, end, tag, is_end_tag)`` the scanner must record on :data:`SCANNER_PROBE`.
SCANNER_PROBE_TAGS: Final = (
    (0, 6, "html", False),
    (6, 12, "body", False),
    (23, 38, "p", False),
    (42, 46, "p", True),
    (59, 62, "b", False),
    (63, 67, "b", True),
    (81, 92, "noscript", True),
    (92, 95, "i", False),
    (96, 100, "i", True),
    (155, 164, "script", True),
    (176, 184, "style", True),
    (253, 256, "p", False),
    (257, 261, "p", True),
    (261, 268, "body", True),
    (268, 275, "html", True),
)


def check_scanner() -> None:
    """Raise ``RuntimeError`` unless the scanner reads :data:`SCANNER_PROBE` exactly.

    Every recorded tag must match :data:`SCANNER_PROBE_TAGS` to the byte. Run by the
    cell image build and by the tests, so a change of behaviour fails loudly.
    """
    tags = tuple(_TagScanner(SCANNER_PROBE).tags)
    if tags != SCANNER_PROBE_TAGS:
        raise RuntimeError(f"the tag scanner misreads its probe page: {tags}")


def _boundary_offsets(decoded: bytes, fractions: Sequence[float]) -> list[int] | None:
    """Where in ``decoded`` the in-page text for each relative fraction goes.

    The page is tokenised once (:class:`_TagScanner`). The point is the end of the
    first start or end tag whose end is at or after ``floor(len(decoded) * fraction)``
    (inclusive: a tag ending exactly there is used), between the real ``<body>`` start
    tag (its own end counts) and the real last ``</body>``.
    If there is none, just before that ``</body>``. With no real ``</body>`` (an
    unclosed script, comment, plaintext or quote swallowed it) the point is the end of
    the last tag in normal content, which always lies before the swallowing construct.
    ``None`` if the page has no tag in normal content at all: there is no safe place.
    Positions are in ``decoded``; nothing is ever inserted inside a raw-text element,
    comment, tag, attribute value, foreign content (svg, math), template or select.
    """
    tags = _TagScanner(decoded).tags
    opened = next((t for t in tags if t[2] == "body" and not t[3]), None)
    floor = opened[1] if opened is not None else 0
    closes = [t[0] for t in tags if t[2] == "body" and t[3] and t[0] >= floor]
    inside = [t[1] for t in tags if t[1] >= floor]
    if closes:
        close = closes[-1]
    elif inside:
        close = inside[-1]
    else:
        return None
    if opened is None:
        return [close] * len(fractions)
    out: list[int] = []
    for fraction in fractions:
        target = int(len(decoded) * fraction)
        out.append(next((end for end in inside if target <= end <= close), close))
    return out


def plant_into_body(
    body: bytes,
    encoding: str | None,
    payload: bytes,
    *,
    before: bytes | None = None,
    fraction: float | None = None,
) -> tuple[bytes, int, bool]:
    """Insert ``payload`` into a body sent with Content-Encoding ``encoding``.

    The body is decoded (:func:`decode_body`) and ``payload`` is inserted, then the
    result is re-encoded with the same encoding. Where it goes:

    * ``fraction`` given: at the tag boundary the relative offset snaps to
      (:func:`_boundary_offsets`);
    * else before the last occurrence of ``before`` (ASCII case-insensitive);
    * else, or if ``before`` is absent, at the end.

    Returns ``(new wire bytes, offset of payload in the decoded body, True)``. If the
    encoding is unsupported or the body cannot be decoded or re-encoded, returns
    ``(body, -1, False)`` unchanged. The caller must fix the framing headers.
    """
    if not payload:
        raise ValueError("payload must be non-empty")
    if fraction is not None and not 0 <= fraction <= 1:
        raise ValueError("fraction must be between 0 and 1")
    decoded = decode_body(body, encoding)
    if decoded is None:
        return body, -1, False
    if fraction is not None:
        offsets = _boundary_offsets(decoded, [fraction])
        if offsets is None:
            return body, -1, False
        offset = offsets[0]
    else:
        offset = _rfind_ci(decoded, before) if before else -1
        if offset < 0:
            offset = len(decoded)
    wire = encode_body(decoded[:offset] + payload + decoded[offset:], encoding)
    if wire is None:
        return body, -1, False
    return wire, offset, True


def plant_many_into_body(
    body: bytes, encoding: str | None, items: Sequence[tuple[bytes, float]]
) -> tuple[bytes, tuple[int, ...], tuple[int, ...], bool]:
    """Insert several ``(payload, fraction)`` texts into one body, each at its own point.

    Every point is found once, on the body as the app sent it (:func:`_boundary_offsets`),
    so no text can land inside another and a point never depends on the others. The
    texts are then inserted from the end of the page backwards. Texts that share a point
    appear in the order of ``items`` (callers pass them in a fixed order).

    Returns ``(new wire bytes, offsets in the ORIGINAL decoded body, offsets in the NEW
    decoded body, True)``, each tuple in the order of ``items``; or ``(body, (), (),
    False)`` unchanged if the body cannot be decoded or re-encoded.
    """
    if any(not payload for payload, _ in items):
        raise ValueError("payload must be non-empty")
    if any(not 0 <= fraction <= 1 for _, fraction in items):
        raise ValueError("fraction must be between 0 and 1")
    decoded = decode_body(body, encoding)
    if decoded is None:
        return body, (), (), False
    found = _boundary_offsets(decoded, [fraction for _, fraction in items])
    if found is None:
        return body, (), (), False
    original = found
    order = sorted(range(len(items)), key=lambda i: (original[i], i))
    final = [0] * len(items)
    parts: list[bytes] = []
    done = shift = 0
    for i in order:
        parts.append(decoded[done : original[i]])
        final[i] = original[i] + shift
        parts.append(items[i][0])
        shift += len(items[i][0])
        done = original[i]
    parts.append(decoded[done:])
    wire = encode_body(b"".join(parts), encoding)
    if wire is None:
        return body, (), (), False
    return wire, tuple(original), tuple(final), True


def recompute_etag(old: str, wire: bytes) -> str:
    """A new entity tag for a changed body: a quoted digest, keeping a ``W/`` prefix."""
    weak = old.strip().startswith("W/")
    return f'{"W/" if weak else ""}"{hashlib.sha256(wire).hexdigest()[:32]}"'


# --------------------------------------------------------------------------- plants


class SurfaceMarkup:
    """What each surface plants around its rendered text, and which texts it refuses.

    P1 and P7 plant the text as it is. P2-P5 wrap it in HTML (the text is escaped, so
    it is always a plain text node), P6 in a JSON-LD block and P3 in a comment. P8 is a
    header value, not markup.
    """

    _OFFSCREEN: Final = (
        '<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;'
        'overflow:hidden">{}</div>'
    )

    @staticmethod
    def check(surface: Surface, text: str) -> None:
        """Raise ``ValueError`` if ``text`` cannot be planted on ``surface`` as it is."""
        if surface is Surface.P3:
            for closer in ("-->", "--!>", "<!--"):
                if closer in text:
                    raise ValueError(f"a P3 text must not contain {closer!r}")
        elif surface is Surface.P8:
            if not text or text != text.strip() or not text.isascii() or not text.isprintable():
                raise ValueError(
                    "a P8 text must be single-line printable ASCII, "
                    "with no leading or trailing space"
                )
            if len(text.encode("ascii")) > MAX_NOTICE_BYTES:
                raise ValueError(f"a P8 text must be at most {MAX_NOTICE_BYTES} bytes")

    @classmethod
    def render(cls, surface: Surface, text: str) -> bytes:
        """The bytes planted into a body for ``text`` (P8's header value is the text)."""
        escaped = html.escape(text, quote=False)
        if surface is Surface.P2:
            markup = f"<p>{escaped}</p>"
        elif surface is Surface.P3:
            markup = f"<!-- {text} -->"
        elif surface is Surface.P4:
            markup = cls._OFFSCREEN.format(escaped)
        elif surface is Surface.P5:
            markup = f'<div aria-hidden="true">{escaped}</div>'
        elif surface is Surface.P6:
            doc = {"@context": "https://schema.org", "@type": "WebPage", "description": text}
            data = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
            safe = data.replace("<", "\\u003c")  # so a text can never close the script tag
            markup = f'<script type="application/ld+json">{safe}</script>'
        else:
            markup = text
        return markup.encode("utf-8")


@dataclass(frozen=True, slots=True)
class Plant:
    """One placement and the exact text to plant for it."""

    placement: Placement
    content: bytes

    @property
    def payload(self) -> bytes:
        """The bytes that land in the body: :attr:`content` wrapped for its surface."""
        return SurfaceMarkup.render(self.placement.surface, self.content.decode("utf-8"))


@dataclass(frozen=True, slots=True)
class Planted:
    """Where one plant ended up in a decoded response body (``None`` if not planted)."""

    plant: Plant
    #: Page plants (P2-P6): the point in the app's ORIGINAL decoded body the text was
    #: inserted at. Other plants: the offset in the served decoded body.
    offset: int | None
    insert_ok: bool
    #: Page plants: where the text sits in the served decoded body (``None``: same as
    #: ``offset``).
    final: int | None = None


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
    PAGE = "page"
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
    #: P2-P6 and P8 plants, by the path of the page they go on.
    pages: Mapping[str, Action] = field(default_factory=dict)
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
        page = self.pages.get(path)
        if page is not None:
            return page
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


def _check_page_placement(placement: Placement, path: str, text: bytes) -> None:
    """Refuse a P2-P6 or P8 placement whose locator, url, offset or text is not allowed."""
    surface = placement.surface
    where = f"placement {placement.placement_id}: {surface.value}"
    if surface is Surface.P8:
        named = _HEADER_LOCATOR.fullmatch(placement.locator)
        if named is not None and named.group(1).lower() in PROTECTED_HEADERS:
            raise ValueError(f"{where} may never set the protected header {named.group(1)!r}")
    if placement.locator != SURFACE_LOCATORS[surface]:
        raise ValueError(
            f"{where} locator {placement.locator!r} must be {SURFACE_LOCATORS[surface]!r}"
        )
    if path == ROBOTS_PATH:
        raise ValueError(f"{where} cannot use robots.txt")
    if surface in BODY_SURFACES and placement.offset_fraction is None:
        raise ValueError(f"{where} needs an offset_fraction")
    if surface not in BODY_SURFACES and placement.offset_fraction is not None:
        raise ValueError(f"{where} takes no offset_fraction")
    try:
        SurfaceMarkup.check(surface, text.decode("utf-8"))
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}") from exc


def build_plan(
    manifest: RunManifest, contents: Mapping[str, str], *, synthesize_robots: bool = False
) -> InjectionPlan:
    """Validate a manifest and its rendered texts and decide what the injector acts on.

    ``contents`` maps ``placement_id`` to the rendered text; it must cover exactly the
    manifest's placements (so it is empty for a control run). Raises ``ValueError`` on
    any mismatch, unsupported surface or malformed locator.

    ``synthesize_robots`` (set for every run of an experiment that plants P1, in both
    arms) adds a robots action with no plants where the run has none: if the app has
    no robots.txt (404) the injector serves :data:`DEFAULT_ROBOTS_BASE`, exactly the
    base a treated run gets, so the arms' robots.txt differ only by the planted line.
    An app's own robots.txt is then served unchanged.
    """
    _check_content(manifest, contents)
    base_only = Action(ActionKind.ROBOTS) if synthesize_robots else None
    if manifest.arm is Arm.CONTROL:
        return InjectionPlan(arm=Arm.CONTROL, robots=base_only)

    robots: list[Plant] = []
    errors: dict[str, Action] = {}
    pages: dict[str, Action] = {}
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
        elif placement.surface in BODY_SURFACES or placement.surface is Surface.P8:
            _check_page_placement(placement, path, plant.content)
            action = pages.setdefault(path, Action(ActionKind.PAGE))
            if any(p.placement.surface is placement.surface for p in action.plants):
                raise ValueError(
                    f"more than one {placement.surface.value} placement on path {path}"
                )
            pages[path] = Action(ActionKind.PAGE, (*action.plants, plant))
        else:
            raise ValueError(
                f"placement {placement.placement_id}: surface {placement.surface.value} "
                "is not supported by the injector"
            )

    if manifest.tag is None:  # pragma: no cover - RunManifest forbids it for injected
        raise ValueError("injected manifest has no tag")
    prefix = decoy_prefix(manifest.tag)
    if any(under_decoy(p, prefix) for p in errors):
        raise ValueError("a P7 path lies under the decoy path")
    if any(under_decoy(p, prefix) for p in pages):
        raise ValueError("a page placement lies under the decoy path")
    if shared := sorted(set(errors) & set(pages)):
        raise ValueError(f"a P7 placement shares its path with a page placement: {shared}")
    return InjectionPlan(
        arm=Arm.INJECTED,
        robots=Action(ActionKind.ROBOTS, tuple(robots)) if robots else base_only,
        errors=errors,
        pages=pages,
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
