"""Surfaces P2-P6 and P8: markup, the relative offset rule and the plan (no I/O).

The addon and the pre-flight probe on top of these rules are in
``test_injector_addon.py``.
"""

from __future__ import annotations

import gzip
import json
import re
from html.parser import HTMLParser
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cell.injector.placement import (
    BODY_SURFACES,
    MAX_NOTICE_BYTES,
    PROTECTED_HEADERS,
    SURFACE_LOCATORS,
    ActionKind,
    Plant,
    SurfaceMarkup,
    _boundary_offsets,
    _TagScanner,
    build_plan,
    plant_into_body,
    plant_many_into_body,
)
from control.core.models import Arm, Placement, RunManifest, Surface
from tests.cell.test_injector import (
    P1_ID,
    P1_TEXT,
    P7_ID,
    P7_TEXT,
    TAG,
    _manifest,
    _placement,
    _sha,
)

PAGE = "/page"
TEXT = f"lab test page text {TAG}"
HTML = (
    b"<!doctype html><html><head><title>t</title></head><body>"
    b"<h1>Hello</h1><p>one</p><p>two</p><p>three</p></body></html>"
)

ID_BY_SURFACE = {
    Surface.P2: "pl_p2",
    Surface.P3: "pl_p3",
    Surface.P4: "pl_p4",
    Surface.P5: "pl_p5",
    Surface.P6: "pl_p6",
    Surface.P8: "pl_p8",
}


def page_placement(
    surface: Surface,
    *,
    url: str = PAGE,
    text: str = TEXT,
    locator: str | None = None,
    offset: float | str | None = "default",
) -> tuple[Placement, str]:
    """A placement of an in-page surface and its text; ``offset`` defaults per surface."""
    base = _placement(
        ID_BY_SURFACE[surface], surface, url, locator or SURFACE_LOCATORS[surface], text
    )
    if offset == "default":
        offset = 0.5 if surface in BODY_SURFACES else None
    assert offset is None or isinstance(offset, float)
    return base.model_copy(update={"offset_fraction": offset}), text


def page_manifest(*pairs: tuple[Placement, str]) -> tuple[RunManifest, dict[str, str]]:
    manifest = _manifest(*(p for p, _ in pairs))
    return manifest, {p.placement_id: t for p, t in pairs}


def plan_for(*pairs: tuple[Placement, str]) -> Any:
    manifest, contents = page_manifest(*pairs)
    return build_plan(manifest, contents)


def render(surface: Surface, text: str = TEXT) -> bytes:
    return SurfaceMarkup.render(surface, text)


# --------------------------------------------------------------------------- markup


def test_markup_is_exactly_the_registered_shape_for_each_surface() -> None:
    assert render(Surface.P2) == f"<p>{TEXT}</p>".encode()
    assert render(Surface.P3) == f"<!-- {TEXT} -->".encode()
    assert (
        render(Surface.P4)
        == (
            f'<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;'
            f'overflow:hidden">{TEXT}</div>'
        ).encode()
    )
    assert render(Surface.P5) == f'<div aria-hidden="true">{TEXT}</div>'.encode()
    assert (
        render(Surface.P6)
        == (
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"WebPage","description":"' + TEXT + '"}'
            "</script>"
        ).encode()
    )
    assert render(Surface.P8) == TEXT.encode()  # the header value is the text itself


def test_p4_has_no_aria_hidden_and_p5_has_it() -> None:
    assert b"aria-hidden" not in render(Surface.P4)
    assert b'aria-hidden="true"' in render(Surface.P5)


def test_html_surfaces_escape_the_text_so_it_stays_a_text_node() -> None:
    nasty = f"</div><script>alert(1)</script> & {TAG}"
    for surface in (Surface.P2, Surface.P4, Surface.P5):
        markup = render(surface, nasty).decode()
        assert "<script>" not in markup and "</div><" not in markup.replace("</div>", "", 1)
        assert "&lt;/div&gt;&lt;script&gt;" in markup and "&amp;" in markup and TAG in markup


@pytest.mark.parametrize(
    "text",
    [
        f"</script><script>x</script>{TAG}",  # tries to close the block
        f'quote " backslash \\ newline\n tab\t {TAG}',
        f"non-ascii \u00e9\u4e2d\U0001f600 \u2028 {TAG}",
        TAG,
    ],
)
def test_jsonld_block_always_parses_back_to_the_text(text: str) -> None:
    markup = render(Surface.P6, text).decode()
    assert markup.count("</script>") == 1 and markup.endswith("</script>")  # only our closer
    start = markup.index(">") + 1
    doc = json.loads(markup[start : -len("</script>")])
    assert doc == {"@context": "https://schema.org", "@type": "WebPage", "description": text}
    assert list(doc) == ["@context", "@type", "description"]


@pytest.mark.parametrize("closer", ["-->", "--!>", "<!--", f"a {TAG} --> b"])
def test_p3_text_cannot_close_or_nest_its_comment(closer: str) -> None:
    with pytest.raises(ValueError, match="P3"):
        SurfaceMarkup.check(Surface.P3, closer)
    SurfaceMarkup.check(Surface.P3, f"a -- dash and > and < are fine {TAG}")


def test_p8_rejects_multiline_and_over_512_bytes() -> None:
    SurfaceMarkup.check(Surface.P8, "x" * MAX_NOTICE_BYTES)  # exactly the limit
    bad = [
        "x" * (MAX_NOTICE_BYTES + 1),
        f"line one\nline two {TAG}",
        f"carriage\rreturn {TAG}",
        f"nul\x00byte {TAG}",
        f"tab\tinside {TAG}",
        f"del\x7fbyte {TAG}",
        f"café {TAG}",  # non-ASCII: not a safe header value
        f"\U0001f600 {TAG}",
        f" leading space {TAG}",
        f"trailing space {TAG} ",
        "",
        " ",
    ]
    for text in bad:
        with pytest.raises(ValueError, match="P8"):
            SurfaceMarkup.check(Surface.P8, text)


def test_p8_rejects_multiline_text_in_a_plan_too() -> None:
    placement, text = page_placement(Surface.P8, text=f"one\r\nX-Evil: 1 {TAG}")
    with pytest.raises(ValueError, match="P8"):
        plan_for((placement, text))


def test_other_surfaces_accept_any_text_that_parses() -> None:
    for surface in (Surface.P2, Surface.P4, Surface.P5, Surface.P6, Surface.P1, Surface.P7):
        SurfaceMarkup.check(surface, f"-->\né\x00{TAG}")


# --------------------------------------------------------------------------- offset rule


def _at(decoded: bytes, offset: int, payload: bytes) -> bytes:
    return decoded[:offset] + payload + decoded[offset:]


def _tag_ends(page: bytes) -> list[int]:
    """End offsets of every plain tag of a page without raw text, comments or odd quoting."""
    return [m.end() for m in re.finditer(rb"</?[a-zA-Z][^<>]*>", page)]


def test_offset_fraction_snaps_to_tag_boundary() -> None:
    payload = b"<!-- X -->"
    body_open = HTML.index(b"<body>") + len(b"<body>")
    close = HTML.index(b"</body>")
    ends = [e for e in _tag_ends(HTML) if body_open <= e <= close]
    for fraction in (0.0, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0):
        wire, offset, ok = plant_into_body(HTML, None, payload, fraction=fraction)
        assert ok is True
        target = int(len(HTML) * fraction)
        expected = next((e for e in ends if e > target), close)  # first tag end after target
        assert offset == expected
        assert wire == _at(HTML, offset, payload)


def test_fraction_zero_goes_after_the_body_start_tag_not_into_the_head() -> None:
    _wire, offset, _ok = plant_into_body(HTML, None, b"X", fraction=0.0)
    assert offset == HTML.index(b"<body>") + len(b"<body>")


def test_fraction_one_or_no_boundary_after_it_goes_before_body_close() -> None:
    close = HTML.index(b"</body>")
    assert plant_into_body(HTML, None, b"X", fraction=1.0)[1] == close
    page = b"<html><body>some text with no tags after the start</body></html>"
    assert plant_into_body(page, None, b"X", fraction=0.5)[1] == page.index(b"</body>")


def test_boundary_inside_the_closing_body_tag_is_not_used() -> None:
    page = b"<html><body>text</body></html>"
    # the first '>' after the target is the one that ends </body>: that is past the limit
    assert plant_into_body(page, None, b"X", fraction=0.6)[1] == page.index(b"</body>")


def test_body_tag_matching_ignores_case_and_a_greater_than_in_its_attributes() -> None:
    page = b'<HTML><BODY class="a>b" id=x><p>one</p><p>two</p></BoDy></HTML>'
    after_body = page.index(b" id=x>") + len(b" id=x>")  # the real end of the start tag
    _w, offset, ok = plant_into_body(page, None, b"X", fraction=0.0)
    assert ok is True and offset == after_body
    assert plant_into_body(page, None, b"X", fraction=1.0)[1] == page.index(b"</BoDy>")


def test_look_alike_tags_are_not_the_body_tag() -> None:
    page = b"<html><bodyguard>x</bodyguard><body><p>a</p></body></html>"
    _w, offset, _ok = plant_into_body(page, None, b"X", fraction=0.0)
    assert offset == page.index(b"<body>") + len(b"<body>")


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        (b"<html><p>one</p><p>two</p></body></html>", b"</body>"),  # close only
        (b"<p>fragment</p>", len(b"<p>fragment</p>")),  # the end of its last tag
        (b"<body><p>unclosed", len(b"<body><p>")),  # no close: after the last tag
        (b"text<b>x</b> tail text", len(b"text<b>x</b>")),  # trailing text stays after
        (b"plain text with no markup at all", None),  # no tag: no safe place
        (b"", None),
        (b"<body", None),  # malformed: an unfinished start tag
    ],
)
def test_a_page_without_a_body_pair_takes_the_text_at_a_real_tag_end_or_not_at_all(
    page: bytes, expected: bytes | int | None
) -> None:
    wire, offset, ok = plant_into_body(page, None, b"X", fraction=0.5)
    if expected is None:
        assert (wire, offset, ok) == (page, -1, False)  # never appended blindly
        return
    assert ok is True and wire == _at(page, offset, b"X")
    assert offset == (page.index(expected) if isinstance(expected, bytes) else expected)


def test_body_close_before_body_open_is_ignored_as_a_limit() -> None:
    page = b"</body><html><body><p>x</p><p>y</p>"
    _w, offset, ok = plant_into_body(page, None, b"Z", fraction=0.9)
    assert ok is True and offset <= len(page)
    assert offset > page.index(b"<body>")


def test_fraction_out_of_range_is_refused() -> None:
    for bad in (-0.1, 1.0001, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="fraction"):
            plant_into_body(HTML, None, b"X", fraction=bad)


def test_fraction_takes_precedence_over_before() -> None:
    _w, offset, _ok = plant_into_body(HTML, None, b"X", before=b"<h1>", fraction=1.0)
    assert offset == HTML.index(b"</body>")


@pytest.mark.parametrize("encoding", ["gzip", "br", "zstd"])
@pytest.mark.parametrize("surface", sorted(BODY_SURFACES))
def test_every_body_surface_plants_into_compressed_pages(surface: Surface, encoding: str) -> None:
    codec = {
        "gzip": gzip,
        "br": pytest.importorskip("brotli"),
        "zstd": pytest.importorskip("backports.zstd"),
    }[encoding]
    payload = render(surface)
    wire, offset, ok = plant_into_body(codec.compress(HTML), encoding, payload, fraction=0.5)
    assert ok is True
    decoded = codec.decompress(wire)
    assert decoded[offset : offset + len(payload)] == payload
    assert decoded == _at(HTML, offset, payload)


def test_stacked_or_unknown_encodings_and_corrupt_bodies_are_left_alone() -> None:
    for encoding, body in (
        ("gzip, br", gzip.compress(HTML)),
        ("compress", HTML),
        ("gzip", b"not gzip at all"),
        ("br", b"\x00\x01\x02 garbage"),
    ):
        assert plant_into_body(body, encoding, b"X", fraction=0.5) == (body, -1, False)


def test_a_huge_body_is_planted_at_the_right_boundary() -> None:
    chunk = b"<p>0123456789abcdef0123456789abcdef</p>\n"
    page = b"<html><body>" + chunk * 100_000 + b"</body></html>"  # about 4 MB
    wire, offset, ok = plant_into_body(page, None, b"<!--X-->", fraction=0.5)
    assert ok is True
    target = int(len(page) * 0.5)
    assert page.find(b">", target) + 1 == offset
    assert len(wire) == len(page) + len(b"<!--X-->")


def test_a_body_that_is_all_one_long_tagless_run_goes_before_the_close() -> None:
    page = b"<html><body>" + b"a" * 200_000 + b"</body></html>"
    assert plant_into_body(page, None, b"X", fraction=0.1)[1] == page.index(b"</body>")


def test_non_ascii_and_binary_bytes_do_not_confuse_the_offset() -> None:
    page = "<html><body><p>café 中文</p><p>\U0001f600</p>\x00\xff</body></html>".encode(
        "utf-8", "surrogateescape"
    )
    wire, offset, ok = plant_into_body(page, None, b"X", fraction=0.4)
    assert ok is True and wire == _at(page, offset, b"X")
    assert page[offset - 1 : offset] == b">"


def test_planting_needs_a_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        plant_into_body(HTML, None, b"", fraction=0.5)


# --------------------------------------------------------------------------- the plan


def test_each_locator_builds_a_page_action() -> None:
    for surface in (*sorted(BODY_SURFACES), Surface.P8):
        placement, text = page_placement(surface)
        plan = plan_for((placement, text))
        action = plan.match("GET", PAGE + "?x=1")
        assert action is not None and action.kind is ActionKind.PAGE
        (plant,) = action.plants
        assert plant.placement.surface is surface and plant.content == text.encode()
        assert plan.match("GET", "/other") is None


def test_locators_are_the_registered_strings() -> None:
    assert SURFACE_LOCATORS == {
        Surface.P2: "html:body",
        Surface.P3: "html:comment",
        Surface.P4: "html:offscreen",
        Surface.P5: "html:aria-hidden",
        Surface.P6: "jsonld:description",
        Surface.P8: "header:x-security-notice",
    }


def test_surfaces_share_a_page_and_keep_manifest_order() -> None:
    pairs = [page_placement(s) for s in (Surface.P5, Surface.P3, Surface.P8, Surface.P6)]
    plan = plan_for(*pairs)
    action = plan.match("GET", PAGE)
    assert action is not None
    assert [p.placement.surface for p in action.plants] == [
        Surface.P5,
        Surface.P3,
        Surface.P8,
        Surface.P6,
    ]


def test_page_placements_on_different_paths_get_their_own_actions() -> None:
    a = page_placement(Surface.P3, url="/a")
    b = page_placement(Surface.P4, url="/b")
    plan = plan_for(a, b)
    assert plan.match("GET", "/a") is not plan.match("GET", "/b")
    assert set(plan.pages) == {"/a", "/b"}


def test_only_get_is_ever_acted_on() -> None:
    plan = plan_for(page_placement(Surface.P3), page_placement(Surface.P8, url="/h"))
    for method in ("HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "get "):
        assert plan.match(method, PAGE) is None
        assert plan.match(method, "/h") is None
    assert plan.match("get", PAGE) is not None  # method names are case-insensitive


def test_control_arm_plants_nothing_for_new_surfaces() -> None:
    control = _manifest(arm=Arm.CONTROL)
    plan = build_plan(control, {})
    assert plan.arm is Arm.CONTROL and not plan.pages and not plan.errors
    for path in (PAGE, "/h", "/robots.txt", "/.env"):
        assert plan.match("GET", path) is None
    # the model itself forbids a control manifest from carrying a placement
    placement, _ = page_placement(Surface.P3)
    with pytest.raises(ValueError, match="control"):
        RunManifest.model_validate({**control.model_dump(), "placements": [placement.model_dump()]})


@pytest.mark.parametrize("surface", [*sorted(BODY_SURFACES), Surface.P8])
def test_a_wrong_locator_is_refused(surface: Surface) -> None:
    placement, text = page_placement(surface, locator="html:something-else")
    with pytest.raises(ValueError, match="locator"):
        plan_for((placement, text))


@pytest.mark.parametrize("name", sorted(PROTECTED_HEADERS))
def test_p8_never_touches_protected_headers(name: str) -> None:
    for spelled in (name, name.upper(), name.title()):
        placement, text = page_placement(Surface.P8, locator=f"header:{spelled}")
        with pytest.raises(ValueError, match="protected header"):
            plan_for((placement, text))


@pytest.mark.parametrize(
    "locator", ["header:x-other", "header:", "header:x security", "header:x-security-notice2", "x"]
)
def test_p8_only_sets_the_notice_header(locator: str) -> None:
    placement, text = page_placement(Surface.P8, locator=locator)
    with pytest.raises(ValueError, match="locator"):
        plan_for((placement, text))


def test_the_registered_protected_headers_are_exactly_these() -> None:
    assert {
        "content-type",
        "content-security-policy",
        "set-cookie",
        "etag",
        "last-modified",
        "cache-control",
        "content-length",
        "content-encoding",
    } == PROTECTED_HEADERS


def test_offset_fraction_is_required_for_body_surfaces_and_forbidden_for_p8() -> None:
    for surface in sorted(BODY_SURFACES):
        placement, text = page_placement(surface, offset=None)
        with pytest.raises(ValueError, match="needs an offset_fraction"):
            plan_for((placement, text))
    placement, text = page_placement(Surface.P8, offset=0.5)
    with pytest.raises(ValueError, match="takes no offset_fraction"):
        plan_for((placement, text))


def test_page_placements_cannot_use_robots_txt_or_the_decoy_path() -> None:
    for surface in (Surface.P3, Surface.P8):
        placement, text = page_placement(surface, url="/robots.txt")
        with pytest.raises(ValueError, match=r"robots\.txt"):
            plan_for((placement, text))
        placement, text = page_placement(surface, url=f"/x-{TAG}/deep")
        with pytest.raises(ValueError, match="decoy"):
            plan_for((placement, text))


def test_a_page_cannot_share_its_path_with_p7() -> None:
    p7 = _placement(P7_ID, Surface.P7, PAGE, "error:404", P7_TEXT)
    manifest = _manifest(p7, page_placement(Surface.P3)[0])
    with pytest.raises(ValueError, match="shares its path"):
        build_plan(manifest, {P7_ID: P7_TEXT, "pl_p3": TEXT})


def test_two_placements_of_one_surface_on_one_path_are_refused() -> None:
    one, text = page_placement(Surface.P3)
    two = one.model_copy(update={"placement_id": "pl_p3b"})
    manifest = _manifest(one, two)
    with pytest.raises(ValueError, match="more than one P3"):
        build_plan(manifest, {"pl_p3": text, "pl_p3b": text})


def test_p1_and_p7_still_plan_beside_page_surfaces() -> None:
    p1 = _placement(P1_ID, Surface.P1, "/robots.txt", "robots.txt:append", P1_TEXT)
    p7 = _placement(P7_ID, Surface.P7, "/.env", "error:404", P7_TEXT)
    p3, text = page_placement(Surface.P3)
    manifest = _manifest(p1, p7, p3)
    plan = build_plan(manifest, {P1_ID: P1_TEXT, P7_ID: P7_TEXT, p3.placement_id: text})
    assert plan.robots is not None and "/.env" in plan.errors and PAGE in plan.pages


def test_content_must_still_match_its_hash_and_carry_the_tag() -> None:
    placement, text = page_placement(Surface.P3)
    manifest = _manifest(placement)
    with pytest.raises(ValueError, match="content_sha256"):
        build_plan(manifest, {placement.placement_id: text + " tampered"})
    no_tag = "no tag here"
    bare = placement.model_copy(update={"content_sha256": _sha(no_tag.encode())})
    with pytest.raises(ValueError, match="tag"):
        build_plan(_manifest(bare), {bare.placement_id: no_tag})


def test_plant_payload_wraps_page_text_and_leaves_p1_and_p7_alone() -> None:
    placement, text = page_placement(Surface.P3)
    assert Plant(placement, text.encode()).payload == f"<!-- {text} -->".encode()
    p7 = _placement(P7_ID, Surface.P7, "/.env", "error:404", P7_TEXT)
    assert Plant(p7, P7_TEXT.encode()).payload == P7_TEXT.encode()


# --------------------------------------------------------------------------- forbidden contexts

# A page with one forbidden context ahead of the body text. The text planted must never
# land inside it, whatever the fraction: it goes at a real tag end or before </body>.
CONTEXTS = {
    "script": b"<script>if (a > b) { x = '<p>' } // >>> </p> ></script>",
    "script-in-head": b"<head><script>var s = '<body>'; if (a > b) {}</script></head>",
    "style": b"<style>p > a { color: red } /* > <b> */</style>",
    "textarea": b"<textarea>a > b <p>not a tag</p> ></textarea>",
    "title": b"<title>x > y <i>no</i> ></title>",
    "comment": b"<!-- a > b <p>nope</p> -->",
    "comment-with-fake-body": b"<!-- <body> <p>x</p> </body> -->",
    "attribute": b'<a href="/x" title="x>y" data-z=\'>>\'>link</a>',
    "unquoted-then-quoted": b'<img alt="a > b" src=x>',
}


def _forbidden_spans(page: bytes) -> list[tuple[int, int]]:
    """Byte spans a plant must stay out of: raw-text elements, comments, attribute values."""
    spans = []
    for pattern in (
        rb"<script\b[^>]*>(.*?)</script>",
        rb"<style\b[^>]*>(.*?)</style>",
        rb"<textarea\b[^>]*>(.*?)</textarea>",
        rb"<title\b[^>]*>(.*?)</title>",
        rb"<!--(.*?)-->",
    ):
        spans += [m.span(1) for m in re.finditer(pattern, page, re.DOTALL)]
    spans += [m.span() for m in re.finditer(rb'="[^"]*"|=\'[^\']*\'', page)]
    return spans


def _inside(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < offset < end for start, end in spans)


@pytest.mark.parametrize("name", sorted(CONTEXTS))
def test_text_never_lands_inside_a_forbidden_context(name: str) -> None:
    context = CONTEXTS[name]
    page = b"<html><body>" + context + b"<p>one</p><p>two</p></body></html>"
    if name == "script-in-head":
        page = b"<html>" + context + b"<body><p>one</p><p>two</p></body></html>"
    spans = _forbidden_spans(page)
    body_open = page.index(b"<body>") + len(b"<body>")
    for tenth in range(11):
        _wire, offset, ok = plant_into_body(page, None, b"X", fraction=tenth / 10)
        assert ok is True
        assert not _inside(offset, spans), (name, tenth, page[:offset])
        assert body_open <= offset <= page.rindex(b"</body>")


def test_a_greater_than_in_a_script_is_not_a_boundary() -> None:
    page = b"<html><body><script>if (a > b) { go() }</script><p>x</p></body></html>"
    script_start = page.index(b"<script>") + len(b"<script>")
    script_end = page.index(b"</script>")
    for fraction in (0.0, 0.2, 0.3, 0.4):
        offset = plant_into_body(page, None, b"X", fraction=fraction)[1]
        assert not script_start <= offset <= script_end - 1 or offset == script_end


@pytest.mark.parametrize(
    "tail",
    [
        b"<!-- todo <p>b</p></body></html>",  # an unterminated comment
        b"<script>var x = 1;</body></html>",  # an unclosed script
        b"<plaintext>text</body></html>",  # plaintext never ends
        b"<style>a { b: c }</body></html>",
        b'<a href="never closed></body></html>',  # an unterminated attribute quote
        b"<textarea>text</body></html>",
        b"<title>t</body></html>",
    ],
)
@pytest.mark.parametrize("fraction", [0.0, 0.5, 0.9, 1.0])
def test_an_unterminated_construct_swallows_the_close_so_the_text_goes_before_it(
    tail: bytes, fraction: float
) -> None:
    head = b"<html><body><p>a</p>"
    page = head + tail
    wire, offset, ok = plant_into_body(page, None, b"X", fraction=fraction)
    assert ok is True and wire == _at(page, offset, b"X")
    # a browser reads everything from the construct on as its content: stay before it
    assert offset <= len(head)
    assert page[offset - 1 : offset] == b">"


def test_the_body_tag_inside_a_comment_or_script_is_not_the_body() -> None:
    page = (
        b"<html><head><!-- <body> --><script>document.write('<body>')</script></head>"
        b"<body><p>real</p></body></html>"
    )
    real = page.index(b"<body><p>real") + len(b"<body>")
    assert plant_into_body(page, None, b"X", fraction=0.0)[1] == real
    assert plant_into_body(page, None, b"X", fraction=1.0)[1] == page.rindex(b"</body>")


def test_a_closing_body_tag_inside_a_comment_or_script_is_not_the_close() -> None:
    page = (
        b"<html><body><p>a</p><script>x = '</body>'</script><!-- </body> --><p>b</p></body></html>"
    )
    assert plant_into_body(page, None, b"X", fraction=1.0)[1] == page.rindex(b"</body>")


def test_offsets_count_bytes_not_characters_in_a_non_ascii_page() -> None:
    page = "<html><body><p>caf\u00e9 \u4e2d\u6587 \U0001f600</p><p>two</p></body></html>".encode()
    wire, offset, ok = plant_into_body(page, None, b"X", fraction=0.4)
    assert ok is True and wire == _at(page, offset, b"X")
    assert page[offset - 1 : offset] == b">"
    assert offset == page.index(b"</p>") + len(b"</p>")  # the first tag end after 40% of the bytes
    assert plant_into_body(page, None, b"X", fraction=1.0)[1] == page.index(b"</body>")


def test_multi_line_pages_map_their_positions_to_bytes() -> None:
    page = b"<html>\n<body>\r\n<p>a</p>\n\n<p>b</p>\n<p>c</p>\n</body>\n</html>\n"
    body_open = page.index(b"<body>") + len(b"<body>")
    ends = [e for e in _tag_ends(page) if body_open <= e <= page.index(b"</body>")]
    for fraction in (0.0, 0.3, 0.5, 0.7, 1.0):
        offset = plant_into_body(page, None, b"X", fraction=fraction)[1]
        target = int(len(page) * fraction)
        assert offset == next((e for e in ends if e > target), page.index(b"</body>"))


@pytest.mark.parametrize(
    "junk", [b"<", b"<<<", b"<a", b'<a b="', b"<!--", b"<![CDATA[", b"</", b"<?x"]
)
def test_unterminated_markup_is_never_planted_into(junk: bytes) -> None:
    """Whatever the junk is, the text lands at the end of a real tag before it, or nowhere."""
    for page in (b"<html><body><p>a</p>" + junk, junk + b"<body><p>a</p></body>", junk):
        for fraction in (0.0, 0.5, 1.0):
            wire, offset, ok = plant_into_body(page, None, b"X", fraction=fraction)
            if not ok:
                assert (wire, offset) == (page, -1)
                continue
            assert wire == _at(page, offset, b"X")
            assert re.search(rb"<[^<>]*>\Z", page[:offset]), page[:offset]  # right after a tag
            if page.endswith(junk) and not page.startswith(junk):
                assert offset <= len(page) - len(junk)  # never past the junk


# --------------------------------------------------------------------------- tag ends


# the exact pages that put plants inside a tag, a style or a list in the first review
AMPERSAND_PAGES = [
    b"<html><body><h1>R&#D</h1><div><span>row</span></div><p>x</p><style>a{b:c;}</style>"
    b"</body></html>",
    b"<html><body><p>Q&#A; see FAQ</p><ul><li>one</li><li>two</li></ul><p>end</p></body></html>",
    b"<p>Q&#A; see FAQ</p><ul><li>x</li></ul>",
]


def _ends_a_tag(prefix: bytes) -> bool:
    """Whether ``prefix`` ends with a whole start or end tag (quoted ``>`` allowed)."""
    return (
        re.search(rb"""</?[a-zA-Z][^<>"']*(?:(?:"[^"]*"|'[^']*')[^<>"']*)*>\Z""", prefix)
        is not None
    )


@pytest.mark.parametrize("page", AMPERSAND_PAGES)
def test_a_bad_character_reference_does_not_shift_later_tag_ends(page: bytes) -> None:
    for tenth in range(11):
        wire, offset, ok = plant_into_body(page, None, b"|PLANT|", fraction=tenth / 10)
        assert ok is True
        assert _ends_a_tag(page[:offset]), (tenth, page[:offset])
        assert wire == _at(page, offset, b"|PLANT|")


def test_the_style_in_the_first_probe_is_never_split() -> None:
    page = AMPERSAND_PAGES[0]
    inside = range(page.index(b"<style>") + len(b"<style>"), page.index(b"</style>") + 1)
    for tenth in range(11):
        assert plant_into_body(page, None, b"X", fraction=tenth / 10)[1] not in inside


@pytest.mark.parametrize(
    "page",
    [
        b'<body><p class="x>y">a</p class="x>y"><p>b</p><p>c</p></body>',
        b"<body><p id='a>b'>a</p id='a>b'><p>b</p></body>",
        b'<body><div></div title="x>y"><p>b</p></body>',
    ],
)
def test_an_end_tag_with_a_quoted_greater_than_ends_where_the_parser_says(page: bytes) -> None:
    for tenth in range(11):
        offset = plant_into_body(page, None, b"X", fraction=tenth / 10)[1]
        assert _ends_a_tag(page[:offset]), page[:offset]


@pytest.mark.parametrize(
    "page",
    [
        b"<p>a</p><iframe><p>n</p></iframe><p>z</p>",
        b"<p>a</p><xmp><p>n</p></xmp><p>z</p>",
        b"<p>a</p><noembed><p>n</p></noembed><p>z</p>",
        b"<p>a</p><noframes><p>n</p></noframes><p>z</p>",
        b"<p>a</p><noscript><p>n</p></noscript><p>z</p>",
        b"<p>a</p><plaintext><p>n</p><p>z</p>",
        b"<p>a</p><textarea><p>n</p></textarea><p>z</p>",
        b"<p>a</p><title><p>n</p></title><p>z</p>",
    ],
)
def test_raw_text_and_non_rendered_elements_are_never_planted_into(page: bytes) -> None:
    name = re.search(rb"<(iframe|xmp|noembed|noframes|noscript|plaintext|textarea|title)>", page)
    assert name is not None
    start = page.index(name.group(0)) + len(name.group(0))
    end = page.find(b"</" + name.group(1) + b">")
    end = len(page) if end < 0 else end
    for tenth in range(11):
        offset = plant_into_body(page, None, b"X", fraction=tenth / 10)[1]
        assert not start <= offset <= end, (name.group(1), tenth, page[:offset])
        assert _ends_a_tag(page[:offset])


def test_the_html_parser_behaviour_the_scanner_relies_on_has_not_drifted() -> None:
    """The cell image's Python patch release may differ from this host's: fail loudly."""
    assert {"script", "style"} <= set(HTMLParser.CDATA_CONTENT_ELEMENTS)
    assert {"textarea", "title"} <= set(getattr(HTMLParser, "RCDATA_CONTENT_ELEMENTS", ()))
    assert {"script", "style", "textarea", "title", "xmp", "iframe", "noscript"} <= _TagScanner._RAW

    def tags(page: bytes) -> list[tuple[str, bool]]:
        return [(t[2], t[3]) for t in _TagScanner(page).tags]

    assert tags(b"<p>a</p>") == [("p", False), ("p", True)]
    assert tags(b"<!-- x <p>y</p> --><b>") == [("b", False)]
    assert tags(b"<script>if (a > b) {}</script><i>") == [("script", True), ("i", False)]
    assert tags(b"<textarea><p>x</p></textarea>") == [("textarea", True)]
    assert tags(b"<plaintext><p>x</p></plaintext>") == []
    assert tags(b"<p>a</p><!-- never closed <p>b</p>") == [("p", False), ("p", True)]
    assert tags(b"<p>a</p><script>never closed <p>b</p>") == [("p", False), ("p", True)]
    # an end tag's end is the parser's own, even after an invalid character reference
    page = b"<h1>R&#D</h1><div><span>x</span></div><style>a{b:c;}</style>"
    for _start, end, tag, is_end in _TagScanner(page).tags:
        assert page[:end].endswith(b">"), (tag, is_end, page[:end])
        assert _ends_a_tag(page[:end])
    assert [page[: t[1]][-8:] for t in _TagScanner(page).tags][-1] == b"</style>"


# --------------------------------------------------------------------------- property test

_TEXT = st.sampled_from(
    [b"hello", b" a > b ", b"R&#D", b"Q&#A; see FAQ", b"&amp;", b"&#", b"&", b";", b"&#x;", b"\n"]
)
_TAGS = st.sampled_from(
    [b"<p>", b"</p>", b'<a href="x>y">', b"</a>", b'</p class="x>y">', b"<br/>", b"<b id='q>'>"]
)
_COMMENT = st.sampled_from([b"<!-- a > b <p> -->", b"<!---->", b"<!-- &#D; -->"])
_RAW_NAMES = st.sampled_from(
    [b"script", b"style", b"textarea", b"title", b"xmp", b"iframe", b"noembed", b"noframes"]
)
_RAW_CONTENT = st.sampled_from(
    [b"a > b", b"<p>", b"if (x) { y = '<b>' }", b"&#D;", b"<!-- not a comment ->", b"x;"]
)


@st.composite
def _documents(draw: Any) -> tuple[bytes, set[int]]:
    """A page and the offsets that are safe: right after a tag in normal content."""
    page = b"<html><body>"
    safe = {len(page)}  # the body start tag's own end
    for _ in range(draw(st.integers(0, 14))):
        kind = draw(st.sampled_from(["text", "tag", "tag", "comment", "raw"]))
        if kind == "text":
            page += draw(_TEXT)
        elif kind == "tag":
            page += draw(_TAGS)
            safe.add(len(page))
        elif kind == "comment":
            page += draw(_COMMENT)
        else:
            name = draw(_RAW_NAMES)
            page += b"<" + name + b">" + draw(_RAW_CONTENT) + b"</" + name + b">"
            safe.add(len(page))  # only the end of the closing tag is in normal content
    safe.add(len(page))  # just before </body>
    return page + b"</body></html>", safe


@settings(max_examples=300, deadline=None)
@given(doc=_documents(), fractions=st.lists(st.floats(0, 1), min_size=1, max_size=6))
def test_every_recorded_boundary_is_the_end_of_a_real_tag_in_normal_content(
    doc: tuple[bytes, set[int]], fractions: list[float]
) -> None:
    page, safe = doc
    offsets = _boundary_offsets(page, fractions)
    assert offsets is not None
    for fraction, offset in zip(fractions, offsets, strict=True):
        assert offset in safe, (fraction, page[:offset], page[offset:])
        assert offset >= page.index(b"<body>") + len(b"<body>")
        assert offset <= page.index(b"</body>")
    # and nothing the scanner records is ever inside a raw element or comment
    for _start, end, _tag, _is_end in _TagScanner(page).tags:
        assert end in safe or end > page.index(b"</body>") or page[:end].endswith(b"<html>")


# --------------------------------------------------------------------------- several texts at once

PAGE_FOR_MANY = (
    b"<html><body><h1>t</h1><p>one</p><p>two</p><p>three</p><p>four</p><p>five</p>"
    b"<p>six</p></body></html>"
)


def test_several_texts_are_placed_on_the_original_page_and_never_nest() -> None:
    # every text holds '>' and '<', the characters that used to confuse the next boundary
    items = [
        (f"<p>a > b {i} </p><!-- > -->".encode(), f)
        for i, f in enumerate((0.5, 0.5, 0.5, 0.0, 1.0))
    ]
    wire, original, final, ok = plant_many_into_body(PAGE_FOR_MANY, None, items)
    assert ok is True
    assert wire.count(b"<!-- > -->") == 5
    for (payload, _f), at, now in zip(items, original, final, strict=True):
        assert wire[now : now + len(payload)] == payload  # each text whole, in one piece
        assert PAGE_FOR_MANY[at - 1 : at] in (b">", b"")
    removed = wire
    for payload, _f in items:
        removed = removed.replace(payload, b"", 1)
    assert removed == PAGE_FOR_MANY  # nothing else changed
    for i in range(len(items)):  # none sits inside another
        for j, (other, _g) in enumerate(items):
            if i != j:
                assert not final[j] < final[i] < final[j] + len(other)


def test_offsets_are_on_the_original_body_and_do_not_depend_on_the_order_given() -> None:
    items = [(b"<!--A-->", 0.2), (b"<!--B-->", 0.6), (b"<!--C-->", 1.0), (b"<!--D-->", 0.0)]
    _w, original, _f, _ok = plant_many_into_body(PAGE_FOR_MANY, None, items)
    for order in ([3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]):
        shuffled = [items[i] for i in order]
        _w2, original2, _f2, _ok2 = plant_many_into_body(PAGE_FOR_MANY, None, shuffled)
        assert [original2[order.index(i)] for i in range(4)] == list(original)
    # each offset is what the single-text rule gives on the untouched page
    for (payload, fraction), at in zip(items, original, strict=True):
        assert plant_into_body(PAGE_FOR_MANY, None, payload, fraction=fraction)[1] == at


def test_texts_sharing_a_point_keep_the_order_given() -> None:
    items = [(b"<!--1-->", 0.5), (b"<!--2-->", 0.5), (b"<!--3-->", 0.5)]
    wire, original, final, _ok = plant_many_into_body(PAGE_FOR_MANY, None, items)
    assert len(set(original)) == 1
    assert wire[final[0] : final[0] + 24] == b"<!--1--><!--2--><!--3-->"
    assert list(final) == [original[0], original[0] + 8, original[0] + 16]


@pytest.mark.parametrize("encoding", ["gzip", "br", "zstd"])
def test_several_texts_into_compressed_pages(encoding: str) -> None:
    codec = {
        "gzip": gzip,
        "br": pytest.importorskip("brotli"),
        "zstd": pytest.importorskip("backports.zstd"),
    }[encoding]
    items = [(b"<!--A-->", 0.3), (b"<!--B-->", 0.9)]
    wire, original, final, ok = plant_many_into_body(codec.compress(PAGE_FOR_MANY), encoding, items)
    assert ok is True
    decoded = codec.decompress(wire)
    for (payload, _f), now in zip(items, final, strict=True):
        assert decoded[now : now + len(payload)] == payload
    assert len(original) == 2


def test_several_texts_refuse_bad_input_and_leave_bad_bodies_alone() -> None:
    assert plant_many_into_body(b"junk", "gzip", [(b"X", 0.5)]) == (b"junk", (), (), False)
    assert plant_many_into_body(b"junk", "gzip, br", [(b"X", 0.5)]) == (b"junk", (), (), False)
    with pytest.raises(ValueError, match="payload"):
        plant_many_into_body(PAGE_FOR_MANY, None, [(b"", 0.5)])
    with pytest.raises(ValueError, match="fraction"):
        plant_many_into_body(PAGE_FOR_MANY, None, [(b"X", 1.5)])
    wire, original, final, ok = plant_many_into_body(PAGE_FOR_MANY, None, [])
    assert (wire, original, final, ok) == (PAGE_FOR_MANY, (), (), True)
