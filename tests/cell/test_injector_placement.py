"""Surfaces P2-P6 and P8: markup, the relative offset rule and the plan (no I/O).

The addon and the pre-flight probe on top of these rules are in
``test_injector_addon.py``.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest

from cell.injector.placement import (
    BODY_SURFACES,
    MAX_NOTICE_BYTES,
    PROTECTED_HEADERS,
    SURFACE_LOCATORS,
    ActionKind,
    Plant,
    SurfaceMarkup,
    build_plan,
    plant_into_body,
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


def test_offset_fraction_snaps_to_tag_boundary() -> None:
    payload = b"<!-- X -->"
    body_open = HTML.index(b"<body>") + len(b"<body>") - 1  # the start tag's own '>'
    close = HTML.index(b"</body>")
    for fraction in (0.0, 0.25, 0.5, 0.75, 0.9, 0.99):
        wire, offset, ok = plant_into_body(HTML, None, payload, fraction=fraction)
        assert ok is True
        target = max(int(len(HTML) * fraction), body_open)
        assert HTML[offset - 1 : offset] == b">"  # a tag boundary
        boundary = HTML.find(b">", target, close)
        assert offset == (boundary + 1 if boundary >= 0 else close)  # the first one at/after
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


def test_body_tag_matching_ignores_case_and_attributes() -> None:
    page = b'<HTML><BODY class="a>b" id=x><p>one</p><p>two</p></BoDy></HTML>'
    start = page.index(b"<BODY")
    _w, offset, ok = plant_into_body(page, None, b"X", fraction=0.0)
    assert ok is True and offset > start
    assert page[offset - 1 : offset] == b">"


def test_look_alike_tags_are_not_the_body_tag() -> None:
    page = b"<html><bodyguard>x</bodyguard><body><p>a</p></body></html>"
    _w, offset, _ok = plant_into_body(page, None, b"X", fraction=0.0)
    assert offset == page.index(b"<body>") + len(b"<body>")


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        (b"<html><p>one</p><p>two</p></body></html>", b"</body>"),  # close only
        (b"plain text with no markup at all", None),  # nothing: the very end
        (b"<p>fragment</p>", None),
        (b"", None),
        (b"<body", None),  # malformed: an unfinished start tag
        (b"<body><p>unclosed", None),  # no close tag: boundary search runs to the end
    ],
)
def test_a_body_with_no_body_tag_pair_still_takes_the_text(
    page: bytes, expected: bytes | None
) -> None:
    wire, offset, ok = plant_into_body(page, None, b"X", fraction=0.5)
    assert ok is True and wire == _at(page, offset, b"X")
    if expected is not None:
        assert offset == page.index(expected)
    elif page.startswith(b"<body><p>"):
        assert page[offset - 1 : offset] == b">"
    else:
        assert offset == len(page)


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
