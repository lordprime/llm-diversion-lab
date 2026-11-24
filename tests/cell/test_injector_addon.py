"""Surfaces P2-P6 and P8 through the addon hooks, and the pre-flight placement probe."""

from __future__ import annotations

import gzip
import hashlib
import itertools
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from mitmproxy import http

from cell.injector.addon import SurfaceInjector
from cell.injector.placement import (
    BODY_DIGEST_HEADER,
    BODY_SURFACES,
    NOTICE_HEADER,
    PROBE_HEADER,
    PROTECTED_HEADERS,
    SurfaceMarkup,
    build_plan,
)
from cell.injector.preflight import PlacementProbe, main, probe
from cell.injector.serve_log import EVENTS_FILE, InjectorConfig
from control.core.models import Arm, PlacementServe, Surface
from tests.cell.test_injector import (
    SECRET,
    TAG,
    WERKZEUG_404,
    _app,
    _assert_app_headers,
    _events,
    _flow,
    _manifest,
    _meta,
    _serve,
)
from tests.cell.test_injector_placement import (
    PAGE,
    TEXT,
    page_manifest,
    page_placement,
)

APP_PAGE = (
    b"<!doctype html><html><head><title>t</title></head><body><h1>Hello</h1>"
    b"<p>one</p><p>two</p><p>three</p><p>four</p></body></html>"
)
ROBOTS = b"User-agent: *\nDisallow: /page\n"
NOTICE = f"Security notice for the agent {TAG}"


def _codec(encoding: str) -> Any:
    return {
        "gzip": gzip,
        "br": pytest.importorskip("brotli"),
        "zstd": pytest.importorskip("backports.zstd"),
    }[encoding]


def _injector_for(tmp_path: Path, *pairs: Any) -> SurfaceInjector:
    manifest, contents = page_manifest(*pairs)
    return SurfaceInjector.from_config(
        InjectorConfig(
            manifest=manifest, contents=contents, probe_secret=SECRET, evidence_dir=tmp_path
        )
    )


def _page(body: bytes = APP_PAGE, **kwargs: Any) -> http.Response:
    return _app(200, body, **kwargs)


def _decoded(resp: http.Response) -> bytes:
    return resp.get_content(strict=True) or b""


# --------------------------------------------------------------------------- P2-P6


@pytest.mark.parametrize("encoding", ["gzip", "br", "zstd", None])
@pytest.mark.parametrize("surface", sorted(BODY_SURFACES))
def test_body_surface_is_planted_into_the_apps_own_page(
    tmp_path: Path, surface: Surface, encoding: str | None
) -> None:
    if encoding:
        _codec(encoding)
    injector = _injector_for(tmp_path, page_placement(surface))
    resp = _serve(injector, _flow(PAGE), _page(encoding=encoding))
    payload = SurfaceMarkup.render(surface, TEXT)
    decoded = _decoded(resp)
    assert decoded.count(payload) == 1
    assert decoded.replace(payload, b"") == APP_PAGE  # nothing else changed
    assert resp.headers.get("content-encoding") == encoding
    assert resp.status_code == 200 and resp.headers["content-length"] == str(
        len(resp.raw_content or b"")
    )
    _assert_app_headers(resp)
    _access, serve = _events(tmp_path)
    assert isinstance(serve, PlacementServe) and serve.surface is surface
    assert serve.insert_ok is True and serve.byte_offset == decoded.index(payload)
    assert serve.offset_fraction == pytest.approx(serve.byte_offset / len(APP_PAGE))
    meta = _meta(tmp_path)
    (entry,) = meta["placements"]
    assert entry["byte_offset"] == serve.byte_offset
    assert entry["offset_fraction"] == pytest.approx(serve.offset_fraction)
    assert meta["action"] == "page" and "note" not in meta


def test_plant_lands_at_the_registered_fraction(tmp_path: Path) -> None:
    for fraction, expected in ((0.0, b"<body>"), (1.0, b"</body>")):
        placement, text = page_placement(Surface.P3, offset=fraction)
        injector = _injector_for(tmp_path / str(fraction), (placement, text))
        resp = _serve(injector, _flow(PAGE), _page(encoding=None))
        decoded = _decoded(resp)
        comment = f"<!-- {text} -->".encode()
        at = decoded.index(comment)
        if fraction == 0.0:
            assert at == decoded.index(expected) + len(expected)
        else:
            assert decoded[at + len(comment) :].startswith(expected)


def test_page_without_body_tag_gets_the_text_at_the_end(tmp_path: Path) -> None:
    fragment = b"<div>just a fragment</div>"
    injector = _injector_for(tmp_path, page_placement(Surface.P4))
    resp = _serve(injector, _flow(PAGE), _page(fragment))
    assert _decoded(resp) == fragment + SurfaceMarkup.render(Surface.P4, TEXT)


@pytest.mark.parametrize("body", [b"", b"<", b"<body", b"<<<>>>"])
def test_pages_with_no_tag_at_all_are_left_alone(tmp_path: Path, body: bytes) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    app = _page(body, encoding=None)
    raw = app.raw_content
    assert _serve(injector, _flow(PAGE), app).raw_content == raw
    assert _events(tmp_path)[1].insert_ok is False


@pytest.mark.parametrize("body", [b"<body><p>unclosed", b"\xff\xfe\x00<body>"])
def test_malformed_pages_with_a_tag_still_take_the_text(tmp_path: Path, body: bytes) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    resp = _serve(injector, _flow(PAGE), _page(body, encoding=None))
    comment = f"<!-- {TEXT} -->".encode()
    assert resp.get_content() is not None and comment in resp.get_content()  # type: ignore[operator]
    assert resp.get_content().replace(comment, b"") == body  # type: ignore[union-attr]
    (_a, serve) = _events(tmp_path)
    assert serve.insert_ok is True


def test_existing_jsonld_is_left_alone_and_a_new_block_added(tmp_path: Path) -> None:
    existing = b'<script type="application/ld+json">{"@type":"Product","name":"x"}</script>'
    app_body = b"<html><body>" + existing + b"<p>a</p><p>b</p></body></html>"
    injector = _injector_for(tmp_path, page_placement(Surface.P6, offset=1.0))
    decoded = _decoded(_serve(injector, _flow(PAGE), _page(app_body)))
    assert existing in decoded  # untouched, same bytes
    blocks = decoded.count(b'<script type="application/ld+json">')
    assert blocks == 2
    assert decoded.replace(SurfaceMarkup.render(Surface.P6, TEXT), b"") == app_body


def test_several_surfaces_on_one_page_all_land_and_offsets_stay_true(tmp_path: Path) -> None:
    pairs = [page_placement(s, offset=0.5) for s in (Surface.P2, Surface.P3, Surface.P4)]
    pairs += [page_placement(Surface.P5, offset=0.0), page_placement(Surface.P6, offset=1.0)]
    injector = _injector_for(tmp_path, *pairs)
    resp = _serve(injector, _flow(PAGE), _page())
    decoded = _decoded(resp)
    serves = [e for e in _events(tmp_path) if isinstance(e, PlacementServe)]
    assert len(serves) == 5 and all(s.insert_ok for s in serves)
    for serve, (placement, text) in zip(serves, pairs, strict=True):
        payload = SurfaceMarkup.render(placement.surface, text)
        assert serve.byte_offset is not None
        # the offset is a point in the app's own page, not in the served one
        assert serve.byte_offset <= len(APP_PAGE) and decoded.count(payload) == 1
    stripped = decoded
    for placement, text in pairs:
        stripped = stripped.replace(SurfaceMarkup.render(placement.surface, text), b"")
    assert stripped == APP_PAGE


def test_page_that_is_not_html_is_not_planted(tmp_path: Path) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    app = _page(b'{"a": 1}', content_type="application/json")
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(injector, _flow(PAGE), app)
    assert (resp.raw_content, resp.headers.fields) == (raw, fields)
    _a, serve = _events(tmp_path)
    assert serve.insert_ok is False and serve.byte_offset is None and serve.offset_fraction is None
    assert "not HTML" in _meta(tmp_path)["note"]


def test_xhtml_counts_as_html(tmp_path: Path) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    resp = _serve(injector, _flow(PAGE), _page(content_type="Application/XHTML+xml; charset=x"))
    assert f"<!-- {TEXT} -->".encode() in _decoded(resp)


@pytest.mark.parametrize("status", [201, 301, 304, 404, 500])
@pytest.mark.parametrize("surface", [Surface.P3, Surface.P8])
def test_only_a_200_page_is_planted(tmp_path: Path, surface: Surface, status: int) -> None:
    injector = _injector_for(tmp_path, page_placement(surface))
    app = _app(status, APP_PAGE)
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(injector, _flow(PAGE), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (status, raw, fields)
    _a, serve = _events(tmp_path)
    assert serve.insert_ok is False
    assert "nothing planted" in _meta(tmp_path)["note"]


@pytest.mark.parametrize("encoding", ["gzip, br", "compress", "gzip"])
def test_undecodable_bodies_are_left_exactly_as_they_were(tmp_path: Path, encoding: str) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    app = http.Response.make(200, b"not really compressed", {"content-type": "text/html"})
    app.headers["content-encoding"] = encoding
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(injector, _flow(PAGE), app)
    assert (resp.raw_content, resp.headers.fields) == (raw, fields)
    _a, serve = _events(tmp_path)
    assert serve.insert_ok is False


def test_range_responses_are_not_planted(tmp_path: Path) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    app = _page(encoding=None, content_range="bytes 0-9/100")
    raw = app.raw_content
    resp = _serve(injector, _flow(PAGE), app)
    assert resp.raw_content == raw
    assert _events(tmp_path)[1].insert_ok is False


def test_etag_and_digests_follow_a_planted_body(tmp_path: Path) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    app = _page(etag='W/"v1"', content_md5="abc", digest="sha-256=zzz")
    resp = _serve(injector, _flow(PAGE), app)
    assert resp.headers["etag"].startswith('W/"') and resp.headers["etag"] != 'W/"v1"'
    assert "content-md5" not in resp.headers and "digest" not in resp.headers


@pytest.mark.parametrize("method", ["HEAD", "POST", "PUT", "DELETE", "OPTIONS"])
@pytest.mark.parametrize("surface", [Surface.P3, Surface.P6, Surface.P8])
def test_head_and_post_never_planted(tmp_path: Path, surface: Surface, method: str) -> None:
    injector = _injector_for(tmp_path, page_placement(surface))
    app = _page()
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(injector, _flow(PAGE, method=method), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (200, raw, fields)
    (access,) = _events(tmp_path)  # a request, but no placement_serve
    assert access.method == method
    assert not (tmp_path / "injector" / "0000.body").exists()


@pytest.mark.parametrize("surface", [*sorted(BODY_SURFACES), Surface.P8])
def test_control_arm_plants_nothing_for_new_surfaces(tmp_path: Path, surface: Surface) -> None:
    """The control arm serves the app's response byte for byte, tag or no tag."""
    control = _manifest(arm=Arm.CONTROL)
    injector = SurfaceInjector.from_config(
        InjectorConfig(manifest=control, contents={}, probe_secret=SECRET, evidence_dir=tmp_path)
    )
    app = _page(etag='"v1"')
    before = (app.raw_content, app.headers.fields, app.status_code, app.reason)
    resp = _serve(injector, _flow(PAGE), app)
    assert (resp.raw_content, resp.headers.fields, resp.status_code, resp.reason) == before
    assert TAG.encode() not in (resp.raw_content or b"")
    (access,) = _events(tmp_path)
    assert access.status == 200
    assert not (tmp_path / "injector" / "0000.body").exists()


def test_a_treated_page_differs_from_the_control_one_only_by_the_planted_bytes(
    tmp_path: Path,
) -> None:
    placement, text = page_placement(Surface.P5)
    treated = _serve(_injector_for(tmp_path / "t", (placement, text)), _flow(PAGE), _page())
    control = _manifest(arm=Arm.CONTROL)
    plain = _serve(
        SurfaceInjector.from_config(
            InjectorConfig(
                manifest=control, contents={}, probe_secret=SECRET, evidence_dir=tmp_path / "c"
            )
        ),
        _flow(PAGE),
        _page(),
    )
    payload = SurfaceMarkup.render(Surface.P5, text)
    assert _decoded(treated).replace(payload, b"") == _decoded(plain)
    assert {k: v for k, v in treated.headers.items() if k not in ("content-length",)} == {
        k: v for k, v in plain.headers.items() if k not in ("content-length",)
    }


def test_non_ascii_page_text_is_planted_as_utf8(tmp_path: Path) -> None:
    text = f"café 中文 \U0001f600 {TAG}"
    injector = _injector_for(tmp_path, page_placement(Surface.P4, text=text))
    decoded = _decoded(_serve(injector, _flow(PAGE), _page()))
    assert text.encode("utf-8") in decoded


def test_a_huge_page_is_planted_without_losing_a_byte(tmp_path: Path) -> None:
    big = b"<html><body>" + b"<p>row of text in a long page</p>\n" * 80_000 + b"</body></html>"
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    decoded = _decoded(_serve(injector, _flow(PAGE), _page(big)))
    assert decoded.replace(f"<!-- {TEXT} -->".encode(), b"") == big
    serve = _events(tmp_path)[1]
    assert serve.offset_fraction == pytest.approx(0.5, abs=0.001)


def test_error_page_of_the_app_is_not_a_page_target(tmp_path: Path) -> None:
    injector = _injector_for(tmp_path, page_placement(Surface.P3))
    resp = _serve(injector, _flow(PAGE), _app(404, WERKZEUG_404))
    assert resp.get_content() == WERKZEUG_404
    assert _events(tmp_path)[1].insert_ok is False


# --------------------------------------------------------------------------- P8


def _p8(tmp_path: Path, text: str = NOTICE) -> SurfaceInjector:
    return _injector_for(tmp_path, page_placement(Surface.P8, text=text))


def test_p8_sets_the_header_and_leaves_everything_else_alone(tmp_path: Path) -> None:
    app = _page(
        etag='"v1"', last_modified="Tue, 03 Nov 2026 10:00:00 GMT", cache_control="max-age=60"
    )
    raw = app.raw_content
    before = [f for f in app.headers.fields if f[0].lower() != b"x-security-notice"]
    resp = _serve(_p8(tmp_path), _flow(PAGE), app)
    assert resp.headers.get_all(NOTICE_HEADER) == [NOTICE]
    assert resp.raw_content == raw  # the body bytes, as encoded on the wire
    assert [f for f in resp.headers.fields if f[0].lower() != b"x-security-notice"] == before
    assert resp.status_code == 200
    _a, serve = _events(tmp_path)
    assert isinstance(serve, PlacementServe) and serve.surface is Surface.P8
    assert serve.insert_ok is True and serve.byte_offset is None and serve.offset_fraction is None
    assert serve.decoded_sha256 == hashlib.sha256(APP_PAGE).hexdigest()
    meta = _meta(tmp_path)
    assert meta["replaced_header"] is False and "note" not in meta
    assert meta["placements"][0]["offset_fraction"] is None


def test_p8_body_hash_unchanged(tmp_path: Path) -> None:
    for encoding in (None, "gzip"):
        injector = _p8(tmp_path / str(encoding))
        resp = _serve(injector, _flow(PAGE), _page(encoding=encoding))
        assert hashlib.sha256(_decoded(resp)).hexdigest() == hashlib.sha256(APP_PAGE).hexdigest()


def test_p8_replaces_a_header_the_app_already_sends(tmp_path: Path) -> None:
    app = _page()
    app.headers.add("X-Security-Notice", "the app's own")
    app.headers.add("x-security-notice", "and a second one")
    resp = _serve(_p8(tmp_path), _flow(PAGE), app)
    assert resp.headers.get_all(NOTICE_HEADER) == [NOTICE]
    assert _meta(tmp_path)["replaced_header"] is True


def test_p8_applies_to_a_page_that_is_not_html_or_even_empty(tmp_path: Path) -> None:
    app = _app(200, b"", content_type="application/octet-stream", encoding=None)
    resp = _serve(_p8(tmp_path), _flow(PAGE), app)
    assert resp.headers.get_all(NOTICE_HEADER) == [NOTICE]
    assert resp.raw_content == b""


def test_p8_never_sets_a_protected_header(tmp_path: Path) -> None:
    app = _page(etag='"v1"')
    resp = _serve(_p8(tmp_path), _flow(PAGE), app)
    for name in PROTECTED_HEADERS:
        assert resp.headers.get_all(name) == app.headers.get_all(name)
    assert resp.headers["etag"] == '"v1"'  # not even recomputed: the body did not change


def test_p8_is_only_on_probe_responses_with_the_digest_header(tmp_path: Path) -> None:
    injector = _p8(tmp_path)
    plain = _serve(injector, _flow(PAGE), _page())
    assert BODY_DIGEST_HEADER not in plain.headers
    probed = _serve(injector, _flow(PAGE, headers={PROBE_HEADER: SECRET}), _page())
    assert probed.headers[BODY_DIGEST_HEADER] == hashlib.sha256(APP_PAGE).hexdigest()
    spoof = _serve(injector, _flow(PAGE, headers={PROBE_HEADER: "wrong"}), _page())
    assert BODY_DIGEST_HEADER not in spoof.headers


def test_a_page_with_body_and_header_surfaces_together(tmp_path: Path) -> None:
    injector = _injector_for(
        tmp_path, page_placement(Surface.P3), page_placement(Surface.P8, text=NOTICE)
    )
    resp = _serve(injector, _flow(PAGE), _page())
    assert resp.headers.get_all(NOTICE_HEADER) == [NOTICE]
    assert f"<!-- {TEXT} -->".encode() in _decoded(resp)
    serves = [e for e in _events(tmp_path) if isinstance(e, PlacementServe)]
    assert [s.insert_ok for s in serves] == [True, True]


def test_event_lines_with_the_new_field_round_trip(tmp_path: Path) -> None:
    _serve(_injector_for(tmp_path, page_placement(Surface.P2)), _flow(PAGE), _page())
    lines = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    for line, event in zip(lines, _events(tmp_path), strict=True):
        assert line == event.model_dump_json().encode()


# --------------------------------------------------------------------------- pre-flight probe


def _probe_response(tmp_path: Path, *pairs: Any, body: bytes = APP_PAGE) -> Any:
    """Serve a probe request through the injector; return the plan and the wire response."""
    manifest, contents = page_manifest(*pairs)
    injector = _injector_for(tmp_path, *pairs)
    resp = _serve(injector, _flow(PAGE, headers={PROBE_HEADER: SECRET}), _page(body))
    headers: dict[str, list[str]] = {}
    for name, value in resp.headers.fields:
        headers.setdefault(name.decode().lower(), []).append(value.decode())
    return build_plan(manifest, contents), headers, resp.raw_content or b""


@pytest.mark.parametrize("surface", [*sorted(BODY_SURFACES), Surface.P8])
def test_probe_passes_every_surface_as_planted(tmp_path: Path, surface: Surface) -> None:
    plan, headers, wire = _probe_response(tmp_path, page_placement(surface, text=NOTICE))
    checker = PlacementProbe(plan)
    action = checker.action(PAGE)
    assert action is not None
    (check,) = checker.check(action, headers, wire, ROBOTS)
    assert check == {
        "placement_id": page_placement(surface)[0].placement_id,
        "surface": surface.value,
        "ok": True,
        "detail": "ok",
    }


def test_probe_ignores_paths_without_a_page_action(tmp_path: Path) -> None:
    plan, _h, _w = _probe_response(tmp_path, page_placement(Surface.P3))
    checker = PlacementProbe(plan)
    assert checker.action("/elsewhere") is None and PlacementProbe(None).action(PAGE) is None


def _check(
    plan: Any, headers: dict[str, list[str]], wire: bytes, robots: bytes | None = ROBOTS
) -> list[dict[str, Any]]:
    checker = PlacementProbe(plan)
    action = checker.action(PAGE)
    assert action is not None
    return checker.check(action, headers, wire, robots)  # type: ignore[return-value]


def test_probe_fails_a_p8_header_that_is_wrong_missing_or_doubled(tmp_path: Path) -> None:
    plan, headers, wire = _probe_response(tmp_path, page_placement(Surface.P8, text=NOTICE))
    for bad in ([], ["something else"], [NOTICE, NOTICE], [NOTICE + " "]):
        tampered = {**headers, NOTICE_HEADER: bad}
        (check,) = _check(plan, tampered, wire)
        assert check["ok"] is False and NOTICE_HEADER in check["detail"]


def test_probe_fails_a_p8_body_that_is_not_the_apps_own(tmp_path: Path) -> None:
    plan, headers, _wire = _probe_response(tmp_path, page_placement(Surface.P8, text=NOTICE))
    (check,) = _check(plan, headers, gzip.compress(b"a different body"))
    assert check["ok"] is False  # undecodable without the right encoding header, or a hash miss
    plain = {k: v for k, v in headers.items() if k != "content-encoding"}
    (check,) = _check(plan, plain, b"a different body")
    assert check["ok"] is False and "app's own body" in check["detail"]
    missing = {k: v for k, v in plain.items() if k != BODY_DIGEST_HEADER}
    (check,) = _check(plan, missing, APP_PAGE)
    assert check["ok"] is False


@pytest.mark.parametrize("surface", sorted(BODY_SURFACES))
def test_probe_fails_when_the_markup_is_missing(tmp_path: Path, surface: Surface) -> None:
    plan, headers, _wire = _probe_response(tmp_path, page_placement(surface))
    plain = {k: v for k, v in headers.items() if k != "content-encoding"}
    (check,) = _check(plan, plain, APP_PAGE)
    assert check["ok"] is False and "missing" in check["detail"]


def test_probe_fails_a_body_it_cannot_decode(tmp_path: Path) -> None:
    plan, headers, _wire = _probe_response(tmp_path, page_placement(Surface.P3))
    (check,) = _check(plan, {**headers, "content-encoding": ["gzip"]}, b"not gzip")
    assert check["ok"] is False and "decoded" in check["detail"]


def test_probe_p6_needs_a_block_that_parses_with_a_type_and_the_text(tmp_path: Path) -> None:
    placement, text = page_placement(Surface.P6)
    plan, headers, _wire = _probe_response(tmp_path, (placement, text))
    plain = {k: v for k, v in headers.items() if k != "content-encoding"}
    payload = SurfaceMarkup.render(Surface.P6, text)
    (ok,) = _check(plan, plain, APP_PAGE + payload)
    assert ok["ok"] is True
    # the exact planted bytes are missing in each of these, so the markup check catches them
    for broken in (
        payload.replace(b'"@type":"WebPage",', b""),
        payload.replace(b"{", b"{{", 1),
        payload.replace(text.encode(), b"other text"),
    ):
        (bad,) = _check(plan, plain, APP_PAGE + broken)
        assert bad["ok"] is False


def test_probe_p4_and_p5_look_at_the_served_element(tmp_path: Path) -> None:
    for surface in (Surface.P4, Surface.P5):
        plan, headers, _wire = _probe_response(tmp_path / surface.value, page_placement(surface))
        plain = {k: v for k, v in headers.items() if k != "content-encoding"}
        payload = SurfaceMarkup.render(surface, TEXT)
        (ok,) = _check(plan, plain, APP_PAGE + payload)
        assert ok["ok"] is True
        wrong = (
            payload.replace(b"<div ", b'<div aria-hidden="true" ', 1)
            if surface is Surface.P4
            else payload
        )
        (bad,) = _check(plan, plain, APP_PAGE + wrong)
        assert bad["ok"] is (surface is Surface.P5)  # the planted bytes are what is checked


# a real listener, so ``probe`` and ``main`` run their HTTP and JSON paths


class _Served:
    """What the fake injector answers: the planted response captured from the addon."""

    headers: dict[str, list[str]] = {}  # noqa: RUF012 - set per test
    body: bytes = b""
    #: per-path answers (headers, body); used instead of the two above when set
    pages: dict[str, tuple[dict[str, list[str]], bytes]] = {}  # noqa: RUF012


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        headers, body = _Served.pages.get(self.path, (_Served.headers, _Served.body))
        self.send_response(200)
        for name, values in headers.items():
            for value in values:
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def listener() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _env(tmp_path: Path, manifest: Any, contents: dict[str, str]) -> dict[str, str]:
    (tmp_path / "manifest.json").write_text(manifest.model_dump_json())
    (tmp_path / "payloads.json").write_text(json.dumps(contents))
    return {
        "LAB_MANIFEST": str(tmp_path / "manifest.json"),
        "LAB_PAYLOADS": str(tmp_path / "payloads.json"),
        "LAB_EVIDENCE_DIR": str(tmp_path / "evidence"),
        "LAB_PROBE_SECRET": SECRET,
    }


@pytest.mark.parametrize("surface", [Surface.P3, Surface.P8])
def test_main_reports_checks_and_fails_on_a_bad_one(
    tmp_path: Path,
    listener: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    surface: Surface,
) -> None:
    pairs = (page_placement(surface, text=NOTICE),)
    manifest, contents = page_manifest(*pairs)
    _plan, headers, wire = _probe_response(tmp_path / "ev", *pairs)
    _Served.headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
    _Served.headers["content-length"] = [str(len(wire))]
    _Served.body = wire
    for key, value in _env(tmp_path, manifest, contents).items():
        monkeypatch.setenv(key, value)

    assert main(["--port", str(listener), PAGE]) == 0
    (result,) = json.loads(capsys.readouterr().out)["results"]
    assert result["status"] == 200 and result["checks"][0]["ok"] is True

    _Served.body = APP_PAGE  # an injector that planted nothing
    _Served.headers = {"content-length": [str(len(APP_PAGE))]}
    assert main(["--port", str(listener), PAGE]) == 1
    (result,) = json.loads(capsys.readouterr().out)["results"]
    assert result["status"] == 200 and result["checks"][0]["ok"] is False


def test_probe_without_a_plan_adds_no_checks(listener: int) -> None:
    _Served.headers, _Served.body = {"content-length": ["2"]}, b"ok"
    assert "checks" not in probe(PAGE, port=listener, secret=SECRET)
    assert "checks" not in probe("/other", port=listener, secret=SECRET, plan=None)


def test_main_refuses_a_plan_it_cannot_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    placement, text = page_placement(Surface.P3)
    manifest, _contents = page_manifest((placement, text))
    for key, value in _env(tmp_path, manifest, {placement.placement_id: "tampered"}).items():
        monkeypatch.setenv(key, value)
    assert main(["--port", "1", PAGE]) == 1
    assert "cannot build the injector plan" in capsys.readouterr().out


# --------------------------------------------------------------------------- P8 with P3, P2


def test_probe_passes_p3_and_p8_on_the_same_path(tmp_path: Path) -> None:
    """P8 never changes the body, so its check compares with the body after the P3 text."""
    pairs = (page_placement(Surface.P3), page_placement(Surface.P8, text=NOTICE))
    plan, headers, wire = _probe_response(tmp_path, *pairs)
    checks = _check(plan, headers, wire)
    assert [c["ok"] for c in checks] == [True, True], checks
    assert headers[BODY_DIGEST_HEADER] != [hashlib.sha256(APP_PAGE).hexdigest()]
    plain = {k: v for k, v in headers.items() if k != "content-encoding"}
    (_p3, p8) = _check(plan, plain, APP_PAGE)  # a body without the P3 text does not match
    assert p8["ok"] is False


@pytest.mark.parametrize(
    "robots",
    [
        b"User-agent: *\nDisallow: /page\n",
        b"User-agent: *\nDisallow: /\n",
        b"User-agent: *\nDisallow: /pa\n",
        b"# a treated run adds this\nUser-agent: *\nDisallow: /page\n# lab 0123456789abcdef\n",
        b"User-agent: *\r\nDisallow: /page\r\n",
    ],
)
def test_probe_p2_passes_when_robots_disallows_its_path(tmp_path: Path, robots: bytes) -> None:
    plan, headers, wire = _probe_response(tmp_path, page_placement(Surface.P2))
    (check,) = _check(plan, headers, wire, robots)
    assert check["ok"] is True, check


@pytest.mark.parametrize(
    "robots",
    [
        None,  # robots.txt could not be read
        b"",
        b"User-agent: *\nDisallow:\n",
        b"User-agent: *\nDisallow: /other\n",
        b"User-agent: googlebot\nDisallow: /page\n",  # not for every crawler
        b"User-agent: *\nAllow: /page\nDisallow: /page\n",
        b"\xff\xfe\x00 not a robots file",
    ],
)
def test_probe_p2_fails_when_its_path_is_not_disallowed(
    tmp_path: Path, robots: bytes | None
) -> None:
    plan, headers, wire = _probe_response(tmp_path, page_placement(Surface.P2))
    (check,) = _check(plan, headers, wire, robots)
    assert check["ok"] is False and "robots.txt" in check["detail"]


def test_p1_lines_in_a_treated_robots_do_not_change_what_is_disallowed() -> None:
    """P1 text is a comment or non-standard line; robotparser ignores it."""
    base = b"User-agent: *\nDisallow: /private\n"
    treated = base + b"# lab test line one 0123456789abcdef\nX-Note: 0123456789abcdef\n"
    for robots in (base, treated):
        assert PlacementProbe._disallowed("/private", robots) is None
        assert PlacementProbe._disallowed("/public", robots) is not None


def test_probe_fetches_robots_through_the_injector_for_p2(
    tmp_path: Path,
    listener: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End to end: probe() asks for /robots.txt as well and judges the P2 path by it."""
    pairs = (page_placement(Surface.P2),)
    manifest, contents = page_manifest(*pairs)
    _plan, headers, wire = _probe_response(tmp_path / "ev", *pairs)
    page = ({k: v for k, v in headers.items() if k != "content-length"}, wire)
    page[0]["content-length"] = [str(len(wire))]
    for key, value in _env(tmp_path, manifest, contents).items():
        monkeypatch.setenv(key, value)
    try:
        _Served.pages = {
            PAGE: page,
            "/robots.txt": ({"content-length": [str(len(ROBOTS))]}, ROBOTS),
        }
        assert main(["--port", str(listener), PAGE]) == 0
        (result,) = json.loads(capsys.readouterr().out)["results"]
        assert result["checks"][0]["ok"] is True
        open_robots = b"User-agent: *\nAllow:\n"
        _Served.pages = {
            PAGE: page,
            "/robots.txt": ({"content-length": [str(len(open_robots))]}, open_robots),
        }
        assert main(["--port", str(listener), PAGE]) == 1
        (result,) = json.loads(capsys.readouterr().out)["results"]
        assert result["checks"][0]["ok"] is False
    finally:
        _Served.pages = {}


def test_texts_with_angle_brackets_never_nest_and_manifest_order_does_not_matter(
    tmp_path: Path,
) -> None:
    text = f"if a > b then <b>x</b> --> end {TAG}"
    # P3 refuses '-->', so P3 gets a text without it
    texts = {s: (text if s is not Surface.P3 else f"a > b {TAG}") for s in BODY_SURFACES}
    pairs = [page_placement(s, text=texts[s], offset=0.5) for s in sorted(BODY_SURFACES)]
    bodies, offsets = [], []
    for n, order in enumerate((pairs, pairs[::-1], pairs[2:] + pairs[:2])):
        injector = _injector_for(tmp_path / str(n), *order)
        decoded = _decoded(_serve(injector, _flow(PAGE), _page(encoding=None)))
        bodies.append(decoded)
        serves = [e for e in _events(tmp_path / str(n)) if isinstance(e, PlacementServe)]
        offsets.append({s.surface: s.byte_offset for s in serves})
    assert bodies[0] == bodies[1] == bodies[2]  # the same page whatever the manifest order
    assert offsets[0] == offsets[1] == offsets[2]
    decoded = bodies[0]
    spans = []
    for surface in BODY_SURFACES:
        payload = SurfaceMarkup.render(surface, texts[surface])
        assert decoded.count(payload) == 1
        start = decoded.index(payload)
        spans.append((start, start + len(payload)))
    spans.sort()
    assert all(a[1] <= b[0] for a, b in itertools.pairwise(spans))
    # the offsets are points of the app's own page, every one at a tag boundary there
    for at in offsets[0].values():
        assert at is not None and APP_PAGE[at - 1 : at] == b">"


def test_a_page_with_no_safe_place_is_left_alone_and_says_why(tmp_path: Path) -> None:
    for n, body in enumerate((b"just words, no tags at all", b"<script>var x = 1;</body></html>")):
        injector = _injector_for(tmp_path / str(n), page_placement(Surface.P3))
        app = _page(body, encoding=None)
        raw, fields = app.raw_content, app.headers.fields
        resp = _serve(injector, _flow(PAGE), app)
        assert (resp.raw_content, resp.headers.fields) == (raw, fields)
        serve = _events(tmp_path / str(n))[1]
        assert serve.insert_ok is False and serve.byte_offset is None
        assert "no safe place" in _meta(tmp_path / str(n))["note"]


def test_a_page_with_an_unterminated_comment_is_planted_before_the_comment(
    tmp_path: Path,
) -> None:
    body = b"<html><body><p>a</p><!-- todo <p>b</p></body></html>"
    injector = _injector_for(tmp_path, page_placement(Surface.P4, offset=0.9))
    decoded = _decoded(_serve(injector, _flow(PAGE), _page(body, encoding=None)))
    payload = SurfaceMarkup.render(Surface.P4, TEXT)
    assert decoded.index(payload) < decoded.index(b"<!--")
