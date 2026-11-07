"""Surface injector: planting helpers, the arm logic, and the mitmproxy shell.

No live proxy is started: the pure helpers are called directly, and the addon's hooks
are driven with mitmproxy's in-memory test flows.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from mitmproxy import http
from mitmproxy.addons.script import load_script
from mitmproxy.test import tflow, tutils
from pydantic import TypeAdapter

from cell.injector.addon import SurfaceInjector, plant_into_response, plantable
from cell.injector.placement import (
    DECOY_PAGE,
    DEFAULT_ROBOTS_BASE,
    INJECTOR_STREAM,
    PROBE_HEADER,
    ActionKind,
    Plant,
    build_plan,
    is_probe,
    plant_into_body,
    recompute_etag,
    render_robots,
    request_path,
)
from cell.injector.serve_log import EVENTS_FILE, InjectorConfig, ServeLog
from control.core.ids import new_id
from control.core.models import (
    Arm,
    Event,
    Placement,
    PlacementServe,
    RunManifest,
    Surface,
    TargetAccessEvent,
)
from control.core.tokens import derive_token, new_tag

RUN_ID = new_id("run")
TAG = new_tag()
TS = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
SECRET = "probe-secret-0123456789abcdef"  # noqa: S105 -- per-test probe secret fixture
P1_ID = new_id("pl")
P7_ID = new_id("pl")
# Test payloads only; real wording comes from the payload library via the manifest.
P1_TEXT = f"# lab test line one {TAG}"
P7_TEXT = f"lab test error text {TAG}"
P7_PATH = "/.env"
EVENTS = TypeAdapter(Event)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _placement(pid: str, surface: Surface, url: str, locator: str, text: str) -> Placement:
    return Placement(
        placement_id=pid,
        run_id=RUN_ID,
        surface=surface,
        url=url,
        locator=locator,
        payload_id="test-payload",
        payload_version="1",
        tag=TAG,
        token=derive_token(b"lab-test-key", RUN_ID, pid),
        content_sha256=_sha(text.encode()),
    )


def _manifest(*placements: Placement, arm: Arm = Arm.INJECTED) -> RunManifest:
    injected = arm is Arm.INJECTED
    if injected and not placements:
        placements = (
            _placement(P1_ID, Surface.P1, "http://target/robots.txt", "robots.txt:append", P1_TEXT),
            _placement(P7_ID, Surface.P7, f"http://target{P7_PATH}", "error:404", P7_TEXT),
        )
    return RunManifest(
        run_id=RUN_ID,
        experiment_id=new_id("exp"),
        pair_id=new_id("pair"),
        arm=arm,
        target="dvga",
        agent="scripted",
        model="stub",
        schedule_index=0,
        tag=TAG if injected else None,
        placements=list(placements) if injected else [],
        created_at=TS,
    )


def _contents(manifest: RunManifest) -> dict[str, str]:
    by_id = {P1_ID: P1_TEXT, P7_ID: P7_TEXT}
    return {p.placement_id: by_id[p.placement_id] for p in manifest.placements}


def _events(root: Path) -> list[Any]:
    path = root / EVENTS_FILE
    if not path.exists():
        return []
    return [EVENTS.validate_json(line) for line in path.read_bytes().splitlines()]


# --------------------------------------------------------------------------- plant_into_body


HTML = b"<!doctype html><html><body><h1>Hello</h1></body></html>"


def test_plant_into_gzip_body_round_trips() -> None:
    payload = f"<!-- {TAG} -->".encode()
    wire = gzip.compress(HTML)
    new_wire, offset, ok = plant_into_body(wire, "gzip", payload, before=b"</body>")
    assert ok is True
    decoded = gzip.decompress(new_wire)  # still valid gzip
    assert decoded[offset : offset + len(payload)] == payload
    assert decoded == HTML.replace(b"</body>", payload + b"</body>")
    assert offset == HTML.index(b"</body>")


def test_plant_into_brotli_body_round_trips() -> None:
    brotli = pytest.importorskip("brotli")
    payload = TAG.encode()
    new_wire, offset, ok = plant_into_body(brotli.compress(HTML), "br", payload)
    assert ok is True
    decoded = brotli.decompress(new_wire)
    assert decoded == HTML + payload  # no anchor: appended
    assert offset == len(HTML)


def test_plant_into_zstd_body_round_trips() -> None:
    zstd = pytest.importorskip("backports.zstd")
    payload = TAG.encode()
    new_wire, offset, ok = plant_into_body(zstd.compress(HTML), "zstd", payload, before=b"</BODY>")
    assert ok is True
    decoded = zstd.decompress(new_wire)
    assert decoded[offset : offset + len(payload)] == payload
    assert decoded.endswith(payload + b"</body></html>")  # anchor matched case-insensitively


@pytest.mark.parametrize("encoding", [None, "", "identity", " Identity "])
def test_plant_into_identity_body(encoding: str | None) -> None:
    new_wire, offset, ok = plant_into_body(HTML, encoding, b"XYZ", before=b"</body>")
    assert ok is True
    assert new_wire == HTML.replace(b"</body>", b"XYZ</body>")
    assert new_wire[offset : offset + 3] == b"XYZ"


def test_plant_into_deflate_body_round_trips() -> None:
    import zlib

    new_wire, offset, ok = plant_into_body(zlib.compress(HTML), "deflate", b"XYZ")
    assert ok is True
    assert zlib.decompress(new_wire) == HTML + b"XYZ"
    assert offset == len(HTML)


def test_plant_inserts_before_last_anchor() -> None:
    body = b"a</body>b</body>c"
    new_wire, offset, ok = plant_into_body(body, None, b"X", before=b"</body>")
    assert ok and new_wire == b"a</body>bX</body>c" and offset == 9


@pytest.mark.parametrize("encoding", ["compress", "gzip, br", "x-unknown"])
def test_plant_into_unsupported_encoding_changes_nothing(encoding: str) -> None:
    assert plant_into_body(HTML, encoding, b"X") == (HTML, -1, False)


def test_plant_into_corrupt_gzip_changes_nothing() -> None:
    assert plant_into_body(b"not gzip at all", "gzip", b"X") == (b"not gzip at all", -1, False)


def test_plant_requires_a_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        plant_into_body(HTML, None, b"")


# --------------------------------------------------------------------------- response edits


def _gzip_resp(**headers: str) -> http.Response:
    resp = tutils.tresp()
    resp.headers["content-encoding"] = "gzip"
    for name, value in headers.items():
        resp.headers[name.replace("_", "-")] = value
    resp.raw_content = gzip.compress(HTML)
    resp.headers["content-length"] = str(len(resp.raw_content))
    return resp


def test_plant_into_gzip_response_fixes_framing_headers() -> None:
    resp = _gzip_resp(etag='"abc123"', digest="sha-256=old", repr_digest="sha-256=:old:")
    payload = f"<!-- {TAG} -->".encode()

    offset, ok = plant_into_response(resp, payload, before=b"</body>")

    assert ok is True
    wire = resp.raw_content or b""
    assert resp.headers["content-encoding"] == "gzip"
    assert resp.headers["content-length"] == str(len(wire))
    assert resp.headers["etag"] == recompute_etag('"abc123"', wire) != '"abc123"'
    assert "digest" not in resp.headers and "repr-digest" not in resp.headers
    assert resp.headers["header-response"] == "svalue"  # the app's other headers stay
    decoded = gzip.decompress(wire)
    assert decoded[offset : offset + len(payload)] == payload
    assert resp.get_content() == decoded


def test_recompute_etag_keeps_weakness_and_quotes() -> None:
    strong = recompute_etag('"v1"', b"body")
    weak = recompute_etag('W/"v1"', b"body")
    assert strong.startswith('"') and strong.endswith('"') and len(strong) == 34
    assert weak == "W/" + strong
    assert recompute_etag('"v1"', b"other") != strong


def test_plant_into_response_keeps_weak_etag_weak() -> None:
    resp = _gzip_resp(etag='W/"abc"')
    plant_into_response(resp, b"X")
    assert resp.headers["etag"].startswith('W/"')


def test_plant_into_response_leaves_undecodable_response_alone() -> None:
    resp = tutils.tresp()
    resp.headers["content-encoding"] = "gzip"
    resp.headers["etag"] = '"abc123"'
    resp.raw_content = b"broken"
    before = (resp.raw_content, resp.headers.fields)
    assert plant_into_response(resp, b"X") == (-1, False)
    assert (resp.raw_content, resp.headers.fields) == before


@pytest.mark.parametrize("status", [204, 206, 304])
def test_plant_into_response_skips_unplantable_statuses(status: int) -> None:
    resp = _gzip_resp(etag='"abc"')
    resp.status_code = status
    before = (resp.raw_content, resp.headers.fields)
    assert plantable(resp) is False
    assert plant_into_response(resp, b"X") == (-1, False)
    assert (resp.raw_content, resp.headers.fields) == before


def test_plant_into_response_skips_ranges() -> None:
    resp = _gzip_resp(content_range="bytes 0-9/100")
    before = (resp.raw_content, resp.headers.fields)
    assert plant_into_response(resp, b"X") == (-1, False)
    assert (resp.raw_content, resp.headers.fields) == before


# --------------------------------------------------------------------------- rendering


def _plants(manifest: RunManifest) -> tuple[Plant, ...]:
    contents = _contents(manifest)
    return tuple(
        Plant(p, contents[p.placement_id].encode())
        for p in manifest.placements
        if p.surface is Surface.P1
    )


def test_render_robots_appends_lines_with_the_tag() -> None:
    base = DEFAULT_ROBOTS_BASE.encode()
    body, (offset,) = render_robots(base, _plants(_manifest()))
    assert TAG.encode() in body
    assert body.startswith(base)
    assert offset == len(base)
    assert body[offset:] == P1_TEXT.encode() + b"\n"


def test_render_robots_plants_every_p1_placement_in_order() -> None:
    second_id = new_id("pl")
    second = f"# second lab test line {TAG}"
    p1 = _placement(P1_ID, Surface.P1, "/robots.txt", "robots.txt:append", P1_TEXT)
    p2 = _placement(second_id, Surface.P1, "/robots.txt", "robots.txt:append", second)
    plants = (Plant(p1, P1_TEXT.encode()), Plant(p2, second.encode()))
    body, offsets = render_robots(b"Disallow: /admin", plants)  # no final newline
    assert body == f"Disallow: /admin\n{P1_TEXT}\n{second}\n".encode()
    assert offsets == (17, 17 + len(P1_TEXT) + 1)


# --------------------------------------------------------------------------- plan


def test_build_plan_for_control_acts_on_nothing() -> None:
    plan = build_plan(_manifest(arm=Arm.CONTROL), {})
    assert plan.arm is Arm.CONTROL
    for path in ("/robots.txt", P7_PATH, f"/x-{TAG}/", "/"):
        assert plan.match("GET", path) is None


def test_build_plan_matches_injected_surfaces_on_get_only() -> None:
    manifest = _manifest()
    plan = build_plan(manifest, _contents(manifest))
    robots = plan.match("GET", "/robots.txt?x=1")
    assert robots is not None and robots.kind is ActionKind.ROBOTS
    assert [p.placement.placement_id for p in robots.plants] == [P1_ID]
    error = plan.match("get", P7_PATH)
    assert error is not None and error.kind is ActionKind.ERROR
    assert error.expected_status == 404 and error.plants[0].content == P7_TEXT.encode()
    for decoy_path in (f"/x-{TAG}/", f"/x-{TAG}", f"/x-{TAG}/deeper/page?q=1"):
        decoy = plan.match("GET", decoy_path)
        assert decoy is not None and decoy.kind is ActionKind.DECOY and decoy.plants == ()
    assert TAG not in DECOY_PAGE
    for method in ("HEAD", "POST", "OPTIONS"):
        for path in ("/robots.txt", P7_PATH, f"/x-{TAG}/"):
            assert plan.match(method, path) is None  # never planted
    assert plan.match("GET", "/robots.txt.bak") is None
    assert plan.match("GET", f"/x-{TAG}extra") is None
    assert plan.match("GET", "/graphql") is None


def _bad_plan(manifest: RunManifest, contents: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        build_plan(manifest, contents)


def test_build_plan_rejects_content_that_does_not_match_its_hash() -> None:
    manifest = _manifest()
    _bad_plan(manifest, {P1_ID: P1_TEXT + " edited", P7_ID: P7_TEXT}, "content_sha256")


def test_build_plan_rejects_content_without_the_tag() -> None:
    text = "no tag in here"
    manifest = _manifest(_placement(P1_ID, Surface.P1, "/robots.txt", "robots.txt:append", text))
    _bad_plan(manifest, {P1_ID: text}, "tag")


def test_build_plan_rejects_missing_or_extra_content() -> None:
    manifest = _manifest()
    _bad_plan(manifest, {P1_ID: P1_TEXT}, "missing")
    _bad_plan(manifest, {**_contents(manifest), "pl_other": "x"}, "unknown")
    _bad_plan(_manifest(arm=Arm.CONTROL), {"pl_other": "x"}, "unknown")


def test_build_plan_rejects_unsupported_surfaces_and_locators() -> None:
    p3 = _placement(P1_ID, Surface.P3, "/login", "css:body", P1_TEXT)
    _bad_plan(_manifest(p3), {P1_ID: P1_TEXT}, "not supported")
    bad_p1 = _placement(P1_ID, Surface.P1, "/robots.txt", "robots.txt:prepend", P1_TEXT)
    _bad_plan(_manifest(bad_p1), {P1_ID: P1_TEXT}, "locator")
    wrong_url = _placement(P1_ID, Surface.P1, "/sitemap.xml", "robots.txt:append", P1_TEXT)
    _bad_plan(_manifest(wrong_url), {P1_ID: P1_TEXT}, "robots")
    bad_p7 = _placement(P7_ID, Surface.P7, P7_PATH, "error:500", P7_TEXT)
    _bad_plan(_manifest(bad_p7), {P7_ID: P7_TEXT}, "locator")
    other_id = new_id("pl")
    dup = _manifest(
        _placement(P7_ID, Surface.P7, P7_PATH, "error:404", P7_TEXT),
        _placement(other_id, Surface.P7, P7_PATH, "error:403", P7_TEXT),
    )
    _bad_plan(dup, {P7_ID: P7_TEXT, other_id: P7_TEXT}, "more than one")


def test_request_path_drops_query_and_fragment() -> None:
    assert request_path("/robots.txt?a=1#f") == "/robots.txt"
    assert request_path("http://target/robots.txt?a=1") == "/robots.txt"
    assert request_path("") == "/"


def test_is_probe_needs_the_exact_secret() -> None:
    assert is_probe([SECRET], SECRET) is True
    assert is_probe([], SECRET) is False
    assert is_probe(["wrong"], SECRET) is False
    assert is_probe([SECRET + "x"], SECRET) is False
    assert is_probe([SECRET, SECRET], SECRET) is False  # ambiguous: not a probe
    assert is_probe([""], "") is False  # no secret configured: nothing is a probe
    assert is_probe(["é"], SECRET) is False  # non-ASCII values compare safely


# --------------------------------------------------------------------------- addon shell

APP_HEADERS = {
    "date": "Sat, 07 Nov 2026 12:00:00 GMT",
    "server": "Werkzeug/3.0.6 Python/3.12.7",
    "set-cookie": "session=abc; Path=/; HttpOnly",
}
APP_ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /graphiql\n"
# Werkzeug's standard 404 page (what DVGA answers); note: no </body>.
WERKZEUG_404 = (
    b"<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n"
    b"<p>The requested URL was not found on the server. If you entered the URL manually "
    b"please check your spelling and try again.</p>\n"
)


def _injector(tmp_path: Path, manifest: RunManifest | None = None) -> SurfaceInjector:
    manifest = manifest or _manifest()
    config = InjectorConfig(
        manifest=manifest,
        contents=_contents(manifest),
        probe_secret=SECRET,
        evidence_dir=tmp_path,
    )
    return SurfaceInjector.from_config(config)


def _flow(path: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> Any:
    req = http.Request.make(method, f"http://target:5013{path}", b"", headers or {})
    req.timestamp_start = TS.timestamp()
    return tflow.tflow(req=req)


def _app(
    status: int = 200,
    body: bytes = b"app says hi",
    *,
    content_type: str = "text/html; charset=utf-8",
    encoding: str | None = "gzip",
    **extra: str,
) -> http.Response:
    """An app response with the app's header shape (Date, Server, cookie)."""
    resp = http.Response.make(status, b"", {**APP_HEADERS, "content-type": content_type})
    for name, value in extra.items():
        resp.headers[name.replace("_", "-")] = value
    if encoding:
        resp.headers["content-encoding"] = encoding
    resp.content = body  # encoded on the wire, content-length set
    return resp


def _serve(injector: SurfaceInjector, flow: Any, app: http.Response | None = None) -> Any:
    """Run a flow through both hooks with the app answering ``app``."""
    injector.request(flow)
    assert flow.response is None  # the injector never answers by itself
    flow.response = app if app is not None else _app()
    injector.response(flow)
    return flow.response


def _meta(root: Path, seq: int = 0) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((root / "injector" / f"{seq:04d}.meta.json").read_bytes())
    return doc


def _assert_app_headers(resp: http.Response) -> None:
    for name, value in APP_HEADERS.items():
        assert resp.headers[name] == value


def test_robots_lines_are_appended_to_the_apps_file(tmp_path: Path) -> None:
    """(a) The app's own Disallow lines survive; P1 is appended; app headers kept."""
    flow = _flow("/robots.txt")
    resp = _serve(
        _injector(tmp_path), flow, _app(200, APP_ROBOTS, content_type="text/plain", etag='"r1"')
    )
    body = resp.get_content() or b""
    assert resp.status_code == 200
    assert body == APP_ROBOTS + P1_TEXT.encode() + b"\n"
    _assert_app_headers(resp)
    assert resp.headers["content-encoding"] == "gzip"  # same encoding as the app's
    assert resp.headers["content-length"] == str(len(resp.raw_content or b""))
    assert resp.headers["etag"] == recompute_etag('"r1"', resp.raw_content or b"")

    access, serve = _events(tmp_path)
    assert isinstance(access, TargetAccessEvent)
    assert (access.stream, access.seq, access.status) == (INJECTOR_STREAM, 0, 200)
    assert access.probe is False and access.method == "GET"
    assert access.url.endswith("/robots.txt") and access.flow_id == flow.id and access.ts == TS
    assert isinstance(serve, PlacementServe)
    assert (serve.stream, serve.seq, serve.placement_id) == (INJECTOR_STREAM, 1, P1_ID)
    assert serve.surface is Surface.P1 and serve.status == 200 and serve.flow_id == flow.id
    assert serve.insert_ok is True and serve.probe is False
    assert serve.byte_offset == len(APP_ROBOTS)
    assert serve.decoded_sha256 == _sha(body)
    assert serve.wire_sha256 == _sha(resp.raw_content or b"")
    assert (tmp_path / "injector" / "0000.body").read_bytes() == resp.raw_content
    meta = _meta(tmp_path)
    assert meta["synthesized_base"] is False and meta["app_status"] == 200
    assert meta["action"] == "robots" and meta["content_encoding"] == "gzip"
    assert meta["placements"] == [
        {"placement_id": P1_ID, "byte_offset": len(APP_ROBOTS), "insert_ok": True}
    ]


def test_robots_base_is_synthesized_when_the_app_has_none(tmp_path: Path) -> None:
    """(b) App 404 -> 200 text/plain base + P1, app headers kept, base recorded."""
    resp = _serve(_injector(tmp_path), _flow("/robots.txt"), _app(404, WERKZEUG_404))
    assert resp.status_code == 200 and resp.reason == "OK"
    assert resp.headers["content-type"].startswith("text/plain")
    assert "content-encoding" not in resp.headers
    assert resp.raw_content == DEFAULT_ROBOTS_BASE.encode() + P1_TEXT.encode() + b"\n"
    assert resp.headers["content-length"] == str(len(resp.raw_content))
    _assert_app_headers(resp)
    access, serve = _events(tmp_path)
    assert access.status == 200
    assert serve.insert_ok is True and serve.status == 200
    assert serve.byte_offset == len(DEFAULT_ROBOTS_BASE)
    meta = _meta(tmp_path)
    assert meta["synthesized_base"] is True
    assert (meta["app_status"], meta["served_status"]) == (404, 200)


@pytest.mark.parametrize("status", [301, 403, 500, 206])
def test_robots_other_statuses_are_not_planted(tmp_path: Path, status: int) -> None:
    app = _app(status, b"whatever")
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(_injector(tmp_path), _flow("/robots.txt"), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (status, raw, fields)
    _access, serve = _events(tmp_path)
    assert serve.insert_ok is False and serve.byte_offset is None
    assert "not planted" in _meta(tmp_path)["note"]


def test_p7_payload_is_planted_into_the_apps_own_404(tmp_path: Path) -> None:
    """(c) Werkzeug's page is kept; the payload is appended (it has no </body>)."""
    resp = _serve(_injector(tmp_path), _flow(P7_PATH + "?debug=1"), _app(404, WERKZEUG_404))
    assert resp.status_code == 404 and resp.reason == "Not Found"
    assert resp.get_content() == WERKZEUG_404 + P7_TEXT.encode()
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    _assert_app_headers(resp)
    access, serve = _events(tmp_path)
    assert access.status == 404
    assert serve.placement_id == P7_ID and serve.surface is Surface.P7
    assert serve.status == 404 and serve.insert_ok is True
    assert serve.byte_offset == len(WERKZEUG_404)
    meta = _meta(tmp_path)
    assert (meta["expected_status"], meta["app_status"]) == (404, 404)
    assert "note" not in meta


def test_p7_payload_goes_before_body_close(tmp_path: Path) -> None:
    page = b"<html><body><h1>Forbidden</h1></body></html>"
    manifest = _manifest(_placement(P7_ID, Surface.P7, P7_PATH, "error:403", P7_TEXT))
    resp = _serve(_injector(tmp_path, manifest), _flow(P7_PATH), _app(403, page))
    assert resp.get_content() == page.replace(b"</body>", P7_TEXT.encode() + b"</body>")
    assert resp.status_code == 403


def test_p7_unexpected_4xx_is_planted_and_recorded(tmp_path: Path) -> None:
    manifest = _manifest(_placement(P7_ID, Surface.P7, P7_PATH, "error:403", P7_TEXT))
    resp = _serve(_injector(tmp_path, manifest), _flow(P7_PATH), _app(404, WERKZEUG_404))
    assert resp.status_code == 404  # the app's status, never rewritten
    (_access, serve) = _events(tmp_path)
    assert serve.insert_ok is True and serve.status == 404
    meta = _meta(tmp_path)
    assert (meta["expected_status"], meta["app_status"]) == (403, 404)
    assert "expected 403" in meta["note"]


def test_p7_non_error_response_is_not_planted(tmp_path: Path) -> None:
    """(d) The app answers 200 on the probe path: nothing planted, insert_ok false."""
    app = _app(200, b"<html><body>secret=1</body></html>")
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(_injector(tmp_path), _flow(P7_PATH), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (200, raw, fields)
    _access, serve = _events(tmp_path)
    assert serve.insert_ok is False and serve.byte_offset is None and serve.status == 200
    meta = _meta(tmp_path)
    assert meta["app_status"] == 200 and "not 4xx" in meta["note"]
    assert (tmp_path / "injector" / "0000.body").read_bytes() == raw


def test_decoy_keeps_app_headers(tmp_path: Path) -> None:
    """(e) The app's 404 becomes a 200 decoy page with the app's other headers."""
    resp = _serve(_injector(tmp_path), _flow(f"/x-{TAG}/"), _app(404, WERKZEUG_404, etag='"d"'))
    assert resp.status_code == 200 and resp.reason == "OK"
    assert resp.raw_content == DECOY_PAGE.encode()
    assert resp.headers["content-type"].startswith("text/html")
    assert "content-encoding" not in resp.headers
    assert resp.headers["content-length"] == str(len(DECOY_PAGE.encode()))
    assert resp.headers["etag"] == recompute_etag('"d"', DECOY_PAGE.encode())
    _assert_app_headers(resp)
    (access,) = _events(tmp_path)  # a decoy carries no placement
    assert isinstance(access, TargetAccessEvent)
    assert access.status == 200 and access.url.endswith(f"/x-{TAG}/")
    assert not (tmp_path / "injector" / "0000.body").exists()


@pytest.mark.parametrize("path", ["/robots.txt", P7_PATH, f"/x-{TAG}/"])
def test_head_is_never_planted(tmp_path: Path, path: str) -> None:
    """(f) HEAD passes through untouched and creates no placement_serve."""
    app = _app(404, b"")
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(_injector(tmp_path), _flow(path, method="HEAD"), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (404, raw, fields)
    (access,) = _events(tmp_path)
    assert access.method == "HEAD"


def test_not_modified_robots_is_not_planted(tmp_path: Path) -> None:
    """(f) A 304 keeps its empty body and headers."""
    app = http.Response.make(304, b"", {**APP_HEADERS, "etag": '"r1"'})
    raw, fields = app.raw_content, app.headers.fields
    resp = _serve(_injector(tmp_path), _flow("/robots.txt"), app)
    assert (resp.status_code, resp.raw_content, resp.headers.fields) == (304, raw, fields)
    _access, serve = _events(tmp_path)
    assert serve.insert_ok is False


def test_event_lines_are_exactly_the_models_json(tmp_path: Path) -> None:
    _serve(_injector(tmp_path), _flow("/robots.txt"), _app(200, APP_ROBOTS))
    for line, event in zip(
        (tmp_path / EVENTS_FILE).read_bytes().splitlines(), _events(tmp_path), strict=True
    ):
        assert line == event.model_dump_json().encode()


@pytest.mark.parametrize("path", ["/robots.txt", P7_PATH, f"/x-{TAG}/"])
def test_control_arm_passes_everything_through(tmp_path: Path, path: str) -> None:
    manifest = _manifest(arm=Arm.CONTROL)
    injector = SurfaceInjector.from_config(
        InjectorConfig(manifest=manifest, contents={}, probe_secret=SECRET, evidence_dir=tmp_path)
    )
    app = _app(404, WERKZEUG_404, etag='"v1"')
    before = (app.raw_content, app.headers.fields, app.status_code)
    resp = _serve(injector, _flow(path), app)
    assert (resp.raw_content, resp.headers.fields, resp.status_code) == before
    (access,) = _events(tmp_path)
    assert isinstance(access, TargetAccessEvent) and access.status == 404
    assert not (tmp_path / "injector" / "0000.body").exists()


def test_unrelated_path_is_forwarded_byte_identical(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/graphql", method="POST", headers={"content-type": "application/json"})
    flow.request.content = b'{"query":"{ pastes { id } }"}'
    req_before = (flow.request.raw_content, flow.request.headers.fields, flow.request.url)
    injector.request(flow)
    assert flow.response is None
    assert (flow.request.raw_content, flow.request.headers.fields, flow.request.url) == req_before
    app = _app(200, b"<html><body>pastes</body></html>", etag='"v1"')
    raw, fields = app.raw_content, app.headers.fields
    flow.response = app
    injector.response(flow)
    assert flow.response.raw_content == raw
    assert flow.response.headers.fields == fields
    (access,) = _events(tmp_path)
    assert access.method == "POST" and access.status == 200 and access.probe is False


def test_probe_request_is_marked_and_header_stripped(tmp_path: Path) -> None:
    flow = _flow("/robots.txt", headers={PROBE_HEADER: SECRET})
    _serve(_injector(tmp_path), flow, _app(200, APP_ROBOTS))
    assert PROBE_HEADER not in flow.request.headers
    access, serve = _events(tmp_path)
    assert access.probe is True and serve.probe is True
    for path in (tmp_path / "injector").iterdir():
        assert SECRET.encode() not in path.read_bytes()


def test_spoofed_probe_header_is_an_ordinary_request(tmp_path: Path) -> None:
    flow = _flow("/robots.txt", headers={PROBE_HEADER: "guessed-value"})
    _serve(_injector(tmp_path), flow, _app(200, APP_ROBOTS))
    assert PROBE_HEADER not in flow.request.headers
    access, serve = _events(tmp_path)
    assert access.probe is False
    assert serve.probe is False and serve.insert_ok is True  # counts toward Access


def test_probe_header_is_stripped_before_forwarding(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/graphql", headers={PROBE_HEADER: SECRET})
    injector.request(flow)
    assert flow.response is None
    assert PROBE_HEADER not in flow.request.headers
    flow.response = _app()
    injector.response(flow)
    (access,) = _events(tmp_path)
    assert access.probe is True


def test_error_hook_logs_request_without_status(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt")
    injector.request(flow)
    injector.error(flow)
    injector.error(flow)  # logged once
    (access,) = _events(tmp_path)
    assert access.status is None


def test_response_after_logging_is_not_logged_twice(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/graphql")
    _serve(injector, flow)
    injector.error(flow)
    injector.response(flow)
    assert len(_events(tmp_path)) == 1


def test_flow_the_request_hook_did_not_see_is_still_logged(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/graphql")
    flow.response = _app()
    injector.response(flow)
    (access,) = _events(tmp_path)
    assert access.status == 200


def test_numbering_resumes_after_restart(tmp_path: Path) -> None:
    _serve(_injector(tmp_path), _flow("/robots.txt"), _app(200, APP_ROBOTS))  # seq 0, 1
    _serve(_injector(tmp_path), _flow("/robots.txt"), _app(200, APP_ROBOTS))  # seq 2, 3
    assert [e.seq for e in _events(tmp_path)] == [0, 1, 2, 3]
    assert (tmp_path / "injector" / "0002.body").exists()
    assert _meta(tmp_path, 2)["seq"] == 2


def test_resume_isolates_a_torn_last_line(tmp_path: Path) -> None:
    _serve(_injector(tmp_path), _flow("/graphql"))
    with (tmp_path / EVENTS_FILE).open("ab") as fh:
        fh.write(b'{"kind":"target_access","seq":7')  # crash mid-write
    _serve(_injector(tmp_path), _flow("/graphql"))
    lines = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    assert len(lines) == 3
    last = EVENTS.validate_json(lines[-1])
    assert last.seq == 1  # the torn line's seq was never committed


def test_unrecordable_flow_is_withheld(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    injector = _injector(tmp_path)

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(ServeLog, "record", broken)
    resp = _serve(injector, _flow("/robots.txt"), _app(200, APP_ROBOTS))
    assert resp.status_code == 502
    assert TAG.encode() not in (resp.raw_content or b"")


def test_body_collision_withholds_planted_bytes(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt")
    injector.request(flow)
    (tmp_path / "injector" / "0000.body").write_bytes(b"not ours")  # appears after startup
    flow.response = _app(200, APP_ROBOTS)
    injector.response(flow)
    assert flow.response.status_code == 502
    assert (tmp_path / "injector" / "0000.body").read_bytes() == b"not ours"
    (access,) = _events(tmp_path)  # what the agent got: a 502, nothing planted
    assert access.status == 502


# --------------------------------------------------------------------------- configuration


def _write_env(tmp_path: Path, manifest: RunManifest, contents: dict[str, str]) -> dict[str, str]:
    mpath = tmp_path / "manifest.json"
    mpath.write_text(manifest.model_dump_json())
    ppath = tmp_path / "payloads.json"
    ppath.write_text(json.dumps(contents))
    return {
        "LAB_MANIFEST": str(mpath),
        "LAB_PAYLOADS": str(ppath),
        "LAB_PROBE_SECRET": SECRET,
        "LAB_EVIDENCE_DIR": str(tmp_path / "evidence"),
    }


def test_config_from_env(tmp_path: Path) -> None:
    manifest = _manifest()
    env = _write_env(tmp_path, manifest, _contents(manifest))
    config = InjectorConfig.from_env({**env, "LAB_RUN_ID": RUN_ID})
    assert config.manifest == manifest
    assert config.contents == _contents(manifest)
    assert config.evidence_dir == tmp_path / "evidence"
    assert SECRET not in repr(config)


def test_config_control_needs_no_payload_file(tmp_path: Path) -> None:
    manifest = _manifest(arm=Arm.CONTROL)
    env = _write_env(tmp_path, manifest, {})
    del env["LAB_PAYLOADS"]
    config = InjectorConfig.from_env(env)
    assert config.contents == {}
    assert SurfaceInjector.from_config(config).plan.arm is Arm.CONTROL


def test_config_rejects_bad_environment(tmp_path: Path) -> None:
    manifest = _manifest()
    env = _write_env(tmp_path, manifest, _contents(manifest))
    with pytest.raises(ValueError, match="LAB_MANIFEST"):
        InjectorConfig.from_env({k: v for k, v in env.items() if k != "LAB_MANIFEST"})
    with pytest.raises(ValueError, match="LAB_RUN_ID"):
        InjectorConfig.from_env({**env, "LAB_RUN_ID": new_id("run")})
    with pytest.raises(ValueError, match="LAB_PAYLOADS"):
        InjectorConfig.from_env({k: v for k, v in env.items() if k != "LAB_PAYLOADS"})
    Path(env["LAB_PAYLOADS"]).write_text('["not", "an", "object"]')
    with pytest.raises(ValueError, match="LAB_PAYLOADS"):
        InjectorConfig.from_env(env)


def test_addon_script_loads_like_mitmdump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``mitmdump -s cell/injector/addon.py`` loads the file this way."""
    manifest = _manifest()
    for key, value in _write_env(tmp_path, manifest, _contents(manifest)).items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("LAB_RUN_ID", raising=False)
    path = Path(__file__).resolve().parents[2] / "cell" / "injector" / "addon.py"
    module = load_script(str(path))
    assert module is not None
    (injector,) = module.addons
    assert type(injector).__name__ == "SurfaceInjector"
    assert (tmp_path / "evidence" / "injector").is_dir()


def test_addon_script_without_manifest_fails_to_load(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAB_MANIFEST", raising=False)
    path = Path(__file__).resolve().parents[2] / "cell" / "injector" / "addon.py"
    assert load_script(str(path)) is None  # logged as an error: mitmdump exits at startup
