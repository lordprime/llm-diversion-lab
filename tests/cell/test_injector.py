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

from cell.injector.addon import SurfaceInjector, plant_into_response
from cell.injector.placement import (
    DECOY_PAGE,
    DEFAULT_ROBOTS_BASE,
    INJECTOR_STREAM,
    PROBE_HEADER,
    build_plan,
    is_probe,
    plant_into_body,
    render_error,
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


def test_plant_into_gzip_response_fixes_framing_headers() -> None:
    resp = tutils.tresp()
    resp.headers["content-encoding"] = "gzip"
    resp.headers["etag"] = '"abc123"'
    resp.raw_content = gzip.compress(HTML)
    resp.headers["content-length"] = str(len(resp.raw_content))
    payload = f"<!-- {TAG} -->".encode()

    offset, ok = plant_into_response(resp, payload, before=b"</body>")

    assert ok is True
    assert resp.headers["content-encoding"] == "gzip"
    assert resp.headers["content-length"] == str(len(resp.raw_content or b""))
    assert "etag" not in resp.headers  # the old entity tag no longer describes the body
    decoded = gzip.decompress(resp.raw_content or b"")
    assert decoded[offset : offset + len(payload)] == payload
    assert resp.get_content() == decoded


def test_plant_into_response_leaves_undecodable_response_alone() -> None:
    resp = tutils.tresp()
    resp.headers["content-encoding"] = "gzip"
    resp.headers["etag"] = '"abc123"'
    resp.raw_content = b"broken"
    before = (resp.raw_content, resp.headers.fields)
    assert plant_into_response(resp, b"X") == (-1, False)
    assert (resp.raw_content, resp.headers.fields) == before


# --------------------------------------------------------------------------- rendering


def test_render_robots_includes_tag_after_base() -> None:
    manifest = _manifest()
    robots = render_robots(manifest, _contents(manifest))
    assert robots.status == 200
    assert robots.content_type.startswith("text/plain")
    assert TAG.encode() in robots.body
    assert robots.body.startswith(DEFAULT_ROBOTS_BASE.encode())
    (plant,) = robots.plants
    assert plant.placement.placement_id == P1_ID
    assert plant.offset == len(DEFAULT_ROBOTS_BASE.encode())
    assert robots.body[plant.offset : plant.offset + len(plant.content)] == P1_TEXT.encode()
    assert robots.body.endswith(b"\n")


def test_render_robots_plants_every_p1_placement_in_order() -> None:
    second_id = new_id("pl")
    second = f"# second lab test line {TAG}"
    manifest = _manifest(
        _placement(P1_ID, Surface.P1, "/robots.txt", "robots.txt:append", P1_TEXT),
        _placement(second_id, Surface.P1, "/robots.txt", "robots.txt:append", second),
    )
    robots = render_robots(manifest, {P1_ID: P1_TEXT, second_id: second}, base="")
    assert robots.body == f"{P1_TEXT}\n{second}\n".encode()
    assert [p.offset for p in robots.plants] == [0, len(P1_TEXT) + 1]


@pytest.mark.parametrize("status", [403, 404])
def test_render_error_carries_status_and_payload(status: int) -> None:
    placement = _placement(P7_ID, Surface.P7, P7_PATH, f"error:{status}", P7_TEXT)
    page = render_error(placement, P7_TEXT)
    assert page.status == status
    assert page.content_type.startswith("text/html")
    (plant,) = page.plants
    assert page.body[plant.offset : plant.offset + len(plant.content)] == P7_TEXT.encode()


def test_build_plan_for_control_plants_nothing() -> None:
    plan = build_plan(_manifest(arm=Arm.CONTROL), {})
    assert plan.arm is Arm.CONTROL
    for path in ("/robots.txt", P7_PATH, f"/x-{TAG}/", "/"):
        assert plan.match("GET", path) is None


def test_build_plan_matches_injected_surfaces() -> None:
    manifest = _manifest()
    plan = build_plan(manifest, _contents(manifest))
    robots = plan.match("GET", "/robots.txt?x=1")
    assert robots is not None and TAG.encode() in robots.body
    error = plan.match("POST", P7_PATH)
    assert error is not None and error.status == 404
    for decoy_path in (f"/x-{TAG}/", f"/x-{TAG}", f"/x-{TAG}/deeper/page?q=1"):
        decoy = plan.match("GET", decoy_path)
        assert decoy is not None
        assert decoy.status == 200 and decoy.plants == ()
        assert decoy.body == DECOY_PAGE.encode()
    assert TAG not in DECOY_PAGE
    assert plan.match("POST", "/robots.txt") is None  # the app answers non-GET robots
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


def _app_response(body: bytes = b"app says hi", status: int = 200) -> http.Response:
    resp = http.Response.make(status, b"", {"content-type": "text/html", "etag": '"v1"'})
    resp.headers["content-encoding"] = "gzip"
    resp.content = body  # gzip on the wire
    return resp


def _serve(injector: SurfaceInjector, flow: Any, app: http.Response | None = None) -> None:
    """Run a flow through the hooks; if the injector did not answer, the app does."""
    injector.request(flow)
    if flow.response is None:
        flow.response = app if app is not None else _app_response()
    injector.response(flow)


def test_injected_robots_is_synthetic_and_logged(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt")
    injector.request(flow)
    assert flow.response is not None  # answered by the injector, never forwarded
    injector.response(flow)
    body = flow.response.raw_content or b""
    assert TAG.encode() in body
    assert flow.response.headers["content-length"] == str(len(body))

    access, serve = _events(tmp_path)
    assert isinstance(access, TargetAccessEvent)
    assert (access.stream, access.seq, access.status, access.probe) == (
        INJECTOR_STREAM,
        0,
        200,
        False,
    )
    assert access.method == "GET" and access.url.endswith("/robots.txt")
    assert access.flow_id == flow.id and access.ts == TS
    assert isinstance(serve, PlacementServe)
    assert (serve.stream, serve.seq, serve.placement_id) == (INJECTOR_STREAM, 1, P1_ID)
    assert serve.surface is Surface.P1 and serve.status == 200 and serve.flow_id == flow.id
    assert serve.insert_ok is True and serve.probe is False
    assert serve.decoded_sha256 == _sha(body) and serve.wire_sha256 == _sha(body)
    assert serve.byte_offset is not None
    assert body[serve.byte_offset :].startswith(P1_TEXT.encode())
    # The served bytes are kept as write-once evidence, named by the access seq.
    assert (tmp_path / "injector" / "0000.body").read_bytes() == body


def test_event_lines_are_exactly_the_models_json(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    _serve(injector, _flow("/robots.txt"))
    for line, event in zip(
        (tmp_path / EVENTS_FILE).read_bytes().splitlines(), _events(tmp_path), strict=True
    ):
        assert line == event.model_dump_json().encode()


@pytest.mark.parametrize("status", [403, 404])
def test_p7_path_returns_configured_status_with_payload(tmp_path: Path, status: int) -> None:
    manifest = _manifest(_placement(P7_ID, Surface.P7, P7_PATH, f"error:{status}", P7_TEXT))
    injector = _injector(tmp_path, manifest)
    flow = _flow(P7_PATH + "?debug=1")
    _serve(injector, flow)
    assert flow.response.status_code == status
    assert P7_TEXT.encode() in (flow.response.content or b"")
    access, serve = _events(tmp_path)
    assert access.status == status
    assert serve.placement_id == P7_ID and serve.surface is Surface.P7
    assert serve.status == status and serve.insert_ok is True


def test_decoy_path_is_served_and_logged_without_a_serve(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow(f"/x-{TAG}/")
    _serve(injector, flow)
    assert flow.response.status_code == 200
    assert flow.response.content == DECOY_PAGE.encode()
    (access,) = _events(tmp_path)
    assert isinstance(access, TargetAccessEvent)
    assert access.status == 200 and access.url.endswith(f"/x-{TAG}/")
    assert not (tmp_path / "injector" / "0000.body").exists()


def test_head_request_gets_headers_but_no_planted_bytes(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt", method="HEAD")
    _serve(injector, flow)
    assert flow.response.status_code == 200
    assert flow.response.raw_content == b""
    assert int(flow.response.headers["content-length"]) > 0
    (access,) = _events(tmp_path)  # no bytes delivered: no placement_serve, no Access
    assert access.method == "HEAD"


@pytest.mark.parametrize("path", ["/robots.txt", P7_PATH, f"/x-{TAG}/"])
def test_control_arm_passes_everything_through(tmp_path: Path, path: str) -> None:
    manifest = _manifest(arm=Arm.CONTROL)
    injector = SurfaceInjector.from_config(
        InjectorConfig(manifest=manifest, contents={}, probe_secret=SECRET, evidence_dir=tmp_path)
    )
    flow = _flow(path)
    injector.request(flow)
    assert flow.response is None  # forwarded to the unmodified app
    app = _app_response(b"the app's own answer", status=404)
    flow.response = app
    before = (app.raw_content, app.headers.fields, app.status_code)
    injector.response(flow)
    assert (flow.response.raw_content, flow.response.headers.fields) == before[:2]
    assert flow.response.status_code == 404
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
    app = _app_response(b"<html><body>pastes</body></html>")
    raw, fields = app.raw_content, app.headers.fields
    flow.response = app
    injector.response(flow)
    assert flow.response.raw_content == raw
    assert flow.response.headers.fields == fields
    (access,) = _events(tmp_path)
    assert access.method == "POST" and access.status == 200 and access.probe is False


def test_probe_request_is_marked_and_header_stripped(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt", headers={PROBE_HEADER: SECRET})
    _serve(injector, flow)
    assert PROBE_HEADER not in flow.request.headers
    access, serve = _events(tmp_path)
    assert access.probe is True and serve.probe is True
    for path in (tmp_path / "injector").iterdir():
        assert SECRET.encode() not in path.read_bytes()


def test_spoofed_probe_header_is_an_ordinary_request(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt", headers={PROBE_HEADER: "guessed-value"})
    _serve(injector, flow)
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
    flow.response = _app_response()
    injector.response(flow)
    (access,) = _events(tmp_path)
    assert access.probe is True


def test_error_hook_logs_request_without_status(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/graphql")
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
    flow.response = _app_response()
    injector.response(flow)
    (access,) = _events(tmp_path)
    assert access.status == 200


def test_numbering_resumes_after_restart(tmp_path: Path) -> None:
    _serve(_injector(tmp_path), _flow("/robots.txt"))  # seq 0, 1
    _serve(_injector(tmp_path), _flow("/robots.txt"))  # restarted: seq 2, 3
    assert [e.seq for e in _events(tmp_path)] == [0, 1, 2, 3]
    assert (tmp_path / "injector" / "0002.body").exists()


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
    flow = _flow("/robots.txt")
    _serve(injector, flow)
    assert flow.response.status_code == 502
    assert TAG.encode() not in (flow.response.raw_content or b"")


def test_body_collision_withholds_planted_bytes(tmp_path: Path) -> None:
    injector = _injector(tmp_path)
    flow = _flow("/robots.txt")
    injector.request(flow)
    (tmp_path / "injector" / "0000.body").write_bytes(b"not ours")  # appears after startup
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
