"""LLM tap: tag detection, evidence files, LlmCall JSONL, and the mitmproxy shell.

No live proxy is started: the recorder is driven directly, and the addon's hooks are
driven with mitmproxy's in-memory test flows.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.addons.script import load_script
from mitmproxy.test import tflow

from cell.tap.addon import LlmTap
from cell.tap.recorder import (
    DEFAULT_EVIDENCE_DIR,
    EVENTS_FILE,
    TAP_STREAM,
    Recorder,
    RequestMeta,
    ResponseMeta,
    TapConfig,
    extract_requested_model,
    extract_returned_model,
    find_tags,
    parse_tags,
    redact_path,
)
from control.core.ids import new_id
from control.core.models import LlmCall, LlmRole
from control.core.tokens import new_tag

RUN_ID = new_id("run")
TAG = new_tag()
OTHER_TAG = new_tag()
TS = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
MODEL = "claude-test-model"


def _escape_all(text: str) -> str:
    """JSON-escape every character as ``\\uXXXX`` (valid JSON, tag not literally present)."""
    return "".join(f"\\u{ord(c):04x}" for c in text)


def _request(content: str, *, model: str = MODEL) -> bytes:
    return json.dumps(
        {"model": model, "max_tokens": 64, "messages": [{"role": "user", "content": content}]}
    ).encode()


def _escaped_request(tag: str) -> bytes:
    # Built by hand so the tag only ever appears \u-escaped on the wire.
    body = (
        '{"model": "' + MODEL + '", "messages": [{"role": "user", "content": '
        '"page says <!-- ' + _escape_all(tag) + ' -->"}]}'
    ).encode()
    assert tag.encode() not in body
    return body


def _response(model: str = MODEL) -> bytes:
    return json.dumps(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
        }
    ).encode()


def _recorder(tmp_path: Path, tags: tuple[str, ...] = (TAG,)) -> Recorder:
    return Recorder(TapConfig(run_id=RUN_ID, tags=tags, evidence_dir=tmp_path))


# --------------------------------------------------------------------------- find_tags


def test_find_tags_raw_json() -> None:
    assert find_tags(_request(f"robots.txt says {TAG}"), [TAG]) is True


def test_find_tags_unicode_escaped_json() -> None:
    assert find_tags(_escaped_request(TAG), [TAG]) is True


def test_find_tags_partially_escaped_json() -> None:
    half = TAG[:8] + _escape_all(TAG[8:])
    body = ('{"messages": [{"content": "x' + half + 'y"}]}').encode()
    assert TAG.encode() not in body
    assert find_tags(body, [TAG]) is True


def test_find_tags_in_object_key() -> None:
    body = ('{"' + _escape_all(TAG) + '": 1}').encode()
    assert find_tags(body, [TAG]) is True


def test_find_tags_in_earlier_duplicate_key() -> None:
    # json.loads keeps only the last value of a duplicate key; the raw search still sees it.
    body = ('{"content": "' + TAG + '", "content": "clean"}').encode()
    assert find_tags(body, [TAG]) is True


def test_find_tags_digits_only_tag_inside_json_number() -> None:
    digits = "1234567890123456"
    body = ('{"max_tokens": ' + digits + "}").encode()
    assert find_tags(body, [digits]) is True


def test_find_tags_non_json_falls_back_to_raw_bytes() -> None:
    assert find_tags(b"plain text with " + TAG.encode() + b" inside", [TAG]) is True
    assert find_tags(b"plain text without it", [TAG]) is False


def test_find_tags_absent() -> None:
    assert find_tags(_request("nothing planted here"), [TAG]) is False


def test_find_tags_no_tags_or_empty_body() -> None:
    assert find_tags(_request(TAG), []) is False
    assert find_tags(b"", [TAG]) is False


def test_find_tags_any_of_several() -> None:
    assert find_tags(_request(OTHER_TAG), [TAG, OTHER_TAG]) is True


def test_find_tags_is_case_sensitive_as_given() -> None:
    assert find_tags(_request(TAG.upper()), [TAG]) is (TAG.upper() == TAG)


def test_find_tags_deeply_nested_json_does_not_crash() -> None:
    deep = b"[" * 100_000 + b"]" * 100_000
    assert find_tags(deep, [TAG]) is False


# --------------------------------------------------------------------------- models


def test_extract_requested_model() -> None:
    assert extract_requested_model(_request("x", model="m-1")) == "m-1"
    assert extract_requested_model(b"not json") is None
    assert extract_requested_model(b'{"model": 3}') is None
    assert extract_requested_model(b"[]") is None


def test_extract_returned_model_json() -> None:
    assert extract_returned_model(_response("m-2")) == "m-2"
    assert extract_returned_model(b'{"type": "error"}') is None


def test_extract_returned_model_anthropic_sse() -> None:
    sse = (
        b"event: message_start\n"
        b'data: {"type":"message_start","message":{"id":"msg_1","model":"m-3"}}\n\n'
        b"event: ping\n"
        b'data: {"type": "ping"}\n\n'
    )
    assert extract_returned_model(sse) == "m-3"


def test_extract_returned_model_openai_sse() -> None:
    sse = b'data: {"id":"c1","model":"m-4","choices":[]}\n\ndata: [DONE]\n\n'
    assert extract_returned_model(sse) == "m-4"


def test_extract_returned_model_garbage() -> None:
    assert extract_returned_model(b"\x00\x01 garbage") is None
    assert extract_returned_model(b"") is None


# --------------------------------------------------------------------------- recorder


def test_tag_detection(tmp_path: Path) -> None:
    """Brief step 2: raw and \\u-escaped tags are seen; first_tag_seq is the first one."""
    rec = _recorder(tmp_path)
    calls = [
        rec.record(_request("tag-free prompt"), _response(), TS),
        rec.record(_request(f"saw <!-- {TAG} --> in the page"), _response(), TS),
        rec.record(_escaped_request(TAG), _response(), TS),
        rec.record(_request("tag-free again"), _response(), TS),
    ]
    assert [c.seq for c in calls] == [0, 1, 2, 3]
    assert [c.tag_present for c in calls] == [False, True, True, False]
    assert [c.first_tag_seq for c in calls] == [None, 1, 1, 1]
    for c in calls:
        assert isinstance(c, LlmCall)
        assert c.run_id == RUN_ID
        assert c.stream == TAP_STREAM == "tap"
        assert c.role is LlmRole.MAIN


def test_tag_free_run_never_sets_first_tag_seq(tmp_path: Path) -> None:
    rec = _recorder(tmp_path, tags=())
    calls = [rec.record(_request(TAG), _response(), TS) for _ in range(3)]
    assert all(c.tag_present is False and c.first_tag_seq is None for c in calls)


def test_escaped_tag_first(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    first = rec.record(_escaped_request(TAG), _response(), TS)
    assert first.tag_present is True
    assert first.first_tag_seq == 0


def test_evidence_files_and_event_line(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    req, resp = _request(f"x {TAG}", model="m-req"), _response("m-resp")
    call = rec.record(req, resp, TS)

    llm = tmp_path / "llm"
    assert (llm / "0000.req.json").read_bytes() == req
    assert (llm / "0000.resp.body").read_bytes() == resp
    assert call.request_artifact == "llm/0000.req.json"
    assert call.response_artifact == "llm/0000.resp.body"
    assert call.request_sha256 == hashlib.sha256(req).hexdigest()
    assert call.response_sha256 == hashlib.sha256(resp).hexdigest()
    assert call.requested_model == "m-req"
    assert call.returned_model == "m-resp"  # recorded as reported; no mismatch decision
    assert call.ts == TS

    lines = (tmp_path / EVENTS_FILE).read_bytes().splitlines(keepends=True)
    assert lines == [call.model_dump_json().encode() + b"\n"]


def test_event_line_reships_byte_for_byte(tmp_path: Path) -> None:
    """The stored line is exactly what a re-ship sends: parse -> dump is the identity."""
    rec = _recorder(tmp_path)
    rec.record(_request(TAG), _response(), TS)
    rec.record(_request("none"), None, TS)
    for line in (tmp_path / EVENTS_FILE).read_bytes().splitlines():
        again = LlmCall.model_validate_json(line).model_dump_json().encode()
        assert again == line
        assert json.loads(line)["kind"] == "llm_call"


def test_sse_response_stored_verbatim(tmp_path: Path) -> None:
    sse = (
        b"event: message_start\r\n"
        b'data: {"type":"message_start","message":{"model":"m-sse"}}\r\n\r\n'
        b"event: content_block_delta\r\n"
        b'data: {"type":"content_block_delta","delta":{"text":"hi"}}\r\n\r\n'
    )
    call = _recorder(tmp_path).record(_request("x"), sse, TS)
    assert (tmp_path / "llm" / "0000.resp.body").read_bytes() == sse
    assert call.returned_model == "m-sse"


def test_call_without_response(tmp_path: Path) -> None:
    call = _recorder(tmp_path).record(_request(TAG), None, TS)
    assert call.response_sha256 is None
    assert call.response_artifact is None
    assert call.returned_model is None
    assert call.tag_present is True
    assert not (tmp_path / "llm" / "0000.resp.body").exists()


def test_meta_sidecar(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    req_meta = RequestMeta(
        method="POST",
        path="/v1/messages/count_tokens?beta=true",
        content_type="application/json",
        content_encoding=None,
    )
    resp_meta = ResponseMeta(
        status=429, content_type="application/json", content_encoding="gzip", decoded=False
    )
    rec.record(_request("x"), b"raw gzip bytes", TS, req_meta, resp_meta)
    raw = (tmp_path / "llm" / "0000.meta.json").read_bytes()
    assert json.loads(raw) == {
        "seq": 0,
        "request": {
            "method": "POST",
            "path": "/v1/messages/count_tokens?beta=true",
            "content_type": "application/json",
            "content_encoding": None,
            "decoded": True,
        },
        "response": {
            "status": 429,
            "content_type": "application/json",
            "content_encoding": "gzip",
            "decoded": False,
            "stored": True,
        },
    }


def test_meta_sidecar_without_response(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    rec.record(_request("x"), None, TS, RequestMeta(method="GET", path="/v1/models"))
    meta = json.loads((tmp_path / "llm" / "0000.meta.json").read_bytes())
    assert meta["request"]["method"] == "GET"
    assert meta["response"] is None


def test_meta_sidecar_is_write_once_and_resumed(tmp_path: Path) -> None:
    llm = tmp_path / "llm"
    llm.mkdir()
    (llm / "0004.meta.json").write_bytes(b"{}")
    call = _recorder(tmp_path).record(_request("x"), _response(), TS)
    assert call.seq == 5
    assert (llm / "0004.meta.json").read_bytes() == b"{}"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v1/messages", "/v1/messages"),
        ("/v1/messages?beta=true", "/v1/messages?beta=true"),
        ("/v1/models?key=AIzaSECRET&x=1", "/v1/models?key=REDACTED&x=1"),
        ("/a?API_KEY=s&Access_Token=t&b", "/a?API_KEY=REDACTED&Access_Token=REDACTED&b"),
        ("/a?x-api-key=s", "/a?x-api-key=REDACTED"),
        ("/a?%6Bey=s", "/a?%6Bey=REDACTED"),
    ],
)
def test_redact_path(path: str, expected: str) -> None:
    assert redact_path(path) == expected


def test_meta_path_query_credentials_are_redacted(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    rec.record(_request("x"), None, TS, RequestMeta(method="GET", path="/v1/m?key=SECRETVALUE"))
    raw = (tmp_path / "llm" / "0000.meta.json").read_bytes()
    assert b"SECRETVALUE" not in raw
    assert json.loads(raw)["request"]["path"] == "/v1/m?key=REDACTED"


def test_files_are_write_once(tmp_path: Path) -> None:
    llm = tmp_path / "llm"
    llm.mkdir()
    (llm / "0000.resp.body").write_bytes(b"earlier evidence")
    rec = _recorder(tmp_path)
    # The orphan response file pushes numbering past it instead of overwriting it.
    call = rec.record(_request("x"), _response(), TS)
    assert call.seq == 1
    assert (llm / "0000.resp.body").read_bytes() == b"earlier evidence"


def test_existing_file_fails_loudly_and_is_kept(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    # Another writer creates seq 0's request file behind the recorder's back.
    (tmp_path / "llm" / "0000.req.json").write_bytes(b"not ours")
    with pytest.raises(FileExistsError):
        rec.record(_request("x"), _response(), TS)
    assert (tmp_path / "llm" / "0000.req.json").read_bytes() == b"not ours"
    assert not (tmp_path / EVENTS_FILE).exists()
    # The next call gets a fresh seq and records normally.
    assert rec.record(_request("y"), _response(), TS).seq == 1


def test_response_file_collision_still_writes_event(tmp_path: Path) -> None:
    """A response that cannot be stored still leaves the call's event, then raises."""
    rec = _recorder(tmp_path)
    pending = rec.begin(_request(f"tagged {TAG}"), TS)
    (tmp_path / "llm" / "0000.resp.body").write_bytes(b"not ours")
    with pytest.raises(FileExistsError):
        rec.finish(pending, _response("m-resp"), ResponseMeta(status=200))
    assert (tmp_path / "llm" / "0000.resp.body").read_bytes() == b"not ours"
    (line,) = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    call = LlmCall.model_validate_json(line)
    assert call.seq == 0
    assert call.tag_present is True
    assert call.first_tag_seq == 0
    assert call.response_artifact is None
    assert call.returned_model == "m-resp"
    meta = json.loads((tmp_path / "llm" / "0000.meta.json").read_bytes())
    assert meta["response"]["status"] == 200
    assert meta["response"]["stored"] is False
    # The next call is unaffected.
    assert rec.record(_request("y"), _response(), TS).seq == 1


def test_meta_file_collision_still_writes_event(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    pending = rec.begin(_request(TAG), TS)
    (tmp_path / "llm" / "0000.meta.json").write_bytes(b"not ours")
    with pytest.raises(FileExistsError):
        rec.finish(pending, _response())
    assert (tmp_path / "llm" / "0000.meta.json").read_bytes() == b"not ours"
    assert (tmp_path / "llm" / "0000.resp.body").read_bytes() == _response()
    (line,) = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    call = LlmCall.model_validate_json(line)
    assert call.tag_present is True
    assert call.response_artifact == "llm/0000.resp.body"


def test_finish_twice_is_refused(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    pending = rec.begin(_request("x"), TS)
    rec.finish(pending, _response())
    with pytest.raises(RuntimeError):
        rec.finish(pending, None)
    assert len((tmp_path / EVENTS_FILE).read_bytes().splitlines()) == 1


def test_restart_resumes_seq_and_first_tag_seq(tmp_path: Path) -> None:
    first = _recorder(tmp_path)
    first.record(_request("none"), _response(), TS)
    first.record(_request(TAG), _response(), TS)
    first.begin(_request("in flight when the tap died"), TS)  # request file, no event

    again = _recorder(tmp_path)
    call = again.record(_request("after restart"), _response(), TS)
    assert call.seq == 3
    assert call.tag_present is False
    assert call.first_tag_seq == 1
    assert len((tmp_path / EVENTS_FILE).read_bytes().splitlines()) == 3


def test_restart_closes_a_torn_last_event_line(tmp_path: Path) -> None:
    first = _recorder(tmp_path)
    first.record(_request("one"), _response(), TS)
    events = tmp_path / EVENTS_FILE
    with events.open("ab") as fh:
        fh.write(b'{"run_id":"torn')  # the tap died mid-line

    again = _recorder(tmp_path)
    assert events.read_bytes().endswith(b"\n")
    call = again.record(_request("two"), _response(), TS)
    lines = events.read_bytes().splitlines()
    assert lines[1] == b'{"run_id":"torn'
    assert LlmCall.model_validate_json(lines[2]) == call  # not glued onto the torn line
    _recorder(tmp_path)  # a clean file is left alone
    assert events.read_bytes().splitlines() == lines


def test_seq_numbering_widens_past_four_digits(tmp_path: Path) -> None:
    llm = tmp_path / "llm"
    llm.mkdir()
    (llm / "9999.req.json").write_bytes(b"{}")
    call = _recorder(tmp_path).record(_request("x"), _response(), TS)
    assert call.seq == 10000
    assert call.request_artifact == "llm/10000.req.json"


# --------------------------------------------------------------------------- config


def test_parse_tags() -> None:
    assert parse_tags(None) == ()
    assert parse_tags("") == ()
    assert parse_tags(f" {TAG} ") == (TAG,)
    assert parse_tags(f"{TAG},{OTHER_TAG}") == (TAG, OTHER_TAG)
    assert parse_tags(f"{TAG} {OTHER_TAG},{TAG}") == (TAG, OTHER_TAG)


@pytest.mark.parametrize("bad", ["short", "x" * 15 + "!", TAG + "0"])
def test_parse_tags_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError, match="LAB_TAGS"):
        parse_tags(bad)


def test_config_from_env(tmp_path: Path) -> None:
    env = {"LAB_RUN_ID": RUN_ID, "LAB_TAGS": TAG, "LAB_EVIDENCE_DIR": str(tmp_path)}
    cfg = TapConfig.from_env(env)
    assert cfg == TapConfig(run_id=RUN_ID, tags=(TAG,), evidence_dir=tmp_path)


def test_config_defaults() -> None:
    cfg = TapConfig.from_env({"LAB_RUN_ID": RUN_ID})
    assert cfg.tags == ()
    assert cfg.evidence_dir == Path(DEFAULT_EVIDENCE_DIR) == Path("evidence")


@pytest.mark.parametrize("run_id", [None, "", "../etc", "has space"])
def test_config_requires_valid_run_id(run_id: str | None) -> None:
    env = {} if run_id is None else {"LAB_RUN_ID": run_id}
    with pytest.raises(ValueError, match="LAB_RUN_ID"):
        TapConfig.from_env(env)


# --------------------------------------------------------------------------- addon shell


def _flow(body: bytes, *, resp: bytes | None) -> http.HTTPFlow:
    req = http.Request.make("POST", "http://gateway/v1/messages", body)
    req.timestamp_start = TS.timestamp()
    flow = tflow.tflow(req=req)
    if resp is not None:
        flow.response = http.Response.make(200, resp, {"content-type": "application/json"})
    return flow


def test_addon_records_request_and_response(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(_request(TAG), resp=None)
    tap.request(flow)
    assert flow.response is None  # forwarded untouched
    assert (tmp_path / "llm" / "0000.req.json").read_bytes() == _request(TAG)
    assert not (tmp_path / EVENTS_FILE).exists()  # no event until the call completes

    flow.response = http.Response.make(200, _response(), {"content-type": "application/json"})
    tap.response(flow)
    assert flow.response.status_code == 200
    assert flow.response.content == _response()
    (line,) = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    call = LlmCall.model_validate_json(line)
    assert call.tag_present is True
    assert call.first_tag_seq == 0
    assert call.ts == TS
    assert (tmp_path / "llm" / "0000.resp.body").read_bytes() == _response()


def test_addon_records_decoded_request_body(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(b"", resp=None)
    flow.request.headers["content-encoding"] = "gzip"
    flow.request.content = _request(TAG)  # mitmproxy gzips it on the wire
    assert flow.request.raw_content != _request(TAG)
    tap.request(flow)
    assert (tmp_path / "llm" / "0000.req.json").read_bytes() == _request(TAG)


def test_addon_error_hook_records_call_without_response(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(_request("x"), resp=None)
    tap.request(flow)
    tap.error(flow)
    tap.error(flow)  # a second error for the same flow is ignored
    (line,) = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    assert LlmCall.model_validate_json(line).response_artifact is None


def test_addon_refuses_to_forward_unrecorded_request(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    (tmp_path / "llm" / "0000.req.json").write_bytes(b"not ours")
    tap = LlmTap(rec)
    flow = _flow(_request("x"), resp=None)
    tap.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502  # short-circuits: never reaches the gateway
    assert json.loads(flow.response.content or b"")["type"] == "error"
    tap.response(flow)  # the synthetic response is not recorded as a call
    assert not (tmp_path / EVENTS_FILE).exists()


def test_addon_withholds_unrecorded_response(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(_request(TAG), resp=None)
    tap.request(flow)
    (tmp_path / "llm" / "0000.resp.body").write_bytes(b"not ours")
    flow.response = http.Response.make(200, _response(), {"content-type": "application/json"})
    tap.response(flow)
    assert flow.response.status_code == 502
    assert (tmp_path / "llm" / "0000.resp.body").read_bytes() == b"not ours"
    # The call reached the gateway, so its event is still recorded.
    (line,) = (tmp_path / EVENTS_FILE).read_bytes().splitlines()
    call = LlmCall.model_validate_json(line)
    assert call.tag_present is True
    assert call.response_artifact is None


def test_addon_writes_meta_without_credentials(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(_request("x"), resp=None)
    flow.request.path = "/v1/messages/count_tokens?beta=true"
    flow.request.headers["content-type"] = "application/json"
    for name in (
        "authorization",
        "x-api-key",
        "anthropic-api-key",
        "cookie",
        "proxy-authorization",
    ):
        flow.request.headers[name] = f"SECRET-{name}"
    tap.request(flow)
    flow.response = http.Response.make(
        404, b"not found", {"content-type": "text/plain", "set-cookie": "SECRET-set-cookie"}
    )
    tap.response(flow)
    raw = (tmp_path / "llm" / "0000.meta.json").read_bytes()
    assert b"SECRET" not in raw
    meta = json.loads(raw)
    assert meta["request"] == {
        "method": "POST",
        "path": "/v1/messages/count_tokens?beta=true",
        "content_type": "application/json",
        "content_encoding": None,
        "decoded": True,
    }
    assert meta["response"]["status"] == 404
    assert meta["response"]["content_type"] == "text/plain"
    assert meta["response"]["stored"] is True


def test_addon_marks_undecodable_body_as_raw(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(b"", resp=None)
    flow.request.headers["content-encoding"] = "gzip"
    flow.request.raw_content = b"definitely not gzip"
    tap.request(flow)
    assert (tmp_path / "llm" / "0000.req.json").read_bytes() == b"definitely not gzip"
    tap.error(flow)
    meta = json.loads((tmp_path / "llm" / "0000.meta.json").read_bytes())
    assert meta["request"]["content_encoding"] == "gzip"
    assert meta["request"]["decoded"] is False
    assert meta["response"] is None


def test_addon_ignores_flows_it_did_not_see(tmp_path: Path) -> None:
    tap = LlmTap(_recorder(tmp_path))
    flow = _flow(_request("x"), resp=_response())
    tap.response(flow)
    tap.error(flow)
    assert not (tmp_path / EVENTS_FILE).exists()


def test_addon_script_loads_like_mitmdump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``mitmdump -s cell/tap/addon.py`` loads the file this way; it must expose ``addons``."""
    monkeypatch.setenv("LAB_RUN_ID", RUN_ID)
    monkeypatch.setenv("LAB_TAGS", TAG)
    monkeypatch.setenv("LAB_EVIDENCE_DIR", str(tmp_path))
    path = Path(__file__).resolve().parents[2] / "cell" / "tap" / "addon.py"
    module = load_script(str(path))
    assert module is not None
    (tap,) = module.addons
    assert type(tap).__name__ == "LlmTap"
    assert (tmp_path / "llm").is_dir()


def test_addon_script_without_run_id_fails_to_load(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAB_RUN_ID", raising=False)
    path = Path(__file__).resolve().parents[2] / "cell" / "tap" / "addon.py"
    assert load_script(str(path)) is None  # logged as an error: mitmdump exits at startup
