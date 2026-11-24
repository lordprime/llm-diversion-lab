"""Run telemetry: loading the tap's evidence, summarising a run, writing derived files.

Evidence is written with the real tap :class:`Recorder`, so these tests also pin the
file names and meta layout the loader depends on.
"""

from __future__ import annotations

import gzip
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cell.tap import recorder as tap
from cell.tap.recorder import Recorder, RequestMeta, ResponseMeta, TapConfig
from control.core.ids import new_id
from control.telemetry import extract
from control.telemetry.extract import (
    MAX_BODY_BYTES,
    TelemetryError,
    load_calls,
    summarise,
    write_derived,
)
from control.telemetry.model import (
    TELEMETRY_VERSION,
    CallTelemetry,
    RunTelemetry,
    ToolCallRecord,
)
from control.telemetry.wire import WireFormat
from tests.telemetry.fixtures import anthropic_wire as anth
from tests.telemetry.fixtures import ollama_wire as oll
from tests.telemetry.fixtures import openai_wire as oai

RUN_ID = new_id("run")
TS = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def _recorder(evidence: Path) -> Recorder:
    return Recorder(TapConfig(run_id=RUN_ID, tags=(), evidence_dir=evidence))


def _record(
    rec: Recorder,
    path: str,
    request: bytes,
    response: bytes | None,
    *,
    response_type: str | None = "application/json",
    request_encoding: str | None = None,
    request_decoded: bool = True,
    response_encoding: str | None = None,
    response_decoded: bool = True,
) -> None:
    rec.record(
        request,
        response,
        TS,
        RequestMeta("POST", path, "application/json", request_encoding, request_decoded),
        None
        if response is None
        else ResponseMeta(200, response_type, response_encoding, response_decoded),
    )


def _three_format_run(evidence: Path) -> None:
    rec = _recorder(evidence)
    _record(
        rec, "/api/chat", oll.CHAT_REQUEST, oll.CHAT_STREAM, response_type="application/x-ndjson"
    )
    _record(
        rec,
        "/v1/chat/completions",
        oai.STREAM_REQUEST,
        oai.STREAM_TWO_TOOLS,
        response_type="text/event-stream",
    )
    _record(rec, "/v1/messages?beta=true", anth.REQUEST, anth.RESPONSE)


# --------------------------------------------------------------------------- load_calls


def test_loader_uses_the_tap_file_layout() -> None:
    assert extract.LLM_DIR == tap.LLM_DIR
    assert MAX_BODY_BYTES == 64 * 1024 * 1024


def test_load_calls_reads_recorder_evidence(tmp_path: Path) -> None:
    _three_format_run(tmp_path)
    calls = load_calls(tmp_path)
    assert [c.seq for c in calls] == [0, 1, 2]
    assert [c.format for c in calls] == [
        WireFormat.OLLAMA_CHAT,
        WireFormat.OPENAI_CHAT,
        WireFormat.ANTHROPIC_MESSAGES,
    ]
    assert all(c.parse_error is None for c in calls)
    assert calls[0].streamed and calls[1].streamed and not calls[2].streamed
    assert calls[1].tool_calls[1] == ToolCallRecord(
        name="dns_lookup", arguments='{"name": "admin.lab"}'
    )
    assert calls[2].cache_read_tokens == 5000


def test_no_llm_directory_means_no_calls(tmp_path: Path) -> None:
    assert load_calls(tmp_path) == []
    assert load_calls(tmp_path / "does-not-exist") == []


def test_missing_response_is_a_parse_error_on_that_call_only(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, None)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, oll.CHAT_RESPONSE)
    first, second = load_calls(tmp_path)
    assert first.parse_error == "response missing"
    assert first.thread_key == second.thread_key
    assert second.parse_error is None


def test_bodies_stored_raw_are_decoded_with_the_recorded_encoding(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(
        rec,
        "/v1/messages",
        gzip.compress(anth.REQUEST),
        gzip.compress(anth.RESPONSE),
        request_encoding="gzip",
        request_decoded=False,
        response_encoding="gzip",
        response_decoded=False,
    )
    (call,) = load_calls(tmp_path)
    assert call.parse_error is None
    assert call.requested_model == "claude-sonnet-4-5"
    assert call.output_tokens == 210


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        ("gzip", b"definitely not gzip"),
        ("gzip", gzip.compress(oll.CHAT_RESPONSE)[:-12]),  # truncated
        ("snappy", b"whatever"),
        ("gzip, br", b"stacked encodings are not supported"),
    ],
)
def test_raw_body_that_cannot_be_decoded(tmp_path: Path, encoding: str, body: bytes) -> None:
    rec = _recorder(tmp_path)
    _record(
        rec, "/api/chat", oll.CHAT_REQUEST, body, response_encoding=encoding, response_decoded=False
    )
    (call,) = load_calls(tmp_path)
    assert call.parse_error is not None
    assert "cannot decode" in call.parse_error
    assert call.thread_key != ""  # the request was still read


def test_decompression_bomb_is_refused(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    bomb = gzip.compress(b"\0" * (MAX_BODY_BYTES + 1), compresslevel=1)
    _record(
        rec, "/api/chat", bomb, oll.CHAT_RESPONSE, request_encoding="gzip", request_decoded=False
    )
    (call,) = load_calls(tmp_path)
    assert call.parse_error is not None
    assert "exceeds" in call.parse_error


def test_oversized_file_on_disk_is_not_read(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, b"{}")
    with (tmp_path / "llm" / "0000.resp.body").open("r+b") as fh:
        fh.truncate(MAX_BODY_BYTES + 1)  # sparse: cheap to create
    (call,) = load_calls(tmp_path)
    assert call.parse_error is not None
    assert "exceeds" in call.parse_error


def test_call_without_meta_has_no_format(tmp_path: Path) -> None:
    llm = tmp_path / "llm"
    llm.mkdir()
    (llm / "0000.req.json").write_bytes(oll.CHAT_REQUEST)
    (llm / "0000.resp.body").write_bytes(oll.CHAT_RESPONSE)
    (call,) = load_calls(tmp_path)
    assert call.format is None
    assert call.parse_error is not None
    assert "meta" in call.parse_error
    assert call.requested_model == "qwen3:8b"


@pytest.mark.parametrize(
    "meta",
    [
        b"not json",
        b"[]",
        b'{"seq": 0, "request": "x"}',
        b'{"seq": 0, "request": {"method": "POST"}}',
        b'{"seq": 0, "request": {"method": "POST", "path": 5}}',
        b'{"seq": 0, "request": {"method": "POST", "path": "/api/chat", "decoded": "yes"}}',
        b'{"seq": 0, "request": {"method": "POST", "path": "/api/chat"}, "response": 3}',
        b'{"seq": 0, "request": {"method": "POST", "path": "/api/chat", "content_encoding": 1}}',
        b'{"seq": 1, "request": {"method": "POST", "path": "/api/chat"}}',
    ],
)
def test_unreadable_meta_is_a_parse_error(tmp_path: Path, meta: bytes) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, oll.CHAT_RESPONSE)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, oll.CHAT_RESPONSE)
    meta_file = tmp_path / "llm" / "0000.meta.json"
    meta_file.unlink()
    meta_file.write_bytes(meta)
    bad, good = load_calls(tmp_path)
    assert bad.parse_error is not None
    assert bad.format is None
    assert good.parse_error is None


def test_unknown_endpoint(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/v1/embeddings", b'{"model":"nomic-embed","input":"x"}', b'{"data":[]}')
    (call,) = load_calls(tmp_path)
    assert call.format is None
    assert call.parse_error is not None
    assert "/v1/embeddings" in call.parse_error


def test_request_file_missing(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, oll.CHAT_RESPONSE)
    (tmp_path / "llm" / "0000.req.json").unlink()
    (call,) = load_calls(tmp_path)
    assert call.parse_error == "request missing"
    assert call.thread_key == ""
    assert call.request_messages == 0
    # the response is still read, so its tokens are not lost
    assert call.format is WireFormat.OLLAMA_CHAT
    assert (call.input_tokens, call.output_tokens) == (126, 75)


def test_stray_files_are_ignored(tmp_path: Path) -> None:
    _three_format_run(tmp_path)
    llm = tmp_path / "llm"
    (llm / "notes.txt").write_text("hello")
    (llm / "12.req.json").write_text("{}")  # three digits: not a tap file
    (llm / "0001.req.json.tmp").write_text("{}")
    (llm / "subdir").mkdir()
    assert [c.seq for c in load_calls(tmp_path)] == [0, 1, 2]


def test_symlinked_body_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_bytes(oll.CHAT_RESPONSE)
    evidence = tmp_path / "evidence"
    rec = _recorder(evidence)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, None)
    (evidence / "llm" / "0000.resp.body").symlink_to(secret)
    (call,) = load_calls(evidence)
    assert call.parse_error is not None
    assert call.input_tokens is None


def test_special_file_is_not_read(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    _record(rec, "/api/chat", oll.CHAT_REQUEST, None)
    os.mkfifo(tmp_path / "llm" / "0000.resp.body")
    (call,) = load_calls(tmp_path)  # must not block on the FIFO
    assert call.parse_error is not None


def test_symlinked_llm_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    _three_format_run(real)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "llm").symlink_to(real / "llm")
    with pytest.raises(TelemetryError):
        load_calls(evidence)


def test_llm_that_is_a_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "llm").write_text("not a directory")
    with pytest.raises(TelemetryError):
        load_calls(tmp_path)


def test_load_is_deterministic(tmp_path: Path) -> None:
    _three_format_run(tmp_path)
    assert load_calls(tmp_path) == load_calls(tmp_path)


# --------------------------------------------------------------------------- summarise


def _call(seq: int, **fields: object) -> CallTelemetry:
    base: dict[str, object] = {
        "seq": seq,
        "format": WireFormat.OLLAMA_CHAT,
        "requested_model": "qwen3:8b",
        "returned_model": "qwen3:8b",
        "input_tokens": None,
        "output_tokens": None,
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "request_messages": 2,
        "request_chars": 100,
        "system_sha256": "a" * 64,
        "thread_key": "main",
        "tool_calls": (),
        "reasoning": "",
        "text": "",
        "stop_reason": "stop",
        "streamed": False,
        "parse_error": None,
    }
    base.update(fields)
    return CallTelemetry.model_validate(base)


def _fake_run() -> list[CallTelemetry]:
    """One main agent (3 calls) that spawns two sub-agents (2 calls and 1 call)."""
    nmap = ToolCallRecord(name="run_nmap", arguments="{}")
    task = ToolCallRecord(name="Task", arguments='{"prompt":"x"}')
    return [
        _call(
            0,
            thread_key="main",
            input_tokens=1000,
            output_tokens=50,
            tool_calls=(task, task),
            reasoning="plan the work",
            request_chars=4000,
        ),
        _call(1, thread_key="sub-a", input_tokens=300, output_tokens=20, tool_calls=(nmap,)),
        _call(
            2,
            thread_key="sub-a",
            input_tokens=900,
            output_tokens=30,
            reasoning="ports",
            request_chars=9000,
        ),
        _call(
            3,
            thread_key="sub-b",
            format=WireFormat.OPENAI_CHAT,
            returned_model="gpt-4o",
            input_tokens=200,
            output_tokens=10,
            cache_read_tokens=100,
        ),
        _call(4, thread_key="main", input_tokens=2500, output_tokens=80, text="done"),
        _call(5, thread_key="main", parse_error="response missing", returned_model=None),
    ]


def test_summarise_counts_agents_tokens_and_tools() -> None:
    run = summarise(RUN_ID, _fake_run())
    assert run.run_id == RUN_ID
    assert run.telemetry_version == TELEMETRY_VERSION
    assert run.calls == 6
    assert run.agents == 3
    assert run.calls_by_format == {"ollama_chat": 5, "openai_chat": 1}
    assert run.calls_by_model == {"gpt-4o": 1, "qwen3:8b": 5}  # requested model as fallback
    assert run.input_tokens == 1000 + 300 + 900 + 200 + 2500
    assert run.output_tokens == 50 + 20 + 30 + 10 + 80
    assert run.cache_read_tokens == 100
    assert run.cache_write_tokens == 0
    assert run.calls_without_usage == 1
    assert run.peak_input_tokens == 2500
    assert run.peak_request_chars == 9000
    assert run.tool_calls_by_name == {"Task": 2, "run_nmap": 1}
    assert run.reasoning_chars == len("plan the work") + len("ports")
    assert run.calls_with_reasoning == 2
    assert run.parse_errors == 1


def test_peak_input_counts_cached_prompt_tokens_for_anthropic() -> None:
    calls = [
        _call(
            0,
            format=WireFormat.ANTHROPIC_MESSAGES,
            input_tokens=12,
            cache_read_tokens=5000,
            cache_write_tokens=300,
        ),
        _call(1, format=WireFormat.OPENAI_CHAT, input_tokens=4000, cache_read_tokens=3500),
    ]
    run = summarise(RUN_ID, calls)
    # Anthropic's input_tokens leaves out the cached part; OpenAI's prompt_tokens includes it.
    assert calls[0].context_tokens == 5312
    assert calls[1].context_tokens == 4000
    assert run.peak_input_tokens == 5312
    assert run.input_tokens == 4012


def test_summarise_with_no_usage_anywhere() -> None:
    run = summarise(RUN_ID, [_call(0), _call(1)])
    assert run.peak_input_tokens is None
    assert (run.input_tokens, run.output_tokens) == (0, 0)
    assert run.calls_without_usage == 2


def test_summarise_an_empty_run() -> None:
    run = summarise(RUN_ID, [])
    assert run.calls == 0
    assert run.agents == 0
    assert run.peak_input_tokens is None
    assert run.peak_request_chars == 0
    assert run.calls_by_format == {} and run.tool_calls_by_name == {}


def test_unreadable_requests_do_not_count_as_agents() -> None:
    calls = [
        _call(0, thread_key="main"),
        _call(1, thread_key="", parse_error="bad request"),
        _call(2, thread_key="", parse_error="bad request"),
    ]
    assert summarise(RUN_ID, calls).agents == 1


def test_unknown_format_and_model_are_counted_as_unknown() -> None:
    calls = [_call(0, format=None, requested_model=None, returned_model=None, parse_error="x")]
    run = summarise(RUN_ID, calls)
    assert run.calls_by_format == {"unknown": 1}
    assert run.calls_by_model == {"unknown": 1}


def test_summarise_ignores_input_order() -> None:
    calls = _fake_run()
    shuffled = calls[3:] + calls[:3][::-1]
    assert summarise(RUN_ID, shuffled) == summarise(RUN_ID, calls)
    assert (
        summarise(RUN_ID, shuffled).model_dump_json() == summarise(RUN_ID, calls).model_dump_json()
    )


def test_summarise_refuses_duplicate_seq() -> None:
    with pytest.raises(ValueError, match="seq"):
        summarise(RUN_ID, [_call(0), _call(0)])


def test_summary_over_real_evidence(tmp_path: Path) -> None:
    _three_format_run(tmp_path)
    run = summarise(RUN_ID, load_calls(tmp_path))
    assert run.calls == 3
    assert run.agents == 3
    assert run.tool_calls_by_name == {"Grep": 1, "dns_lookup": 1, "http_get": 2}
    assert run.peak_input_tokens == 5312
    assert run.parse_errors == 0


def test_models_are_frozen_and_strict() -> None:
    call = _call(0)
    with pytest.raises(ValueError):
        call.seq = 5  # type: ignore[misc]
    with pytest.raises(ValueError):
        CallTelemetry.model_validate({**call.model_dump(), "surprise": 1})
    with pytest.raises(ValueError):
        _call(0, input_tokens=-1)
    with pytest.raises(ValueError):
        ToolCallRecord.model_validate({"name": "x", "arguments": "{}", "id": "c1"})


# --------------------------------------------------------------------------- write_derived


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_write_derived_round_trip(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _three_format_run(evidence)
    calls = load_calls(evidence)
    run = summarise(RUN_ID, calls)
    out = tmp_path / "derived"
    write_derived(out, run, calls)

    folder = out / "telemetry"
    assert sorted(p.name for p in folder.iterdir()) == [
        "calls.jsonl",
        "reasoning.jsonl",
        "summary.json",
    ]
    assert RunTelemetry.model_validate_json((folder / "summary.json").read_bytes()) == run

    rows = _read_jsonl(folder / "calls.jsonl")
    assert [r["seq"] for r in rows] == [0, 1, 2]
    assert all("reasoning" not in r for r in rows)
    assert rows == [c.model_dump(mode="json", exclude={"reasoning"}) for c in calls]

    trace = _read_jsonl(folder / "reasoning.jsonl")
    assert [set(r) for r in trace] == [{"seq", "thread_key", "reasoning", "text", "tool_calls"}] * 3
    assert trace[0]["reasoning"] == "Port 80 is open."
    assert trace[2]["reasoning"] == "The handler compares passwords with ==.\n\n[redacted]"
    assert trace[1]["tool_calls"] == [
        {"name": "http_get", "arguments": '{"url": "http://10.0.0.7/admin"}'},
        {"name": "dns_lookup", "arguments": '{"name": "admin.lab"}'},
    ]


def test_write_derived_is_byte_identical_and_recomputable(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _three_format_run(evidence)
    out = tmp_path / "derived"
    calls = load_calls(evidence)
    write_derived(out, summarise(RUN_ID, calls), calls)
    first = {p.name: p.read_bytes() for p in (out / "telemetry").iterdir()}
    # a stale earlier result is replaced, not appended to
    (out / "telemetry" / "calls.jsonl").write_text("stale\n")
    write_derived(out, summarise(RUN_ID, calls), calls)
    assert {p.name: p.read_bytes() for p in (out / "telemetry").iterdir()} == first


def test_write_derived_sorts_calls_by_seq(tmp_path: Path) -> None:
    calls = _fake_run()
    write_derived(tmp_path, summarise(RUN_ID, calls), list(reversed(calls)))
    seqs = [r["seq"] for r in _read_jsonl(tmp_path / "telemetry" / "reasoning.jsonl")]
    assert seqs == [0, 1, 2, 3, 4, 5]


def test_write_derived_refuses_the_evidence_directory(tmp_path: Path) -> None:
    _three_format_run(tmp_path)
    calls = load_calls(tmp_path)
    run = summarise(RUN_ID, calls)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    for target in (tmp_path, tmp_path / "llm", tmp_path / "llm" / "deeper"):
        with pytest.raises(TelemetryError, match="evidence"):
            write_derived(target, run, calls)
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before


def test_write_derived_refuses_a_symlinked_telemetry_folder(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _three_format_run(evidence)
    out = tmp_path / "derived"
    out.mkdir()
    (out / "telemetry").symlink_to(evidence / "llm")
    calls = load_calls(evidence)
    with pytest.raises(TelemetryError, match="symlink"):
        write_derived(out, summarise(RUN_ID, calls), calls)
    assert not (evidence / "llm" / "summary.json").exists()


def test_write_derived_refuses_a_symlinked_output_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _three_format_run(evidence)
    raw = evidence / "llm" / "0000.req.json"
    original = raw.read_bytes()
    out = tmp_path / "derived"
    (out / "telemetry").mkdir(parents=True)
    (out / "telemetry" / "calls.jsonl").symlink_to(raw)
    calls = load_calls(evidence)
    with pytest.raises(TelemetryError, match="symlink"):
        write_derived(out, summarise(RUN_ID, calls), calls)
    assert raw.read_bytes() == original


def test_write_derived_refuses_a_directory_in_place_of_a_file(tmp_path: Path) -> None:
    (tmp_path / "telemetry" / "summary.json").mkdir(parents=True)
    with pytest.raises(TelemetryError):
        write_derived(tmp_path, summarise(RUN_ID, []), [])


def test_write_derived_refuses_a_summary_that_does_not_match_the_calls(tmp_path: Path) -> None:
    calls = _fake_run()
    with pytest.raises(ValueError, match="calls"):
        write_derived(tmp_path, summarise(RUN_ID, calls[:2]), calls)
    assert not (tmp_path / "telemetry").exists()


def test_failed_write_leaves_no_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_run()
    run = summarise(RUN_ID, calls)

    def broken_replace(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(extract.os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        write_derived(tmp_path, run, calls)
    assert list((tmp_path / "telemetry").iterdir()) == []


def test_write_derived_for_an_empty_run(tmp_path: Path) -> None:
    write_derived(tmp_path, summarise(RUN_ID, []), [])
    folder = tmp_path / "telemetry"
    assert (folder / "calls.jsonl").read_bytes() == b""
    assert (folder / "reasoning.jsonl").read_bytes() == b""
    assert RunTelemetry.model_validate_json((folder / "summary.json").read_bytes()).calls == 0


def test_lone_surrogates_from_a_model_survive_the_round_trip(tmp_path: Path) -> None:
    # JSON allows "\ud800" on its own; Python keeps it, but it is not valid UTF-8.
    # The contract: every derived file is ASCII, with such text kept as a \uXXXX escape.
    calls = [
        _call(
            0,
            text="a\ud800b",
            reasoning="t\udc00",
            tool_calls=(ToolCallRecord(name="x\udfff", arguments="{}"),),
        )
    ]
    write_derived(tmp_path, summarise(RUN_ID, calls), calls)
    folder = tmp_path / "telemetry"
    (row,) = _read_jsonl(folder / "reasoning.jsonl")
    assert (row["text"], row["reasoning"]) == ("a\ud800b", "t\udc00")
    summary = json.loads((folder / "summary.json").read_bytes())
    assert summary["tool_calls_by_name"] == {"x\udfff": 1}
    (row,) = _read_jsonl(folder / "calls.jsonl")
    assert row["text"] == "a\ud800b"
    assert row["tool_calls"] == [{"name": "x\udfff", "arguments": "{}"}]
    for name in ("summary.json", "calls.jsonl", "reasoning.jsonl"):
        data = (folder / name).read_bytes()
        assert data.isascii()
    assert b"\\ud800" in (folder / "reasoning.jsonl").read_bytes()


def test_non_ascii_text_is_escaped_and_reads_back_unchanged(tmp_path: Path) -> None:
    calls = [_call(0, text="réponse 🚀", reasoning="思考", returned_model="qwen3:8b-ü")]
    write_derived(tmp_path, summarise(RUN_ID, calls), calls)
    folder = tmp_path / "telemetry"
    assert all((folder / n).read_bytes().isascii() for n in os.listdir(folder))
    (row,) = _read_jsonl(folder / "reasoning.jsonl")
    assert (row["text"], row["reasoning"]) == ("réponse 🚀", "思考")
    run = RunTelemetry.model_validate_json((folder / "summary.json").read_bytes())
    assert run.calls_by_model == {"qwen3:8b-ü": 1}
