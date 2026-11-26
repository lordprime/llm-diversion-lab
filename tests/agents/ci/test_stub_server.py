"""The recording stub model: every API shape and streaming mode, read back with the lab's
telemetry parsers; embeddings and listings; errors; redaction; the request record."""

from __future__ import annotations

import base64
import io
import json
import math
import struct
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agents.ci.stub_model.replies import embedding
from agents.ci.stub_model.script import StubScript
from agents.ci.stub_model.server import MAX_REQUEST_BYTES, RequestRecorder, StubModel, create_app
from agents.ci.stub_model.server import main as server_main
from agents.ci.stub_model.verify import RequestLog
from agents.ci.stub_model.verify import main as verify_main
from control.telemetry.model import CallTelemetry, ToolCallRecord, WireFormat
from control.telemetry.wire import parse_call

SCRIPT = """
models: [stub-model, second-model]
embedding_dimensions: 12
final: "That is all."
turns:
  - text: "Looking at the target now."
  - text: "Running two things."
    tool_calls:
      - name: run_command
        arguments: {command: "curl -s http://target/"}
      - name: read_file
        arguments: {path: /etc/hosts, lines: [1, 2]}
"""
MESSAGES = [{"role": "system", "content": "You are a tester."}, {"role": "user", "content": "go"}]
CHAT = {
    "/api/chat": WireFormat.OLLAMA_CHAT,
    "/v1/chat/completions": WireFormat.OPENAI_CHAT,
    "/v1/messages": WireFormat.ANTHROPIC_MESSAGES,
}
EXPECTED_TOOLS = (
    ToolCallRecord(name="run_command", arguments='{"command":"curl -s http://target/"}'),
    ToolCallRecord(name="read_file", arguments='{"path":"/etc/hosts","lines":[1,2]}'),
)
#: the stop reason each API gives a plain reply and a tool-call reply
STOPS = {
    "/api/chat": ("stop", "stop"),
    "/v1/chat/completions": ("stop", "tool_calls"),
    "/v1/messages": ("end_turn", "tool_use"),
}


class Stub:
    """A stub model in-process, with its record kept in memory."""

    def __init__(self, script: str = SCRIPT) -> None:
        self.stream = io.StringIO()
        self.model = StubModel(StubScript.from_yaml(script), RequestRecorder(self.stream))
        self.client = TestClient(create_app(self.model))

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def chat(self, path: str, stream: bool | None, **extra: Any) -> tuple[Any, CallTelemetry]:
        body: dict[str, Any] = {"model": "stub-model", "messages": MESSAGES, **extra}
        if path == "/v1/messages":
            body.update(system=MESSAGES[0]["content"], messages=MESSAGES[1:], max_tokens=64)
        if stream is not None:
            body["stream"] = stream
        response = self.client.post(path, json=body)
        call = parse_call(
            path,
            json.dumps(body).encode(),
            response.content,
            response.headers["content-type"],
        )
        return response, call


@pytest.fixture
def stub() -> Stub:
    return Stub()


@pytest.mark.parametrize("path", sorted(CHAT))
@pytest.mark.parametrize("stream", [None, False, True])
def test_every_chat_shape_reads_back_cleanly(stub: Stub, path: str, stream: bool | None) -> None:
    streamed = stream is True or (path == "/api/chat" and stream is None)
    plain_stop, tool_stop = STOPS[path]

    response, call = stub.chat(path, stream)
    assert response.status_code == 200
    assert call.parse_error is None
    assert call.format is CHAT[path]
    assert call.streamed is streamed
    assert (call.text, call.tool_calls, call.stop_reason) == (
        "Looking at the target now.",
        (),
        plain_stop,
    )
    assert call.requested_model == "stub-model"
    assert call.returned_model == "stub-model"
    # a streamed OpenAI reply reports usage only when asked (as OpenAI does)
    if not (streamed and path == "/v1/chat/completions"):
        assert call.input_tokens and call.output_tokens

    _, call = stub.chat(path, stream)
    assert call.parse_error is None
    assert call.text == "Running two things."
    assert call.tool_calls == EXPECTED_TOOLS
    assert call.stop_reason == tool_stop

    _, call = stub.chat(path, stream)
    assert (call.text, call.tool_calls, call.stop_reason) == ("That is all.", (), plain_stop)
    assert [r["turn"] for r in stub.records()] == [0, 1, "final"]
    assert all(r["stream"] is streamed for r in stub.records())


def test_stream_content_types(stub: Stub) -> None:
    assert stub.chat("/api/chat", True)[0].headers["content-type"] == "application/x-ndjson"
    for path in ("/v1/chat/completions", "/v1/messages"):
        response, _ = stub.chat(path, True)
        assert response.headers["content-type"].startswith("text/event-stream")
    for path in CHAT:
        assert stub.chat(path, False)[0].headers["content-type"] == "application/json"


def test_openai_stream_reports_usage_only_when_asked(stub: Stub) -> None:
    _, call = stub.chat("/v1/chat/completions", True)
    assert call.input_tokens is None
    _, call = stub.chat("/v1/chat/completions", True, stream_options={"include_usage": True})
    assert call.input_tokens and call.output_tokens and call.parse_error is None


def test_openai_tool_call_ids_and_given_ids_are_kept() -> None:
    stub = Stub("turns: [{tool_calls: [{name: t, id: call_given}, {name: u}]}]\n")
    response, _ = stub.chat("/v1/chat/completions", False)
    calls = response.json()["choices"][0]["message"]["tool_calls"]
    assert [c["id"] for c in calls] == ["call_given", "call_stub_0_1"]
    assert response.json()["choices"][0]["message"]["content"] is None


def test_anthropic_tool_use_input_is_an_object() -> None:
    stub = Stub("turns: [{tool_calls: [{name: t, arguments: {a: 1}}]}]\n")
    response, _ = stub.chat("/v1/messages", False)
    blocks = response.json()["content"]
    assert blocks == [{"type": "tool_use", "id": "toolu_stub_0_0", "name": "t", "input": {"a": 1}}]


def test_ollama_tool_call_arguments_are_an_object(stub: Stub) -> None:
    stub.chat("/api/chat", False)
    response, _ = stub.chat("/api/chat", False)
    function = response.json()["message"]["tool_calls"][0]["function"]
    assert function["arguments"] == {"command": "curl -s http://target/"}


def test_a_missing_model_uses_the_scripts_first(stub: Stub) -> None:
    response = stub.client.post("/v1/chat/completions", json={"messages": MESSAGES})
    assert response.json()["model"] == "stub-model"


def test_replies_are_byte_identical_across_runs() -> None:
    first, second = Stub(), Stub()
    for path in CHAT:
        for stream in (False, True):
            assert first.chat(path, stream)[0].content == second.chat(path, stream)[0].content


# --------------------------------------------------------------------------- embeddings


def test_ollama_embed_takes_a_string_or_a_list(stub: Stub) -> None:
    one = stub.client.post("/api/embed", json={"model": "m", "input": "hello"}).json()
    assert one["embeddings"] == [embedding("hello", 12)]
    many = stub.client.post("/api/embed", json={"model": "m", "input": ["a", "b"]}).json()
    assert many["embeddings"] == [embedding("a", 12), embedding("b", 12)]
    assert many["model"] == "m" and many["prompt_eval_count"] >= 1


@pytest.mark.parametrize(
    "body",
    [
        {"model": "m"},
        {"input": None},
        {"input": []},
        {"input": 5},
        {"input": [1, "a"]},
        {"input": {}},
    ],
)
def test_ollama_embed_refuses_bad_input(stub: Stub, body: dict[str, Any]) -> None:
    response = stub.client.post("/api/embed", json=body)
    assert response.status_code == 400
    assert "input is required" in response.json()["error"]


def test_ollama_legacy_embeddings_takes_one_prompt(stub: Stub) -> None:
    response = stub.client.post("/api/embeddings", json={"model": "m", "prompt": "hello"})
    assert response.json() == {"embedding": embedding("hello", 12)}


@pytest.mark.parametrize("body", [{"model": "m"}, {"prompt": ["a"]}, {"prompt": 3}, {"input": "a"}])
def test_ollama_legacy_embeddings_needs_a_prompt(stub: Stub, body: dict[str, Any]) -> None:
    response = stub.client.post("/api/embeddings", json=body)
    assert response.status_code == 400
    assert response.json() == {"error": "prompt is required: a string"}


def test_both_ollama_embedding_endpoints_are_recorded(stub: Stub) -> None:
    stub.client.post("/api/embed", json={"input": "a"})
    stub.client.post("/api/embeddings", json={"prompt": "a"})
    stub.client.post("/api/embeddings", json={})
    records = stub.records()
    assert [(r["path"], r["status"], r["api"], r["turn"]) for r in records] == [
        ("/api/embed", 200, "ollama", None),
        ("/api/embeddings", 200, "ollama", None),
        ("/api/embeddings", 400, "ollama", None),
    ]
    assert records[1]["body"] == {"prompt": "a"}


def test_openai_embeddings_floats_and_base64(stub: Stub) -> None:
    floats = stub.client.post("/v1/embeddings", json={"input": ["a", "b"]}).json()
    assert [d["index"] for d in floats["data"]] == [0, 1]
    assert floats["data"][0]["embedding"] == embedding("a", 12)
    packed = stub.client.post(
        "/v1/embeddings", json={"input": "a", "encoding_format": "base64"}
    ).json()
    raw = base64.b64decode(packed["data"][0]["embedding"])
    decoded = struct.unpack("<12f", raw)
    assert decoded == pytest.approx(embedding("a", 12), abs=1e-6)
    tokens = stub.client.post("/v1/embeddings", json={"input": [[1, 2], [3]]}).json()
    assert len(tokens["data"]) == 2
    single = stub.client.post("/v1/embeddings", json={"input": [1, 2, 3]}).json()
    assert len(single["data"]) == 1


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({}, "input is required"),
        ({"input": ""}, None),
        ({"input": "a", "encoding_format": "int8"}, "encoding_format"),
    ],
)
def test_openai_embeddings_errors(stub: Stub, body: dict[str, Any], message: str | None) -> None:
    response = stub.client.post("/v1/embeddings", json=body)
    if message is None:
        assert response.status_code == 200  # an empty string is still a string
        return
    assert response.status_code == 400
    assert message in response.json()["error"]["message"]


@pytest.mark.parametrize("dimensions", [1, 7, 32, 33, 4096])
def test_embeddings_are_unit_length_and_deterministic(dimensions: int) -> None:
    vector = embedding("text", dimensions)
    assert len(vector) == dimensions
    assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, abs_tol=1e-4)
    assert vector == embedding("text", dimensions)
    if dimensions > 1:  # one dimension leaves only +1 or -1
        assert vector != embedding("other", dimensions)


# --------------------------------------------------------------------------- listings


def test_listings(stub: Stub) -> None:
    tags = stub.client.get("/api/tags").json()
    assert [m["name"] for m in tags["models"]] == ["stub-model", "second-model"]
    models = stub.client.get("/v1/models").json()
    assert [m["id"] for m in models["data"]] == ["stub-model", "second-model"]
    # Anthropic's list shape on the same path
    assert models["data"][0]["type"] == "model" and models["has_more"] is False
    assert stub.client.get("/api/version").json() == {"version": "0.12.0"}
    shown = stub.client.post("/api/show", json={"model": "second-model"})
    assert shown.status_code == 200 and "tools" in shown.json()["capabilities"]
    assert stub.client.post("/api/show", json={"name": "stub-model"}).status_code == 200
    assert stub.client.post("/api/show", json={"model": "nope"}).status_code == 404
    assert stub.client.get("/").text == "Ollama is running"
    # listings never use up a turn
    assert all(r["turn"] is None for r in stub.records())
    assert stub.chat("/api/chat", False)[1].text == "Looking at the target now."


# --------------------------------------------------------------------------- errors


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/api/chat", 404),
        ("POST", "/v2/chat", 404),
        ("DELETE", "/v1/models", 404),
        ("POST", "/api/tags", 404),
        ("PUT", "/v1/messages", 404),
    ],
)
def test_unknown_endpoints_are_404_and_recorded(
    stub: Stub, method: str, path: str, status: int
) -> None:
    response = stub.client.request(method, path)
    assert response.status_code == status
    (record,) = stub.records()
    assert (record["method"], record["path"], record["api"], record["status"]) == (
        method,
        path,
        None,
        status,
    )


@pytest.mark.parametrize("path", sorted(CHAT))
@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"text"', b""])
def test_a_chat_body_that_is_not_an_object_is_refused(stub: Stub, path: str, body: bytes) -> None:
    response = stub.client.post(path, content=body, headers={"content-type": "application/json"})
    assert response.status_code == 400
    record = stub.records()[0]
    assert record["turn"] is None  # a refused request uses no turn
    assert record["body_format"] in ("text", "json", "empty")
    # the error is in the API's own shape
    doc = response.json()
    if path == "/api/chat":
        assert isinstance(doc["error"], str)
    elif path == "/v1/messages":
        assert doc["type"] == "error"
    else:
        assert "message" in doc["error"]


def test_an_oversized_body_is_refused(stub: Stub) -> None:
    body = b'{"input": "' + b"x" * (MAX_REQUEST_BYTES + 1) + b'"}'
    response = stub.client.post("/api/embed", content=body)
    assert response.status_code == 413


def test_hostile_unicode_and_odd_json_are_survived(stub: Stub) -> None:
    messages = [{"role": "user", "content": "‮\x00\ud800 ok"}]
    response = stub.client.post(
        "/v1/chat/completions",
        content=json.dumps({"messages": messages, "stream": "yes"}).encode(),
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"  # "yes" is not true
    response = stub.client.post("/v1/messages", content=b"\xff\xfe{}")
    assert response.status_code == 400


# --------------------------------------------------------------------------- the record


def test_the_record_masks_auth_and_keeps_the_body(stub: Stub) -> None:
    stub.client.post(
        "/v1/messages?api_key=sk-secret-in-query&beta=true",
        json={"model": "stub-model", "max_tokens": 5, "messages": MESSAGES[1:]},
        headers={
            "Authorization": "Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "x-api-key": "sk-ant-secret",
            "Proxy-Authorization": "Basic dXNlcjpwYXNz",
            "Cookie": "session=abc",
            "X-Goog-Api-Key": "AIzaSy-secret",
            "api-key": "azure-secret",
            "anthropic-version": "2023-06-01",
            "X-Custom": "token=sk-ant-api03-hiddeninanotherheader",
        },
    )
    (record,) = stub.records()
    text = json.dumps(record)
    for secret in (
        "sk-secret-in-query",
        "sk-ant-api03-abc",
        "sk-ant-secret",
        "dXNlcjpwYXNz",
        "session=abc",
        "AIzaSy-secret",
        "azure-secret",
        "hiddeninanotherheader",
    ):
        assert secret not in text, secret
    headers = record["headers"]
    for name in (
        "authorization",
        "x-api-key",
        "proxy-authorization",
        "cookie",
        "x-goog-api-key",
        "api-key",
    ):
        assert headers[name] == "[REDACTED]", name
    assert headers["anthropic-version"] == "2023-06-01"
    assert record["path"] == "/v1/messages?api_key=REDACTED&beta=true"
    assert record["body"]["messages"] == MESSAGES[1:]
    assert set(record) == {
        "seq",
        "ts",
        "method",
        "path",
        "api",
        "headers",
        "body_format",
        "body",
        "stream",
        "turn",
        "status",
        "response_content_type",
        "response",
    }


def test_record_sequence_numbers_and_body_formats(stub: Stub) -> None:
    stub.client.get("/api/tags")
    stub.client.post("/api/chat", content=b"plain words")
    stub.client.post("/api/embed", json={"input": "a"})
    records = stub.records()
    assert [r["seq"] for r in records] == [0, 1, 2]
    assert [r["body_format"] for r in records] == ["empty", "text", "json"]
    assert records[1]["body"] == "plain words"
    assert json.loads(records[2]["response"])["embeddings"]


# --------------------------------------------------------------------------- verify


def _write(path: Path, stub: Stub) -> Path:
    path.write_text(stub.stream.getvalue(), encoding="utf-8")
    return path


def test_verify_passes_a_good_run_and_names_what_is_missing(stub: Stub, tmp_path: Path) -> None:
    for path in CHAT:
        stub.chat(path, True)
    stub.client.post("/api/embeddings", json={"prompt": "a"})
    log = RequestLog.load(_write(tmp_path / "r.jsonl", stub))
    assert log.check(["/api/chat", "/api/embeddings"], ["run_command", "read_file"]) == []
    assert log.check(["/api/embed"], ["write_file"]) == [
        "never called: /api/embed",
        "tool call never sent: write_file",
    ]


def test_verify_flags_broken_lines_and_unreadable_replies(tmp_path: Path) -> None:
    good = Stub()
    good.chat("/v1/messages", True)
    record = good.records()[0]
    record["response"] = record["response"].replace("message_stop", "message_stopp")
    path = tmp_path / "r.jsonl"
    path.write_text(
        json.dumps(record) + "\n\nnot json\n" + json.dumps({"seq": 1}) + "\n", encoding="utf-8"
    )
    problems = RequestLog.load(path).check()
    assert "line 3: not JSON" in problems
    assert "line 4: not a stub request record" in problems
    assert any("truncated stream: no message_stop" in p for p in problems)


def test_verify_cli(stub: Stub, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert verify_main([str(empty)]) == 1
    assert "no request reached the stub model" in capsys.readouterr().err
    assert verify_main([str(tmp_path / "missing.jsonl")]) == 2
    stub.chat("/api/chat", False)
    path = _write(tmp_path / "r.jsonl", stub)
    assert verify_main([str(path), "--expect", "/api/chat"]) == 0
    assert "1 requests (/api/chat x1)" in capsys.readouterr().out
    assert verify_main([str(path), "--expect-tool", "run_command"]) == 1


# --------------------------------------------------------------------------- the entry point


def test_main_checks_a_script(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(SCRIPT, encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text("turns: [{}]\n", encoding="utf-8")
    record = str(tmp_path / "r.jsonl")
    assert server_main(["--check", "--script", str(good), "--record", record]) == 0
    assert "is valid (2 turns)" in capsys.readouterr().out
    assert server_main(["--check", "--script", str(bad), "--record", record]) == 2
    assert "needs text, tool_calls, or both" in capsys.readouterr().err
    assert server_main(["--script", str(tmp_path / "none.yaml"), "--record", record]) == 2
    assert not Path(record).exists()  # nothing is served or recorded for a bad script
