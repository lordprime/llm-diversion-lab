"""Wire parsers: one call's request and response bytes turned into CallTelemetry.

Fixtures are hand-written from each provider's public API docs (see the fixture
modules). Beyond the happy paths, every parser is fed broken, truncated, oversized and
nonsensical bodies and must answer with ``parse_error`` instead of raising.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from control.telemetry.model import CallTelemetry, ToolCallRecord
from control.telemetry.wire import (
    MAX_BODY_BYTES,
    AnthropicMessagesParser,
    OllamaChatParser,
    OpenAIChatParser,
    WireFormat,
    WireParser,
    detect_format,
    parse_call,
    parser_for,
)
from tests.telemetry.fixtures import anthropic_wire as anth
from tests.telemetry.fixtures import ollama_wire as oll
from tests.telemetry.fixtures import openai_wire as oai

SSE = "text/event-stream"
NDJSON = "application/x-ndjson"
JSON = "application/json"


def _sha(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


# --------------------------------------------------------------------------- detect_format


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/chat", WireFormat.OLLAMA_CHAT),
        ("/api/generate", WireFormat.OLLAMA_CHAT),
        ("/ollama/api/chat", WireFormat.OLLAMA_CHAT),
        ("/api/chat?keep_alive=5m", WireFormat.OLLAMA_CHAT),
        ("/v1/chat/completions", WireFormat.OPENAI_CHAT),
        ("/openai/v1/chat/completions?api-key=REDACTED", WireFormat.OPENAI_CHAT),
        ("/v1/messages", WireFormat.ANTHROPIC_MESSAGES),
        ("/anthropic/v1/messages?beta=true", WireFormat.ANTHROPIC_MESSAGES),
        ("http://gateway:8080/v1/messages", WireFormat.ANTHROPIC_MESSAGES),
        ("/v1/messages/count_tokens", None),
        ("/v1/embeddings", None),
        ("/api/tags", None),
        ("/api/chatty", None),
        ("/xapi/chat", None),
        ("/V1/MESSAGES", None),
        ("", None),
        ("/", None),
        ("?/v1/messages", None),
    ],
)
def test_detect_format(path: str, expected: WireFormat | None) -> None:
    assert detect_format(path) == expected


def test_every_format_has_one_parser() -> None:
    parsers = {fmt: parser_for(fmt) for fmt in WireFormat}
    assert isinstance(parsers[WireFormat.OLLAMA_CHAT], OllamaChatParser)
    assert isinstance(parsers[WireFormat.OPENAI_CHAT], OpenAIChatParser)
    assert isinstance(parsers[WireFormat.ANTHROPIC_MESSAGES], AnthropicMessagesParser)
    assert all(isinstance(p, WireParser) for p in parsers.values())
    assert all(p.format is fmt for fmt, p in parsers.items())


# --------------------------------------------------------------------------- Ollama


def test_ollama_chat_json() -> None:
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, oll.CHAT_RESPONSE, JSON, seq=3)
    assert call.seq == 3
    assert call.format is WireFormat.OLLAMA_CHAT
    assert call.parse_error is None
    assert (call.requested_model, call.returned_model) == ("qwen3:8b", "qwen3:8b")
    assert (call.input_tokens, call.output_tokens) == (126, 75)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (None, None)
    assert call.request_messages == 4
    assert call.request_chars == len(
        oll.SYSTEM
        + oll.TASK
        + '{"target":"10.0.0.5"}'  # the earlier tool call's arguments
        + "22/tcp open ssh\n80/tcp open http"  # the tool result
    )
    assert call.system_sha256 == _sha(oll.SYSTEM)
    assert call.reasoning == "Port 80 is open, so look at the web server next."
    assert call.text == ""
    assert call.tool_calls == (
        ToolCallRecord(name="http_get", arguments='{"url":"http://10.0.0.5/"}'),
    )
    assert call.stop_reason == "stop"
    assert call.streamed is False


def test_ollama_chat_ndjson_stream_with_thinking() -> None:
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, oll.CHAT_STREAM, NDJSON)
    assert call.parse_error is None
    assert call.streamed is True
    assert call.reasoning == "Port 80 is open."
    assert call.text == "Checking the web server."
    assert call.tool_calls == (
        ToolCallRecord(name="http_get", arguments='{"url":"http://10.0.0.5/"}'),
    )
    assert (call.input_tokens, call.output_tokens) == (126, 75)
    assert call.stop_reason == "stop"
    assert call.returned_model == "qwen3:8b"


def test_ollama_stream_is_found_without_a_content_type() -> None:
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, oll.CHAT_STREAM, None)
    assert call.streamed is True
    assert call.text == "Checking the web server."


def test_ollama_generate_json_moves_inline_think_to_reasoning() -> None:
    call = OllamaChatParser().parse(oll.GENERATE_REQUEST, oll.GENERATE_RESPONSE, JSON)
    assert call.parse_error is None
    assert call.request_messages == 1
    assert call.request_chars == len("You are a penetration tester.") + len(
        "Which port should I probe first?"
    )
    assert call.system_sha256 == _sha("You are a penetration tester.")
    assert call.reasoning == "SSH rarely gives quick wins; HTTP does."
    assert call.text == "Probe port 80."
    assert (call.input_tokens, call.output_tokens) == (31, 40)


def test_ollama_generate_stream() -> None:
    call = OllamaChatParser().parse(oll.GENERATE_REQUEST, oll.GENERATE_STREAM, NDJSON)
    assert call.parse_error is None
    assert call.streamed is True
    assert call.text == "Probe port 80."
    assert (call.input_tokens, call.output_tokens) == (31, 4)


def test_ollama_truncated_stream_keeps_what_arrived() -> None:
    lines = oll.CHAT_STREAM.splitlines(keepends=True)
    cut = b"".join(lines[:4]) + lines[4][:30]
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, cut, NDJSON)
    assert call.parse_error is not None
    assert "truncated" in call.parse_error
    assert call.text == "Checking the web server."
    assert call.reasoning == "Port 80 is open."
    assert call.input_tokens is None


def test_ollama_stream_without_done_is_truncated() -> None:
    lines = oll.CHAT_STREAM.splitlines(keepends=True)
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, b"".join(lines[:-1]), NDJSON)
    assert call.parse_error is not None
    assert "truncated" in call.parse_error


def test_ollama_error_body() -> None:
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, oll.ERROR_RESPONSE, JSON)
    assert call.parse_error is not None
    assert "not found" in call.parse_error
    # the request side is still described
    assert call.request_messages == 4
    assert call.system_sha256 == _sha(oll.SYSTEM)


# --------------------------------------------------------------------------- OpenAI


def test_openai_json_with_tools_reasoning_and_cache() -> None:
    call = OpenAIChatParser().parse(oai.REQUEST, oai.RESPONSE, JSON, seq=7)
    assert call.parse_error is None
    assert call.format is WireFormat.OPENAI_CHAT
    assert (call.requested_model, call.returned_model) == ("gpt-4o-2024-08-06",) * 2
    assert (call.input_tokens, call.output_tokens) == (1117, 46)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (1024, None)
    assert call.request_messages == 4
    assert call.request_chars == len(
        oai.SYSTEM + oai.TASK + '{"url":"http://10.0.0.7/"}' + "<html>Welcome</html>"
    )
    assert call.system_sha256 == _sha(oai.SYSTEM)
    assert call.reasoning == "Admin panels often live at /admin or /wp-admin."
    assert call.text == "I will try the usual admin paths."
    assert call.tool_calls == (
        ToolCallRecord(name="http_get", arguments='{"url": "http://10.0.0.7/admin"}'),
        ToolCallRecord(name="http_get", arguments='{"url": "http://10.0.0.7/wp-admin"}'),
    )
    assert call.stop_reason == "tool_calls"
    assert call.streamed is False


def test_openai_stream_rebuilds_two_interleaved_tool_calls_and_usage() -> None:
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, oai.STREAM_TWO_TOOLS, SSE)
    assert call.parse_error is None
    assert call.streamed is True
    assert call.tool_calls == (
        ToolCallRecord(name="http_get", arguments='{"url": "http://10.0.0.7/admin"}'),
        ToolCallRecord(name="dns_lookup", arguments='{"name": "admin.lab"}'),
    )
    assert (call.input_tokens, call.output_tokens, call.cache_read_tokens) == (80, 40, 0)
    assert call.stop_reason == "tool_calls"
    assert call.text == ""
    assert call.returned_model == "gpt-4o-2024-08-06"


def test_openai_stream_without_include_usage_has_no_tokens() -> None:
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, oai.STREAM_REASONING_NO_USAGE, SSE)
    assert call.parse_error is None
    assert call.reasoning == "The login form posts to /login."
    assert call.text == "Try /login."
    assert call.input_tokens is None
    assert call.output_tokens is None
    assert call.cache_read_tokens is None
    assert call.stop_reason == "stop"


def test_openai_compatible_reasoning_field_crlf_and_comments() -> None:
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, oai.STREAM_OLLAMA_COMPAT, SSE)
    assert call.parse_error is None
    assert call.reasoning == "Short answer."
    assert call.text == "Done."
    assert call.returned_model == "qwen3:8b"


def test_openai_sse_found_without_a_content_type() -> None:
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, oai.STREAM_TWO_TOOLS, None)
    assert call.streamed is True
    assert len(call.tool_calls) == 2


def test_openai_inline_think_is_moved_to_reasoning() -> None:
    call = OpenAIChatParser().parse(oai.REQUEST, oai.RESPONSE_INLINE_THINK, JSON)
    assert call.reasoning == "The form has no CSRF token."
    assert call.text == "Submit the form twice."


def test_openai_stream_without_done_is_truncated() -> None:
    cut = oai.STREAM_TWO_TOOLS.split(b"data: [DONE]")[0]
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, cut, SSE)
    assert call.parse_error is not None
    assert "truncated" in call.parse_error
    assert len(call.tool_calls) == 2  # what arrived is kept


def test_openai_tool_call_index_reused_with_a_new_id_starts_a_new_call() -> None:
    # Some OpenAI-compatible servers send every complete tool call at index 0.
    chunks = [
        {"index": 0, "id": "c1", "function": {"name": "a", "arguments": "{}"}},
        {"index": 0, "id": "c2", "function": {"name": "b", "arguments": '{"x":1}'}},
    ]
    body = b"".join(
        b"data: "
        + json.dumps(
            {"model": "m", "choices": [{"index": 0, "delta": {"tool_calls": [c]}}]}
        ).encode()
        + b"\n\n"
        for c in chunks
    )
    call = OpenAIChatParser().parse(oai.STREAM_REQUEST, body + b"data: [DONE]\n\n", SSE)
    assert call.tool_calls == (
        ToolCallRecord(name="a", arguments="{}"),
        ToolCallRecord(name="b", arguments='{"x":1}'),
    )


def test_openai_developer_role_counts_as_system() -> None:
    request = json.dumps(
        {
            "model": "o3",
            "messages": [
                {"role": "developer", "content": "Be terse."},
                {"role": "user", "content": "hi"},
            ],
        }
    ).encode()
    call = OpenAIChatParser().parse(request, oai.RESPONSE, JSON)
    assert call.system_sha256 == _sha("Be terse.")


def test_openai_error_body() -> None:
    call = OpenAIChatParser().parse(oai.REQUEST, oai.ERROR_RESPONSE, JSON)
    assert call.parse_error is not None
    assert "Rate limit" in call.parse_error


# --------------------------------------------------------------------------- Anthropic


def test_anthropic_json_with_thinking_redacted_and_cache() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST, anth.RESPONSE, JSON)
    assert call.parse_error is None
    assert call.format is WireFormat.ANTHROPIC_MESSAGES
    assert call.requested_model == "claude-sonnet-4-5"
    assert call.returned_model == "claude-sonnet-4-5-20250929"
    assert (call.input_tokens, call.output_tokens) == (12, 210)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (5000, 300)
    assert call.request_messages == 3
    assert call.request_chars == len(
        "".join(anth.SYSTEM_BLOCKS) + anth.TASK + '{"file_path":"app.py"}' + "def login(): ..."
    )
    assert call.system_sha256 == _sha("\n".join(anth.SYSTEM_BLOCKS))
    assert call.reasoning == "The handler compares passwords with ==.\n\n[redacted]"
    assert call.text == "The login handler is vulnerable to timing attacks."
    assert call.tool_calls == (
        ToolCallRecord(name="Grep", arguments='{"pattern":"==","path":"app.py"}'),
    )
    assert call.stop_reason == "tool_use"
    assert call.streamed is False


def test_anthropic_sse_thinking_redacted_and_input_json_delta() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST, anth.STREAM, SSE)
    assert call.parse_error is None
    assert call.streamed is True
    assert call.returned_model == "claude-sonnet-4-5-20250929"
    assert call.reasoning == "The handler compares passwords with ==.\n\n[redacted]"
    assert call.text == "The login handler is vulnerable to timing attacks."
    assert call.tool_calls == (
        ToolCallRecord(name="Grep", arguments='{"pattern": "==", "path": "app.py"}'),
    )
    # input from message_start, final output from message_delta
    assert (call.input_tokens, call.output_tokens) == (12, 210)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (5000, 300)
    assert call.stop_reason == "tool_use"


def test_anthropic_sse_tool_without_input_deltas_gets_its_start_input() -> None:
    call = AnthropicMessagesParser().parse(
        anth.REQUEST_STRING_SYSTEM, anth.STREAM_EMPTY_TOOL_INPUT, SSE
    )
    assert call.parse_error is None
    assert call.tool_calls == (ToolCallRecord(name="ListFiles", arguments="{}"),)
    assert (call.input_tokens, call.output_tokens) == (40, 9)


def test_anthropic_string_system() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST_STRING_SYSTEM, anth.RESPONSE, JSON)
    assert call.system_sha256 == _sha("You are a sub-agent that searches files.")
    assert call.request_messages == 1


def test_anthropic_truncated_sse_keeps_partial_text() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST, anth.STREAM_TRUNCATED, SSE)
    assert call.parse_error is not None
    assert "truncated" in call.parse_error
    assert call.text == "Partial ans"
    assert call.input_tokens == 30
    assert call.output_tokens is None


def test_anthropic_error_event_in_stream() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST, anth.STREAM_ERROR, SSE)
    assert call.parse_error is not None
    assert "Overloaded" in call.parse_error


def test_anthropic_error_body() -> None:
    call = AnthropicMessagesParser().parse(anth.REQUEST, anth.ERROR_RESPONSE, JSON)
    assert call.parse_error is not None
    assert "max_tokens" in call.parse_error


def test_message_delta_cumulative_usage_wins_when_present() -> None:
    stream = anth.STREAM.replace(
        b'"usage":{"output_tokens":210}',
        b'"usage":{"input_tokens":15,"cache_read_input_tokens":6000,"output_tokens":211}',
    )
    call = AnthropicMessagesParser().parse(anth.REQUEST, stream, SSE)
    assert (call.input_tokens, call.output_tokens, call.cache_read_tokens) == (15, 211, 6000)
    assert call.cache_write_tokens == 300  # not repeated, so the message_start value stays


# --------------------------------------------------------------------------- <think> spans


@pytest.mark.parametrize(
    ("content", "reasoning", "text"),
    [
        ("<think>plan</think>answer", "plan", "answer"),
        ("\n <think>\n plan \n</think>\n\nanswer", "plan", "answer"),
        ("<think></think>answer", "", "answer"),
        ("<think>never closed because max_tokens hit", "never closed because max_tokens hit", ""),
        ("answer <think>not leading</think>", "", "answer <think>not leading</think>"),
        ("<think>a</think>b<think>c</think>", "a", "b<think>c</think>"),
        # the chat template pre-filled <think>, so only the closing tag is in the reply
        ("Let me think...\n</think>\n\nProbe 80.", "Let me think...", "Probe 80."),
        ("</think>answer", "", "answer"),
        ("a</think>b</think>c", "a", "b</think>c"),
        # a closing tag after an opening tag in prose is left alone
        (
            "Use <think> to open and </think> to close.",
            "",
            "Use <think> to open and </think> to close.",
        ),
        # a bare closing tag in prose looks exactly like a pre-filled template: it is split
        ("Close the span with </think> and go on.", "Close the span with", "and go on."),
        ("plain", "", "plain"),
        ("", "", ""),
    ],
)
def test_leading_think_span(content: str, reasoning: str, text: str) -> None:
    response = json.dumps(
        {"model": "m", "message": {"role": "assistant", "content": content}, "done": True}
    ).encode()
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, response, JSON)
    assert (call.reasoning, call.text) == (reasoning, text)


def test_think_span_is_added_after_native_reasoning() -> None:
    response = json.dumps(
        {
            "model": "m",
            "message": {"role": "assistant", "content": "<think>b</think>c", "thinking": "a"},
            "done": True,
        }
    ).encode()
    call = OllamaChatParser().parse(oll.CHAT_REQUEST, response, JSON)
    assert (call.reasoning, call.text) == ("a\n\nb", "c")


# --------------------------------------------------------------------------- thread_key


def _ollama_request(system: str | None, *turns: str) -> bytes:
    messages = [{"role": "system", "content": system}] if system is not None else []
    messages += [
        {"role": "user" if i % 2 == 0 else "assistant", "content": t} for i, t in enumerate(turns)
    ]
    return json.dumps({"model": "m", "messages": messages}).encode()


def _key(request: bytes) -> str:
    return OllamaChatParser().parse(request, oll.CHAT_RESPONSE, JSON).thread_key


def test_thread_key_is_stable_while_history_grows() -> None:
    first = _key(_ollama_request("sys", "task"))
    later = _key(_ollama_request("sys", "task", "step 1", "result 1", "step 2"))
    assert first == later
    assert len(first) == 64
    int(first, 16)


def test_thread_key_ignores_whitespace_layout() -> None:
    assert _key(_ollama_request("You  are\n a tester.", "task")) == _key(
        _ollama_request("You are a tester.", "task")
    )


def test_thread_key_differs_per_system_prompt_and_per_first_task() -> None:
    main = _key(_ollama_request("main agent", "audit the app"))
    sub_a = _key(_ollama_request("search sub-agent", "audit the app"))
    sub_b = _key(_ollama_request("main agent", "look for eval() calls"))
    assert len({main, sub_a, sub_b}) == 3


def test_thread_key_without_system_prompt() -> None:
    a = _key(_ollama_request(None, "task one"))
    b = _key(_ollama_request(None, "task two"))
    assert a != b
    assert OllamaChatParser().parse(_ollama_request(None, "x"), None, None).system_sha256 is None


def test_thread_key_is_the_same_across_formats_for_the_same_conversation() -> None:
    o = OllamaChatParser().parse(_ollama_request("sys", "task"), None, None)
    a_req = json.dumps(
        {"model": "m", "system": "sys", "messages": [{"role": "user", "content": "task"}]}
    ).encode()
    a = AnthropicMessagesParser().parse(a_req, None, None)
    assert o.thread_key == a.thread_key


# --------------------------------------------------------------------------- broken input

PARSERS: list[WireParser] = [OllamaChatParser(), OpenAIChatParser(), AnthropicMessagesParser()]
REQUESTS = {
    WireFormat.OLLAMA_CHAT: oll.CHAT_REQUEST,
    WireFormat.OPENAI_CHAT: oai.REQUEST,
    WireFormat.ANTHROPIC_MESSAGES: anth.REQUEST,
}


@pytest.mark.parametrize("parser", PARSERS, ids=lambda p: p.format.value)
def test_missing_response_keeps_the_request_side(parser: WireParser) -> None:
    call = parser.parse(REQUESTS[parser.format], None, None, seq=9)
    assert call.seq == 9
    assert call.parse_error == "response missing"
    assert call.thread_key != ""
    assert call.request_messages > 0
    assert call.tool_calls == ()
    assert (call.text, call.reasoning, call.returned_model, call.input_tokens) == (
        "",
        "",
        None,
        None,
    )


@pytest.mark.parametrize("parser", PARSERS, ids=lambda p: p.format.value)
@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"\x00\xff\xfe garbage \x89PNG",
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00",  # a gzip header: stored still encoded
        b"null",
        b"[]",
        b"42",
        b'"just a string"',
        b"{",
        b"data: {\n\n",
        b"\n\n\n",
        b"event: message_start\n\n",
    ],
)
def test_bad_response_bodies_give_parse_error(parser: WireParser, response: bytes) -> None:
    call = parser.parse(REQUESTS[parser.format], response, None)
    assert isinstance(call, CallTelemetry)
    assert call.parse_error is not None


@pytest.mark.parametrize("parser", PARSERS, ids=lambda p: p.format.value)
@pytest.mark.parametrize(
    "request_body", [b"", b"\xff\xfe", b"[1,2]", b'{"messages": 5}', b"{", b"null"]
)
def test_bad_request_bodies_give_parse_error(parser: WireParser, request_body: bytes) -> None:
    call = parser.parse(request_body, None, None)
    assert call.parse_error is not None
    assert call.thread_key == ""
    assert call.request_messages == 0


@pytest.mark.parametrize("parser", PARSERS, ids=lambda p: p.format.value)
def test_oversized_bodies_are_refused(parser: WireParser) -> None:
    huge = b" " * (MAX_BODY_BYTES + 1)
    call = parser.parse(huge, huge, JSON)
    assert call.parse_error is not None
    assert "exceeds" in call.parse_error
    assert call.thread_key == ""


def test_absurd_field_types_never_raise() -> None:
    request = json.dumps(
        {
            "model": ["not", "a", "string"],
            "system": {"nested": True},
            "messages": [
                None,
                7,
                {"role": 5, "content": [1, None, {"type": "text", "text": 3}]},
                {"role": "user", "content": {"weird": "object"}},
                {"role": "assistant", "tool_calls": "nope"},
            ],
        }
    ).encode()
    response = json.dumps(
        {
            "model": 12,
            "choices": "x",
            "message": [],
            "content": [{"type": "tool_use", "name": None, "input": "not an object"}, 4],
            "usage": {
                "input_tokens": -5,
                "output_tokens": True,
                "prompt_tokens": "12",
                "cache_read_input_tokens": 1.5,
            },
            "stop_reason": 99,
        }
    ).encode()
    for parser in PARSERS:
        call = parser.parse(request, response, JSON)
        assert isinstance(call, CallTelemetry)
        assert call.requested_model is None
        assert call.returned_model is None
        assert call.input_tokens is None
        assert call.output_tokens is None
        assert call.cache_read_tokens is None
        assert call.stop_reason is None


def test_deeply_nested_json_is_a_parse_error_not_a_crash() -> None:
    deep = b"[" * 100_000 + b"]" * 100_000
    for parser in PARSERS:
        call = parser.parse(deep, deep, JSON)
        assert call.parse_error is not None


def test_unicode_is_kept_and_counted_in_characters() -> None:
    request = _ollama_request("système 🛡", "énumère")
    response = json.dumps(
        {"model": "m", "message": {"content": "réponse 🚀", "thinking": "思考"}, "done": True},
        ensure_ascii=False,
    ).encode()
    call = OllamaChatParser().parse(request, response, JSON)
    assert call.request_chars == len("système 🛡") + len("énumère")
    assert (call.text, call.reasoning) == ("réponse 🚀", "思考")


# --------------------------------------------------------------------------- parse_call


def test_parse_call_dispatches_on_the_path() -> None:
    call = parse_call("/ollama/api/chat", oll.CHAT_REQUEST, oll.CHAT_RESPONSE, JSON, seq=2)
    assert call.format is WireFormat.OLLAMA_CHAT
    assert call.seq == 2
    assert call.input_tokens == 126


@pytest.mark.parametrize("path", ["/v1/embeddings", None, ""])
def test_unknown_path_gives_no_format_and_a_parse_error(path: str | None) -> None:
    call = parse_call(path, oll.CHAT_REQUEST, oll.CHAT_RESPONSE, JSON, seq=4)
    assert call.format is None
    assert call.parse_error is not None
    assert call.seq == 4
    assert call.requested_model == "qwen3:8b"
    assert call.thread_key == ""


# --------------------------------------------------------------------------- determinism, fuzzing


@pytest.mark.parametrize(
    ("parser", "request_body", "response"),
    [
        (OllamaChatParser(), oll.CHAT_REQUEST, oll.CHAT_STREAM),
        (OpenAIChatParser(), oai.STREAM_REQUEST, oai.STREAM_TWO_TOOLS),
        (AnthropicMessagesParser(), anth.REQUEST, anth.STREAM),
    ],
)
def test_parsing_is_deterministic(parser: WireParser, request_body: bytes, response: bytes) -> None:
    first = parser.parse(request_body, response, None, seq=1)
    for _ in range(3):
        assert parser.parse(request_body, response, None, seq=1) == first
    assert (
        first.model_dump_json()
        == parser.parse(request_body, response, None, seq=1).model_dump_json()
    )


@settings(max_examples=150, deadline=None)
@given(request_body=st.binary(max_size=300), response=st.binary(max_size=300))
def test_random_bytes_never_raise(request_body: bytes, response: bytes) -> None:
    for parser in PARSERS:
        assert isinstance(parser.parse(request_body, response, None), CallTelemetry)
        assert isinstance(parser.parse(request_body, response, SSE), CallTelemetry)


_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=8),
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(
            st.sampled_from(
                [
                    "model",
                    "messages",
                    "message",
                    "content",
                    "role",
                    "system",
                    "choices",
                    "delta",
                    "tool_calls",
                    "function",
                    "arguments",
                    "name",
                    "usage",
                    "type",
                    "text",
                    "thinking",
                    "index",
                    "input",
                    "done",
                    "response",
                    "prompt",
                    "error",
                    "partial_json",
                ]
            )
            | st.text(max_size=4),
            inner,
            max_size=5,
        )
    ),
    max_leaves=25,
)


@settings(max_examples=200, deadline=None)
@given(request_doc=_json_values, response_doc=_json_values)
def test_random_json_shapes_never_raise(request_doc: object, response_doc: object) -> None:
    request_body = json.dumps(request_doc).encode()
    response = json.dumps(response_doc).encode()
    sse = b"data: " + response + b"\n\n"
    for parser in PARSERS:
        assert isinstance(parser.parse(request_body, response, JSON), CallTelemetry)
        assert isinstance(parser.parse(request_body, sse, SSE), CallTelemetry)
        assert isinstance(
            parser.parse(request_body, response + b"\n" + response, NDJSON), CallTelemetry
        )


# --------------------------------------------------------------------------- v2 rule changes


def test_anthropic_text_blocks_are_joined_like_reasoning_blocks() -> None:
    response = json.dumps(
        {
            "model": "claude-sonnet-4-5",
            "content": [
                {"type": "text", "text": "First part."},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {}},
                {"type": "text", "text": "Second part."},
            ],
            "usage": {"input_tokens": 1, "output_tokens": 2},
        }
    ).encode()
    call = AnthropicMessagesParser().parse(anth.REQUEST, response, JSON)
    assert call.text == "First part.\n\nSecond part."


def test_anthropic_null_usage_does_not_wipe_earlier_counts() -> None:
    stream = anth.STREAM.replace(
        b'"usage":{"output_tokens":210}',
        b'"usage":{"output_tokens":210,"input_tokens":null,"cache_read_input_tokens":null,'
        b'"cache_creation_input_tokens":"bad"}',
    )
    call = AnthropicMessagesParser().parse(anth.REQUEST, stream, SSE)
    assert (call.input_tokens, call.output_tokens) == (12, 210)
    assert (call.cache_read_tokens, call.cache_write_tokens) == (5000, 300)


def _ollama_body(stream: object = None) -> bytes:
    doc: dict[str, object] = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    if stream is not None:
        doc["stream"] = stream
    return json.dumps(doc).encode()


ONE_DONE_OBJECT = b'{"model":"m","message":{"content":"ok"},"done":true,"eval_count":1}'


@pytest.mark.parametrize(
    ("request_body", "content_type", "response", "streamed"),
    [
        # /api/chat and /api/generate stream unless the request says "stream": false
        (_ollama_body(), JSON, ONE_DONE_OBJECT, True),
        (_ollama_body(stream=True), JSON, ONE_DONE_OBJECT, True),
        (_ollama_body(stream=False), JSON, ONE_DONE_OBJECT, False),
        (_ollama_body(stream=False), NDJSON, ONE_DONE_OBJECT, True),
        (_ollama_body(stream=False), None, oll.CHAT_STREAM, True),
        (oll.GENERATE_REQUEST, JSON, oll.GENERATE_RESPONSE, False),
        (b'{"model":"m","prompt":"x"}', None, oll.GENERATE_RESPONSE, True),
        (b"not json", None, ONE_DONE_OBJECT, False),
    ],
)
def test_ollama_streamed_follows_the_request(
    request_body: bytes, content_type: str | None, response: bytes, streamed: bool
) -> None:
    call = OllamaChatParser().parse(request_body, response, content_type)
    assert call.streamed is streamed


def test_ollama_streamed_single_object_without_done_is_truncated() -> None:
    body = b'{"model":"m","message":{"content":"o"}}'
    call = OllamaChatParser().parse(_ollama_body(), body, None)
    assert call.parse_error is not None
    assert "truncated" in call.parse_error


def test_ollama_error_body_is_not_also_called_truncated() -> None:
    call = OllamaChatParser().parse(_ollama_body(), oll.ERROR_RESPONSE, JSON)
    assert call.parse_error is not None
    assert "truncated" not in call.parse_error


# --------------------------------------------------------------------------- history hashes


def _messages_request(system: str, *messages: dict[str, object]) -> bytes:
    return json.dumps(
        {"model": "m", "messages": [{"role": "system", "content": system}, *messages]}
    ).encode()


def test_ollama_next_call_extends_the_previous_reply() -> None:
    task = {"role": "user", "content": oll.TASK}
    first = OllamaChatParser().parse(
        _messages_request("sys at 12:00", task), oll.CHAT_RESPONSE, JSON
    )
    echo = {
        "role": "assistant",
        "content": "",
        "thinking": "not part of the history hash",
        "tool_calls": [
            {"function": {"name": "http_get", "arguments": {"url": "http://10.0.0.5/"}}}
        ],
    }
    tool = {"role": "tool", "content": "<html>"}
    second = OllamaChatParser().parse(
        _messages_request("sys at 12:01", task, echo, tool), oll.CHAT_RESPONSE, JSON
    )
    assert len(first.history_hashes) == 1
    assert len(second.history_hashes) == 3
    assert second.history_hashes[0] == first.history_hashes[0]
    assert first.reply_hash is not None
    assert second.history_hashes[1] == first.reply_hash


def test_openai_echo_with_reformatted_arguments_still_links() -> None:
    first = OpenAIChatParser().parse(oai.STREAM_REQUEST, oai.STREAM_TWO_TOOLS, SSE)
    calls = [
        ("call_a", "http_get", '{"url":"http://10.0.0.7/admin"}'),
        ("call_b", "dns_lookup", '{ "name" : "admin.lab" }'),
    ]
    echo = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": i, "type": "function", "function": {"name": n, "arguments": a}}
            for i, n, a in calls
        ],
    }
    request = json.dumps(
        {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "A different system prompt."},
                {"role": "user", "content": oai.TASK},
                echo,
                {"role": "tool", "tool_call_id": "call_a", "content": "404"},
                {"role": "system", "content": "a reminder injected mid-history"},
                {"role": "tool", "tool_call_id": "call_b", "content": "NXDOMAIN"},
            ],
        }
    ).encode()
    second = OpenAIChatParser().parse(request, oai.RESPONSE, JSON)
    assert second.history_hashes[1] == first.reply_hash
    assert len(second.history_hashes) == 4  # system messages are not part of the history


def test_anthropic_echo_with_thinking_blocks_still_links() -> None:
    first = AnthropicMessagesParser().parse(anth.REQUEST_STRING_SYSTEM, anth.RESPONSE, JSON)
    echo = [
        {"type": "thinking", "thinking": "x", "signature": "s"},
        {"type": "redacted_thinking", "data": "d"},
        {"type": "text", "text": "The login handler is vulnerable to timing attacks."},
        {
            "type": "tool_use",
            "id": "toolu_02",
            "name": "Grep",
            "input": {"path": "app.py", "pattern": "=="},
        },
    ]
    result = [{"type": "tool_result", "tool_use_id": "toolu_02", "content": "12: if a == b"}]
    request = json.dumps(
        {
            "model": "claude-haiku-4-5",
            "system": "You are a sub-agent that searches files.",
            "messages": [
                {"role": "user", "content": "Find every call to eval()."},
                {"role": "assistant", "content": echo},
                {"role": "user", "content": result},
            ],
        }
    ).encode()
    second = AnthropicMessagesParser().parse(request, anth.RESPONSE, JSON)
    assert second.history_hashes[1] == first.reply_hash


@pytest.mark.parametrize("echoed", ["<think>plan</think>answer", "answer", "plan\n</think>answer"])
def test_inline_think_echo_links_with_or_without_the_thought(echoed: str) -> None:
    task = {"role": "user", "content": "go"}
    reply = json.dumps(
        {"model": "m", "message": {"content": "<think>plan</think>answer"}, "done": True}
    ).encode()
    first = OllamaChatParser().parse(_messages_request("s", task), reply, JSON)
    echo = {"role": "assistant", "content": echoed}
    more = {"role": "user", "content": "more"}
    second = OllamaChatParser().parse(_messages_request("s", task, echo, more), reply, JSON)
    assert second.history_hashes[1] == first.reply_hash


def test_a_different_reply_does_not_link() -> None:
    task = {"role": "user", "content": "go"}
    first = OllamaChatParser().parse(_messages_request("s", task), ONE_DONE_OBJECT, JSON)
    echo = {"role": "assistant", "content": "something else"}
    second = OllamaChatParser().parse(_messages_request("s", task, echo), ONE_DONE_OBJECT, JSON)
    assert first.reply_hash not in second.history_hashes


def test_no_reply_hash_without_a_response_or_a_request() -> None:
    assert OllamaChatParser().parse(oll.CHAT_REQUEST, None, None).reply_hash is None
    no_request = OllamaChatParser().parse(b"junk", oll.CHAT_RESPONSE, JSON)
    assert no_request.reply_hash is None
    assert no_request.history_hashes == ()


@pytest.mark.parametrize(
    "content", ["a</think>b</think>c", "<think>x</think>y</think>z", "p\n</think>q"]
)
def test_a_verbatim_echo_links_however_the_reply_splits(content: str) -> None:
    # the reply side is hashed from the text as sent, like the echo, so the inline
    # thinking is split exactly once on both sides
    task = {"role": "user", "content": "go"}
    reply = json.dumps({"model": "m", "message": {"content": content}, "done": True}).encode()
    first = OllamaChatParser().parse(_messages_request("s", task), reply, JSON)
    echo = {"role": "assistant", "content": content}
    second = OllamaChatParser().parse(_messages_request("s", task, echo), reply, JSON)
    assert second.history_hashes[1] == first.reply_hash


def _persona(system: str | None) -> str | None:
    messages = [{"role": "user", "content": "x"}]
    if system is not None:
        messages.insert(0, {"role": "system", "content": system})
    body = json.dumps({"model": "m", "messages": messages}).encode()
    return OllamaChatParser().parse(body, None, None).persona_sha256


def test_persona_ignores_numbers_and_whitespace_only() -> None:
    base = _persona("You are an agent. Date: 2026-11-24 12:00:01, run 7.")
    assert base is not None
    assert _persona("You are an agent.  Date: 2027-01-01\n09:59:59, run 12345.") == base
    assert _persona("You are a different agent. Date: 2026-11-24 12:00:01, run 7.") != base
    assert _persona(None) is None
    assert _persona("   ") is None


def test_persona_and_system_hash_differ_in_what_they_ignore() -> None:
    body = _messages_request("Agent v1 at 10:00", {"role": "user", "content": "x"})
    other = _messages_request("Agent v2 at 11:30", {"role": "user", "content": "x"})
    first = OllamaChatParser().parse(body, None, None)
    second = OllamaChatParser().parse(other, None, None)
    assert first.system_sha256 != second.system_sha256
    assert first.persona_sha256 == second.persona_sha256
