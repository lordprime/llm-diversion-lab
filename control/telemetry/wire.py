"""Reading one model call's request and response bytes, per wire format.

There is one parser per wire format, all behind :class:`WireParser`:

* :class:`OllamaChatParser`: Ollama's ``/api/chat`` and ``/api/generate``. A streamed
  reply is NDJSON; the last object (``"done": true``) carries ``prompt_eval_count``
  and ``eval_count``. Reasoning is ``message.thinking`` (``thinking`` for generate).
* :class:`OpenAIChatParser`: ``/v1/chat/completions``. A streamed reply is SSE ending in
  ``data: [DONE]``; tool-call arguments arrive in pieces keyed by ``index``; usage
  comes in the last chunk only if the client set ``stream_options.include_usage``.
  Reasoning is ``reasoning_content`` or ``reasoning`` (on messages and on deltas).
* :class:`AnthropicMessagesParser`: ``/v1/messages``. A streamed reply is SSE with
  ``event:`` lines; input usage comes in ``message_start`` and the final output count
  in ``message_delta``. Reasoning is ``thinking`` blocks; a ``redacted_thinking`` block
  shows up as ``[redacted]``.

In every format, inline thinking in the reply text (models with no reasoning parser in
front of them) is moved into the reasoning: a leading ``<think>...</think>`` span, or
everything before a bare ``</think>`` when the chat template pre-filled the opening tag
(see :func:`_split_think` for how a tag inside ordinary prose is treated).

Parsers never raise on bad input. A body that is not JSON, a stream cut off half way,
a provider error, or a body over :data:`MAX_BODY_BYTES` all end up in
``parse_error``, and whatever could be read is still returned.

Grouping calls into agents
--------------------------
This is a heuristic, and it counts *conversations*, not processes. Each call carries
two kinds of key, and :class:`control.telemetry.model.ThreadLinker` combines them:

* ``history_hashes`` and ``reply_hash``, rolling hashes over the non-system messages.
  An agent that re-sends its growing history sends, as a prefix, the previous call's
  messages followed by that call's reply, so the later call is linked to the earlier
  one whatever its system prompt says (a timestamp or a changing reminder there does
  not matter). Messages are compared in a canonical form (whitespace collapsed,
  reasoning and inline thinking dropped, JSON arguments re-serialised), so the usual
  ways clients re-echo a reply still match.
* ``thread_key``, the fallback for a call that extends no earlier call: the SHA-256 of
  ``system_sha256`` plus the whitespace-normalised text of the first non-system
  message. A sub-agent starts with its own system prompt or its own first task, so it
  gets its own key.

What still breaks it (each makes ``agents`` too high):

* a sliding window or history compaction that drops or rewrites earlier messages, so
  the previous call's messages are no longer a prefix;
* ``/api/generate``, or any framework that rebuilds one prompt from scratch each round:
  there is no message history to link, and each new prompt looks like a new task;
* a client that edits the echoed reply beyond the canonical form (for example
  truncating long tool arguments).

Two sub-agents given the same system prompt and the same first task count as one.
``RunTelemetry.single_call_threads`` and ``largest_thread_calls`` show when linking has
collapsed: many single-call threads and a small largest thread mean ``agents`` is
close to ``calls`` and should not be trusted.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Final

from pydantic import JsonValue

from control.core.tags import parse_json, request_path
from control.telemetry.model import CallTelemetry, ToolCallRecord, WireFormat

__all__ = [
    "MAX_BODY_BYTES",
    "AnthropicMessagesParser",
    "OllamaChatParser",
    "OpenAIChatParser",
    "WireFormat",
    "WireParser",
    "detect_format",
    "parse_call",
    "parser_for",
    "unparsed_call",
]

#: Largest single body (request or response) that is parsed at all.
MAX_BODY_BYTES: Final = 64 * 1024 * 1024

#: Endpoint path endings of each format. A gateway prefix (``/ollama/api/chat``) is fine.
_PATH_SUFFIXES: Final[tuple[tuple[str, WireFormat], ...]] = (
    ("/api/chat", WireFormat.OLLAMA_CHAT),
    ("/api/generate", WireFormat.OLLAMA_CHAT),
    ("/v1/chat/completions", WireFormat.OPENAI_CHAT),
    ("/v1/messages", WireFormat.ANTHROPIC_MESSAGES),
)

#: Provider error messages are cut to this many characters in ``parse_error``.
_MAX_ERROR_CHARS: Final = 300
_THINK_OPEN: Final = "<think>"
_THINK_CLOSE: Final = "</think>"
_SSE_FIELDS: Final = (b"data:", b"event:", b"id:", b"retry:", b":")


def detect_format(path: str) -> WireFormat | None:
    """The wire format of a request path from the tap's meta, or ``None`` if unknown.

    The query string is ignored and any prefix a gateway adds is accepted, so
    ``/ollama/api/chat?x=1`` is Ollama. Matching is exact and case-sensitive.
    """
    if not path:
        return None
    clean = request_path(path)
    for suffix, fmt in _PATH_SUFFIXES:
        if clean.endswith(suffix):
            return fmt
    return None


# --------------------------------------------------------------------------- small readers


def _str(value: JsonValue | None) -> str | None:
    return value if isinstance(value, str) else None


def _count(value: JsonValue | None) -> int | None:
    """A token count: a non-negative integer, else ``None`` (bools are not counts)."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _index(value: JsonValue | None, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _arguments(value: JsonValue | None) -> str:
    """Tool-call arguments as JSON text: kept as sent if already text, else compact JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _normalise(text: str) -> str:
    return " ".join(text.split())


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _error_text(value: JsonValue | None) -> str:
    """The readable part of a provider's error value (Ollama: text; others: an object)."""
    if isinstance(value, dict):
        message = value.get("message")
        if isinstance(message, str):
            return message[:_MAX_ERROR_CHARS]
    if isinstance(value, str):
        return value[:_MAX_ERROR_CHARS]
    return json.dumps(value)[:_MAX_ERROR_CHARS]


def _split_think(text: str) -> tuple[str | None, str]:
    """Split the model's inline thinking off ``text``: ``(thought, rest)``.

    Two shapes are recognised:

    * a leading ``<think>...</think>`` span (leading whitespace allowed). A span that
      is never closed (the model ran out of tokens while thinking) is all thought;
    * a closing ``</think>`` with no opening tag before it, which is what a chat
      template that pre-fills ``<think>`` produces (DeepSeek-R1 distills, some Qwen
      templates): everything before the first ``</think>`` is thought.

    ``thought`` is ``None`` when neither shape is there. A ``</think>`` that follows a
    ``<think>`` somewhere later in the text is prose about the tags and is left alone.
    A bare ``</think>`` in ordinary prose cannot be told apart from a pre-filled
    template, so it is split too; replies that mention the closing tag literally are
    rare enough to accept that.
    """
    stripped = text.lstrip()
    if stripped.startswith(_THINK_OPEN):
        body = stripped[len(_THINK_OPEN) :]
        end = body.find(_THINK_CLOSE)
        if end < 0:
            return body.strip(), ""
        return body[:end].strip(), body[end + len(_THINK_CLOSE) :].lstrip()
    end = text.find(_THINK_CLOSE)
    if end < 0 or _THINK_OPEN in text[:end]:
        return None, text
    return text[:end].strip(), text[end + len(_THINK_CLOSE) :].lstrip()


@dataclass(frozen=True, slots=True)
class _SseEvent:
    name: str | None
    data: bytes


def _looks_like_sse(body: bytes, content_type: str | None) -> bool:
    if content_type and "event-stream" in content_type.lower():
        return True
    return body.lstrip().startswith(_SSE_FIELDS)


def _sse_events(body: bytes) -> Iterator[_SseEvent]:
    """The events of a server-sent-events body, per the SSE spec.

    ``data:`` lines of one event are joined with newlines; a blank line ends an event;
    comment lines (``:``) are skipped. An event left open at the end (no blank line
    after it) is still yielded, so a cut-off stream shows up as unparseable data.
    """
    name: str | None = None
    data: list[bytes] = []
    for raw in body.splitlines():
        line = raw.rstrip(b"\r")
        if not line:
            if data:
                yield _SseEvent(name, b"\n".join(data))
            name, data = None, []
            continue
        if line.startswith(b":"):
            continue
        key, _, value = line.partition(b":")
        value = value.removeprefix(b" ")
        if key == b"data":
            data.append(value)
        elif key == b"event":
            name = value.decode("utf-8", errors="replace")
    if data:
        yield _SseEvent(name, b"\n".join(data))


# --------------------------------------------------------------------------- parse state


@dataclass(slots=True)
class _ToolDraft:
    """A tool call being rebuilt; streamed arguments arrive as pieces."""

    name: str = ""
    call_id: str | None = None
    pieces: list[str] = field(default_factory=list)
    #: Arguments to use when no pieces arrive (Anthropic's ``content_block_start`` input).
    fallback: str = ""

    def record(self) -> ToolCallRecord:
        return ToolCallRecord(name=self.name, arguments="".join(self.pieces) or self.fallback)


@dataclass(slots=True)
class _Reply:
    """The response side of one call while it is being rebuilt.

    Text and reasoning are kept per content block (Ollama and OpenAI only have block
    0), so Anthropic's separate thinking blocks stay apart in the final reasoning.
    """

    text: dict[int, list[str]] = field(default_factory=dict)
    reasoning: dict[int, list[str]] = field(default_factory=dict)
    tools: list[_ToolDraft] = field(default_factory=list)
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    returned_model: str | None = None
    stop_reason: str | None = None
    streamed: bool = False
    errors: list[str] = field(default_factory=list)

    def add_text(self, piece: str | None, block: int = 0) -> None:
        if piece:
            self.text.setdefault(block, []).append(piece)

    def add_reasoning(self, piece: str | None, block: int = 0) -> None:
        if piece:
            self.reasoning.setdefault(block, []).append(piece)

    def note_model(self, doc: JsonValue | None) -> None:
        """Keep the first model name the response reports."""
        if self.returned_model is None and isinstance(doc, dict):
            self.returned_model = _str(doc.get("model"))

    def note_stop(self, value: JsonValue | None) -> None:
        stop = _str(value)
        if stop:
            self.stop_reason = stop

    def fail(self, reason: str) -> None:
        if reason not in self.errors:
            self.errors.append(reason)

    def final_text_and_reasoning(self) -> tuple[str, str]:
        """The reply text and reasoning; separate blocks are joined with a blank line."""
        text = "\n\n".join(b for k in sorted(self.text) if (b := "".join(self.text[k])))
        blocks = ["".join(self.reasoning[k]) for k in sorted(self.reasoning)]
        thought, text = _split_think(text)
        if thought:
            blocks.append(thought)
        return text, "\n\n".join(b for b in blocks if b)


@dataclass(frozen=True, slots=True)
class _Message:
    """One message of a request (or a reply), reduced to what telemetry needs.

    ``texts`` is every piece of text the model reads in it (content, text parts or
    blocks, tool results); ``tools`` is the ``(name, arguments)`` of each tool call it
    carries. Reasoning sent back in history is left out on purpose: clients often drop
    or rewrite it, and the model does not always see it again.
    """

    role: str
    texts: tuple[str, ...] = ()
    tools: tuple[tuple[str, str], ...] = ()
    system: bool = False

    @property
    def chars(self) -> int:
        return sum(map(len, self.texts)) + sum(len(arguments) for _, arguments in self.tools)

    def flat_text(self) -> str:
        return "".join(self.texts) + "".join(arguments for _, arguments in self.tools)

    def canonical(self) -> str:
        """A form that survives how clients echo a reply back in the next request.

        Whitespace is collapsed, inline thinking is dropped from assistant text, and
        tool arguments that are JSON are re-serialised with sorted keys, so ``content:
        null`` versus ``""``, re-spaced arguments or a stripped ``<think>`` span still
        give the same form.
        """
        text = "\n\n".join(self.texts)
        if self.role == "assistant":
            text = _split_think(text)[1]
        tools = "".join(f"\x1f{name}\x1e{_canonical_arguments(args)}" for name, args in self.tools)
        return f"{self.role}\x1d{_normalise(text)}{tools}"


def _canonical_arguments(arguments: str) -> str:
    doc = parse_json(arguments.encode("utf-8", errors="surrogatepass"))
    if doc is None:
        return _normalise(arguments)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


#: Length (hex digits) of the history hashes: 64 bits, plenty to tell one run's
#: message prefixes apart, and short enough to store one per message.
_HISTORY_HASH_CHARS: Final = 16


def _extend_history(previous: str, message: _Message) -> str:
    """The rolling hash of a history extended by one message."""
    return _sha256(f"{previous}\n{message.canonical()}")[:_HISTORY_HASH_CHARS]


@dataclass(frozen=True, slots=True)
class _RequestParts:
    """What a request carries: its message count, system prompt and other messages.

    ``system`` is the system prompt text; ``turns`` is every other message in order
    (a system message after the first non-system one stays in ``turns`` but has
    ``system`` set, so it is counted in characters but kept out of the history).
    """

    messages: int
    system: list[str]
    turns: list[_Message]


@dataclass(frozen=True, slots=True)
class _RequestShape:
    requested_model: str | None = None
    messages: int = 0
    chars: int = 0
    system_sha256: str | None = None
    thread_key: str = ""
    history_hashes: tuple[str, ...] = ()

    @classmethod
    def of(cls, model: str | None, parts: _RequestParts) -> _RequestShape:
        system = _normalise("\n".join(parts.system))
        system_sha = _sha256(system) if system else None
        first = _normalise(parts.turns[0].flat_text()) if parts.turns else ""
        hashes: list[str] = []
        for message in parts.turns:
            if not message.system:
                hashes.append(_extend_history(hashes[-1] if hashes else "", message))
        return cls(
            requested_model=model,
            messages=parts.messages,
            chars=sum(map(len, parts.system)) + sum(m.chars for m in parts.turns),
            system_sha256=system_sha,
            thread_key=_sha256(f"{system_sha or ''}\n{first}"),
            history_hashes=tuple(hashes),
        )

    def reply_hash(self, text: str, tools: Sequence[ToolCallRecord]) -> str | None:
        """The history hash once the reply is appended (``None`` without a request)."""
        if not self.thread_key:
            return None
        reply = _Message("assistant", (text,), tuple((t.name, t.arguments) for t in tools))
        return _extend_history(self.history_hashes[-1] if self.history_hashes else "", reply)


def _load_object(
    body: bytes | None, label: str, problem: str | None
) -> tuple[dict[str, JsonValue] | None, str | None]:
    """Parse a body that must be one JSON object: ``(object, None)`` or ``(None, why)``."""
    if body is None:
        return None, problem or f"{label} missing"
    if len(body) > MAX_BODY_BYTES:
        return None, f"{label} exceeds {MAX_BODY_BYTES} bytes"
    doc = parse_json(body)
    if doc is None:
        return None, f"{label} is not valid JSON" if body.strip() else f"{label} is empty"
    if not isinstance(doc, dict):
        return None, f"{label} is not a JSON object"
    return doc, None


def unparsed_call(
    seq: int, request: bytes | None, reason: str, fmt: WireFormat | None = None
) -> CallTelemetry:
    """A call no parser could read: only the requested model (if any) is filled in."""
    doc, _ = _load_object(request, "request", None)
    return CallTelemetry(
        seq=seq,
        format=fmt,
        requested_model=_str(doc.get("model")) if doc else None,
        returned_model=None,
        input_tokens=None,
        output_tokens=None,
        cache_read_tokens=None,
        cache_write_tokens=None,
        request_messages=0,
        request_chars=0,
        system_sha256=None,
        thread_key="",
        history_hashes=(),
        reply_hash=None,
        tool_calls=(),
        reasoning="",
        text="",
        stop_reason=None,
        streamed=False,
        parse_error=reason,
    )


# --------------------------------------------------------------------------- the interface


class WireParser(ABC):
    """Turns one call's stored request and response into :class:`CallTelemetry`.

    Subclasses say how their format lays out the request (:meth:`_request_parts`) and
    how to read a reply (:meth:`_read_response`); everything else is shared.
    """

    format: ClassVar[WireFormat]

    def parse(
        self,
        request: bytes | None,
        response: bytes | None,
        content_type: str | None,
        *,
        seq: int = 0,
        request_problem: str | None = None,
        response_problem: str | None = None,
    ) -> CallTelemetry:
        """Read one call. Never raises: problems are reported in ``parse_error``.

        ``response`` is ``None`` when no response was stored (the call failed). The
        ``*_problem`` arguments let a caller say why a body is ``None`` (for example a
        stored body it could not decode); they replace the plain "missing" message.
        """
        try:
            return self._parse(
                request, response, content_type, seq, request_problem, response_problem
            )
        except Exception as exc:  # last line of defence: one bad call must not stop a run
            return unparsed_call(seq, request, f"parser failed: {type(exc).__name__}", self.format)

    def _parse(
        self,
        request: bytes | None,
        response: bytes | None,
        content_type: str | None,
        seq: int,
        request_problem: str | None,
        response_problem: str | None,
    ) -> CallTelemetry:
        errors: list[str] = []
        doc, shape = self._describe_request(request, request_problem, errors)

        reply = _Reply()
        replied = False
        if response is None:
            errors.append(response_problem or "response missing")
        elif len(response) > MAX_BODY_BYTES:
            errors.append(f"response exceeds {MAX_BODY_BYTES} bytes")
        elif not response.strip():
            errors.append("response is empty")
        else:
            self._read_response(response, content_type, reply, doc)
            replied = True
        errors.extend(reply.errors)

        text, reasoning = reply.final_text_and_reasoning()
        tool_calls = tuple(t.record() for t in reply.tools)
        return CallTelemetry(
            seq=seq,
            format=self.format,
            requested_model=shape.requested_model,
            returned_model=reply.returned_model,
            input_tokens=reply.input_tokens,
            output_tokens=reply.output_tokens,
            cache_read_tokens=reply.cache_read_tokens,
            cache_write_tokens=reply.cache_write_tokens,
            request_messages=shape.messages,
            request_chars=shape.chars,
            system_sha256=shape.system_sha256,
            thread_key=shape.thread_key,
            history_hashes=shape.history_hashes,
            reply_hash=shape.reply_hash(text, tool_calls) if replied else None,
            tool_calls=tool_calls,
            reasoning=reasoning,
            text=text,
            stop_reason=reply.stop_reason,
            streamed=reply.streamed,
            parse_error="; ".join(errors) or None,
        )

    def _describe_request(
        self, request: bytes | None, problem: str | None, errors: list[str]
    ) -> tuple[dict[str, JsonValue] | None, _RequestShape]:
        """The parsed request (``None`` if unreadable) and what it carries."""
        doc, why = _load_object(request, "request", problem)
        if doc is None:
            errors.append(why or "request unreadable")
            return None, _RequestShape()
        model = _str(doc.get("model"))
        parts = self._request_parts(doc)
        if parts is None:
            errors.append("request has no messages")
            return doc, _RequestShape(requested_model=model)
        return doc, _RequestShape.of(model, parts)

    @abstractmethod
    def _request_parts(self, doc: dict[str, JsonValue]) -> _RequestParts | None:
        """The request's system text and messages, or ``None`` if it has none."""

    @abstractmethod
    def _read_response(
        self,
        body: bytes,
        content_type: str | None,
        reply: _Reply,
        request: dict[str, JsonValue] | None,
    ) -> None:
        """Fill ``reply`` from a non-empty response body (JSON or a stream).

        ``request`` is the parsed request (``None`` if unreadable), for formats whose
        reply shape depends on what was asked for.
        """


# --------------------------------------------------------------------------- messages-array formats


class _MessagesArrayParser(WireParser):
    """Shared request reading for formats with a ``messages`` array (Ollama, OpenAI).

    The leading messages whose role is a system role are the system prompt; a system
    message further down is counted in characters but kept out of the history hashes.
    A message's text is its ``content`` (a string or a list of ``{"text": ...}`` parts);
    its tools are the ``tool_calls`` it carries. Tool results are ``role: tool``
    messages, so they are ordinary content.
    """

    _system_roles: ClassVar[frozenset[str]] = frozenset({"system"})

    def _request_parts(self, doc: dict[str, JsonValue]) -> _RequestParts | None:
        messages = doc.get("messages")
        if not isinstance(messages, list):
            return None
        system: list[str] = []
        turns: list[_Message] = []
        for raw in messages:
            message = self._message(raw)
            if message.system and not turns:
                system.append(message.flat_text())
            else:
                turns.append(message)
        return _RequestParts(len(messages), system, turns)

    def _message(self, raw: JsonValue) -> _Message:
        if not isinstance(raw, dict):
            return _Message("")
        role = _str(raw.get("role")) or ""
        texts: list[str] = []
        content = raw.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(
                str(part["text"])
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
        tools: list[tuple[str, str]] = []
        tool_calls = raw.get("tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict):
                    name = _str(function.get("name")) or ""
                    tools.append((name, _arguments(function.get("arguments"))))
        return _Message(role, tuple(texts), tuple(tools), role in self._system_roles)

    @staticmethod
    def _read_tool_calls(
        value: JsonValue | None, reply: _Reply, drafts: dict[int, _ToolDraft]
    ) -> None:
        """Add tool calls from a message or a streamed delta.

        Pieces with the same ``index`` belong to one call. A piece whose ``id`` differs
        from the call already at that index starts a new call (some OpenAI-compatible
        servers send every complete call at index 0).
        """
        if not isinstance(value, list):
            return
        for position, call in enumerate(value):
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            function = function if isinstance(function, dict) else {}
            index = _index(call.get("index"), position)
            call_id = _str(call.get("id"))
            draft = drafts.get(index)
            if draft is None or (call_id and draft.call_id and call_id != draft.call_id):
                draft = _ToolDraft(call_id=call_id)
                drafts[index] = draft
                reply.tools.append(draft)
            name = _str(function.get("name"))
            if name and not draft.name:
                draft.name = name
            if call_id and not draft.call_id:
                draft.call_id = call_id
            piece = _arguments(function.get("arguments"))
            if piece:
                draft.pieces.append(piece)


class OllamaChatParser(_MessagesArrayParser):
    """Ollama's native API: ``/api/chat`` (messages) and ``/api/generate`` (prompt)."""

    format = WireFormat.OLLAMA_CHAT

    def _request_parts(self, doc: dict[str, JsonValue]) -> _RequestParts | None:
        parts = super()._request_parts(doc)
        if parts is not None:
            return parts
        prompt = doc.get("prompt")
        if not isinstance(prompt, str):
            return None
        system = _str(doc.get("system"))
        return _RequestParts(1, [system] if system else [], [_Message("user", (prompt,))])

    def _read_response(
        self,
        body: bytes,
        content_type: str | None,
        reply: _Reply,
        request: dict[str, JsonValue] | None,
    ) -> None:
        """Read a single JSON object or an NDJSON stream.

        ``streamed`` follows what was asked for: both endpoints stream unless the
        request sets ``"stream": false``. An NDJSON content type, or a body of several
        objects, also counts as streamed. If the request could not be read, only those
        two signs are used.
        """
        asked = request is not None and request.get("stream", True) is not False
        ndjson = content_type is not None and "ndjson" in content_type.lower()
        reply.streamed = asked or ndjson
        drafts: dict[int, _ToolDraft] = {}
        doc = parse_json(body)
        if isinstance(doc, dict):
            chunks: list[dict[str, JsonValue]] = [doc]
        elif doc is not None:
            reply.fail("response is not a JSON object")
            return
        else:
            chunks = []
            lines = [line for line in body.splitlines() if line.strip()]
            for number, line in enumerate(lines):
                chunk = parse_json(line)
                if not isinstance(chunk, dict):
                    if number == 0:
                        reply.fail("response is not JSON or NDJSON")
                        return
                    reply.fail(f"truncated stream: line {number + 1} is not a JSON object")
                    break
                chunks.append(chunk)
            reply.streamed = True
        for chunk in chunks:
            self._read_chunk(chunk, reply, drafts)
        if not reply.errors and chunks[-1].get("done") is not True:
            reply.fail("truncated stream: no final done object")

    def _read_chunk(
        self, chunk: dict[str, JsonValue], reply: _Reply, drafts: dict[int, _ToolDraft]
    ) -> None:
        if "error" in chunk:
            reply.fail(f"provider error: {_error_text(chunk['error'])}")
        reply.note_model(chunk)
        message = chunk.get("message")
        if isinstance(message, dict):  # /api/chat
            reply.add_text(_str(message.get("content")))
            reply.add_reasoning(_str(message.get("thinking")))
            # each Ollama tool call arrives whole, so give each its own slot
            self._read_tool_calls(message.get("tool_calls"), reply, {})
        else:  # /api/generate
            reply.add_text(_str(chunk.get("response")))
            reply.add_reasoning(_str(chunk.get("thinking")))
        if chunk.get("done") is True:
            reply.input_tokens = _count(chunk.get("prompt_eval_count"))
            reply.output_tokens = _count(chunk.get("eval_count"))
            reply.note_stop(chunk.get("done_reason"))


class OpenAIChatParser(_MessagesArrayParser):
    """OpenAI-style ``/v1/chat/completions`` (OpenAI, Ollama, vLLM, OpenRouter...)."""

    format = WireFormat.OPENAI_CHAT
    # newer OpenAI models take the system prompt as a "developer" message
    _system_roles = frozenset({"system", "developer"})

    def _read_response(
        self,
        body: bytes,
        content_type: str | None,
        reply: _Reply,
        request: dict[str, JsonValue] | None,
    ) -> None:
        drafts: dict[int, _ToolDraft] = {}
        if not _looks_like_sse(body, content_type):
            doc = parse_json(body)
            if not isinstance(doc, dict):
                reply.fail("response is not a JSON object")
                return
            self._read_chunk(doc, reply, drafts, key="message")
            return
        reply.streamed = True
        done = False
        for number, event in enumerate(_sse_events(body), start=1):
            if event.data.strip() == b"[DONE]":
                done = True
                continue
            chunk = parse_json(event.data)
            if not isinstance(chunk, dict):
                reply.fail(f"stream event {number} is not a JSON object")
                continue
            self._read_chunk(chunk, reply, drafts, key="delta")
        if not done:
            reply.fail("truncated stream: no [DONE]")

    def _read_chunk(
        self, chunk: dict[str, JsonValue], reply: _Reply, drafts: dict[int, _ToolDraft], *, key: str
    ) -> None:
        """Read a whole completion (``key="message"``) or one stream chunk (``"delta"``)."""
        if "error" in chunk:
            reply.fail(f"provider error: {_error_text(chunk['error'])}")
        reply.note_model(chunk)
        self._read_usage(chunk.get("usage"), reply)
        choice = self._first_choice(chunk.get("choices"))
        if choice is None:
            return
        message = choice.get(key)
        if isinstance(message, dict):
            reply.add_text(_str(message.get("content")))
            reply.add_reasoning(
                _str(message.get("reasoning_content")) or _str(message.get("reasoning"))
            )
            self._read_tool_calls(message.get("tool_calls"), reply, drafts)
        reply.note_stop(choice.get("finish_reason"))

    @staticmethod
    def _first_choice(choices: JsonValue | None) -> dict[str, JsonValue] | None:
        """Choice 0 (a client asking for several choices still gets its first one counted)."""
        if not isinstance(choices, list):
            return None
        for choice in choices:
            if isinstance(choice, dict) and _index(choice.get("index"), 0) == 0:
                return choice
        return None

    @staticmethod
    def _read_usage(usage: JsonValue | None, reply: _Reply) -> None:
        if not isinstance(usage, dict):
            return
        reply.input_tokens = _count(usage.get("prompt_tokens"))
        reply.output_tokens = _count(usage.get("completion_tokens"))
        details = usage.get("prompt_tokens_details")
        reply.cache_read_tokens = (
            _count(details.get("cached_tokens")) if isinstance(details, dict) else None
        )


# --------------------------------------------------------------------------- Anthropic


class AnthropicMessagesParser(WireParser):
    """Anthropic's ``/v1/messages``: a top-level ``system`` and content blocks."""

    format = WireFormat.ANTHROPIC_MESSAGES

    #: Usage fields and the reply attribute each one sets.
    _USAGE_FIELDS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("input_tokens", "input_tokens"),
        ("output_tokens", "output_tokens"),
        ("cache_read_input_tokens", "cache_read_tokens"),
        ("cache_creation_input_tokens", "cache_write_tokens"),
    )
    #: ``message_start`` carries a placeholder output count (usually 1), so only the
    #: prompt-side counts are taken from it; the output count comes from ``message_delta``.
    _START_FIELDS: ClassVar[tuple[tuple[str, str], ...]] = tuple(
        f for f in _USAGE_FIELDS if f[0] != "output_tokens"
    )

    def _request_parts(self, doc: dict[str, JsonValue]) -> _RequestParts | None:
        messages = doc.get("messages")
        if not isinstance(messages, list):
            return None
        system = self._message({"role": "system", "content": doc.get("system")})
        return _RequestParts(
            len(messages), list(system.texts), [self._message(m) for m in messages]
        )

    @classmethod
    def _message(cls, raw: JsonValue) -> _Message:
        """A message's text blocks and tool results as text, its ``tool_use`` as tools.

        Thinking blocks sent back in history are left out (see :class:`_Message`).
        """
        if not isinstance(raw, dict):
            return _Message("")
        role = _str(raw.get("role")) or ""
        content = raw.get("content")
        if isinstance(content, str):
            return _Message(role, (content,))
        texts: list[str] = []
        tools: list[tuple[str, str]] = []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text" and isinstance(block.get("text"), str):
                texts.append(str(block["text"]))
            elif kind == "tool_use":
                tools.append((_str(block.get("name")) or "", _arguments(block.get("input"))))
            elif kind == "tool_result":
                inner = block.get("content")
                if isinstance(inner, str):
                    texts.append(inner)
                elif isinstance(inner, list):  # text blocks only, never nested results
                    texts.extend(
                        str(part["text"])
                        for part in inner
                        if isinstance(part, dict) and isinstance(part.get("text"), str)
                    )
        return _Message(role, tuple(texts), tuple(tools))

    def _read_response(
        self,
        body: bytes,
        content_type: str | None,
        reply: _Reply,
        request: dict[str, JsonValue] | None,
    ) -> None:
        drafts: dict[int, _ToolDraft] = {}
        if not _looks_like_sse(body, content_type):
            doc = parse_json(body)
            if not isinstance(doc, dict):
                reply.fail("response is not a JSON object")
                return
            if doc.get("type") == "error" or "error" in doc:
                reply.fail(f"provider error: {_error_text(doc.get('error'))}")
            reply.note_model(doc)
            content = doc.get("content")
            if isinstance(content, list):
                for position, block in enumerate(content):
                    if isinstance(block, dict):
                        self._start_block(position, block, reply, drafts)
            reply.note_stop(doc.get("stop_reason"))
            self._read_usage(doc.get("usage"), reply)
            return
        reply.streamed = True
        stopped = False
        for number, event in enumerate(_sse_events(body), start=1):
            data = parse_json(event.data)
            if not isinstance(data, dict):
                reply.fail(f"stream event {number} is not a JSON object")
                continue
            stopped = self._read_event(data, reply, drafts) or stopped
        if not stopped:
            reply.fail("truncated stream: no message_stop")

    def _read_event(
        self, data: dict[str, JsonValue], reply: _Reply, drafts: dict[int, _ToolDraft]
    ) -> bool:
        """Apply one stream event; return whether it was ``message_stop``."""
        kind = data.get("type")
        if kind == "message_start":
            message = data.get("message")
            reply.note_model(message)
            if isinstance(message, dict):
                self._read_usage(message.get("usage"), reply, self._START_FIELDS)
        elif kind == "content_block_start":
            block = data.get("content_block")
            if isinstance(block, dict):
                self._start_block(_index(data.get("index"), 0), block, reply, drafts)
        elif kind == "content_block_delta":
            delta = data.get("delta")
            if isinstance(delta, dict):
                self._apply_delta(_index(data.get("index"), 0), delta, reply, drafts)
        elif kind == "message_delta":
            delta = data.get("delta")
            if isinstance(delta, dict):
                reply.note_stop(delta.get("stop_reason"))
            # usage here is cumulative, so any count it carries is the final one
            self._read_usage(data.get("usage"), reply)
        elif kind == "error":
            reply.fail(f"provider error: {_error_text(data.get('error'))}")
        return kind == "message_stop"

    @staticmethod
    def _start_block(
        index: int, block: dict[str, JsonValue], reply: _Reply, drafts: dict[int, _ToolDraft]
    ) -> None:
        """A whole block (JSON reply) or the opening of a streamed one."""
        kind = block.get("type")
        if kind == "text":
            reply.add_text(_str(block.get("text")), index)
        elif kind == "thinking":
            reply.add_reasoning(_str(block.get("thinking")), index)
        elif kind == "redacted_thinking":
            reply.add_reasoning("[redacted]", index)
        elif kind == "tool_use":
            draft = _ToolDraft(name=_str(block.get("name")) or "", call_id=_str(block.get("id")))
            draft.fallback = _arguments(block.get("input"))
            drafts[index] = draft
            reply.tools.append(draft)

    @staticmethod
    def _apply_delta(
        index: int, delta: dict[str, JsonValue], reply: _Reply, drafts: dict[int, _ToolDraft]
    ) -> None:
        kind = delta.get("type")
        if kind == "text_delta":
            reply.add_text(_str(delta.get("text")), index)
        elif kind == "thinking_delta":
            reply.add_reasoning(_str(delta.get("thinking")), index)
        elif kind == "input_json_delta":
            piece = _str(delta.get("partial_json"))
            if piece:
                draft = drafts.get(index)
                if draft is None:  # a delta with no block start: keep it anyway
                    draft = drafts[index] = _ToolDraft()
                    reply.tools.append(draft)
                draft.pieces.append(piece)

    @classmethod
    def _read_usage(
        cls,
        usage: JsonValue | None,
        reply: _Reply,
        fields: tuple[tuple[str, str], ...] | None = None,
    ) -> None:
        """Set each usable count in ``usage``.

        A count that is missing, ``null`` or not a count leaves the earlier value alone,
        so a ``message_delta`` with nulls cannot wipe what ``message_start`` reported.
        """
        if not isinstance(usage, dict):
            return
        for wire_name, attribute in fields or cls._USAGE_FIELDS:
            count = _count(usage.get(wire_name))
            if count is not None:
                setattr(reply, attribute, count)


# --------------------------------------------------------------------------- dispatch

_PARSERS: Final[dict[WireFormat, WireParser]] = {
    parser.format: parser
    for parser in (OllamaChatParser(), OpenAIChatParser(), AnthropicMessagesParser())
}


def parser_for(fmt: WireFormat) -> WireParser:
    """The parser of a wire format."""
    return _PARSERS[fmt]


def parse_call(
    path: str | None,
    request: bytes | None,
    response: bytes | None,
    content_type: str | None,
    *,
    seq: int = 0,
    request_problem: str | None = None,
    response_problem: str | None = None,
) -> CallTelemetry:
    """Read one call whose endpoint path is ``path`` (from the tap's meta).

    An unknown or missing path gives ``format=None`` and a ``parse_error``.
    """
    fmt = detect_format(path) if path else None
    if fmt is None:
        reason = f"unknown endpoint {path!r}" if path else "no request path in the tap meta"
        return unparsed_call(seq, request, reason)
    return parser_for(fmt).parse(
        request,
        response,
        content_type,
        seq=seq,
        request_problem=request_problem,
        response_problem=response_problem,
    )
