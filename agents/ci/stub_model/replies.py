"""How the stub model's replies look on the wire, one class per model API.

Each :class:`ApiShape` turns a scripted :class:`~agents.ci.stub_model.script.Turn` into
that API's own reply, streamed or not, and answers its listing and embedding calls:

* :class:`OllamaShape`: ``/api/chat`` (NDJSON unless the request says
  ``"stream": false``), ``/api/embed``, the older ``/api/embeddings``, ``/api/tags``,
  ``/api/show`` and ``/api/version``;
* :class:`OpenAIShape`: ``/v1/chat/completions`` (SSE when ``"stream": true``; a usage
  chunk when ``stream_options.include_usage`` is set), ``/v1/embeddings`` (floats or
  base64) and ``/v1/models``;
* :class:`AnthropicShape`: ``/v1/messages`` (SSE events when ``"stream": true``).

``/v1/models`` is shared by OpenAI and Anthropic clients, so each listed model carries
both APIs' fields.

Replies are deterministic: ids come from the request's sequence number and embeddings
from a hash of the text, so two runs of the same agent give the same bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from agents.ci.stub_model.script import StubScript, ToolCall, Turn

__all__ = [
    "API_SHAPES",
    "AnthropicShape",
    "ApiShape",
    "ChatRequest",
    "OllamaShape",
    "OpenAIShape",
    "StubReply",
    "embedding",
]

#: A fixed timestamp, so replies don't change from run to run.
CREATED_AT: Final = "2026-01-01T00:00:00Z"
CREATED: Final = 1767225600
JSON: Final = "application/json"
NDJSON: Final = "application/x-ndjson"
SSE: Final = "text/event-stream"


def _dumps(doc: object) -> bytes:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _pieces(text: str) -> list[str]:
    """Split text into a few stream pieces (at a space when there is one)."""
    if len(text) < 2:
        return [text] if text else []
    middle = text.find(" ", len(text) // 2)
    middle = middle if middle > 0 else len(text) // 2
    return [text[:middle], text[middle:]]


def _tokens(size: int) -> int:
    """A rough token count: four bytes a token, at least one."""
    return max(1, size // 4)


def embedding(text: str, dimensions: int) -> list[float]:
    """A unit-length vector that depends only on ``text`` and ``dimensions``."""
    values: list[float] = []
    counter = 0
    while len(values) < dimensions:
        block = hashlib.sha256(f"{counter}:{text}".encode()).digest()
        values.extend((b - 127.5) / 127.5 for b in block)
        counter += 1
    values = values[:dimensions]
    norm = math.sqrt(sum(v * v for v in values)) or 1.0
    return [round(v / norm, 6) for v in values]


@dataclass(frozen=True, slots=True)
class StubReply:
    """One answer: status, content type and the body in the pieces it is sent in."""

    status: int
    media_type: str
    chunks: tuple[bytes, ...]
    streamed: bool = False

    @property
    def body(self) -> bytes:
        return b"".join(self.chunks)

    @classmethod
    def json(cls, doc: object, status: int = 200) -> StubReply:
        return cls(status, JSON, (_dumps(doc),))


@dataclass(frozen=True, slots=True)
class ChatRequest:
    """What a reply needs from a request: its sequence number, the parsed body and size."""

    seq: int
    doc: Mapping[str, Any]
    size: int

    def model(self, script: StubScript) -> str:
        model = self.doc.get("model")
        return model if isinstance(model, str) and model else script.models[0]

    def flag(self, *keys: str) -> object:
        """A nested value of the body, e.g. ``flag("stream_options", "include_usage")``."""
        value: object = self.doc
        for key in keys:
            if not isinstance(value, Mapping):
                return None
            value = value.get(key)
        return value


class ApiShape(ABC):
    """One model API: its chat endpoint, its other endpoints and its error shape."""

    name: ClassVar[str]
    chat_path: ClassVar[str]
    #: (method, path) -> the name of the method that answers the API's other endpoints
    endpoints: ClassVar[Mapping[tuple[str, str], str]] = {}

    def answer(
        self, method: str, path: str, script: StubScript, request: ChatRequest
    ) -> StubReply | None:
        """The reply of a non-chat endpoint of this API, or ``None`` if it has no such one."""
        name = self.endpoints.get((method, path))
        if name is None:
            return None
        handler: Callable[[StubScript, ChatRequest], StubReply] = getattr(self, name)
        return handler(script, request)

    def wants_stream(self, request: ChatRequest) -> bool:
        return request.flag("stream") is True

    def chat(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        if self.wants_stream(request):
            return self._chat_stream(script, turn, request)
        return self._chat_whole(script, turn, request)

    def error(self, status: int, message: str) -> StubReply:
        return StubReply.json(
            {"error": {"type": "invalid_request_error", "message": message}}, status
        )

    def call_id(self, request: ChatRequest, call: ToolCall, index: int) -> str:
        return call.call_id or f"call_stub_{request.seq}_{index}"

    @staticmethod
    def output_tokens(turn: Turn) -> int:
        return _tokens(len(turn.text) + sum(len(c.arguments_json) for c in turn.tool_calls))

    @abstractmethod
    def _chat_whole(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        """The reply as one JSON document."""

    @abstractmethod
    def _chat_stream(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        """The reply as this API's stream."""

    @staticmethod
    def texts(value: object) -> list[str] | None:
        """Embedding input as a list of texts: a string, a list of strings, or token lists."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list) and value:
            if all(isinstance(v, str) for v in value):
                return list(value)
            if all(isinstance(v, int) and not isinstance(v, bool) for v in value):
                return [json.dumps(value)]
            if all(isinstance(v, list) for v in value):
                return [json.dumps(v) for v in value]
        return None


# --------------------------------------------------------------------------- Ollama


class OllamaShape(ApiShape):
    name = "ollama"
    chat_path = "/api/chat"

    def wants_stream(self, request: ChatRequest) -> bool:
        return request.flag("stream") is not False  # Ollama streams unless told not to

    def error(self, status: int, message: str) -> StubReply:
        return StubReply.json({"error": message}, status)

    def _message(self, turn: Turn, request: ChatRequest, text: str) -> dict[str, Any]:
        message: dict[str, Any] = {"role": "assistant", "content": text}
        if turn.tool_calls:
            message["tool_calls"] = [
                {
                    "id": self.call_id(request, call, i),
                    "function": {"index": i, "name": call.name, "arguments": dict(call.arguments)},
                }
                for i, call in enumerate(turn.tool_calls)
            ]
        return message

    def _done(self, model: str, turn: Turn, request: ChatRequest) -> dict[str, Any]:
        return {
            "model": model,
            "created_at": CREATED_AT,
            "done": True,
            "done_reason": "stop",
            "total_duration": 1000,
            "load_duration": 0,
            "prompt_eval_count": _tokens(request.size),
            "prompt_eval_duration": 1,
            "eval_count": self.output_tokens(turn),
            "eval_duration": 1,
        }

    def _chat_whole(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        model = request.model(script)
        doc: dict[str, Any] = {"model": model, "created_at": CREATED_AT}
        doc["message"] = self._message(turn, request, turn.text)
        doc.update(self._done(model, turn, request))
        return StubReply.json(doc)

    def _chat_stream(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        model = request.model(script)
        lines: list[dict[str, Any]] = [
            {
                "model": model,
                "created_at": CREATED_AT,
                "message": {"role": "assistant", "content": piece},
                "done": False,
            }
            for piece in _pieces(turn.text)
        ]
        if turn.tool_calls:
            lines.append(
                {
                    "model": model,
                    "created_at": CREATED_AT,
                    "message": self._message(turn, request, ""),
                    "done": False,
                }
            )
        last: dict[str, Any] = {"model": model, "created_at": CREATED_AT}
        last["message"] = {"role": "assistant", "content": ""}
        last.update(self._done(model, turn, request))
        lines.append(last)
        return StubReply(200, NDJSON, tuple(_dumps(line) + b"\n" for line in lines), True)

    def embed(self, script: StubScript, request: ChatRequest) -> StubReply:
        texts = self.texts(request.doc.get("input"))
        if texts is None:
            return self.error(400, "input is required: a string or a list of strings")
        return StubReply.json(
            {
                "model": request.model(script),
                "embeddings": [embedding(t, script.embedding_dimensions) for t in texts],
                "total_duration": 1000,
                "load_duration": 0,
                "prompt_eval_count": _tokens(request.size),
            }
        )

    def embeddings(self, script: StubScript, request: ChatRequest) -> StubReply:
        """The older endpoint: one ``prompt`` in, one ``embedding`` out."""
        prompt = request.doc.get("prompt")
        if not isinstance(prompt, str):
            return self.error(400, "prompt is required: a string")
        return StubReply.json({"embedding": embedding(prompt, script.embedding_dimensions)})

    def tags(self, script: StubScript, request: ChatRequest) -> StubReply:
        return StubReply.json(
            {"models": [self._model_entry(m) for m in script.models]},
        )

    def show(self, script: StubScript, request: ChatRequest) -> StubReply:
        name = request.doc.get("model") or request.doc.get("name")
        if not isinstance(name, str) or name not in script.models:
            return self.error(404, f"model {name!r} not found")
        return StubReply.json(
            {
                "modelfile": "",
                "parameters": "",
                "template": "{{ .Prompt }}",
                "details": self._details(),
                "model_info": {"general.architecture": "stub", "stub.context_length": 131072},
                "capabilities": ["completion", "tools", "embedding"],
                "modified_at": CREATED_AT,
            }
        )

    def version(self, script: StubScript, request: ChatRequest) -> StubReply:
        return StubReply.json({"version": "0.12.0"})

    @staticmethod
    def _details() -> dict[str, Any]:
        return {
            "parent_model": "",
            "format": "gguf",
            "family": "stub",
            "families": ["stub"],
            "parameter_size": "1B",
            "quantization_level": "Q4_0",
        }

    def _model_entry(self, model: str) -> dict[str, Any]:
        return {
            "name": model,
            "model": model,
            "modified_at": CREATED_AT,
            "size": 1,
            "digest": hashlib.sha256(model.encode()).hexdigest(),
            "details": self._details(),
        }

    endpoints: ClassVar[Mapping[tuple[str, str], str]] = {
        ("POST", "/api/embed"): "embed",
        ("POST", "/api/embeddings"): "embeddings",
        ("GET", "/api/tags"): "tags",
        ("POST", "/api/show"): "show",
        ("GET", "/api/version"): "version",
    }


# --------------------------------------------------------------------------- OpenAI


class OpenAIShape(ApiShape):
    name = "openai"
    chat_path = "/v1/chat/completions"

    def _calls(self, turn: Turn, request: ChatRequest) -> list[dict[str, Any]]:
        return [
            {
                "id": self.call_id(request, call, i),
                "type": "function",
                "function": {"name": call.name, "arguments": call.arguments_json},
            }
            for i, call in enumerate(turn.tool_calls)
        ]

    @staticmethod
    def _finish(turn: Turn) -> str:
        return "tool_calls" if turn.calls_tools else "stop"

    def _usage(self, turn: Turn, request: ChatRequest) -> dict[str, int]:
        prompt, completion = _tokens(request.size), self.output_tokens(turn)
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        }

    def _envelope(self, request: ChatRequest, model: str, kind: str) -> dict[str, Any]:
        return {
            "id": f"chatcmpl-stub-{request.seq}",
            "object": kind,
            "created": CREATED,
            "model": model,
        }

    def _chat_whole(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        message: dict[str, Any] = {"role": "assistant", "content": turn.text or None}
        if turn.tool_calls:
            message["tool_calls"] = self._calls(turn, request)
        doc = self._envelope(request, request.model(script), "chat.completion")
        doc["choices"] = [{"index": 0, "message": message, "finish_reason": self._finish(turn)}]
        doc["usage"] = self._usage(turn, request)
        return StubReply.json(doc)

    def _chat_stream(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        model = request.model(script)

        def chunk(delta: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
            doc = self._envelope(request, model, "chat.completion.chunk")
            doc["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish}]
            return doc

        chunks = [chunk({"role": "assistant", "content": ""})]
        chunks += [chunk({"content": piece}) for piece in _pieces(turn.text)]
        for index, call in enumerate(self._calls(turn, request)):
            head = {
                "index": index,
                "id": call["id"],
                "type": "function",
                "function": {"name": call["function"]["name"], "arguments": ""},
            }
            chunks.append(chunk({"tool_calls": [head]}))
            for piece in _pieces(call["function"]["arguments"]):
                chunks.append(
                    chunk({"tool_calls": [{"index": index, "function": {"arguments": piece}}]})
                )
        chunks.append(chunk({}, self._finish(turn)))
        if request.flag("stream_options", "include_usage") is True:
            tail = self._envelope(request, model, "chat.completion.chunk")
            tail["choices"] = []
            tail["usage"] = self._usage(turn, request)
            chunks.append(tail)
        events = (*(b"data: " + _dumps(c) + b"\n\n" for c in chunks), b"data: [DONE]\n\n")
        return StubReply(200, SSE, events, True)

    def embeddings(self, script: StubScript, request: ChatRequest) -> StubReply:
        texts = self.texts(request.doc.get("input"))
        if texts is None:
            return self.error(400, "input is required: a string, a list of strings or tokens")
        encoding = request.doc.get("encoding_format", "float")
        if encoding not in ("float", "base64"):
            return self.error(400, f"encoding_format {encoding!r} is not float or base64")
        data = []
        for index, text in enumerate(texts):
            vector = embedding(text, script.embedding_dimensions)
            value: object = vector
            if encoding == "base64":
                value = base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode()
            data.append({"object": "embedding", "index": index, "embedding": value})
        tokens = _tokens(request.size)
        return StubReply.json(
            {
                "object": "list",
                "data": data,
                "model": request.model(script),
                "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
            }
        )

    def models(self, script: StubScript, request: ChatRequest) -> StubReply:
        # OpenAI's and Anthropic's model lists share the path, so carry both shapes
        data = [
            {
                "id": m,
                "object": "model",
                "created": CREATED,
                "owned_by": "stub",
                "type": "model",
                "display_name": m,
                "created_at": CREATED_AT,
            }
            for m in script.models
        ]
        return StubReply.json(
            {
                "object": "list",
                "data": data,
                "has_more": False,
                "first_id": script.models[0],
                "last_id": script.models[-1],
            }
        )

    endpoints: ClassVar[Mapping[tuple[str, str], str]] = {
        ("POST", "/v1/embeddings"): "embeddings",
        ("GET", "/v1/models"): "models",
    }


# --------------------------------------------------------------------------- Anthropic


class AnthropicShape(ApiShape):
    name = "anthropic"
    chat_path = "/v1/messages"

    def error(self, status: int, message: str) -> StubReply:
        return StubReply.json(
            {"type": "error", "error": {"type": "invalid_request_error", "message": message}},
            status,
        )

    def call_id(self, request: ChatRequest, call: ToolCall, index: int) -> str:
        return call.call_id or f"toolu_stub_{request.seq}_{index}"

    @staticmethod
    def _stop(turn: Turn) -> str:
        return "tool_use" if turn.calls_tools else "end_turn"

    def _blocks(self, turn: Turn, request: ChatRequest) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = []
        if turn.text:
            blocks.append({"type": "text", "text": turn.text})
        blocks += [
            {
                "type": "tool_use",
                "id": self.call_id(request, call, i),
                "name": call.name,
                "input": dict(call.arguments),
            }
            for i, call in enumerate(turn.tool_calls)
        ]
        return blocks

    def _message(self, model: str, request: ChatRequest, content: list[Any]) -> dict[str, Any]:
        return {
            "id": f"msg_stub_{request.seq}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": content,
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": _tokens(request.size), "output_tokens": 1},
        }

    def _chat_whole(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        doc = self._message(request.model(script), request, self._blocks(turn, request))
        doc["stop_reason"] = self._stop(turn)
        doc["usage"]["output_tokens"] = self.output_tokens(turn)
        return StubReply.json(doc)

    def _chat_stream(self, script: StubScript, turn: Turn, request: ChatRequest) -> StubReply:
        events: list[tuple[str, dict[str, Any]]] = [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": self._message(request.model(script), request, []),
                },
            ),
            ("ping", {"type": "ping"}),
        ]
        for index, block in enumerate(self._blocks(turn, request)):
            events += list(self._block_events(index, block))
        events += [
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": self._stop(turn), "stop_sequence": None},
                    "usage": {"output_tokens": self.output_tokens(turn)},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
        chunks = tuple(
            f"event: {name}\ndata: ".encode() + _dumps(data) + b"\n\n" for name, data in events
        )
        return StubReply(200, SSE, chunks, True)

    @staticmethod
    def _block_events(index: int, block: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        if block["type"] == "text":
            start: dict[str, Any] = {"type": "text", "text": ""}
            deltas = [{"type": "text_delta", "text": p} for p in _pieces(block["text"])]
        else:
            start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
            arguments = json.dumps(block["input"], separators=(",", ":"), ensure_ascii=False)
            deltas = [{"type": "input_json_delta", "partial_json": p} for p in _pieces(arguments)]
        yield (
            "content_block_start",
            {"type": "content_block_start", "index": index, "content_block": start},
        )
        for delta in deltas:
            yield (
                "content_block_delta",
                {"type": "content_block_delta", "index": index, "delta": delta},
            )
        yield "content_block_stop", {"type": "content_block_stop", "index": index}


#: Every API the stub speaks, in the order paths are matched.
API_SHAPES: Final[Sequence[ApiShape]] = (OllamaShape(), OpenAIShape(), AnthropicShape())
