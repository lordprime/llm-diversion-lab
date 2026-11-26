"""The scripted-turns file the stub model answers from.

A script is a small YAML document::

    version: 1                      # optional; only 1 exists
    models: [stub-model]            # optional; what /api/tags and /v1/models list
    embedding_dimensions: 8         # optional; length of every embedding vector
    final: "Done."                  # optional; the reply once every turn is used
    turns:
      - text: "Let me look at the target first."
      - tool_calls:
          - name: run_command
            arguments: {command: "curl -s http://target/"}
      - when: {path: /v1/chat/completions, contains: "summarise"}
        text: "Summary: one page fetched, nothing found."

Every chat request (Ollama ``/api/chat``, OpenAI ``/v1/chat/completions``, Anthropic
``/v1/messages``) takes the first turn that has not been used yet and whose ``when``
matches the request; a turn without ``when`` matches any chat request. A turn is a plain
text reply, tool calls (with optional text), or both. Tool calls are rendered in each
API's own shape and end the reply with that API's tool-call stop reason; any other turn
ends with a normal stop. Once no turn is left, every chat request gets ``final`` as a
plain text reply with a normal stop, so an agent always gets a way to finish.

Listing and embedding endpoints never use a turn.

The file is checked strictly: unknown keys, wrong types, empty names, YAML aliases and
duplicate keys are refused with :class:`ScriptError`, so a typo can't silently turn a
tool call into a text reply.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Final

import yaml

from control.core.yaml_loader import UniqueKeyLoader

__all__ = [
    "CHAT_PATHS",
    "MAX_SCRIPT_BYTES",
    "ScriptError",
    "StubScript",
    "ToolCall",
    "Turn",
    "TurnFilter",
    "TurnPlayer",
]

#: The chat endpoints a turn can be pinned to with ``when.path``.
CHAT_PATHS: Final = frozenset({"/api/chat", "/v1/chat/completions", "/v1/messages"})
#: Largest script file accepted.
MAX_SCRIPT_BYTES: Final = 1024 * 1024
_MAX_TURNS: Final = 1000
_MAX_TEXT: Final = 64 * 1024
_MAX_ARGUMENTS: Final = 64 * 1024
_MAX_DIMENSIONS: Final = 4096
_NAME_RE: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$")
_MODEL_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$")


class ScriptError(ValueError):
    """The script file is not a valid stub script."""


class _Fields:
    """Strict readers for one mapping of the script, naming where a problem is."""

    def __init__(self, doc: object, where: str, allowed: frozenset[str]) -> None:
        if not isinstance(doc, Mapping):
            raise ScriptError(f"{where}: expected a mapping, got {type(doc).__name__}")
        unknown = sorted(str(k) for k in doc if k not in allowed)
        if unknown:
            raise ScriptError(f"{where}: unknown key(s) {', '.join(unknown)}")
        self._doc: Mapping[Any, Any] = doc
        self._where = where

    def has(self, key: str) -> bool:
        return key in self._doc

    def raw(self, key: str) -> Any:
        return self._doc.get(key)

    def text(self, key: str, *, default: str | None = None, allow_empty: bool = False) -> str:
        if key not in self._doc:
            if default is None:
                raise ScriptError(f"{self._where}: {key} is required")
            return default
        value = self._doc[key]
        if not isinstance(value, str):
            raise ScriptError(f"{self._where}.{key}: expected text, got {type(value).__name__}")
        if not value and not allow_empty:
            raise ScriptError(f"{self._where}.{key}: must not be empty")
        if len(value) > _MAX_TEXT:
            raise ScriptError(f"{self._where}.{key}: longer than {_MAX_TEXT} characters")
        return value

    def integer(self, key: str, default: int, low: int, high: int) -> int:
        value = self._doc.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ScriptError(f"{self._where}.{key}: expected an integer from {low} to {high}")
        return value

    def items(self, key: str) -> list[Any]:
        value = self._doc.get(key)
        if not isinstance(value, list):
            raise ScriptError(f"{self._where}.{key}: expected a list")
        return value


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One tool the scripted model asks to run; ``arguments`` is a JSON object."""

    name: str
    arguments: Mapping[str, Any]
    call_id: str | None = None

    @property
    def arguments_json(self) -> str:
        return json.dumps(self.arguments, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_doc(cls, doc: object, where: str) -> ToolCall:
        fields = _Fields(doc, where, frozenset({"name", "arguments", "id"}))
        name = fields.text("name")
        if not _NAME_RE.fullmatch(name):
            raise ScriptError(f"{where}.name: {name!r} is not a tool name")
        arguments = fields.raw("arguments") if fields.has("arguments") else {}
        if not isinstance(arguments, Mapping):
            raise ScriptError(f"{where}.arguments: expected a mapping")
        try:
            encoded = json.dumps(arguments, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ScriptError(f"{where}.arguments: not plain JSON data ({exc})") from None
        if len(encoded) > _MAX_ARGUMENTS:
            raise ScriptError(f"{where}.arguments: larger than {_MAX_ARGUMENTS} bytes")
        call_id = fields.text("id") if fields.has("id") else None
        if call_id is not None and not _NAME_RE.fullmatch(call_id):
            raise ScriptError(f"{where}.id: {call_id!r} is not a usable call id")
        # a JSON round trip, so the stored arguments are exactly what gets sent
        return cls(name, json.loads(encoded), call_id)


@dataclass(frozen=True, slots=True)
class TurnFilter:
    """Which chat requests a turn may answer: an endpoint, a substring, or both."""

    path: str | None = None
    contains: str | None = None

    def matches(self, path: str, body_text: str) -> bool:
        if self.path is not None and path != self.path:
            return False
        return self.contains is None or self.contains in body_text

    @classmethod
    def from_doc(cls, doc: object, where: str) -> TurnFilter:
        fields = _Fields(doc, where, frozenset({"path", "contains"}))
        path = fields.text("path") if fields.has("path") else None
        if path is not None and path not in CHAT_PATHS:
            raise ScriptError(f"{where}.path: {path!r} is not one of {sorted(CHAT_PATHS)}")
        contains = fields.text("contains") if fields.has("contains") else None
        if path is None and contains is None:
            raise ScriptError(f"{where}: give a path, a contains, or both")
        return cls(path, contains)


@dataclass(frozen=True, slots=True)
class Turn:
    """One scripted reply."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    when: TurnFilter | None = None

    @property
    def calls_tools(self) -> bool:
        return bool(self.tool_calls)

    def accepts(self, path: str, body_text: str) -> bool:
        return self.when is None or self.when.matches(path, body_text)

    @classmethod
    def from_doc(cls, doc: object, where: str) -> Turn:
        fields = _Fields(doc, where, frozenset({"text", "tool_calls", "when"}))
        text = fields.text("text", allow_empty=True) if fields.has("text") else ""
        calls: tuple[ToolCall, ...] = ()
        if fields.has("tool_calls"):
            raw = fields.items("tool_calls")
            if not raw:
                raise ScriptError(f"{where}.tool_calls: must not be empty")
            calls = tuple(
                ToolCall.from_doc(item, f"{where}.tool_calls[{i}]") for i, item in enumerate(raw)
            )
        if not text and not calls:
            raise ScriptError(f"{where}: a turn needs text, tool_calls, or both")
        when = (
            TurnFilter.from_doc(fields.raw("when"), f"{where}.when") if fields.has("when") else None
        )
        return cls(text, calls, when)


@dataclass(frozen=True, slots=True)
class StubScript:
    """A whole script: the turns, the final reply and what the listings report."""

    DEFAULT_MODELS: ClassVar[tuple[str, ...]] = ("stub-model",)
    DEFAULT_FINAL: ClassVar[str] = "Done. Nothing more to do."
    DEFAULT_DIMENSIONS: ClassVar[int] = 8

    turns: tuple[Turn, ...] = ()
    final: str = DEFAULT_FINAL
    models: tuple[str, ...] = DEFAULT_MODELS
    embedding_dimensions: int = DEFAULT_DIMENSIONS

    @classmethod
    def from_doc(cls, doc: object) -> StubScript:
        fields = _Fields(
            doc,
            "script",
            frozenset({"version", "models", "embedding_dimensions", "final", "turns"}),
        )
        if fields.has("version"):
            fields.integer("version", 1, 1, 1)  # only version 1 exists
        raw_turns = fields.items("turns") if fields.has("turns") else []
        if len(raw_turns) > _MAX_TURNS:
            raise ScriptError(f"script.turns: more than {_MAX_TURNS} turns")
        turns = tuple(Turn.from_doc(t, f"script.turns[{i}]") for i, t in enumerate(raw_turns))
        models = cls.DEFAULT_MODELS
        if fields.has("models"):
            raw_models = fields.items("models")
            if not raw_models:
                raise ScriptError("script.models: must not be empty")
            for i, model in enumerate(raw_models):
                if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
                    raise ScriptError(f"script.models[{i}]: {model!r} is not a model name")
            if len(set(raw_models)) != len(raw_models):
                raise ScriptError("script.models: duplicate model name")
            models = tuple(raw_models)
        return cls(
            turns=turns,
            final=fields.text("final", default=cls.DEFAULT_FINAL),
            models=models,
            embedding_dimensions=fields.integer(
                "embedding_dimensions", cls.DEFAULT_DIMENSIONS, 1, _MAX_DIMENSIONS
            ),
        )

    @classmethod
    def from_yaml(cls, text: str) -> StubScript:
        if len(text.encode("utf-8", errors="replace")) > MAX_SCRIPT_BYTES:
            raise ScriptError(f"script: larger than {MAX_SCRIPT_BYTES} bytes")
        try:
            # aliases could expand a small file into a huge one; a script never needs them
            if any(isinstance(token, yaml.AliasToken) for token in yaml.scan(text)):
                raise ScriptError("script: YAML aliases are not allowed")
            doc = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506 -- a SafeLoader subclass
        except yaml.YAMLError as exc:
            raise ScriptError(f"script: not valid YAML ({exc})") from None
        return cls.from_doc(doc)

    @classmethod
    def load(cls, path: Path) -> StubScript:
        try:
            with path.open("rb") as fh:
                data = fh.read(MAX_SCRIPT_BYTES + 1)
        except OSError as exc:
            raise ScriptError(f"script: cannot read {path}: {exc.strerror or exc}") from None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ScriptError(f"script: {path} is not UTF-8 text") from None
        return cls.from_yaml(text)


@dataclass(slots=True)
class TurnPlayer:
    """Hands out the script's turns to chat requests, each turn once, safely across threads.

    :meth:`next_turn` returns the turn's index in the script, or ``None`` for the final
    reply once no unused turn matches.
    """

    script: StubScript
    _used: list[bool] = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._used = [False] * len(self.script.turns)

    def next_turn(self, path: str, body_text: str) -> tuple[int | None, Turn]:
        with self._lock:
            for index, turn in enumerate(self.script.turns):
                if not self._used[index] and turn.accepts(path, body_text):
                    self._used[index] = True
                    return index, turn
        return None, Turn(text=self.script.final)

    @property
    def remaining(self) -> Sequence[int]:
        with self._lock:
            return [i for i, used in enumerate(self._used) if not used]
