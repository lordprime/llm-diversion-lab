"""The shapes of run telemetry: one record per model call, one summary per run.

These are derived data. They are rebuilt from the tap's evidence whenever needed and
never written back into it. :data:`TELEMETRY_VERSION` is stamped on every summary;
bump it whenever a parsing or counting rule changes, so numbers computed under
different rules are never mixed up.

``WireFormat`` lives here rather than in :mod:`control.telemetry.wire` so the models
and the parsers can both use it without a circular import; ``wire`` re-exports it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, NonNegativeInt

__all__ = [
    "TELEMETRY_VERSION",
    "UNKNOWN",
    "CallTelemetry",
    "RunTelemetry",
    "ToolCallRecord",
    "WireFormat",
]

#: Version of the parsing and counting rules. Bump on any rule change.
TELEMETRY_VERSION: Final = "1"

#: Bucket name for calls whose format or model is not known.
UNKNOWN: Final = "unknown"


class WireFormat(StrEnum):
    """The model APIs the parsers understand, named after their endpoints."""

    #: Ollama's native ``/api/chat`` (and ``/api/generate``).
    OLLAMA_CHAT = "ollama_chat"
    #: OpenAI-style ``/v1/chat/completions`` (also Ollama's and vLLM's compatible API).
    OPENAI_CHAT = "openai_chat"
    #: Anthropic's ``/v1/messages``.
    ANTHROPIC_MESSAGES = "anthropic_messages"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolCallRecord(_Frozen):
    """One tool the model asked to run. ``arguments`` is the JSON text as sent."""

    name: str
    arguments: str


class CallTelemetry(_Frozen):
    """What one model call did, read from its stored request and response.

    Token counts are ``None`` when the provider did not report them. ``parse_error``
    is set (instead of raising) when part of the call could not be read; whatever
    could be read is still filled in.
    """

    # identity
    seq: NonNegativeInt
    format: WireFormat | None
    requested_model: str | None
    returned_model: str | None

    # tokens, exactly as the provider reported them
    input_tokens: NonNegativeInt | None
    output_tokens: NonNegativeInt | None
    cache_read_tokens: NonNegativeInt | None
    cache_write_tokens: NonNegativeInt | None

    # what was sent
    request_messages: NonNegativeInt
    #: Characters of every message text the model received (system prompt, user and
    #: assistant text, tool-call arguments and tool results).
    request_chars: NonNegativeInt
    system_sha256: str | None
    #: Groups calls into conversations (see :mod:`control.telemetry.wire`); empty when
    #: the request could not be read.
    thread_key: str

    # what came back
    tool_calls: tuple[ToolCallRecord, ...]
    reasoning: str
    text: str
    stop_reason: str | None

    streamed: bool
    parse_error: str | None

    @property
    def context_tokens(self) -> int | None:
        """The whole prompt this call sent, in tokens, cached part included.

        Anthropic reports cached prompt tokens apart from ``input_tokens``, so they are
        added back here; OpenAI's ``prompt_tokens`` already includes them.
        """
        if self.input_tokens is None:
            return None
        if self.format is WireFormat.ANTHROPIC_MESSAGES:
            return (
                self.input_tokens + (self.cache_read_tokens or 0) + (self.cache_write_tokens or 0)
            )
        return self.input_tokens


class RunTelemetry(_Frozen):
    """Totals for one run, built from its calls by :meth:`from_calls`."""

    run_id: str
    telemetry_version: str
    calls: NonNegativeInt
    calls_by_format: dict[str, NonNegativeInt]
    calls_by_model: dict[str, NonNegativeInt]

    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    cache_read_tokens: NonNegativeInt
    cache_write_tokens: NonNegativeInt
    #: Calls that reported no input token count (so the totals leave them out).
    calls_without_usage: NonNegativeInt
    #: The largest prompt a single call sent, in tokens: the "context used".
    peak_input_tokens: NonNegativeInt | None
    peak_request_chars: NonNegativeInt

    #: Distinct conversations (``thread_key``), i.e. the main agent plus sub-agents.
    agents: NonNegativeInt
    tool_calls_by_name: dict[str, NonNegativeInt]
    reasoning_chars: NonNegativeInt
    calls_with_reasoning: NonNegativeInt
    parse_errors: NonNegativeInt

    @classmethod
    def from_calls(cls, run_id: str, calls: Sequence[CallTelemetry]) -> RunTelemetry:
        """Add up ``calls``. Order does not matter; a repeated ``seq`` is refused."""
        ordered = sorted(calls, key=lambda c: c.seq)
        seqs = [c.seq for c in ordered]
        if len(set(seqs)) != len(seqs):
            raise ValueError(f"run {run_id}: the same call seq appears more than once")

        def total(values: Sequence[int | None]) -> int:
            return sum(v for v in values if v is not None)

        contexts = [c.context_tokens for c in ordered if c.context_tokens is not None]
        return cls(
            run_id=run_id,
            telemetry_version=TELEMETRY_VERSION,
            calls=len(ordered),
            calls_by_format=_sorted_counts(
                c.format.value if c.format else UNKNOWN for c in ordered
            ),
            calls_by_model=_sorted_counts(
                c.returned_model or c.requested_model or UNKNOWN for c in ordered
            ),
            input_tokens=total([c.input_tokens for c in ordered]),
            output_tokens=total([c.output_tokens for c in ordered]),
            cache_read_tokens=total([c.cache_read_tokens for c in ordered]),
            cache_write_tokens=total([c.cache_write_tokens for c in ordered]),
            calls_without_usage=sum(1 for c in ordered if c.input_tokens is None),
            peak_input_tokens=max(contexts, default=None),
            peak_request_chars=max((c.request_chars for c in ordered), default=0),
            agents=len({c.thread_key for c in ordered if c.thread_key}),
            tool_calls_by_name=_sorted_counts(t.name for c in ordered for t in c.tool_calls),
            reasoning_chars=sum(len(c.reasoning) for c in ordered),
            calls_with_reasoning=sum(1 for c in ordered if c.reasoning),
            parse_errors=sum(1 for c in ordered if c.parse_error is not None),
        )


def _sorted_counts(names: Iterable[str]) -> dict[str, int]:
    """Count ``names`` into a dict with sorted keys, so output is always the same."""
    return dict(sorted(Counter(names).items()))
