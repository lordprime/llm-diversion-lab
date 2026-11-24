"""The shapes of run telemetry: one record per model call, one summary per run.

These are derived data. They are rebuilt from the tap's evidence whenever needed and
never written back into it. :data:`TELEMETRY_VERSION` is stamped on every summary;
bump it whenever a parsing or counting rule changes, so numbers computed under
different rules are never mixed up.

``WireFormat`` lives here rather than in :mod:`control.telemetry.wire` so the models
and the parsers can both use it without a circular import; ``wire`` re-exports it.

Counting agents
---------------
:class:`ThreadLinker` groups a run's calls into agents (threads). It is a heuristic;
:mod:`control.telemetry.wire` explains the per-call keys it uses and what still breaks
it. ``RunTelemetry.single_call_threads`` and ``largest_thread_calls`` show when it has
collapsed: if most threads have a single call, the run's framework probably rebuilds
its prompt every round and ``agents`` is close to ``calls``, which overstates it.
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
    "ThreadLinker",
    "ToolCallRecord",
    "WireFormat",
]

#: Version of the parsing and counting rules. Bump on any rule change.
#: 2: agents linked by history; closing-only ``</think>``; Anthropic text blocks joined
#: with a blank line; null usage never wipes a count; Ollama ``streamed`` from the request.
TELEMETRY_VERSION: Final = "2"

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
    #: The call's conversation key: system prompt plus first task (see
    #: :mod:`control.telemetry.wire`); empty when the request could not be read.
    thread_key: str
    #: Rolling hashes of the non-system messages: entry ``k`` covers the first ``k + 1``.
    history_hashes: tuple[str, ...]
    #: The rolling hash of the whole history followed by this call's reply, or ``None``
    #: without a reply. A later call whose history contains it continues this thread.
    reply_hash: str | None

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


class ThreadLinker:
    """Assigns each call to an agent thread, in ``seq`` order.

    A call continues a thread when its history starts with an earlier call's history
    followed by that call's reply (``reply_hash`` is among its ``history_hashes``),
    whatever its system prompt; when several earlier calls match, the most recent one
    wins. A call with no such match joins the thread its ``thread_key`` belongs to, or
    starts a new one. A thread is named after the ``thread_key`` of its first call, and
    every call that joins it also lends it its own ``thread_key`` (if no thread has it
    yet), so a retry of a linked call lands in the same thread. Calls whose request
    could not be read (empty ``thread_key``) belong to no thread.

    Each call costs one dictionary lookup per message in its history, so a run with
    ``n`` calls of up to ``m`` messages costs O(n·m).
    """

    def assign(self, calls: Sequence[CallTelemetry]) -> dict[int, str]:
        """Map each readable call's ``seq`` to its thread's name."""
        by_reply: dict[str, tuple[int, str]] = {}  # reply hash -> (seq, thread)
        by_key: dict[str, str] = {}  # thread_key -> thread
        threads: dict[int, str] = {}
        for call in sorted(calls, key=lambda c: c.seq):
            if not call.thread_key:
                continue
            # the most recent earlier call whose reply this call's history extends
            matches = [by_reply[h] for h in call.history_hashes if h in by_reply]
            fallback = by_key.get(call.thread_key, call.thread_key)
            thread = max(matches)[1] if matches else fallback
            by_key.setdefault(call.thread_key, thread)
            if call.reply_hash is not None:
                by_reply[call.reply_hash] = (call.seq, thread)
            threads[call.seq] = thread
        return threads


class RunTelemetry(_Frozen):
    """Totals for one run, built from its calls by :meth:`from_calls`.

    Token totals add up what each provider reported, so their meaning follows the
    provider. Summed ``input_tokens`` leaves out Anthropic's cached prompt tokens (they
    are in ``cache_read_tokens`` and ``cache_write_tokens``) but includes OpenAI's
    (which ``cache_read_tokens`` then counts a second time, as a subset). On Ollama the
    input count is ``prompt_eval_count``, taken after the prompt was cut to the model's
    ``num_ctx``, so ``peak_input_tokens`` there can never exceed ``num_ctx`` even when
    the agent sent more.
    """

    run_id: str
    telemetry_version: str
    calls: NonNegativeInt
    calls_by_format: dict[str, NonNegativeInt]
    calls_by_model: dict[str, NonNegativeInt]

    #: Sum of reported input tokens (see the class notes on cached tokens).
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    #: Prompt tokens read from a cache: Anthropic ``cache_read_input_tokens``, OpenAI
    #: ``prompt_tokens_details.cached_tokens`` (already inside OpenAI's input count).
    cache_read_tokens: NonNegativeInt
    #: Prompt tokens written to a cache (Anthropic ``cache_creation_input_tokens`` only).
    cache_write_tokens: NonNegativeInt
    #: Calls that reported no input token count (so the totals leave them out).
    calls_without_usage: NonNegativeInt
    #: The largest prompt a single call sent, in tokens: the "context used". Anthropic
    #: cached tokens are added back in; on Ollama it is capped by ``num_ctx``.
    peak_input_tokens: NonNegativeInt | None
    peak_request_chars: NonNegativeInt

    #: Agent threads (:class:`ThreadLinker`): the main agent plus its sub-agents.
    agents: NonNegativeInt
    #: Threads with exactly one call. Close to ``agents`` means linking found little
    #: shared history, so ``agents`` is likely an over-count.
    single_call_threads: NonNegativeInt
    #: Calls in the busiest thread; usually the main agent.
    largest_thread_calls: NonNegativeInt
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
        thread_sizes = Counter(ThreadLinker().assign(ordered).values())
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
            agents=len(thread_sizes),
            single_call_threads=sum(1 for size in thread_sizes.values() if size == 1),
            largest_thread_calls=max(thread_sizes.values(), default=0),
            tool_calls_by_name=_sorted_counts(t.name for c in ordered for t in c.tool_calls),
            reasoning_chars=sum(len(c.reasoning) for c in ordered),
            calls_with_reasoning=sum(1 for c in ordered if c.reasoning),
            parse_errors=sum(1 for c in ordered if c.parse_error is not None),
        )


def _sorted_counts(names: Iterable[str]) -> dict[str, int]:
    """Count ``names`` into a dict with sorted keys, so output is always the same."""
    return dict(sorted(Counter(names).items()))
