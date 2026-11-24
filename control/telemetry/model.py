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
:mod:`control.telemetry.wire` explains the per-call keys it uses, and the
:class:`ThreadLinker` docstring the rules and where they go wrong in each direction.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, NonNegativeInt

__all__ = [
    "TELEMETRY_VERSION",
    "UNKNOWN",
    "CallTelemetry",
    "RunTelemetry",
    "ThreadLinker",
    "ThreadLinks",
    "ToolCallRecord",
    "WireFormat",
]

#: Version of the parsing and counting rules. Bump on any rule change.
#: 2: agents linked by history; closing-only ``</think>``; Anthropic text blocks joined
#: with a blank line; null usage never wipes a count; Ollama ``streamed`` from the request.
#: 3: branch points and persona changes start new threads; a shared reply goes to the
#: matching persona; the reply is hashed before its inline thinking is split off.
TELEMETRY_VERSION: Final = "3"

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
    #: The system prompt with every run of digits turned into ``0`` (and whitespace
    #: collapsed), hashed: who the agent is meant to be, ignoring timestamps and counters.
    persona_sha256: str | None
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


@dataclass(frozen=True, slots=True)
class ThreadLinks:
    """The result of :meth:`ThreadLinker.link`."""

    #: The thread of each readable call, by ``seq``.
    by_seq: dict[int, str]
    #: Earlier replies that two or more later calls continued in different ways.
    branch_points: int


class ThreadLinker:
    """Assigns each call to an agent thread, in ``seq`` order.

    Rules:

    1. **Parent.** A call extends an earlier call when its history starts with that
       call's history followed by that call's reply (the earlier ``reply_hash`` is
       among its ``history_hashes``), whatever its system prompt. When several earlier
       calls qualify, one with the same persona (``persona_sha256``) is preferred, and
       then the most recent, so two agents that happen to give the same reply keep
       their own threads.
    2. **Branch points.** What follows the parent's reply in the call's history is its
       *continuation*. The first continuation of a reply that suits the parent's thread
       stays in it; every other distinct continuation starts a new thread (forked
       workers, parallel sub-agents). A reply continued in two or more different ways
       is a branch point. The same continuation sent again is a retry, not a branch,
       and goes where the first one went.
    3. **Persona change.** A continuation whose persona differs from the last persona
       of the parent's thread starts a new thread (a handoff to another agent with the
       full history). The persona ignores digits and whitespace, so a timestamp in the
       system prompt is not a change.
    4. **Fallback.** A call that extends no earlier call joins the thread its
       ``thread_key`` (system prompt plus first task) already belongs to, or starts a
       new one. Every call lends its ``thread_key`` to its thread if no thread has it
       yet, so a retry of a linked call with a fresh history still lands there.

    A thread is named after the ``thread_key`` of its first call (with ``:<seq>``
    added if that name is taken). Calls whose request could not be read (empty
    ``thread_key``) belong to no thread.

    Where it is still wrong:

    * Over-counts: history that is dropped or rewritten between calls (sliding windows,
      compaction), prompts rebuilt each round (``/api/generate``), or a persona that
      really changes wording between rounds of one agent. Every such call looks new.
      ``RunTelemetry.single_call_threads == calls`` is the clear alarm; one-shot
      sub-agents also raise ``single_call_threads`` legitimately.
    * Under-counts: forks that keep the parent's persona and whose branches share the
      next message (only their later messages differ), or a handoff whose new system
      prompt differs from the old one only in digits. ``branch_points`` is the sign to
      look for: forks the linker *did* see.

    Each call costs one dictionary lookup per message in its history, plus one per
    earlier call sharing a matched reply, so ``n`` calls of up to ``m`` messages cost
    about O(n·m).
    """

    def link(self, calls: Sequence[CallTelemetry]) -> ThreadLinks:
        """Assign every readable call to a thread."""
        replies: dict[str, list[CallTelemetry]] = {}  # reply hash -> calls that gave it
        continuations: dict[int, dict[str | None, str]] = {}  # parent seq -> next -> thread
        parent_kept: set[int] = set()  # parents whose own thread already continued
        last_persona: dict[str, str | None] = {}  # thread -> persona of its latest call
        by_key: dict[str, str] = {}  # thread_key -> thread
        by_seq: dict[int, str] = {}
        branch_points = 0

        def new_thread(call: CallTelemetry) -> str:
            name = call.thread_key if call.thread_key not in last_persona else None
            return name or f"{call.thread_key}:{call.seq}"

        for call in sorted(calls, key=lambda c: c.seq):
            if not call.thread_key:
                continue
            parent, following = self._parent(call, replies)
            if parent is None:
                thread = by_key.get(call.thread_key) or new_thread(call)
            else:
                taken = continuations.setdefault(parent.seq, {})
                if following in taken:  # a retry of a continuation already seen
                    thread = taken[following]
                else:
                    parent_thread = by_seq[parent.seq]
                    same_persona = last_persona[parent_thread] == call.persona_sha256
                    if parent.seq not in parent_kept and same_persona:
                        thread = parent_thread
                        parent_kept.add(parent.seq)
                    else:
                        thread = new_thread(call)
                    taken[following] = thread
                    if len(taken) == 2:
                        branch_points += 1
            by_seq[call.seq] = thread
            last_persona[thread] = call.persona_sha256
            by_key.setdefault(call.thread_key, thread)
            if call.reply_hash is not None:
                replies.setdefault(call.reply_hash, []).append(call)
        return ThreadLinks(by_seq=by_seq, branch_points=branch_points)

    @staticmethod
    def _parent(
        call: CallTelemetry, replies: dict[str, list[CallTelemetry]]
    ) -> tuple[CallTelemetry | None, str | None]:
        """The earlier call this one extends, and the history hash right after its reply.

        Same persona first, then the most recent. ``None`` if it extends none.
        """
        best: CallTelemetry | None = None
        best_rank = (False, -1)
        best_position = -1
        hashes = call.history_hashes
        persona = call.persona_sha256
        for position, history_hash in enumerate(hashes):
            earlier_calls = replies.get(history_hash)
            if earlier_calls is None:
                continue
            for earlier in earlier_calls:
                rank = (earlier.persona_sha256 == persona, earlier.seq)
                if rank > best_rank:
                    best, best_rank, best_position = earlier, rank, position
        following = hashes[best_position + 1] if 0 <= best_position < len(hashes) - 1 else None
        return best, following


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
    #: Threads with exactly one call. Only ``single_call_threads == calls`` (with more
    #: than one call) is a clear over-count alarm: no call could be linked to any
    #: other. Below that it is not a verdict, since one-shot sub-agents legitimately
    #: have a single call each.
    single_call_threads: NonNegativeInt
    #: Calls in the busiest thread; usually the main agent.
    largest_thread_calls: NonNegativeInt
    #: Earlier replies that later calls continued in two or more different ways (forks).
    #: This is the under-count signal: it shows the linker saw forks. If a framework is
    #: known to fork and this is 0, the forks were missed and ``agents`` is too low.
    branch_points: NonNegativeInt
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
        links = ThreadLinker().link(ordered)
        thread_sizes = Counter(links.by_seq.values())
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
            branch_points=links.branch_points,
            tool_calls_by_name=_sorted_counts(t.name for c in ordered for t in c.tool_calls),
            reasoning_chars=sum(len(c.reasoning) for c in ordered),
            calls_with_reasoning=sum(1 for c in ordered if c.reasoning),
            parse_errors=sum(1 for c in ordered if c.parse_error is not None),
        )


def _sorted_counts(names: Iterable[str]) -> dict[str, int]:
    """Count ``names`` into a dict with sorted keys, so output is always the same."""
    return dict(sorted(Counter(names).items()))
