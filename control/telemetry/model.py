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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

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
#: 4: a retry must match persona too; rewritten history joins the thread instead of
#: forking; failed calls take no continuation; parents ranked by depth; persona splits
#: counted apart from branch points; agent ids from an adapter can replace the linker.
TELEMETRY_VERSION: Final = "4"

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
    #: Index (into ``history_hashes``) of the latest assistant message sent back in the
    #: request, or ``None`` if it carries none. Used to tell a rewritten history from a
    #: fork (see :class:`ThreadLinker`).
    last_assistant_index: NonNegativeInt | None
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
    """Which agent each call belongs to, from :class:`ThreadLinker` or from an adapter."""

    #: The agent (thread) of each attributed call, by ``seq``.
    by_seq: dict[int, str]
    #: Parent replies continued by two or more different next messages (see the linker).
    branch_points: int = 0
    #: Continuations that started a new agent because their persona changed.
    persona_splits: int = 0

    @classmethod
    def resolve(
        cls, calls: Sequence[CallTelemetry], agent_ids: Mapping[int, str] | None = None
    ) -> ThreadLinks:
        """The linker's inference, or ``agent_ids`` from a framework adapter if given.

        Adapter ids must name every call and nothing else, each with a non-empty id;
        the inference diagnostics are then zero, since nothing was inferred.
        """
        if agent_ids is None:
            return ThreadLinker().link(calls)
        seqs = {call.seq for call in calls}
        if set(agent_ids) != seqs:
            missing = sorted(seqs - set(agent_ids))
            extra = sorted(set(agent_ids) - seqs)
            raise ValueError(f"agent ids must name every call: missing {missing}, extra {extra}")
        if not all(agent_ids.values()):
            raise ValueError("agent ids must not be empty")
        return cls(by_seq={seq: agent_ids[seq] for seq in sorted(seqs)})


class ThreadLinker:
    """Infers which agent (thread) made each call, in ``seq`` order.

    This is an inference from traffic alone, and no rule set gets every framework
    right; where a framework adapter knows the real agent of each call, its ids replace
    this (:meth:`ThreadLinks.resolve`). Rules:

    1. **Parent.** A call extends an earlier call when its history contains that call's
       history followed by that call's reply (the earlier ``reply_hash`` is among its
       ``history_hashes``), whatever its system prompt. Among several such calls the
       one with the same persona (``persona_sha256``) wins, then the deepest in the
       history, then the most recent, so two agents that happen to give the same reply
       keep their own threads.
    2. **Rewritten history.** If the parent's reply is not the latest assistant message
       of the call, later history was rewritten (masked, truncated or re-serialised
       old messages, as condensers and context editing do) and only an older ancestor
       still matches. The call joins the parent's thread and records nothing else: no
       continuation and no branch. A real fork always has the parent's reply as its
       latest assistant message.
    3. **Continuations.** What follows the parent's reply is the call's continuation.
       Continuations are kept per parent reply and parent thread. The first one that
       suits the parent's thread (same persona) stays in it, so in a same-persona fork
       the earliest branch keeps the parent's thread. Every other distinct one starts a
       new agent. The same continuation under the same persona is a retry and goes
       where the first went; under another persona it is not a retry.
    4. **Branch points and persona splits.** A parent reply continued by two or more
       different next messages is a branch point. A continuation that starts a new
       agent because its persona differs from the parent thread's latest persona is a
       persona split (a handoff, or a worker with its own persona). The persona ignores
       digits and whitespace, so a timestamp is not a change.
    5. **Failed calls.** A call with no reply (it failed or was abandoned) joins where a
       matching continuation went, else the parent's thread, and takes no slot, so the
       retry that follows it is not a branch.
    6. **Fallback.** A call that extends no earlier call joins the thread its
       ``thread_key`` (system prompt plus first task) already belongs to, or starts a
       new one. Calls placed by rules 3 or 6 lend their ``thread_key`` to their thread
       if no thread has it yet, so a retry with a fresh history still lands there.

    A thread is named after the ``thread_key`` of its first call (with ``:<seq>``
    added if that name is taken). Calls whose request could not be read (empty
    ``thread_key``) belong to no thread.

    Known errors, by direction:

    * Over-count: history dropped by a sliding window or compaction before any of it
      matches; prompts rebuilt each round (``/api/generate``); a reply folded into the
      next user turn; one agent whose system prompt changes wording between rounds; an
      answered call the client abandons and then continues differently (probe S5),
      which looks exactly like a fork and also raises ``branch_points``.
    * Under-count: a same-persona fork whose branches send the same next message and
      only differ later (probe S1); two sub-agents with the same system prompt and the
      same first task; a handoff to a persona that differs only in digits (probe S7).

    Each call costs one dictionary lookup per message in its history, plus one per
    earlier call sharing a matched reply, so ``n`` calls of up to ``m`` messages cost
    about O(n·m).
    """

    def link(self, calls: Sequence[CallTelemetry]) -> ThreadLinks:
        """Assign every readable call to a thread."""
        replies: dict[str, list[CallTelemetry]] = {}  # reply hash -> calls that gave it
        # (parent reply, parent thread) -> (next message, persona) -> thread
        continuations: dict[tuple[str, str], dict[tuple[str | None, str | None], str]] = {}
        next_messages: dict[tuple[str, str], set[str | None]] = {}
        kept: set[tuple[str, str]] = set()  # parent replies whose own thread continued
        last_persona: dict[str, str | None] = {}  # thread -> persona of its latest call
        by_key: dict[str, str] = {}  # thread_key -> thread
        by_seq: dict[int, str] = {}
        branch_points = persona_splits = 0

        def new_thread(call: CallTelemetry) -> str:
            name = call.thread_key if call.thread_key not in last_persona else None
            return name or f"{call.thread_key}:{call.seq}"

        for call in sorted(calls, key=lambda c: c.seq):
            if not call.thread_key:
                continue
            found = self._parent(call, replies)
            placed = True  # False for calls that must not shape their thread
            if found is None:
                thread = by_key.get(call.thread_key) or new_thread(call)
            else:
                parent, position = found
                parent_thread = by_seq[parent.seq]
                key = (str(parent.reply_hash), parent_thread)
                hashes = call.history_hashes
                following = hashes[position + 1] if position + 1 < len(hashes) else None
                slot = (following, call.persona_sha256)
                taken = continuations.setdefault(key, {})
                latest = call.last_assistant_index
                if latest is not None and latest != position:  # rule 2: rewritten history
                    thread, placed = parent_thread, False
                elif call.reply_hash is None:  # rule 5: a failed call takes no slot
                    thread, placed = taken.get(slot, parent_thread), False
                elif slot in taken:  # a retry of a continuation already seen
                    thread = taken[slot]
                else:
                    same_persona = last_persona[parent_thread] == call.persona_sha256
                    if key not in kept and same_persona:
                        thread = parent_thread
                        kept.add(key)
                    else:
                        thread = new_thread(call)
                        if not same_persona:
                            persona_splits += 1
                    taken[slot] = thread
                    seen = next_messages.setdefault(key, set())
                    seen.add(following)
                    if len(seen) == 2:  # counted once, when the second way appears
                        branch_points += 1
            by_seq[call.seq] = thread
            if placed:
                last_persona[thread] = call.persona_sha256
                by_key.setdefault(call.thread_key, thread)
            if call.reply_hash is not None:
                replies.setdefault(call.reply_hash, []).append(call)
        return ThreadLinks(by_seq, branch_points, persona_splits)

    @staticmethod
    def _parent(
        call: CallTelemetry, replies: dict[str, list[CallTelemetry]]
    ) -> tuple[CallTelemetry, int] | None:
        """The earlier call this one extends and where its reply sits in the history.

        Ranked by same persona, then depth in the history, then recency. ``None`` if
        the call extends no earlier call.
        """
        best: tuple[CallTelemetry, int] | None = None
        best_rank = (False, -1, -1)
        persona = call.persona_sha256
        for position, history_hash in enumerate(call.history_hashes):
            earlier_calls = replies.get(history_hash)
            if earlier_calls is None:
                continue
            for earlier in earlier_calls:
                rank = (earlier.persona_sha256 == persona, position, earlier.seq)
                if rank > best_rank:
                    best, best_rank = (earlier, position), rank
        return best


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

    #: Agents: the main agent plus its sub-agents. See ``agents_source`` for whether
    #: this was inferred from traffic or given by a framework adapter.
    agents: NonNegativeInt
    #: ``"inferred"``: :class:`ThreadLinker` guessed the agents from the traffic, which
    #: cannot be exact for every framework (see its docstring for the known errors).
    #: ``"adapter"``: a framework adapter named the agent of every call.
    agents_source: Literal["inferred", "adapter"] = "inferred"
    #: Agents with exactly one call. Only ``single_call_threads == calls`` (with more
    #: than one call) is a clear over-count alarm: no call could be linked to any
    #: other. Below that it is not a verdict, since one-shot sub-agents legitimately
    #: have a single call each.
    single_call_threads: NonNegativeInt
    #: Calls in the busiest agent thread. Often the main agent, but not always: a
    #: sub-agent can make more calls, and in a same-persona fork the first branch keeps
    #: the parent's thread.
    largest_thread_calls: NonNegativeInt
    #: Parent replies continued by two or more different next messages: forks the
    #: linker saw. Each one added at least one agent. It is the under-count signal (a
    #: framework known to fork that shows 0 was not seen forking), but a false branch
    #: (an answered call abandoned, then a different continuation) also raises it.
    branch_points: NonNegativeInt
    #: Continuations that became a new agent because their persona differed from the
    #: parent thread's (handoffs, workers with their own persona). Each added an agent.
    persona_splits: NonNegativeInt
    tool_calls_by_name: dict[str, NonNegativeInt]
    reasoning_chars: NonNegativeInt
    calls_with_reasoning: NonNegativeInt
    parse_errors: NonNegativeInt

    @classmethod
    def from_calls(
        cls,
        run_id: str,
        calls: Sequence[CallTelemetry],
        agent_ids: Mapping[int, str] | None = None,
    ) -> RunTelemetry:
        """Add up ``calls``. Order does not matter; a repeated ``seq`` is refused.

        ``agent_ids`` (call ``seq`` to agent id, from a framework adapter) overrides
        the inferred agents and sets ``agents_source`` to ``"adapter"``.
        """
        ordered = sorted(calls, key=lambda c: c.seq)
        seqs = [c.seq for c in ordered]
        if len(set(seqs)) != len(seqs):
            raise ValueError(f"run {run_id}: the same call seq appears more than once")

        def total(values: Sequence[int | None]) -> int:
            return sum(v for v in values if v is not None)

        contexts = [c.context_tokens for c in ordered if c.context_tokens is not None]
        links = ThreadLinks.resolve(ordered, agent_ids)
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
            agents_source="inferred" if agent_ids is None else "adapter",
            single_call_threads=sum(1 for size in thread_sizes.values() if size == 1),
            largest_thread_calls=max(thread_sizes.values(), default=0),
            branch_points=links.branch_points,
            persona_splits=links.persona_splits,
            tool_calls_by_name=_sorted_counts(t.name for c in ordered for t in c.tool_calls),
            reasoning_chars=sum(len(c.reasoning) for c in ordered),
            calls_with_reasoning=sum(1 for c in ordered if c.reasoning),
            parse_errors=sum(1 for c in ordered if c.parse_error is not None),
        )


def _sorted_counts(names: Iterable[str]) -> dict[str, int]:
    """Count ``names`` into a dict with sorted keys, so output is always the same."""
    return dict(sorted(Counter(names).items()))
