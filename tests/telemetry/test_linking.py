"""Agent linking on conversation shapes taken from the round-3 review probes.

Each test drives real Ollama ``/api/chat`` request and response bytes through
:func:`parse_call` and checks each thread's members, not just the agent count, so a
call landing in the wrong thread is caught even when the total happens to be right.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from control.telemetry import wire
from control.telemetry.extract import summarise, write_derived
from control.telemetry.model import CallTelemetry, RunTelemetry, ThreadLinker
from control.telemetry.wire import MessageDigests, parse_call

Message = dict[str, object]


def _user(text: str) -> Message:
    return {"role": "user", "content": text}


def _tool(text: str) -> Message:
    return {"role": "tool", "content": text}


class _Run:
    """Builds one run's calls the way an agent framework sends them."""

    def __init__(self) -> None:
        self.calls: list[CallTelemetry] = []
        self._digests = MessageDigests()

    def chat(
        self,
        system: str,
        history: list[Message],
        content: str = "",
        tool: tuple[str, object] | None = None,
        *,
        fail: bool = False,
    ) -> Message:
        """Send one call and return the assistant message (to echo next time)."""
        seq = len(self.calls) + 1
        request = {
            "model": "qwen3:8b",
            "stream": False,
            "messages": [{"role": "system", "content": system}, *history],
        }
        reply: Message = {"role": "assistant", "content": content}
        if tool is not None:
            reply["tool_calls"] = [{"function": {"name": tool[0], "arguments": tool[1]}}]
        response = {"model": "qwen3:8b", "message": reply, "done": True}
        call = parse_call(
            "/api/chat",
            json.dumps(request).encode(),
            None if fail else json.dumps(response).encode(),
            None if fail else "application/json",
            seq=seq,
            digests=self._digests,
        )
        self.calls.append(call)
        return reply

    def loop(
        self,
        system: str,
        history: list[Message],
        rounds: int,
        tag: str,
        rewrite: Callable[[list[Message]], list[Message]] | None = None,
    ) -> list[Message]:
        """An agent loop: call, run the tool, append both, maybe rewrite old history."""
        for i in range(rounds):
            reply = self.chat(system, history, tool=("nmap", json.dumps({"t": f"{tag}{i}"})))
            history = [*history, reply, _tool(json.dumps({"out": f"{tag}{i}", "port": 80}))]
            if rewrite is not None:
                history = rewrite(history)
        return history

    def members(self) -> list[list[int]]:
        """Each thread's call seqs, threads in order of their first call."""
        by_seq = ThreadLinker().link(self.calls).by_seq
        threads: dict[str, list[int]] = {}
        for seq in sorted(by_seq):
            threads.setdefault(by_seq[seq], []).append(seq)
        return list(threads.values())

    def summary(self) -> RunTelemetry:
        return summarise("run_probe", self.calls)


# --------------------------------------------------------------------------- forks and handoffs


def test_p3_forks_sharing_the_last_tool_result_keep_their_own_members() -> None:
    # every fork's history ends with the same tool result, then its own instruction
    run = _Run()
    h = run.loop("MAIN", [_user("pentest 10.0.0.1")], 3, "m")
    worker_a, worker_b = [*h, _user("sub-task: web")], [*h, _user("sub-task: ssh")]
    for i in range(3):
        reply = run.chat("WORKER-A", worker_a, tool=("curl", json.dumps({"u": i})))
        worker_a = [*worker_a, reply, _tool(f"a{i}")]
        reply = run.chat("WORKER-B", worker_b, tool=("ssh", json.dumps({"u": i})))
        worker_b = [*worker_b, reply, _tool(f"b{i}")]
    run.chat("MAIN", [*h, _user("workers done")], "final")

    assert run.members() == [[1, 2, 3, 10], [4, 6, 8], [5, 7, 9]]
    summary = run.summary()
    assert (summary.agents, summary.persona_splits, summary.branch_points) == (3, 2, 0)


@pytest.mark.parametrize("interleaved", [False, True])
def test_s2_different_persona_forks_with_the_same_first_message(interleaved: bool) -> None:
    run = _Run()
    task = _user("audit")
    spawn = run.chat("LEAD", [task], tool=("spawn", "{}"))
    histories = {
        "A": [task, spawn, _tool("spawned")],
        "B": [task, spawn, _tool("spawned")],
    }
    order = ["A", "A", "A", "B", "B", "B"]
    if interleaved:
        order = ["A", "B", "A", "B", "A", "B"]
    for step, who in enumerate(order):
        reply = run.chat(f"WORKER {who}", histories[who], tool=("run", json.dumps({"i": step})))
        histories[who] = [*histories[who], reply, _tool(f"{who}{step}")]

    expected_a = [2, 3, 4] if not interleaved else [2, 4, 6]
    expected_b = [5, 6, 7] if not interleaved else [3, 5, 7]
    assert run.members() == [[1], expected_a, expected_b]
    summary = run.summary()
    assert (summary.agents, summary.persona_splits, summary.branch_points) == (3, 2, 0)


def test_s3_handoff_and_hand_back_with_full_history() -> None:
    run = _Run()
    h = run.loop("TRIAGE", [_user("pentest")], 2, "t")
    h = run.loop("EXPLOIT", [*h, _user("exploit it")], 2, "e")
    run.loop("TRIAGE", [*h, _user("back to you")], 2, "t2")

    assert run.members() == [[1, 2, 5, 6], [3, 4]]
    assert run.summary().persona_splits == 1


def test_s6_same_persona_fork_with_a_retried_parent_in_between() -> None:
    run = _Run()
    task = _user("audit")
    spawn = run.chat("LEAD", [task], tool=("spawn", "{}"))
    worker_a = [task, spawn, _user("worker web")]
    reply = run.chat("LEAD", worker_a, tool=("curl", "{}"))
    worker_a = [*worker_a, reply, _tool("a0")]
    run.chat("LEAD", [task], tool=("spawn", "{}"))  # the parent call retried, same reply
    worker_b = [task, spawn, _user("worker ssh")]
    reply = run.chat("LEAD", worker_b, tool=("ssh", "{}"))
    worker_b = [*worker_b, reply, _tool("b0")]
    run.chat("LEAD", worker_a, tool=("curl", "{}"))
    run.chat("LEAD", worker_b, tool=("ssh", "{}"))

    # the earliest continuation (worker A) stays with the parent, as documented
    assert run.members() == [[1, 2, 3, 5], [4, 6]]
    assert run.summary().branch_points == 1


# --------------------------------------------------------------------------- rewritten history


def _reorder_tool_results(history: list[Message]) -> list[Message]:
    """Re-serialise every tool result with its keys reversed (as some clients do)."""
    out: list[Message] = []
    for message in history:
        if message["role"] == "tool":
            doc = json.loads(str(message["content"]))
            message = _tool(json.dumps(dict(reversed(list(doc.items()))), indent=2))
        out.append(message)
    return out


def _arguments_as_objects(history: list[Message]) -> list[Message]:
    out = _reorder_tool_results(history)
    for index, message in enumerate(out):
        calls = message.get("tool_calls")
        if isinstance(calls, list):
            fixed = [
                {
                    "function": {
                        "name": c["function"]["name"],
                        "arguments": json.loads(c["function"]["arguments"]),
                    }
                }
                if isinstance(c["function"]["arguments"], str)
                else c
                for c in calls
            ]
            out[index] = {**message, "tool_calls": fixed}
    return out


def _mask_old_tool_results(history: list[Message]) -> list[Message]:
    """Keep the last two tool results, replace older ones by a stub (OpenHands style)."""
    tools = [i for i, m in enumerate(history) if m["role"] == "tool"]
    masked = set(tools[:-2])
    return [_tool("[output elided]") if i in masked else m for i, m in enumerate(history)]


def _truncate_two_rounds_back(history: list[Message]) -> list[Message]:
    if len(history) >= 5 and history[-3]["role"] == "tool":
        history = [*history]
        history[-3] = _tool(str(history[-3]["content"])[:10])
    return history


@pytest.mark.parametrize(
    "rewrite",
    [
        _reorder_tool_results,
        _arguments_as_objects,
        _mask_old_tool_results,
        _truncate_two_rounds_back,
    ],
    ids=["P2-reserialised", "P2b-args-as-objects", "C-masking", "C3-truncation"],
)
@pytest.mark.parametrize("timestamped", [False, True], ids=["fixed-system", "ts-system"])
def test_rewritten_history_stays_one_agent(
    rewrite: Callable[[list[Message]], list[Message]], timestamped: bool
) -> None:
    run = _Run()
    history = [_user("go")]
    for i in range(8):
        system = f"S t={i}" if timestamped else "S"
        reply = run.chat(system, history, tool=("nmap", json.dumps({"i": i, "z": 1})))
        history = rewrite(
            [*history, reply, _tool(json.dumps({"out": "x" * 40 + str(i), "port": 80}))]
        )

    assert run.members() == [list(range(1, 9))]
    summary = run.summary()
    assert (summary.agents, summary.branch_points, summary.persona_splits) == (1, 0, 0)


# --------------------------------------------------------------------------- failed and retried


def test_s4_a_failed_call_takes_no_continuation_slot() -> None:
    run = _Run()
    history = [_user("go")]
    for i in range(10):
        reply = run.chat("S", history, tool=("nmap", json.dumps({"i": i})))
        if i == 4:  # the call after this tool errored and got no reply; the tool re-ran
            run.chat("S", [*history, reply, _tool("timeout")], fail=True)
            history = [*history, reply, _tool("rerun ok")]
        else:
            history = [*history, reply, _tool(f"o{i}")]

    assert run.members() == [list(range(1, 12))]
    assert run.summary().branch_points == 0


def test_a_retry_under_another_persona_is_not_a_retry() -> None:
    run = _Run()
    task = _user("audit")
    spawn = run.chat("LEAD", [task], tool=("spawn", "{}"))
    same = [task, spawn, _tool("spawned")]
    run.chat("WORKER A", same, "a")
    run.chat("WORKER B", same, "b")  # same continuation, different persona
    run.chat("WORKER A", same, "a")  # a true retry of worker A

    assert run.members() == [[1], [2, 4], [3]]


# --------------------------------------------------------------------------- documented limits


def test_s1_known_under_count_same_persona_fork_after_a_shared_tool_result() -> None:
    # workers share the lead's system prompt and the same message right after the
    # lead's reply; they only differ later, so the linker cannot see the fork
    run = _Run()
    h = run.loop("LEAD", [_user("pentest")], 2, "l")
    run.loop("LEAD", [*h, _user("you: web")], 2, "a")
    run.loop("LEAD", [*h, _user("you: ssh")], 2, "b")
    summary = run.summary()
    assert summary.agents == 1  # truth is 3: a documented under-count
    assert summary.branch_points == 0


def test_s5_known_false_branch_after_an_abandoned_call() -> None:
    # an answered call the client gave up on, then a different message from the same
    # reply: indistinguishable from a fork
    run = _Run()
    history = [_user("go")]
    reply = run.chat("S", history, tool=("nmap", "{}"))
    run.chat("S", [*history, reply, _tool("first try")], tool=("x", "{}"))
    run.chat("S", [*history, reply, _tool("second try")], tool=("x", "{}"))
    summary = run.summary()
    assert (summary.agents, summary.branch_points) == (2, 1)  # truth is 1: over-count


def test_s7_known_under_count_persona_differing_only_in_digits() -> None:
    run = _Run()
    h = run.loop("You are worker 1.", [_user("go")], 2, "w1")
    run.loop("You are worker 2.", [*h, _user("next")], 2, "w2")
    summary = run.summary()
    assert (summary.agents, summary.persona_splits) == (1, 0)  # truth is 2


# --------------------------------------------------------------------------- adapter agent ids


def _three_calls() -> list[CallTelemetry]:
    run = _Run()
    run.loop("S", [_user("go")], 3, "x")
    return run.calls


def test_summary_is_inferred_by_default() -> None:
    assert summarise("r", _three_calls()).agents_source == "inferred"


def test_adapter_agent_ids_override_the_linker() -> None:
    calls = _three_calls()
    summary = summarise("r", calls, agent_ids={1: "lead", 2: "lead", 3: "worker-7"})
    assert summary.agents_source == "adapter"
    assert (summary.agents, summary.single_call_threads, summary.largest_thread_calls) == (2, 1, 2)
    assert (summary.branch_points, summary.persona_splits) == (0, 0)


def test_adapter_agent_ids_are_written_to_the_rows(tmp_path: Path) -> None:
    calls = _three_calls()
    ids = {1: "lead", 2: "lead", 3: "worker-7"}
    write_derived(tmp_path, summarise("r", calls, agent_ids=ids), calls, agent_ids=ids)
    lines = (tmp_path / "telemetry" / "calls.jsonl").read_text().splitlines()
    assert [json.loads(line)["agent"] for line in lines] == ["lead", "lead", "worker-7"]


@pytest.mark.parametrize(
    "ids",
    [
        {1: "lead", 2: "lead"},  # a call left out
        {1: "a", 2: "b", 3: "c", 4: "d"},  # a seq that is not a call
        {1: "a", 2: "", 3: "c"},  # an empty id
    ],
)
def test_adapter_agent_ids_must_cover_exactly_the_calls(ids: dict[int, str]) -> None:
    with pytest.raises(ValueError, match="agent"):
        summarise("r", _three_calls(), agent_ids=ids)


def test_write_derived_needs_the_ids_of_an_adapter_summary(tmp_path: Path) -> None:
    calls = _three_calls()
    ids = {1: "lead", 2: "lead", 3: "worker-7"}
    with pytest.raises(ValueError, match="agent"):
        write_derived(tmp_path, summarise("r", calls, agent_ids=ids), calls)


def test_digest_cache_belongs_to_one_load_and_never_changes_results() -> None:
    assert not hasattr(wire, "_message_digest")  # no module-wide cache any more
    shared = MessageDigests()
    run = _Run()
    run.loop("S", [_user("go")], 3, "x")
    request = json.dumps(
        {
            "model": "m",
            "messages": [{"role": "user", "content": "go"}, {"role": "tool", "content": "t"}],
        }
    ).encode()
    with_cache = parse_call("/api/chat", request, None, None, digests=shared)
    without = parse_call("/api/chat", request, None, None)
    assert with_cache == without
    assert len(shared) == 2  # one entry per distinct message it has seen
    assert len(MessageDigests()) == 0
