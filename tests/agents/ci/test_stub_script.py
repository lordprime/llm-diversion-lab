"""The stub model's scripted-turns format: what it accepts, what it refuses, and turn order."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from agents.ci.stub_model.script import (
    MAX_SCRIPT_BYTES,
    ScriptError,
    StubScript,
    ToolCall,
    Turn,
    TurnFilter,
    TurnPlayer,
)

FULL = """
version: 1
models: [stub-model, other-model]
embedding_dimensions: 16
final: "All done."
turns:
  - text: "first"
  - tool_calls:
      - name: run_command
        arguments: {command: "curl -s http://target/", flags: [1, 2.5, true, null]}
        id: call_fixed
    text: "running it"
  - when: {path: /v1/messages, contains: "summarise"}
    text: "summary"
"""


def test_a_full_script_loads() -> None:
    script = StubScript.from_yaml(FULL)
    assert script.models == ("stub-model", "other-model")
    assert script.embedding_dimensions == 16
    assert script.final == "All done."
    first, second, third = script.turns
    assert first == Turn(text="first")
    assert second.text == "running it"
    assert second.tool_calls == (
        ToolCall(
            "run_command",
            {"command": "curl -s http://target/", "flags": [1, 2.5, True, None]},
            "call_fixed",
        ),
    )
    assert second.calls_tools and not first.calls_tools
    assert third.when == TurnFilter("/v1/messages", "summarise")


def test_defaults() -> None:
    script = StubScript.from_yaml("turns: []\n")
    assert script.turns == ()
    assert script.models == StubScript.DEFAULT_MODELS
    assert script.final == StubScript.DEFAULT_FINAL
    assert script.embedding_dimensions == StubScript.DEFAULT_DIMENSIONS
    assert StubScript.from_yaml("{}\n") == script


def test_arguments_default_to_an_empty_object_and_render_as_compact_json() -> None:
    call = StubScript.from_yaml("turns:\n  - tool_calls: [{name: t}]\n").turns[0].tool_calls[0]
    assert call.arguments == {} and call.arguments_json == "{}"
    call = ToolCall("t", {"a": "é", "b": [1]})
    assert call.arguments_json == '{"a":"é","b":[1]}'


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- just a list\n", "expected a mapping"),
        ("turnz: []\n", "unknown key(s) turnz"),
        ("version: 2\n", "script.version"),
        ("version: true\n", "script.version"),
        ("turns: {text: hi}\n", "script.turns: expected a list"),
        ("turns: [hi]\n", "script.turns[0]: expected a mapping"),
        ("turns: [{}]\n", "needs text, tool_calls, or both"),
        ("turns: [{text: ''}]\n", "needs text, tool_calls, or both"),
        ("turns: [{text: 5}]\n", "expected text, got int"),
        ("turns: [{text: hi, color: red}]\n", "unknown key(s) color"),
        ("turns: [{tool_calls: []}]\n", "tool_calls: must not be empty"),
        ("turns: [{tool_calls: {name: x}}]\n", "tool_calls: expected a list"),
        ("turns: [{tool_calls: [{arguments: {}}]}]\n", "name is required"),
        ("turns: [{tool_calls: [{name: ''}]}]\n", "name: must not be empty"),
        ("turns: [{tool_calls: [{name: 'rm -rf'}]}]\n", "is not a tool name"),
        ("turns: [{tool_calls: [{name: t, arguments: [1]}]}]\n", "arguments: expected a mapping"),
        ("turns: [{tool_calls: [{name: t, arguments: {d: 2026-01-01}}]}]\n", "not plain JSON"),
        ("turns: [{tool_calls: [{name: t, arguments: {n: .nan}}]}]\n", "not plain JSON"),
        ("turns: [{tool_calls: [{name: t, id: 'a b'}]}]\n", "not a usable call id"),
        ("turns: [{tool_calls: [{name: t, extra: 1}]}]\n", "unknown key(s) extra"),
        ("turns: [{text: hi, when: {}}]\n", "give a path, a contains, or both"),
        ("turns: [{text: hi, when: {path: /api/tags}}]\n", "is not one of"),
        ("turns: [{text: hi, when: {path: /v1/messages, model: x}}]\n", "unknown key(s) model"),
        ("models: []\n", "models: must not be empty"),
        ("models: [a, a]\n", "duplicate model name"),
        ("models: ['bad model']\n", "is not a model name"),
        ("models: [7]\n", "is not a model name"),
        ("embedding_dimensions: 0\n", "embedding_dimensions"),
        ("embedding_dimensions: 4097\n", "embedding_dimensions"),
        ("embedding_dimensions: 8.0\n", "embedding_dimensions"),
        ("embedding_dimensions: true\n", "embedding_dimensions"),
        ("final: ''\n", "final: must not be empty"),
        ("final: [a]\n", "expected text"),
        ("turns: [{text: hi}, {text: hi}\n", "not valid YAML"),
        ("turns: []\nturns: []\n", "duplicate key"),
        ("a: &x [1]\nturns: *x\n", "aliases are not allowed"),
        ("!!python/object:os.system {}\n", "not valid YAML"),
    ],
)
def test_bad_scripts_are_refused(text: str, message: str) -> None:
    with pytest.raises(ScriptError, match=None) as caught:
        StubScript.from_yaml(text)
    assert message in str(caught.value)


def test_absurd_sizes_are_refused() -> None:
    with pytest.raises(ScriptError, match="larger than"):
        StubScript.from_yaml("final: " + "x" * MAX_SCRIPT_BYTES + "\n")
    with pytest.raises(ScriptError, match="longer than"):
        StubScript.from_yaml(f"final: {'x' * 70_000}\n")
    with pytest.raises(ScriptError, match="more than 1000 turns"):
        StubScript.from_yaml("turns:\n" + "  - text: hi\n" * 1001)
    with pytest.raises(ScriptError, match="arguments: larger than"):
        StubScript.from_yaml(
            f"turns: [{{tool_calls: [{{name: t, arguments: {{a: {'y' * 70_000}}}}}]}}]\n"
        )


def test_a_billion_laughs_is_refused_before_it_expands() -> None:
    bomb = 'a: &a ["x","x","x","x","x","x","x","x","x"]\n' + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(8)
    )
    with pytest.raises(ScriptError, match="aliases"):
        StubScript.from_yaml(bomb)


def test_load_reads_a_file_and_reports_unreadable_ones(tmp_path: Path) -> None:
    good = tmp_path / "s.yaml"
    good.write_text("turns: [{text: hi}]\n", encoding="utf-8")
    assert StubScript.load(good).turns == (Turn("hi"),)
    with pytest.raises(ScriptError, match="cannot read"):
        StubScript.load(tmp_path / "missing.yaml")
    with pytest.raises(ScriptError, match="cannot read"):
        StubScript.load(tmp_path)
    binary = tmp_path / "b.yaml"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ScriptError, match="not UTF-8"):
        StubScript.load(binary)
    empty = tmp_path / "e.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ScriptError, match="expected a mapping"):
        StubScript.load(empty)


def test_turns_are_used_in_order_once_then_the_final_reply() -> None:
    player = TurnPlayer(StubScript.from_yaml("final: bye\nturns: [{text: a}, {text: b}]\n"))
    assert player.next_turn("/api/chat", "{}") == (0, Turn("a"))
    assert player.next_turn("/v1/messages", "{}") == (1, Turn("b"))
    assert player.next_turn("/api/chat", "{}") == (None, Turn("bye"))
    assert player.next_turn("/api/chat", "{}") == (None, Turn("bye"))
    assert player.remaining == []


def test_a_filtered_turn_waits_for_its_request() -> None:
    player = TurnPlayer(
        StubScript.from_yaml(
            "turns:\n"
            "  - {text: summary, when: {path: /v1/chat/completions, contains: summarise}}\n"
            "  - {text: plain}\n"
        )
    )
    # a request the filter does not match skips the filtered turn
    assert player.next_turn("/v1/chat/completions", "hello") == (1, Turn("plain"))
    assert player.remaining == [0]
    # the right path without the text, and the text on another path, still do not match
    assert player.next_turn("/v1/chat/completions", "hello")[0] is None
    assert player.next_turn("/api/chat", "please summarise")[0] is None
    index, turn = player.next_turn("/v1/chat/completions", "please summarise this")
    assert (index, turn.text) == (0, "summary")


def test_each_turn_goes_to_exactly_one_of_many_concurrent_requests() -> None:
    script = StubScript.from_yaml("turns:\n" + "".join(f"  - text: t{i}\n" for i in range(200)))
    player = TurnPlayer(script)
    seen: list[int | None] = []
    lock = threading.Lock()

    def take() -> None:
        for _ in range(25):
            index, _turn = player.next_turn("/api/chat", "")
            with lock:
                seen.append(index)

    threads = [threading.Thread(target=take) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    used = [i for i in seen if i is not None]
    assert sorted(used) == list(range(200))
    assert seen.count(None) == 50
