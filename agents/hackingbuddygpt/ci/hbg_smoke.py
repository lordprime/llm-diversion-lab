"""The hackingBuddyGPT image's smoke runs: what to launch, and what the stub must have seen.

``check.sh`` calls it twice per scenario, around ``agents/ci/smoke.sh``:

* ``render <scenario> <dir>`` writes the container command (``command``, NUL-separated)
  and environment (``env``, ``KEY=value`` lines) the adapter renders for the scenario;
* ``verify <scenario> <smoke out dir> <exit code>`` checks what the recording stub saw.

The command is the adapter's own rendering. The only change is a ``sh -c`` wrapper that
first writes the objective file, because a smoke container has no config volume.

A scenario passes when every model call path the sheet lists shows up (each one an
Ollama ``/api/chat`` request with the run's model, ``num_ctx`` and tools), nothing else
reached the stub but the requests the scenario explains, the canary saw nothing, and the
plugin exited with the scenario's code.
"""

from __future__ import annotations

import contextlib
import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from agents.base import AdapterLimits, AdapterRun, AgentLaunch, ModelConfig
from agents.hackingbuddygpt.adapter import HackingBuddyGPTAdapter
from agents.hackingbuddygpt.lab_hbg.contract import OFFERED_TOOLS, ObjectiveFile, RunExit

#: the recording stub, the only host a smoke container can reach
STUB: str = "http://tap:8000"
MODEL: str = "stub-model"
NUM_CTX: int = 8192
OBJECTIVE: str = "Smoke test: list the models the server knows.\nThen call complete."


class SmokeFailure(AssertionError):
    """What the stub saw does not match the scenario."""


@dataclass(frozen=True)
class Scenario:
    """One smoke run: its stub script, turn cap, expected exit and extra requests."""

    SCENARIOS: ClassVar[dict[str, Scenario]]

    name: str
    max_turns: int
    exit_code: RunExit
    chat_calls: int
    #: non-chat paths the run may send to the stub (the HTTPRequest tool's target is
    #: the stub too, and LiteLLM may ask Ollama's /api/show for model metadata)
    extra_paths: frozenset[str]

    @property
    def script(self) -> Path:
        return Path(__file__).with_name(f"stub-{self.name}.yaml")

    def run(self) -> AdapterRun:
        return AdapterRun(
            run_id=f"run_smoke_{self.name}",
            model=ModelConfig(name=MODEL, num_ctx=NUM_CTX),
            target_url=STUB,
            objective=OBJECTIVE,
            llm_base_url=STUB,
            limits=AdapterLimits(max_turns=self.max_turns, timeout_s=600),
        )

    def launch(self) -> AgentLaunch:
        launch = HackingBuddyGPTAdapter().prepare(self.run())
        if not isinstance(launch, AgentLaunch):
            raise SmokeFailure(f"the adapter refused the smoke run: {launch.reason}")
        return launch

    def command(self) -> list[str]:
        launch = self.launch()
        objective_file = "/tmp/" + ObjectiveFile.NAME  # noqa: S108 - inside the container
        args = [
            f"--objective_file={objective_file}" if a.startswith("--objective_file=") else a
            for a in launch.command
        ]
        objective = launch.files[ObjectiveFile.NAME].decode("utf-8")
        script = f"printf '%s' {shlex.quote(objective)} > {objective_file} && exec " + " ".join(
            shlex.quote(a) for a in args
        )
        return ["sh", "-c", script]

    def render(self, out: Path) -> None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "command").write_bytes(b"\0".join(a.encode() for a in self.command()))
        env = self.launch().env
        (out / "env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))

    # verification

    def verify(self, smoke_out: Path, exit_code: int) -> list[str]:
        """Every way the run differs from the scenario (empty when it passed)."""
        problems: list[str] = []
        canary = smoke_out / "canary.jsonl"
        if not canary.is_file():
            problems.append("no canary.jsonl")
        elif canary.read_text().strip():
            problems.append(f"the egress canary saw traffic:\n{canary.read_text()[:2000]}")
        requests = [self._request(line) for line in self._lines(smoke_out / "requests.jsonl")]
        chats = [r for r in requests if r["path"] == "/api/chat"]
        others = sorted({r["path"] for r in requests} - {"/api/chat"} - self.extra_paths)
        if others:
            problems.append(f"requests the scenario does not explain: {others}")
        if len(chats) != self.chat_calls:
            problems.append(f"{len(chats)} /api/chat requests, expected {self.chat_calls}")
        for i, chat in enumerate(chats):
            problems += [f"/api/chat #{i}: {p}" for p in self._chat_problems(chat["body"])]
        # Each call path the sheet lists must be one this check knows how to see: a path
        # that is not an /api/chat call fails until this check learns it.
        sheet = HackingBuddyGPTAdapter().describe()
        unseen = [p for p in sheet.model_call_paths if "/api/chat" not in p or not chats]
        if unseen:
            problems.append(f"model call paths with no request: {unseen}")
        if exit_code != self.exit_code:
            problems.append(
                f"exit {exit_code}, expected {self.exit_code.value} ({self.exit_code.name})"
            )
        return problems

    def _chat_problems(self, body: Any) -> list[str]:
        if not isinstance(body, dict):
            return ["the body is not a JSON object"]
        problems: list[str] = []
        if body.get("model") != MODEL:
            problems.append(f"model {body.get('model')!r}")
        options = body.get("options")
        if not isinstance(options, dict) or options.get("num_ctx") != NUM_CTX:
            problems.append(f"options {options!r}, expected num_ctx {NUM_CTX}")
        if body.get("stream") is not False:
            problems.append(f"stream {body.get('stream')!r}")
        tools = body.get("tools")
        names = (
            {t.get("function", {}).get("name") for t in tools if isinstance(t, dict)}
            if isinstance(tools, list)
            else set()
        )
        if names != OFFERED_TOOLS:
            problems.append(f"tools {sorted(map(str, names))}, expected {sorted(OFFERED_TOOLS)}")
        messages = body.get("messages")
        first = messages[0] if isinstance(messages, list) and messages else {}
        if not isinstance(first, dict) or first.get("role") != "system":
            problems.append("the first message is not the system prompt")
        elif OBJECTIVE not in str(first.get("content")):
            problems.append("the system prompt does not carry the objective")
        return problems

    @staticmethod
    def _lines(path: Path) -> list[str]:
        if not path.is_file():
            raise SmokeFailure(f"{path} is missing")
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    @staticmethod
    def _request(line: str) -> dict[str, Any]:
        record = json.loads(line)
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise SmokeFailure(f"not a recorded request: {line[:200]}")
        body = record.get("body")
        if isinstance(body, str):
            with contextlib.suppress(ValueError):  # a body that is no JSON stays text
                body = json.loads(body)
        return {"path": record["path"].split("?", 1)[0], "body": body}


Scenario.SCENARIOS = {
    s.name: s
    for s in (
        # parallel tool calls (the playbook and a request to the stub), then complete
        Scenario("tools", 5, RunExit.FINISHED, 2, frozenset({"/api/show", "/v1/models"})),
        # text only, until the turn cap ends the run
        Scenario("turn-cap", 2, RunExit.TURN_CAP, 2, frozenset({"/api/show"})),
    )
}


def main(argv: list[str]) -> int:
    usage = "usage: hbg_smoke.py render <scenario> <dir> | verify <scenario> <out> <exit code>"
    if len(argv) < 3 or argv[1] not in Scenario.SCENARIOS:
        print(usage, file=sys.stderr)
        return 2
    scenario = Scenario.SCENARIOS[argv[1]]
    if argv[0] == "render" and len(argv) == 3:
        scenario.render(Path(argv[2]))
        return 0
    if argv[0] == "verify" and len(argv) == 4:
        problems = scenario.verify(Path(argv[2]), int(argv[3]))
        for problem in problems:
            print(f"{scenario.name}: {problem}", file=sys.stderr)
        print(f"{scenario.name}: {'FAILED' if problems else 'ok'}", file=sys.stderr)
        return 1 if problems else 0
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
