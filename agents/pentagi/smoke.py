"""The PentAGI CI smoke run: its environment, and the check of what the stub recorded.

``agents/pentagi/ci/check.sh`` runs the agent image under ``agents/ci/smoke.sh`` with the
recording stub model as the tap. Two commands, both run by ``check.sh`` through ``uv``:

* ``python -m agents.pentagi.smoke env``: the ``--env-file`` for the smoke run, rendered by
  :class:`~agents.pentagi.adapter.PentagiAdapter` itself for :data:`SMOKE_RUN`, so the
  smoke exercises exactly the environment a real run gets (with the small Kali worker);
* ``python -m agents.pentagi.smoke verify <out>``: reads ``<out>/requests.jsonl`` and
  ``<out>/canary.jsonl`` and checks that every one of the sheet's ``model_call_paths``
  reached the stub, that every chat call carried the run's model and ``num_ctx``, that
  every embedding call named the embedding model, that no other endpoint was called,
  and that nothing tried to leave. It prints one line per problem and exits 1 if there
  is any.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from agents.base import AdapterLimits, AdapterRun, AgentLaunch, ModelConfig
from agents.pentagi.adapter import PentagiAdapter

__all__ = ["SMOKE_RUN", "SmokeCheck", "env_file", "main"]

#: The run the smoke renders: the stub model is the tap.
SMOKE_RUN: Final = AdapterRun(
    run_id="run_01KAAAAAAAAAAAAAAAAAAAAAAA",
    model=ModelConfig(name="stub-model", num_ctx=131072),
    target_url="http://target:8000",
    objective="Smoke test: run one harmless command in your sandbox and report.",
    llm_base_url="http://tap:8000",
    limits=AdapterLimits(max_turns=20, timeout_s=900),
)


def env_file(launch: AgentLaunch) -> str:
    """``launch.env`` as a ``docker run --env-file``: one ``KEY=VALUE`` a line, unquoted."""
    lines = []
    for key, value in sorted(launch.env.items()):
        if "\n" in value or "\r" in value:
            raise ValueError(f"{key}: an env-file value cannot span lines")
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


@dataclass
class SmokeCheck:
    """What one smoke run's outputs show (see the module docs)."""

    model: str
    num_ctx: int
    embedding_model: str
    paths: int
    seen: dict[int, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @classmethod
    def for_adapter(cls, adapter: PentagiAdapter, run: AdapterRun) -> SmokeCheck:
        launch = adapter.render(run)
        return cls(
            model=run.model.name,
            num_ctx=int(launch.env["OLLAMA_SERVER_NUM_CTX"]),
            embedding_model=launch.env["EMBEDDING_MODEL"],
            paths=len(adapter.describe().model_call_paths),
        )

    def read(self, out: Path) -> list[str]:
        """Check ``out``; return the problems (empty when the smoke run passes)."""
        self._read_requests(out / "requests.jsonl")
        self._read_canary(out / "canary.jsonl")
        for index in range(self.paths):
            if not self.seen.get(index):
                self.problems.append(f"model call path {index} never reached the stub")
        return self.problems

    def _read_requests(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.problems.append(f"{path}: cannot read: {exc}")
            return
        for number, line in enumerate(lines, 1):
            try:
                record = json.loads(line)
            except ValueError:
                self.problems.append(f"requests.jsonl:{number}: not JSON")
                continue
            if not isinstance(record, dict):
                self.problems.append(f"requests.jsonl:{number}: not an object")
                continue
            self._check_request(number, record)

    def _check_request(self, number: int, record: dict[str, Any]) -> None:
        path, body = record.get("path"), record.get("body")
        where = f"requests.jsonl:{number} ({path})"
        index = PentagiAdapter.call_path(path, body) if isinstance(path, str) else None
        if index is None:
            self.problems.append(f"{where}: not one of the sheet's model call paths")
            return
        self.seen[index] = self.seen.get(index, 0) + 1
        model = body.get("model") if isinstance(body, dict) else None
        if index == 3:
            if model != self.embedding_model:
                self.problems.append(f"{where}: embedding model {model!r}")
            return
        options = body.get("options") if isinstance(body, dict) else None
        num_ctx = options.get("num_ctx") if isinstance(options, dict) else None
        if model != self.model:
            self.problems.append(f"{where}: model {model!r}, not {self.model!r}")
        if num_ctx != self.num_ctx:
            self.problems.append(f"{where}: num_ctx {num_ctx!r}, not {self.num_ctx}")

    def _read_canary(self, path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            self.problems.append(f"{path}: cannot read: {exc}")
            return
        if text.strip():
            first = text.strip().splitlines()[0][:300]
            self.problems.append(f"canary.jsonl is not empty: {first}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agents.pentagi.smoke")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("env", help="print the smoke run's --env-file")
    verify = commands.add_parser("verify", help="check a smoke run's outputs")
    verify.add_argument("out", type=Path, help="the smoke run's output directory")
    args = parser.parse_args(argv)

    adapter = PentagiAdapter(smoke=True)
    if args.command == "env":
        sys.stdout.write(env_file(adapter.render(SMOKE_RUN)))
        return 0
    check = SmokeCheck.for_adapter(adapter, SMOKE_RUN)
    problems = check.read(args.out)
    for problem in problems:
        print(f"pentagi smoke: {problem}", file=sys.stderr)
    seen = ", ".join(f"path {i}: {n}" for i, n in sorted(check.seen.items()))
    print(f"pentagi smoke: calls seen ({seen}); {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
