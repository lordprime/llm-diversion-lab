"""Reading back a smoke run's ``requests.jsonl`` and checking it.

An agent's ``ci/check.sh`` can run::

    uv run python -m agents.ci.stub_model.verify "$SMOKE_OUT/requests.jsonl" \\
        --expect /api/chat --expect /api/embeddings --expect-tool terminal_execute

It exits 0 when every record is well formed, every chat call reads back cleanly
through the lab's telemetry parsers (:func:`control.telemetry.wire.parse_call`, the same
code that reads a real run's tap evidence), every ``--expect`` path was called at least
once and every ``--expect-tool`` name was handed to the agent in a tool call. Otherwise
it prints one line per problem and exits 1 (2 for a file it cannot read).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from control.telemetry.model import CallTelemetry
from control.telemetry.wire import detect_format, parse_call

__all__ = ["RequestLog", "main"]

_FIELDS: Final = frozenset(
    {
        "seq",
        "ts",
        "method",
        "path",
        "api",
        "headers",
        "body_format",
        "body",
        "stream",
        "turn",
        "status",
        "response_content_type",
        "response",
    }
)


@dataclass(frozen=True, slots=True)
class RequestLog:
    """The records of one smoke run, in the order the stub saw them."""

    records: tuple[dict[str, Any], ...]
    problems: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> RequestLog:
        records: list[dict[str, Any]] = []
        problems: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    problems.append(f"line {number}: not JSON")
                    continue
                if not isinstance(record, dict) or set(record) != _FIELDS:
                    problems.append(f"line {number}: not a stub request record")
                    continue
                records.append(record)
        return cls(tuple(records), tuple(problems))

    def paths(self) -> Counter[str]:
        return Counter(str(r["path"]).split("?", 1)[0] for r in self.records)

    def chat_calls(self) -> Iterator[tuple[dict[str, Any], CallTelemetry]]:
        """Each chat record with the telemetry the lab's parsers read from it."""
        for record in self.records:
            path = str(record["path"])
            if detect_format(path) is None or record["status"] != 200:
                continue
            request = (
                json.dumps(record["body"]).encode() if record["body_format"] == "json" else b""
            )
            call = parse_call(
                path,
                request,
                str(record["response"]).encode("utf-8"),
                record["response_content_type"],
                seq=int(record["seq"]),
            )
            yield record, call

    def check(
        self, expect_paths: Sequence[str] = (), expect_tools: Sequence[str] = ()
    ) -> list[str]:
        """Every problem found; an empty list means the run passes."""
        problems = list(self.problems)
        if not self.records:
            problems.append("no request reached the stub model")
        tools: set[str] = set()
        for record, call in self.chat_calls():
            if call.parse_error:
                problems.append(f"seq {record['seq']} {record['path']}: {call.parse_error}")
            tools.update(t.name for t in call.tool_calls)
        seen = self.paths()
        problems += [f"never called: {p}" for p in expect_paths if not seen[p]]
        problems += [f"tool call never sent: {t}" for t in expect_tools if t not in tools]
        return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a smoke run's requests.jsonl.")
    parser.add_argument("requests", type=Path)
    parser.add_argument("--expect", action="append", default=[], metavar="PATH")
    parser.add_argument("--expect-tool", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)
    try:
        log = RequestLog.load(args.requests)
    except OSError as exc:
        print(f"verify: cannot read {args.requests}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    problems = log.check(args.expect, args.expect_tool)
    for problem in problems:
        print(f"verify: {problem}", file=sys.stderr)
    counts = ", ".join(f"{p} x{n}" for p, n in sorted(log.paths().items()))
    print(f"verify: {len(log.records)} requests ({counts or 'none'})")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
