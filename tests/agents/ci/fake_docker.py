"""A stand-in ``docker`` CLI for testing agents/ci/smoke.sh without a daemon.

Every call is appended to ``$FAKE_DOCKER_LOG`` as a JSON list (its argv). What it answers
is set by environment variables:

* ``FAKE_IMAGES``: space-separated images ``image inspect`` finds (others: exit 1);
* ``FAKE_SCRIPT_VALID``: ``0`` makes the stub script check fail;
* ``FAKE_AGENT_EXIT``: the agent's exit status for ``wait``, or ``hang``;
* ``FAKE_CANARY`` / ``FAKE_REQUESTS``: what ``docker cp`` copies out of the helpers;
* ``FAKE_FAIL``: a command prefix (e.g. ``network create``) that fails;
* ``FAKE_DEAD``: a container name suffix reported as not running;
* ``FAKE_EXTRA_MOUNT``: a ``type source destination`` line added to the agent's mounts;
* ``FAKE_WORKERS``: container ids ``ps`` lists (the guard-started workers).

Containers' create/run arguments are kept in ``$FAKE_DOCKER_STATE/<name>.json``, and a
file mounted into a container is copied there as ``<name>.<basename>`` (so a test can
read cell-guard's images.lock after smoke.sh has deleted it).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path


def _state() -> Path:
    return Path(os.environ["FAKE_DOCKER_STATE"])


def _value(args: list[str], flag: str) -> str | None:
    return args[args.index(flag) + 1] if flag in args else None


def _volumes(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "-v"]


def _remember(name: str, args: list[str]) -> None:
    (_state() / f"{name}.json").write_text(json.dumps(args), encoding="utf-8")
    for spec in _volumes(args):
        source = spec.split(":", 1)[0]
        if source.startswith("/") and Path(source).is_file():
            shutil.copy(source, _state() / f"{name}.{Path(source).name}")


def _ip(name: str) -> str:
    for index, suffix in enumerate(("-stub", "-canary", "-holder"), start=2):
        if name.endswith(suffix):
            return f"172.30.0.{index}"
    return "172.30.0.99"


def _inspect(fmt: str, name: str) -> int:
    if "IPAddress" in fmt:
        print(_ip(name))
    elif ".State.Running" in fmt:
        dead = os.environ.get("FAKE_DEAD")
        print("false" if dead and name.endswith(dead) else "true")
    elif ".Mounts" in fmt:
        args = json.loads((_state() / f"{name}.json").read_text(encoding="utf-8"))
        for spec in _volumes(args):
            source, destination = spec.split(":")[:2]
            print(f"{'bind' if source.startswith('/') else 'volume'} {source} {destination}")
        if os.environ.get("FAKE_EXTRA_MOUNT"):
            print(os.environ["FAKE_EXTRA_MOUNT"])
    elif ".Name" in fmt:
        print(f"/{name}")
    return 0


def main(argv: list[str]) -> int:
    with Path(os.environ["FAKE_DOCKER_LOG"]).open("a", encoding="utf-8") as log:
        log.write(json.dumps(argv) + "\n")
    joined = " ".join(argv)
    fail = os.environ.get("FAKE_FAIL")
    if fail and joined.startswith(fail):
        print(f"fake docker: {fail} failed", file=sys.stderr)
        return 1
    command, args = (argv[0], argv[1:]) if argv else ("", [])
    if command == "image" and args[:1] == ["inspect"]:
        ref = args[-1]
        if ref not in os.environ.get("FAKE_IMAGES", "").split():
            return 1
        if "-f" in args and ".Id" in args[args.index("-f") + 1]:
            print("sha256:" + "1" * 64)
        return 0
    if command == "run" and "--check" in args:
        sys.stdin.read()
        return 0 if os.environ.get("FAKE_SCRIPT_VALID", "1") == "1" else 1
    if command in ("run", "create"):
        _remember(_value(args, "--name") or "unnamed", args)
        print("0123456789ab")
        return 0
    if command == "cp" and ":" in args[0]:
        source, destination = args
        kind = "FAKE_CANARY" if source.endswith("canary.jsonl") else "FAKE_REQUESTS"
        Path(destination).write_text(os.environ.get(kind, ""), encoding="utf-8")
        return 0
    if command == "inspect":
        return _inspect(_value(args, "-f") or "", args[-1])
    if command == "wait":
        code = os.environ.get("FAKE_AGENT_EXIT", "0")
        if code == "hang":
            time.sleep(30)
        print(code)
        return 0
    if command == "ps":
        print("\n".join(os.environ.get("FAKE_WORKERS", "").split()))
        return 0
    if command == "exec" and "cat" in args:
        print('{"allowed":false}')
        return 0
    if command == "logs":
        print("fake log line")
        return 0
    return 0  # start, exec, kill, rm, pull, network, volume


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
