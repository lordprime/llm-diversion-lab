"""Run the HTTP and DNS catchers together, as one cell service.

The DNS catcher answers every name with the cell's catcher address, where the HTTP
catcher listens, so both belong in one container with one address. Each stays its own
process with its own stream (one writer per events file). If either exits, the other
is stopped and this process exits non-zero, so the container stops visibly instead of
half-recording::

    python -m cell.catcher.serve
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from types import FrameType
from typing import Final

__all__ = ["COMMANDS", "supervise"]

COMMANDS: Final[tuple[tuple[str, ...], ...]] = (
    (sys.executable, "-m", "cell.catcher.dns_server"),
    (sys.executable, "-m", "cell.catcher.http_app"),
)
_POLL_S: Final = 0.2
_STOP_TIMEOUT_S: Final = 10.0


def _stop(procs: Sequence[subprocess.Popen[bytes]]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + _STOP_TIMEOUT_S
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def supervise(commands: Sequence[Sequence[str]] = COMMANDS) -> int:
    """Start every command; when the first exits (or on SIGTERM), stop the rest.

    Returns the first exited process's code, or 1 if it exited ``0`` (a catcher never
    finishes on its own), or 0 after a requested stop.
    """
    stopping = False

    def _on_signal(_signum: int, _frame: FrameType | None) -> None:
        nonlocal stopping
        stopping = True

    previous = {s: signal.signal(s, _on_signal) for s in (signal.SIGTERM, signal.SIGINT)}
    procs = [subprocess.Popen(list(cmd)) for cmd in commands]  # noqa: S603 - fixed argv
    try:
        while not stopping:
            for proc in procs:
                code = proc.poll()
                if code is not None:
                    print(f"catcher: {proc.args!r} exited with {code}", file=sys.stderr)
                    return code or 1
            time.sleep(_POLL_S)
        return 0
    finally:
        _stop(procs)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(supervise())
