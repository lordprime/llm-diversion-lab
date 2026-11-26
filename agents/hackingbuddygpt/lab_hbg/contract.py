"""What the plugin and the adapter must agree on, in plain Python.

The plugin (inside the image) and the adapter (in the runner) both import this module,
so the use case's name, the tools it offers, its exit codes, the objective file and the
tool-output cap are defined once. Nothing here imports hackingBuddyGPT.
"""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path
from typing import Final

__all__ = [
    "OFFERED_TOOLS",
    "USE_CASE_NAME",
    "ConfigRefused",
    "ObjectiveFile",
    "RunExit",
    "ToolOutputCap",
]

#: The name the use case is registered under (``python -m lab_hbg <name> ...``).
USE_CASE_NAME: Final = "LabWebTesting"

#: The tools the model is offered, by the names hackingBuddyGPT gives them (the
#: capability's class name, or the function's name for ``complete``). The plugin refuses
#: to start if what it registered differs.
OFFERED_TOOLS: Final = frozenset({"HTTPRequest", "PentestPlaybook", "complete", "EndRun"})


class ConfigRefused(ValueError):
    """The plugin's configuration is unusable; the run never starts (``BAD_CONFIG``)."""


class RunExit(IntEnum):
    """The plugin's exit code. Upstream's ``wintermute`` exits 0 whatever happened.

    Its limit reasons come from ``utils/limits.py`` at the pinned commit:
    ``"Reached maximum rounds (N)"``, ``"Reached maximum tokens (N)"`` and so on, and
    ``"Cancelled"`` when the model calls ``EndRun``.
    """

    #: The model ended the run itself: ``complete`` (task done) or ``EndRun`` (gave up).
    FINISHED = 0
    #: An exception escaped the run (upstream's own code for this case).
    CRASHED = 1
    #: The command line or the objective file was refused before the run started.
    BAD_CONFIG = 2
    #: ``limits.max_rounds`` ended the run: the turn cap.
    TURN_CAP = 3
    #: Another upstream limit (tokens, cost, duration) ended it. The adapter sets them
    #: all to 0 (no limit), so this means the configuration did not take.
    OTHER_LIMIT = 4

    @classmethod
    def for_reason(cls, reason: str | None) -> RunExit:
        """The exit code for the reason ``Limits`` gives at the end of a run.

        ``None`` means the run completed (``Limits.complete()`` leaves no reason). A
        reason this does not know is a crash: we cannot tell why the run stopped.
        """
        if reason is None or reason == "Cancelled":
            return cls.FINISHED
        if reason.startswith("Reached maximum rounds ("):
            return cls.TURN_CAP
        if reason.startswith("Reached maximum "):
            return cls.OTHER_LIMIT
        return cls.CRASHED


class ToolOutputCap:
    """How much of one tool result the model sees.

    hackingBuddyGPT has no summariser and appends every tool result to the history
    verbatim, so one large page could fill a local model's whole context. The cap keeps
    the first and the last ``limit // 2`` characters (an HTTP response's status line and
    headers, and the end of its body) and says how much was left out in between. The full
    result still goes to hackingBuddyGPT's own log. The limit is part of the agent's
    configuration and is recorded with every run; 0 keeps everything.
    """

    def __init__(self, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ConfigRefused(f"the tool-output cap is a character count >= 0, not {limit!r}")
        self.limit = limit

    def apply(self, text: str) -> str:
        if self.limit == 0 or len(text) <= self.limit:
            return text
        head = self.limit - self.limit // 2
        tail = self.limit // 2
        cut = len(text) - head - tail
        end = text[len(text) - tail :] if tail else ""
        return f"{text[:head]}\n[... {cut} characters left out ...]\n{end}"


class ObjectiveFile:
    """The run's objective, handed to the plugin as a file in the agent's config volume.

    It is a file because an objective may span lines and the container command cannot.
    The adapter writes it as UTF-8; the plugin reads it back and refuses anything that is
    not a usable objective, so a broken file stops the run before the first model call.
    """

    #: The file's name in the agent's config volume.
    NAME: Final = "objective.txt"
    #: An objective is at most 8192 characters (``AdapterRun.objective``), so 4 bytes each.
    MAX_BYTES: Final = 4 * 8192

    @classmethod
    def encode(cls, objective: str) -> bytes:
        return cls.check(objective).encode("utf-8")

    @classmethod
    def read(cls, path: Path) -> str:
        try:
            with path.open("rb") as fh:
                data = fh.read(cls.MAX_BYTES + 1)
        except OSError as exc:
            raise ConfigRefused(f"cannot read the objective file {path}: {exc}") from exc
        if len(data) > cls.MAX_BYTES:
            raise ConfigRefused(f"the objective file {path} is over {cls.MAX_BYTES} bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigRefused(f"the objective file {path} is not UTF-8: {exc}") from exc
        return cls.check(text)

    @staticmethod
    def check(objective: str) -> str:
        if "\x00" in objective:
            raise ConfigRefused("the objective contains a NUL character")
        if not objective.strip():
            raise ConfigRefused("the objective is empty")
        return objective
