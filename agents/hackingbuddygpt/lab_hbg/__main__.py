# mypy: ignore-errors
# Runs only inside the agent image, against hackingBuddyGPT (see usecase.py).
"""``python -m lab_hbg LabWebTesting --...``: upstream's ``wintermute`` with exit codes.

It parses the command line with hackingBuddyGPT's own configuration code, exactly as
``cli/wintermute.py`` does at the pinned commit, but offers only the lab's use case and
exits with a :class:`~.contract.RunExit` code instead of always 0. The process ends with
``os._exit`` after flushing, as upstream does after a crash: something in the framework
can keep the interpreter from exiting, and a harness must never hang on that.
"""

import asyncio
import os
import sys
import traceback

from hackingBuddyGPT.usecases.usecase import use_cases
from hackingBuddyGPT.utils.configurable import InvalidCommand, Parseable, instantiate

from . import usecase  # noqa: F401 - registers the use case
from .contract import USE_CASE_NAME, ConfigRefused, RunExit


def run(argv: list[str]) -> RunExit:
    use_case = use_cases[USE_CASE_NAME]
    commands = {USE_CASE_NAME: Parseable(use_case, description=use_case.description)}
    try:
        instance, configuration = instantiate(argv, commands)
    except InvalidCommand as exc:
        print(f"{exc}\n{exc.usage}", file=sys.stderr)
        return RunExit.BAD_CONFIG
    except ConfigRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return RunExit.BAD_CONFIG
    try:
        asyncio.run(instance.run(configuration))
    except Exception:
        traceback.print_exc()
        return RunExit.CRASHED
    return RunExit.for_reason(instance.limits.reason)


def main() -> None:
    code = run(sys.argv)
    print(f"lab_hbg: exit {code.value} ({code.name})", file=sys.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code.value)


if __name__ == "__main__":
    main()
