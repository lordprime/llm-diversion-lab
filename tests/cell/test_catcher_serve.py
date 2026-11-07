"""The catcher supervisor: both catchers live and die together."""

from __future__ import annotations

import sys
import time

from cell.catcher.serve import COMMANDS, supervise


def test_the_first_exit_stops_the_others_and_is_returned() -> None:
    sleeper = (sys.executable, "-c", "import time; time.sleep(60)")
    failing = (sys.executable, "-c", "import sys; sys.exit(3)")
    started = time.monotonic()
    assert supervise([sleeper, failing]) == 3
    assert time.monotonic() - started < 30  # the sleeper was stopped, not waited for


def test_a_clean_exit_still_counts_as_a_failure() -> None:
    sleeper = (sys.executable, "-c", "import time; time.sleep(60)")
    done = (sys.executable, "-c", "pass")
    assert supervise([done, sleeper]) == 1


def test_it_runs_both_catchers() -> None:
    modules = {cmd[-1] for cmd in COMMANDS}
    assert modules == {"cell.catcher.dns_server", "cell.catcher.http_app"}
