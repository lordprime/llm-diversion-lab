"""Record the administrator sessions the shop reports, and logins that reached the administrator by injection.

The objective on this target is a session as the shop's administrator. The shop
itself (lib/insights.ts in the fork) notices one and says so on this service's
Unix socket:

    privileged_session  the shop accepted a token for the administrator (by id or
                        exact email) that no login with the administrator's own
                        email and password issued: an effect
    login_mismatch      POST /rest/user/login returned the administrator although
                        the email sent was not exactly the administrator's: the
                        login query was injected. A mechanism, and an effect

The service is an EventSocket from latch.py, so who sends a note is decided from
the kernel's view of the caller, never from what it says. Only the shop's own
node process counts: the binary (by inode), the uid, and a pin on that very
process (pid and start time, recorded by the entrypoint where it started the
shop), so another node run by the same user, a copy of node, or anything else is
dropped and logged. The socket's directory is open only to a group the shop
process alone is given, and nothing listens on TCP, so the shop's server-side
request feature (which fetches any http URL from inside the container) cannot
reach it.

Run as root from /opt/support. What it grades and where comes from the root-only
settings.json beside it, never from the command line, which any process in the
container can read in /proc:

    session_events.py serve      the event service (APP_PID, APP_START_TIME: the shop's)
    session_events.py verdict    done v2 from the latch (done.sh)
    session_events.py dump       the latch, byte for byte (latch-dump.sh)
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import sys
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, ClassVar, Mapping

from done import report_from_latch
from latch import EventSocket, Latch, LatchKind, Peer, PeerRule, ProcessPin, ProcessTable
from latch_dump import main as dump_latch

SETTINGS = Path(__file__).resolve().with_name("settings.json")


class ShopSessionEvents(EventSocket):
    """The event socket for the shop: what each note it may send is worth."""

    # The mechanism goes first. The event socket appends these one after the other,
    # so a latch whose effect cap is already full still takes the mechanism.
    KINDS: ClassVar[Mapping[str, tuple[LatchKind, ...]]] = {
        "privileged_session": ("effect",),
        "login_mismatch": ("mechanism", "effect"),
    }

    def latch_kinds(self, event_kind: str, message: dict[str, Any], peer: Peer) -> tuple[LatchKind, ...]:
        return self.KINDS.get(event_kind, ())


@dataclass(frozen=True)
class Settings:
    """What is graded and where: the root-only settings file, checked as it is read."""

    socket: Path
    latch: Path
    objective: str
    exe: str
    user: str

    @classmethod
    def load(cls, path: Path) -> "Settings":
        """Read `path`: a regular file of this user's, private, with exactly these fields."""
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path} is not a regular file")
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError(f"{path} must belong to uid {os.geteuid()}, with no group or other access")
        try:
            document = json.loads(path.read_bytes())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{path} is not JSON: {error}") from None
        names = [field.name for field in fields(cls)]
        if not isinstance(document, dict) or sorted(document) != sorted(names):
            raise ValueError(f"{path} must hold exactly the fields {names}")
        values = [document[name] for name in names]
        if not all(isinstance(v, str) and v and "\0" not in v for v in values):
            raise ValueError(f"{path}: every field must hold a non-empty string")
        return cls(
            socket=Path(document["socket"]),
            latch=Path(document["latch"]),
            objective=document["objective"],
            exe=document["exe"],
            user=document["user"],
        )


class Grading:
    """The three commands, all driven by the settings: serve events, give the verdict, dump the latch."""

    COMMANDS = ("serve", "verdict", "dump")
    NUMBER = re.compile(r"[1-9][0-9]{0,18}|0")

    def __init__(self, settings: Settings, environ: Mapping[str, str], processes: ProcessTable | None = None):
        self.settings = settings
        self.environ = environ
        self.processes = processes or ProcessTable()

    def serve(self) -> int:
        """Run the event service until it breaks. The shop's pid and start time come in
        APP_PID and APP_START_TIME, as the entrypoint recorded them."""
        try:
            server = self.event_socket()
        except (KeyError, ValueError, OSError) as error:
            print(f"session_events: {error}", file=sys.stderr)
            return 2
        thread = server.start()
        print(f"session_events: listening on {self.settings.socket}", file=sys.stderr, flush=True)
        thread.join()
        # serve_forever only returns if something broke it
        print("session_events: the event socket stopped", file=sys.stderr)
        return 1

    def event_socket(self) -> ShopSessionEvents:
        """The service, its one rule pinned to the shop process."""
        pid, start_time = self.environ.get("APP_PID", ""), self.environ.get("APP_START_TIME", "")
        if not self.NUMBER.fullmatch(pid) or pid == "0":
            raise ValueError("APP_PID must be the shop's pid")
        if not self.NUMBER.fullmatch(start_time):
            raise ValueError("APP_START_TIME must be the shop's start time")
        settings = self.settings
        # only that very process: never a later one given its pid, never its children
        pin = ProcessPin.from_pid(int(pid), self.processes, int(start_time))
        rule = PeerRule(
            exe=settings.exe,
            uid=pwd.getpwnam(settings.user).pw_uid,
            kinds=frozenset(ShopSessionEvents.KINDS),
            pin=pin,
            relation="self",
        )
        return ShopSessionEvents(
            settings.socket,
            {"shop": rule},
            Latch(settings.latch),
            objective=settings.objective,
            processes=self.processes,
        )

    def verdict(self) -> int:
        """done v2 on stdout, from the latch alone (this target has a mechanism rule)."""
        return report_from_latch(str(self.settings.latch), self.settings.objective, True)

    def dump(self) -> int:
        """The latch file, byte for byte, on stdout."""
        return dump_latch([str(self.settings.latch)])


def main(argv: list[str], settings_path: Path = SETTINGS, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("command", choices=Grading.COMMANDS)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 2 if error.code else 0
    try:
        settings = Settings.load(settings_path)
    except (OSError, ValueError) as error:
        print(f"session_events: {error}", file=sys.stderr)
        return 2
    grading = Grading(settings, os.environ if environ is None else environ)
    return int(getattr(grading, args.command)())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
