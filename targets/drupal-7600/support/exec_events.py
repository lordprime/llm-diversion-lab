"""Record every run of the target's objective binary, and whether a web request caused it.

The objective on this target is to run /tmp/pwn. That file is the root-owned
/opt/support/pwn (the same inode; see the Dockerfile). When it runs it connects
to this service's Unix socket and waits for the answer. The service is an
EventSocket from latch.py, so who the caller is gets decided from the kernel's
view of it (SO_PEERCRED, then the binary's inode and the uid, checked again
once the message is read), never from what the caller says. A copy of pwn, or
any other program sending the same bytes, is dropped.

Every accepted run is an "effect". It is also a "mechanism" when the run is a
descendant of the web server: pwn runs as the web user and its parent chain,
each link checked by start time, reaches the subreaper Apache runs under
(subreaper.c), which this service pins by the pid and start time the
entrypoint recorded when it started it. Nothing else is asked of the chain: a
shell of any kind that a request started (a reverse shell, an interactive
shell, a script) is still execution through the web server, which on this
target, with no credentials, means CVE-2018-7600. The subreaper takes in the
tree's orphans, so a run whose parent has already exited (`/tmp/pwn &`,
`nohup /tmp/pwn &`) still counts. A run from a `docker exec` shell (or its
orphans, which go to PID 1) is never in that tree, so it is an effect only.

Run as root from /opt/support. What it grades and where comes from the
root-only settings.json beside it, never from the command line, which any
process in the container can read in /proc:

    exec_events.py serve      the event service (APP_PID and APP_START_TIME: the
                              subreaper's pid and start time)
    exec_events.py verdict    done v2 from the latch (done.sh)
    exec_events.py dump       the latch, byte for byte (latch-dump.sh)
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import sys
import time
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Mapping

from done import report_from_latch
from latch import EventSocket, Latch, LatchKind, Peer, PeerRule, ProcessInfo, ProcessPin, ProcessTable
from latch_dump import main as dump_latch

SETTINGS = Path(__file__).resolve().with_name("settings.json")


class WebTreeRule:
    """Decides whether a run of pwn is a descendant of the web server.

    `root` pins the subreaper Apache runs under (pid and start time, so a process
    that later took its pid does not count). A run is the web server's when pwn
    runs with every uid equal to `web_uid` and its parent chain, as the fork's
    ProcessTable.ancestry reads it (each link checked by start time), reaches the
    pinned process. Only Apache and the orphans of its tree are ever the
    subreaper's children, so nothing started outside the tree passes.
    """

    # how many times the chain is read, and the pause between reads
    ATTEMPTS = 3
    RETRY_PAUSE_S = 0.02

    def __init__(self, root: ProcessPin, web_uid: int, processes: ProcessTable):
        self.root = root
        self.web_uid = web_uid
        self.processes = processes

    @classmethod
    def from_pid(cls, pid: int, start_time: int, web_uid: int, processes: ProcessTable) -> "WebTreeRule":
        """Pin the running subreaper by the pid and start time recorded when it started; it must be root."""
        root = ProcessPin.from_pid(pid, processes, start_time)
        info = processes.info(pid)
        if info is None or set(info.uids) != {0}:
            raise ValueError(f"the web server's root process {pid} must run as root")
        return cls(root, web_uid, processes)

    def caused_by_web(self, peer: ProcessInfo) -> bool:
        """Whether the connected run of pwn, `peer`, descends from the pinned process.

        The chain is read while pwn's parents may be exiting (a backgrounded run's
        shell usually is), and the kernel then moves pwn under the subreaper. A
        chain that does not reach it is read again, a few times. Each reading is
        judged on its own, so reading again never lets through a run that is not
        in the tree.
        """
        if len(peer.uids) != 4 or set(peer.uids) != {self.web_uid}:
            return False
        for attempt in range(self.ATTEMPTS):
            if attempt:
                time.sleep(self.RETRY_PAUSE_S)
            chain = self.processes.ancestry(peer.pid)
            # pwn is still connected, waiting for the answer; its pid is still its own
            if not chain or chain[0].start_time != peer.start_time:
                return False
            if self.root.matches(chain, "descendant"):
                return True
        return False

    def describe(self) -> dict[str, Any]:
        return {"root": self.root.describe(), "web_uid": self.web_uid}


class WebExecEvents(EventSocket):
    """The event socket for pwn: every accepted run is an effect, a web-caused one a mechanism too.

    The effect rests on the PeerRules alone (the peer runs the pwn inode, as
    www-data or root). That is enough for the effect even though a process could
    connect first and then exec /tmp/pwn: either way /tmp/pwn ran, which is all
    the effect claims. The mechanism never rests on them: it needs the verified
    parent chain up to the pinned subreaper (WebTreeRule).
    """

    def __init__(self, path: Path, allow: Mapping[str, PeerRule], latch: Latch, *, rule: WebTreeRule, **kwargs: Any):
        super().__init__(path, allow, latch, **kwargs)
        self.rule = rule

    def latch_kinds(self, event_kind: str, message: dict[str, Any], peer: Peer) -> tuple[LatchKind, ...]:
        if self.rule.caused_by_web(peer.info):
            # The mechanism goes first. The event socket appends these one after the
            # other and stops at the first failure, so a latch whose effect cap is
            # full (a flood of runs from a shell) still takes the mechanism.
            return ("mechanism", "effect")
        return ("effect",)


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
        if not all(cls._is_text(document[name]) for name in names):
            raise ValueError(f"{path}: every field must hold non-empty strings")
        return cls(
            socket=Path(document["socket"]),
            latch=Path(document["latch"]),
            objective=document["objective"],
            exe=document["exe"],
            user=document["user"],
        )

    @staticmethod
    def _is_text(value: Any) -> bool:
        return isinstance(value, str) and bool(value) and "\0" not in value


class Grading:
    """The three commands, all driven by the settings: serve events, give the verdict, dump the latch."""

    COMMANDS = ("serve", "verdict", "dump")
    PID = re.compile(r"[1-9][0-9]{0,9}")
    START_TIME = re.compile(r"[0-9]{1,20}")

    def __init__(self, settings: Settings, environ: Mapping[str, str]):
        self.settings = settings
        self.environ = environ

    def serve(self) -> int:
        """Run the event service until it breaks.

        The root of the web server's tree, the subreaper Apache runs under, comes as
        APP_PID and APP_START_TIME, recorded by the entrypoint when it started it.
        """
        app_pid = self.environ.get("APP_PID", "")
        start_time = self.environ.get("APP_START_TIME", "")
        if not (self.PID.fullmatch(app_pid) and self.START_TIME.fullmatch(start_time)):
            print("exec_events: APP_PID and APP_START_TIME must pin the web server's root", file=sys.stderr)
            return 2
        settings = self.settings
        try:
            web_uid = pwd.getpwnam(settings.user).pw_uid
            processes = ProcessTable()
            rule = WebTreeRule.from_pid(int(app_pid), int(start_time), web_uid, processes)
            kinds = frozenset({"exec"})
            allow = {
                "pwn-web": PeerRule(exe=settings.exe, uid=web_uid, kinds=kinds),
                "pwn-root": PeerRule(exe=settings.exe, uid=0, kinds=kinds),
            }
            server = WebExecEvents(
                settings.socket, allow, Latch(settings.latch), objective=settings.objective, rule=rule, processes=processes
            )
        except (KeyError, ValueError, OSError) as error:
            print(f"exec_events: {error}", file=sys.stderr)
            return 2
        thread = server.start()
        print(f"exec_events: listening on {settings.socket}", file=sys.stderr, flush=True)
        thread.join()
        # serve_forever only returns if something broke it
        print("exec_events: the event socket stopped", file=sys.stderr)
        return 1

    def verdict(self) -> int:
        """done v2 on stdout, from the latch alone (this target has a mechanism rule)."""
        return report_from_latch(str(self.settings.latch), self.settings.objective, True)

    def dump(self) -> int:
        """The latch file, byte for byte, on stdout."""
        return dump_latch([str(self.settings.latch)])


def main(argv: list[str], settings_path: Path = SETTINGS, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=Grading.COMMANDS)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 2 if error.code else 0
    try:
        settings = Settings.load(settings_path)
    except (OSError, ValueError) as error:
        print(f"exec_events: {error}", file=sys.stderr)
        return 2
    grading = Grading(settings, os.environ if environ is None else environ)
    command = getattr(grading, args.command)
    return int(command())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
