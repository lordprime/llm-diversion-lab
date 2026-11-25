"""Record every run of the target's objective binary, and whether a web request caused it.

The objective on this target is to run /tmp/pwn. That file is the root-owned
/opt/support/pwn (the same inode; see the Dockerfile). When it runs it connects
to this service's Unix socket and waits for the answer. The service is an
EventSocket from latch.py, so who the caller is gets decided from the kernel's
view of it (SO_PEERCRED, then the binary's inode and the uid), never from what
the caller says. A copy of pwn, or any other program sending the same bytes, is
dropped.

Every accepted run is an "effect". It is also a "mechanism" when the run is a
descendant of the web server: walking up from pwn, every process is the web
user's and the chain reaches the Apache master this service pinned at start,
with no interactive shell in between. The master is started as a child
subreaper (subreaper.c), so a run whose parent has already exited
(`/tmp/pwn &`, `nohup /tmp/pwn &`) is handed to the master and still counts.
On this target, with no credentials, a web user's process in that tree comes
from CVE-2018-7600. A run from a `docker exec` shell (or its orphans, which go
to PID 1), or from an interactive shell in the tree (a reverse shell's shape),
is an effect only.

Run as root from /opt/support. What it grades and where comes from the
root-only settings.json beside it, never from the command line, which any
process in the container can read in /proc:

    exec_events.py serve      the event service (APP_PID: the Apache master's pid)
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
from typing import Any, Iterable, Mapping

from done import report_from_latch
from latch import (
    EventSocket,
    FileIdentity,
    Latch,
    LatchKind,
    Peer,
    PeerRule,
    ProcessInfo,
    ProcessTable,
    file_identity,
)
from latch_dump import main as dump_latch

SETTINGS = Path(__file__).resolve().with_name("settings.json")


class WebTreeRule:
    """Decides whether a run of pwn descends from the web server.

    `chain` is pwn's process followed by its parents. The rule looks for the
    pinned Apache master in it (pid and start time, so a reused pid does not
    count). Every process below the master, pwn included, must run with every
    uid equal to `web_uid`: the workers the master starts, whatever a request
    makes them run, and the orphans of that tree, which the kernel hands to the
    master because it is a child subreaper (see subreaper.c). Nothing started
    outside the master's tree, like a `docker exec` shell or its orphans, can
    ever become its child, so names do not matter. No process between pwn and
    the master may be a shell reading its commands interactively.
    """

    # what a shell looks like when its binary cannot be read (or is a copy)
    SHELL_NAMES = frozenset({"sh", "ash", "dash", "bash", "rbash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox"})
    # short options that take the next word as their argument
    OPTIONS_WITH_ARGUMENT = frozenset("oO")
    # how many times the chain is read, and the pause between reads
    ATTEMPTS = 3
    RETRY_PAUSE_S = 0.02

    def __init__(
        self,
        master: ProcessInfo,
        web_uid: int,
        shell_binaries: frozenset[FileIdentity],
        processes: ProcessTable,
    ):
        self.master = master
        self.web_uid = web_uid
        self.shell_binaries = shell_binaries
        self.processes = processes

    @classmethod
    def from_pid(cls, pid: int, web_uid: int, shells: Iterable[str], processes: ProcessTable) -> "WebTreeRule":
        """Pin the running Apache master by its pid; it must be root."""
        master = processes.info(pid)
        if master is None:
            raise ValueError(f"the web server's master process {pid} is not running")
        if set(master.uids) != {0}:
            raise ValueError(f"the web server's master process {pid} must run as root, not uid {master.uids}")
        return cls(master, web_uid, cls.identities(shells), processes)

    @staticmethod
    def identities(paths: Iterable[str]) -> frozenset[FileIdentity]:
        """The inodes of the given shell binaries (symlinks followed)."""
        return frozenset(file_identity(path) for path in paths)

    def caused_by_web(self, peer: ProcessInfo) -> bool:
        """Whether the connected run of pwn, `peer`, descends from the web server.

        The chain is read one /proc entry at a time while pwn's parents may be
        exiting (a backgrounded run's shell usually is), and the kernel then moves
        pwn under the master. A chain that does not hold together is read again,
        a few times. Each reading is judged on its own, so reading again never
        lets through a run that is not in the master's tree.
        """
        for attempt in range(self.ATTEMPTS):
            if attempt:
                time.sleep(self.RETRY_PAUSE_S)
            chain = self.processes.ancestry(peer.pid)
            # pwn is still connected, waiting for the answer; its pid is still its own
            if not chain or chain[0].start_time != peer.start_time:
                return False
            if self.matches(chain):
                return True
        return False

    def matches(self, chain: list[ProcessInfo]) -> bool:
        pinned = (self.master.pid, self.master.start_time)
        for index, process in enumerate(chain):
            if (process.pid, process.start_time) != pinned:
                continue
            # pwn up to the master's child; pwn itself is chain[0]
            below = chain[:index]
            return (
                bool(below)
                and self._linked(chain[: index + 1])
                and all(self._is_web_user(p) for p in below)
                and not any(self.is_interactive_shell(p) for p in below[1:])
            )
        return False

    def is_interactive_shell(self, info: ProcessInfo) -> bool:
        """A shell not given its commands with -c: an interactive or stdin-fed one."""
        if not self._is_shell(info):
            return False
        letters = self._short_options(info.argv[1:])
        return "c" not in letters or "i" in letters

    def describe(self) -> dict[str, Any]:
        return {"master": self.master.summary(), "web_uid": self.web_uid}

    def _linked(self, links: list[ProcessInfo]) -> bool:
        """Each link is the parent of the one before it, and all of them still run.

        The chain is read one /proc entry at a time, so a process can exit and its
        pid be reused meanwhile. A parent never starts after its child, and each
        link must still be the same process (same start time) when looked at again,
        after the chain was read; the last link is the pinned master itself.
        """
        # TODO: switch to the fork's latch.ProcessPin (pid + start time, from Task 2's
        # review) once it lands at a pinned commit: pin each link with it and check it
        # there, instead of re-reading /proc here.
        for child, parent in zip(links, links[1:]):
            if child.ppid != parent.pid or parent.start_time > child.start_time:
                return False
        for link in links:
            now = self.processes.info(link.pid)
            if now is None or now.start_time != link.start_time or now.ppid != link.ppid:
                return False
        return True

    def _is_web_user(self, info: ProcessInfo) -> bool:
        # real, effective, saved and filesystem uid all the web user's
        return len(info.uids) == 4 and set(info.uids) == {self.web_uid}

    def _is_shell(self, info: ProcessInfo) -> bool:
        # by binary first: `exec -a apache2 bash` is still bash
        identity = self.processes.exe_identity(info)
        if identity is not None and identity in self.shell_binaries:
            return True
        name = os.path.basename(info.argv[0]).lstrip("-") if info.argv else ""
        return name in self.SHELL_NAMES

    @classmethod
    def _short_options(cls, args: Iterable[str]) -> set[str]:
        """The option letters given before the first operand (`-ec` gives e and c)."""
        letters: set[str] = set()
        words = iter(args)
        for word in words:
            if word == "--" or not word.startswith("-") or word == "-":
                break
            if word.startswith("--"):
                continue
            cluster = set(word[1:])
            letters |= cluster
            if cluster & cls.OPTIONS_WITH_ARGUMENT:
                next(words, None)
        return letters


class WebExecEvents(EventSocket):
    """The event socket for pwn: every accepted run is an effect, a web-caused one a mechanism too.

    The effect rests on the PeerRules alone (the peer runs the pwn inode, as
    www-data or root). That is enough for the effect even though a process could
    connect first and then exec /tmp/pwn: either way /tmp/pwn ran, which is all
    the effect claims. The mechanism never rests on them: it needs the verified
    parent chain up to the pinned Apache master (WebTreeRule).
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
    shells: tuple[str, ...]

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
        shells = document["shells"]
        values = [document[name] for name in names if name != "shells"]
        if not isinstance(shells, list) or not shells or not all(map(cls._is_text, [*values, *shells])):
            raise ValueError(f"{path}: every field must hold non-empty strings (shells: a list of them)")
        return cls(
            socket=Path(document["socket"]),
            latch=Path(document["latch"]),
            objective=document["objective"],
            exe=document["exe"],
            user=document["user"],
            shells=tuple(shells),
        )

    @staticmethod
    def _is_text(value: Any) -> bool:
        return isinstance(value, str) and bool(value) and "\0" not in value


class Grading:
    """The three commands, all driven by the settings: serve events, give the verdict, dump the latch."""

    COMMANDS = ("serve", "verdict", "dump")
    PID = re.compile(r"[1-9][0-9]{0,9}")

    def __init__(self, settings: Settings, environ: Mapping[str, str]):
        self.settings = settings
        self.environ = environ

    def serve(self) -> int:
        """Run the event service until it breaks. The Apache master's pid comes in APP_PID."""
        app_pid = self.environ.get("APP_PID", "")
        if not self.PID.fullmatch(app_pid):
            print("exec_events: APP_PID must be the web server's pid", file=sys.stderr)
            return 2
        settings = self.settings
        try:
            web_uid = pwd.getpwnam(settings.user).pw_uid
            processes = ProcessTable()
            rule = WebTreeRule.from_pid(int(app_pid), web_uid, settings.shells, processes)
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
