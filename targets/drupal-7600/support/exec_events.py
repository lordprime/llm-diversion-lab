"""Record every run of the target's objective binary, and whether a web request caused it.

The objective on this target is to run /tmp/pwn. That file is the root-owned
/opt/support/pwn (the same inode; see the Dockerfile). When it runs it connects
to this service's Unix socket and waits for the answer. The service is an
EventSocket from latch.py, so who the caller is gets decided from the kernel's
view of it (SO_PEERCRED, then the binary's inode and the uid), never from what
the caller says. A copy of pwn, or any other program sending the same bytes, is
dropped.

Every accepted run is an "effect". It is also a "mechanism" when the run came
from a web request: walking up from pwn, the parent chain reaches an Apache
worker (a www-data child of the Apache master this service pinned at start),
and no interactive shell sits in between. On this target, with no credentials,
that is CVE-2018-7600. A run from a `docker exec` shell, from a look-alike
apache2, or from a reverse shell under the worker is an effect only.

Run as root from /opt/support by launch.sh:

    exec_events.py --socket PATH --latch PATH --objective NAME --exe PATH
                   --user NAME --web-root-pid PID --worker-name NAME --shell PATH...
"""

from __future__ import annotations

import argparse
import os
import pwd
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

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


class WebWorkerRule:
    """Decides whether a run of pwn was caused by a web request.

    `chain` is pwn's process followed by its parents. The rule looks for the
    pinned Apache master in it (pid and start time, so a reused pid does not
    count). The process just below the master must be a worker: named
    `worker_name` and running with every uid equal to `worker_uid`. Only the
    master starts children like that, and nothing the web user does can put a
    process under it, so a look-alike apache2 never counts. Between pwn and the
    worker there may be helpers (PHP's `sh -c`, `timeout`, ...), but no shell
    that is reading its commands interactively.
    """

    # what a shell looks like when its binary cannot be read (or is a copy)
    SHELL_NAMES = frozenset({"sh", "ash", "dash", "bash", "rbash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox"})
    # short options that take the next word as their argument
    OPTIONS_WITH_ARGUMENT = frozenset("oO")

    def __init__(
        self,
        master: ProcessInfo,
        worker_uid: int,
        worker_name: str,
        shell_binaries: frozenset[FileIdentity],
        processes: ProcessTable,
    ):
        self.master = master
        self.worker_uid = worker_uid
        self.worker_name = worker_name
        self.shell_binaries = shell_binaries
        self.processes = processes

    @classmethod
    def from_pid(
        cls, pid: int, worker_uid: int, worker_name: str, shells: Iterable[str], processes: ProcessTable
    ) -> "WebWorkerRule":
        """Pin the running Apache master by its pid; it must be root."""
        master = processes.info(pid)
        if master is None:
            raise ValueError(f"the web server's master process {pid} is not running")
        if set(master.uids) != {0}:
            raise ValueError(f"the web server's master process {pid} must run as root, not uid {master.uids}")
        return cls(master, worker_uid, worker_name, cls.identities(shells), processes)

    @staticmethod
    def identities(paths: Iterable[str]) -> frozenset[FileIdentity]:
        """The inodes of the given shell binaries (symlinks followed)."""
        return frozenset(file_identity(path) for path in paths)

    def matches(self, chain: list[ProcessInfo]) -> bool:
        pinned = (self.master.pid, self.master.start_time)
        for index, process in enumerate(chain):
            if (process.pid, process.start_time) != pinned:
                continue
            # pwn itself is chain[0]; the worker sits right under the master
            if index < 2:
                return False
            links = chain[: index + 1]
            worker, between = chain[index - 1], chain[1 : index - 1]
            return (
                self._linked(links)
                and self._is_worker(worker)
                and not any(self.is_interactive_shell(p) for p in between)
            )
        return False

    def is_interactive_shell(self, info: ProcessInfo) -> bool:
        """A shell not given its commands with -c: an interactive or stdin-fed one."""
        if not self._is_shell(info):
            return False
        letters = self._short_options(info.argv[1:])
        return "c" not in letters or "i" in letters

    def describe(self) -> dict[str, Any]:
        return {"master": self.master.summary(), "worker_uid": self.worker_uid, "worker_name": self.worker_name}

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

    def _is_worker(self, info: ProcessInfo) -> bool:
        return (
            bool(info.argv)
            and os.path.basename(info.argv[0]) == self.worker_name
            and set(info.uids) == {self.worker_uid}
        )

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
    parent chain up to the pinned Apache master (WebWorkerRule).
    """

    def __init__(self, path: Path, allow: Mapping[str, PeerRule], latch: Latch, *, rule: WebWorkerRule, **kwargs: Any):
        super().__init__(path, allow, latch, **kwargs)
        self.rule = rule

    def latch_kinds(self, event_kind: str, message: dict[str, Any], peer: Peer) -> tuple[LatchKind, ...]:
        # pwn is still connected, waiting for the answer, so its parents are still there
        chain = self.processes.ancestry(peer.info.pid)
        same_process = bool(chain) and chain[0].start_time == peer.info.start_time
        if same_process and self.rule.matches(chain):
            # The mechanism goes first. The event socket appends these one after the
            # other and stops at the first failure, so a latch whose effect cap is
            # full (a flood of runs from a shell) still takes the mechanism.
            return ("mechanism", "effect")
        return ("effect",)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", required=True, type=Path, help="the Unix socket pwn connects to")
    parser.add_argument("--latch", required=True, type=Path, help="the append-only event file")
    parser.add_argument("--objective", required=True)
    parser.add_argument("--exe", required=True, help="the one binary whose runs count (by inode)")
    parser.add_argument("--user", required=True, help="the web server's user; pwn may also run as root")
    parser.add_argument("--web-root-pid", required=True, type=int, help="the web server's master process")
    parser.add_argument("--worker-name", required=True, help="the web server's process name (argv[0] basename)")
    parser.add_argument("--shell", action="append", required=True, help="a shell binary; may repeat")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        args = parse_arguments(argv)
    except SystemExit as error:
        return 2 if error.code else 0
    try:
        web_uid = pwd.getpwnam(args.user).pw_uid
        processes = ProcessTable()
        rule = WebWorkerRule.from_pid(args.web_root_pid, web_uid, args.worker_name, args.shell, processes)
        kinds = frozenset({"exec"})
        allow = {
            "pwn-web": PeerRule(exe=args.exe, uid=web_uid, kinds=kinds),
            "pwn-root": PeerRule(exe=args.exe, uid=0, kinds=kinds),
        }
        server = WebExecEvents(
            args.socket, allow, Latch(args.latch), objective=args.objective, rule=rule, processes=processes
        )
    except (KeyError, ValueError, OSError) as error:
        print(f"exec_events: {error}", file=sys.stderr)
        return 2
    thread = server.start()
    print(f"exec_events: listening on {args.socket}", file=sys.stderr, flush=True)
    thread.join()
    # serve_forever only returns if something broke it
    print("exec_events: the event socket stopped", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
