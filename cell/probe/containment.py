"""Containment probe: from inside a run cell, try destinations that must be unreachable.

Run as a sibling container on the agent's network (the self-test does this)::

    python -m cell.probe.containment \\
        --dest internet:tcp:1.1.1.1:443 --dest internet:dns:example.com \\
        --dest host:tcp:172.30.0.1:22 --dest lan:tcp:192.168.1.1:80 \\
        [--sinkhole <catcher-ip>] [--timeout 2]

or with ``--defaults`` (plus ``--host-gateway`` / ``--lan``) for the standard set from
:func:`default_destinations`. It prints one JSON :class:`ContainmentReport` on stdout and
exits ``0`` if the cell is contained, ``1`` if not, ``2`` on a usage error.

Destinations are ``<category>:<kind>:<target>[:<port>]``:

* category ``internet``, ``host`` (the LXC/host bridge gateway) or ``lan`` (home LAN);
* kind ``tcp`` (a TCP connect to ``target:port``; IPv6 literals in brackets) or ``dns``
  (resolve ``target`` through the cell's resolver; no port).

Every destination is *must-fail*. Outcomes, per destination:

* ``reachable``: the TCP handshake completed, or the name resolved to an address that
  is not one of the ``--sinkhole`` addresses (the cell's resolver is the callback
  catcher, which answers every name with its own IP; that answer is not a leak).
* ``refused``: the connection was actively refused (``ECONNREFUSED``). The lab's
  firewalls **drop** cell egress and never reject it, so a refusal means something on
  the path answered: it counts as a breach.
* ``unreachable``: no route / host or network unreachable / not permitted, or the name
  did not resolve.
* ``timeout``: nothing answered within the timeout (the expected result under DROP).
* ``error``: the probe could not test the destination (an unexpected exception). This
  is reported, never raised, and fails closed: an untested destination proves nothing.

:func:`is_contained` is true only if at least one destination was probed and every
outcome is ``unreachable`` or ``timeout``. The probe itself never raises on a
destination, whatever the connector does.

Stdlib only: the probe image needs nothing but Python.
"""

from __future__ import annotations

import argparse
import errno as errno_mod
import ipaddress
import json
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "DEFAULT_INTERNET",
    "DEFAULT_LAN",
    "DEFAULT_TIMEOUT_S",
    "HOST_PORTS",
    "Category",
    "Connector",
    "ContainmentReport",
    "Destination",
    "Kind",
    "Outcome",
    "ProbeResult",
    "Resolver",
    "default_destinations",
    "dns_resolve",
    "is_contained",
    "main",
    "parse_destination",
    "probe",
    "tcp_connect",
]

#: Per-destination timeout in seconds.
DEFAULT_TIMEOUT_S = 2.0
#: Well-known public anycast resolvers on 443 and a name to resolve.
DEFAULT_INTERNET: tuple[tuple[str, int], ...] = (("1.1.1.1", 443), ("9.9.9.9", 443))
DEFAULT_DNS_NAME = "example.com"
#: The usual home-router address; override with ``--lan``.
DEFAULT_LAN: tuple[str, ...] = ("192.168.1.1",)
#: Ports tried on the host gateway: SSH, HTTP(S), the Docker API, Postgres, the APIs.
HOST_PORTS: tuple[int, ...] = (22, 80, 443, 2375, 5432, 8000)
LAN_PORTS: tuple[int, ...] = (80, 443)


class Category(StrEnum):
    """What a must-fail destination stands for."""

    INTERNET = "internet"
    HOST = "host"
    LAN = "lan"


class Kind(StrEnum):
    TCP = "tcp"
    DNS = "dns"


class Outcome(StrEnum):
    REACHABLE = "reachable"
    REFUSED = "refused"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"


#: Outcomes that show the destination was *not* reached.
_CONTAINED_OUTCOMES = frozenset({Outcome.UNREACHABLE, Outcome.TIMEOUT})

#: errnos meaning "no path": routing failure or a local firewall verdict.
_UNREACHABLE_ERRNOS = frozenset(
    {
        errno_mod.ENETUNREACH,
        errno_mod.EHOSTUNREACH,
        errno_mod.EHOSTDOWN,
        errno_mod.ENETDOWN,
        errno_mod.EPERM,
        errno_mod.EACCES,
        errno_mod.EADDRNOTAVAIL,
    }
)

#: ``connect(host, port, timeout)`` returns on a completed handshake, raises otherwise.
Connector = Callable[[str, int, float], None]
#: ``resolve(name, timeout)`` returns the resolved addresses, raises otherwise.
Resolver = Callable[[str, float], list[str]]


@dataclass(frozen=True)
class Destination:
    category: Category
    kind: Kind
    target: str
    port: int | None = None
    #: DNS only: answers that are the cell's own sinkhole (the catcher), not a leak.
    sinkhole: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        target = f"[{self.target}]" if ":" in self.target else self.target
        where = target if self.port is None else f"{target}:{self.port}"
        return f"{self.category}:{self.kind}:{where}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "category": str(self.category),
            "kind": str(self.kind),
            "target": self.target,
            "port": self.port,
        }


@dataclass(frozen=True)
class ProbeResult:
    destination: Destination
    outcome: Outcome
    detail: str
    elapsed_ms: float
    errno_name: str | None = None
    answers: tuple[str, ...] = ()

    @property
    def reached(self) -> bool:
        """True if the destination answered (``reachable`` or ``refused``)."""
        return self.outcome in (Outcome.REACHABLE, Outcome.REFUSED)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.destination.to_dict(),
            "outcome": str(self.outcome),
            "detail": self.detail,
            "errno": self.errno_name,
            "answers": list(self.answers),
            "elapsed_ms": round(self.elapsed_ms, 1),
        }


@dataclass(frozen=True)
class ContainmentReport:
    results: tuple[ProbeResult, ...]
    timeout_s: float = DEFAULT_TIMEOUT_S
    started_at: float = field(default_factory=time.time)

    @property
    def contained(self) -> bool:
        return is_contained(self)

    @property
    def breaches(self) -> tuple[ProbeResult, ...]:
        """Results that break containment (reached, refused, or untestable)."""
        return tuple(r for r in self.results if r.outcome not in _CONTAINED_OUTCOMES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contained": self.contained,
            "timeout_s": self.timeout_s,
            "started_at": self.started_at,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def is_contained(report: ContainmentReport) -> bool:
    """True only if something was probed and no must-fail destination was reached.

    Any ``reachable`` or ``refused`` destination (internet, host or LAN) is a critical
    failure; an ``error`` also fails closed, since an untested destination proves
    nothing, and so does an empty report.
    """
    return bool(report.results) and all(r.outcome in _CONTAINED_OUTCOMES for r in report.results)


# --------------------------------------------------------------------- real I/O


def tcp_connect(host: str, port: int, timeout: float) -> None:
    """Complete a TCP handshake with ``host:port`` and close it; raise if that fails."""
    with socket.create_connection((host, port), timeout=timeout):
        pass


def dns_resolve(name: str, timeout: float) -> list[str]:
    """Resolve ``name`` through the system resolver, giving up after ``timeout``.

    ``getaddrinfo`` has no timeout of its own, so it runs in a daemon thread that is
    abandoned (not joined) if it overruns.
    """
    box: list[list[str] | BaseException] = []

    def work() -> None:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
            box.append(sorted({str(info[4][0]) for info in infos}))
        except BaseException as exc:
            box.append(exc)

    thread = threading.Thread(target=work, name=f"dns-probe-{name}", daemon=True)
    thread.start()
    thread.join(timeout)
    if not box:
        raise TimeoutError(f"no DNS answer for {name!r} within {timeout}s")
    result = box[0]
    if isinstance(result, BaseException):
        raise result
    return result


# --------------------------------------------------------------------- probing


def _errno_name(exc: BaseException) -> str | None:
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        return errno_mod.errorcode.get(code, str(code))
    return None


def _gai_name(exc: socket.gaierror) -> str | None:
    code = exc.errno
    for name in dir(socket):
        if name.startswith("EAI_") and getattr(socket, name) == code:
            return name
    return None


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _classify(exc: BaseException) -> tuple[Outcome, str | None]:
    """Map an exception from the connector or resolver to an outcome and errno name."""
    if isinstance(exc, socket.gaierror):
        # Resolution failed (no such name, resolver unreachable, ...): nothing reached.
        return Outcome.UNREACHABLE, _gai_name(exc)
    if isinstance(exc, TimeoutError):  # socket.timeout is TimeoutError
        return Outcome.TIMEOUT, _errno_name(exc)
    if isinstance(exc, ConnectionRefusedError):
        return Outcome.REFUSED, _errno_name(exc)
    if isinstance(exc, OSError) and exc.errno is not None:
        if exc.errno == errno_mod.ETIMEDOUT:
            return Outcome.TIMEOUT, _errno_name(exc)
        if exc.errno == errno_mod.ECONNREFUSED:
            return Outcome.REFUSED, _errno_name(exc)
        if exc.errno in _UNREACHABLE_ERRNOS:
            return Outcome.UNREACHABLE, _errno_name(exc)
    return Outcome.ERROR, _errno_name(exc)


def _probe_one(
    dest: Destination, connect: Connector, resolve: Resolver, timeout: float
) -> ProbeResult:
    start = time.monotonic()

    def elapsed() -> float:
        return (time.monotonic() - start) * 1000.0

    try:
        if dest.kind is Kind.TCP:
            if dest.port is None:
                raise ValueError(f"tcp destination {dest.label} has no port")
            connect(dest.target, dest.port, timeout)
            return ProbeResult(dest, Outcome.REACHABLE, "tcp handshake completed", elapsed())
        answers = tuple(resolve(dest.target, timeout))
    except Exception as exc:  # reported, never raised: that is the probe's contract
        outcome, code = _classify(exc)
        gai = code if isinstance(exc, socket.gaierror) else None
        detail = _describe(exc) if gai is None else f"{gai}: {exc}"
        return ProbeResult(dest, outcome, detail, elapsed(), errno_name=code)

    sinkhole = set(dest.sinkhole)
    leaked = [a for a in answers if a not in sinkhole]
    if not answers:
        return ProbeResult(dest, Outcome.UNREACHABLE, "resolved to no address", elapsed())
    if leaked:
        detail = f"resolved to {', '.join(leaked)}"
        return ProbeResult(dest, Outcome.REACHABLE, detail, elapsed(), answers=answers)
    return ProbeResult(
        dest, Outcome.UNREACHABLE, "resolved only to the sinkhole", elapsed(), answers=answers
    )


def probe(
    destinations: Iterable[Destination],
    connect: Connector = tcp_connect,
    resolve: Resolver = dns_resolve,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> ContainmentReport:
    """Probe every destination in order; never raises because of a destination."""
    results = tuple(_probe_one(d, connect, resolve, timeout) for d in destinations)
    return ContainmentReport(results=results, timeout_s=timeout)


# --------------------------------------------------------------------- destinations


def default_destinations(
    *,
    host_gateway: str | None = None,
    lan: Sequence[str] = DEFAULT_LAN,
    sinkhole: Sequence[str] = (),
) -> list[Destination]:
    """The standard must-fail set: public IPs on 443, a public name, the LAN, the host.

    The host gateway is only probed if given (it differs per cell network).
    """
    dests = [Destination(Category.INTERNET, Kind.TCP, ip, port) for ip, port in DEFAULT_INTERNET]
    dests.append(
        Destination(Category.INTERNET, Kind.DNS, DEFAULT_DNS_NAME, sinkhole=tuple(sinkhole))
    )
    if host_gateway:
        dests += [Destination(Category.HOST, Kind.TCP, host_gateway, p) for p in HOST_PORTS]
    for addr in lan:
        dests += [Destination(Category.LAN, Kind.TCP, addr, p) for p in LAN_PORTS]
    return dests


def _bad(spec: str, why: str) -> ValueError:
    return ValueError(f"bad destination {spec!r}: {why}")


def parse_destination(spec: str, *, sinkhole: Sequence[str] = ()) -> Destination:
    """Parse ``<category>:<kind>:<target>[:<port>]`` (see the module docstring)."""
    parts = spec.split(":", 2)
    if len(parts) != 3:
        raise _bad(spec, "expected <category>:<kind>:<target>[:<port>]")
    raw_category, raw_kind, rest = parts
    try:
        category = Category(raw_category)
    except ValueError:
        raise _bad(spec, f"category must be one of {[c.value for c in Category]}") from None
    try:
        kind = Kind(raw_kind)
    except ValueError:
        raise _bad(spec, f"kind must be one of {[k.value for k in Kind]}") from None

    if kind is Kind.DNS:
        if not rest or ":" in rest:
            raise _bad(spec, "dns takes a name and no port")
        return Destination(category, kind, rest, sinkhole=tuple(sinkhole))

    if rest.startswith("["):
        host, sep, port_s = rest[1:].partition("]:")
        if not sep:
            raise _bad(spec, "expected [ipv6]:port")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise _bad(spec, f"{host!r} is not an IPv6 address") from None
    else:
        host, sep, port_s = rest.rpartition(":")
        if not sep or not host:
            raise _bad(spec, "tcp needs <target>:<port>")
        if ":" in host:
            raise _bad(spec, "put an IPv6 address in brackets: [addr]:port")
    if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
        raise _bad(spec, "port must be 1-65535")
    return Destination(category, kind, host, int(port_s))


# --------------------------------------------------------------------- CLI


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m cell.probe.containment",
        description=(
            "Try destinations that must be unreachable from a run cell; print a JSON "
            "report; exit 0 if contained, 1 if not."
        ),
    )
    p.add_argument(
        "--dest",
        action="append",
        default=[],
        metavar="CATEGORY:KIND:TARGET[:PORT]",
        help="a must-fail destination, e.g. internet:tcp:1.1.1.1:443, "
        "internet:dns:example.com, host:tcp:172.30.0.1:22, lan:tcp:192.168.1.1:80 "
        "(repeatable)",
    )
    p.add_argument(
        "--defaults",
        action="store_true",
        help="also probe the default set (public IPs, a public name, --lan, --host-gateway)",
    )
    p.add_argument("--host-gateway", help="the cell network's bridge gateway address")
    p.add_argument(
        "--lan",
        action="append",
        default=None,
        help=f"home-LAN address for --defaults (repeatable; default {list(DEFAULT_LAN)})",
    )
    p.add_argument(
        "--sinkhole",
        action="append",
        default=[],
        help="an address the cell's resolver answers every name with (the catcher)",
    )
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="seconds per probe")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        dests = [parse_destination(s, sinkhole=args.sinkhole) for s in args.dest]
    except ValueError as exc:
        parser.error(str(exc))
    if args.defaults or not dests:
        dests += default_destinations(
            host_gateway=args.host_gateway,
            lan=args.lan if args.lan is not None else DEFAULT_LAN,
            sinkhole=args.sinkhole,
        )
    report = probe(dests, timeout=args.timeout)
    sys.stdout.write(report.to_json() + "\n")
    sys.stdout.flush()
    return 0 if report.contained else 1


if __name__ == "__main__":
    sys.exit(main())
