"""Containment probe: from inside a run cell, try destinations that must be unreachable.

Run as a sibling container on the agent's network (the self-test does this)::

    python -m cell.probe.containment --defaults \\
        --reach tap:8080 --sinkhole <catcher-ip> --lan 192.168.1.1 \\
        [--host-gateway 172.30.0.1] [--dest lan:tcp:10.0.0.1:22 ...] [--timeout 2]

It prints one JSON :class:`ContainmentReport` on stdout and exits ``0`` if the cell is
contained, ``1`` if not, ``2`` on a usage error.

Destinations are ``<category>:<kind>:<target>[:<port>]``:

* category ``internet``, ``host`` (the LXC/host bridge gateway) or ``lan`` (home LAN):
  **must-fail**; or ``reach``: **must-reach**, a positive control (the tap, the target)
  proving that the probe has a working network at all;
* kind ``tcp`` (a TCP connect to ``target:port``; IPv6 literals in brackets) or ``dns``
  (resolve ``target`` through the cell's resolver; no port).

Rules that keep a broken or mis-specified probe from reading as "contained":

* A must-fail ``tcp`` target **must be an IP literal** that stands for a network path:
  not a hostname (a resolution failure would look like containment although no
  address was tried), and not loopback, unspecified, multicast, broadcast or reserved
  (``255.255.255.255``, ``224.0.0.0/4``, ``240.0.0.0/4``, ``ff00::/8``, IPv4-mapped and
  IPv4-compatible forms included), which fail instantly without testing any path; nor
  IPv6 link-local (``fe80::/10``) or scoped (``fe80::1%lo``), nor a documentation, test
  or discard range that no real path leads to (``0.0.0.0/8``, ``192.0.2.0/24``,
  ``198.51.100.0/24``, ``203.0.113.0/24``, ``2001:db8::/32``, ``100::/64``). The
  metadata address ``169.254.169.254`` stays allowed: it is a real path.
  Rejected at parse time (``--host-gateway`` and ``--lan`` too); a directly
  constructed one, or a bad gateway read from the route table, is ``error``.
* Each must-fail category counts as probed only with at least one **tcp** result. DNS
  results are extra evidence (a leak is still a breach), never coverage: a failed
  lookup says nothing about IP reachability.
* ``reach`` must be **tcp** and must not be anything a probe with no network can still
  reach: loopback, unspecified, multicast, broadcast, reserved, link-local
  (``169.254.0.0/16``, ``fe80::/10``), ``localhost``, a non-standard numeric form
  (``127.1``, ``0x7f.1``, ``2130706433``) or one of the probe's **own** addresses
  (detected by binding to it). A ``reach`` hostname (a cell service name) is resolved
  first; if it does not resolve, or any answer fails these checks, the result is
  ``error``. Otherwise the probe connects to the first resolved address.
* The timeout is within [:data:`MIN_TIMEOUT_S`, :data:`MAX_TIMEOUT_S`] (1-60 s): a tiny
  timeout would turn every reachable destination into ``timeout``, which counts as
  contained; a huge one would stall the self-test.

Outcomes, per destination:

* ``reachable``: the TCP handshake completed, or the name resolved to an address that
  is not one of the ``--sinkhole`` addresses (the cell's resolver is the callback
  catcher, which answers every name with its own IP; that answer is not a leak).
* ``refused``: the connection was actively refused (``ECONNREFUSED``). The lab's
  firewalls **drop** cell egress and never reject it, so a refusal means something on
  the path answered: for a must-fail destination it is a breach.
* ``unreachable``: no route / host or network unreachable / not permitted by the
  firewall (``ENETUNREACH``, ``EHOSTUNREACH``, ``EHOSTDOWN``, ``ENETDOWN``, ``EPERM``),
  or (DNS only) the name did not resolve.
* ``timeout``: nothing answered within the timeout (the expected result under DROP).
* ``error``: the probe could not test the destination: an unexpected exception, a
  local condition (``EACCES``, ``EADDRNOTAVAIL``), a tcp hostname that did not resolve,
  or a destination that could not be determined (no host gateway, no LAN address).
  Reported, never raised; it fails closed.

:func:`is_contained` is true only if **all four categories** are covered (as above),
every must-fail outcome is ``unreachable`` or ``timeout``, and every must-reach outcome
is ``reachable``.

With ``--defaults`` (or no ``--dest`` at all) the probe adds: public IPv4 and IPv6
addresses on 443 and a public name; the host gateway from ``--host-gateway``, else
every distinct IPv4 default-route gateway in ``/proc/net/route`` (lowest metric
first), else an ``error`` result; the home LAN from ``--lan`` (required, or
``--allow-default-lan`` for 192.168.1.1). ``--reach HOST:PORT`` adds must-reach
destinations; without one the ``reach`` category is missing and the cell is reported
as not contained. (IPv6 default gateways are not read: cells are IPv4-only, and the
IPv6 internet is probed directly.)

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
    "ALL_CATEGORIES",
    "DEFAULT_INTERNET",
    "DEFAULT_LAN",
    "DEFAULT_TIMEOUT_S",
    "HOST_PORTS",
    "MAX_TIMEOUT_S",
    "MIN_TIMEOUT_S",
    "Category",
    "Connector",
    "ContainmentReport",
    "Destination",
    "Kind",
    "Outcome",
    "ProbeResult",
    "Resolver",
    "default_destinations",
    "default_gateway",
    "default_gateways",
    "dns_resolve",
    "is_contained",
    "main",
    "parse_destination",
    "probe",
    "tcp_connect",
]

#: Per-destination timeout in seconds, and the floor below which probing is refused.
DEFAULT_TIMEOUT_S = 2.0
MIN_TIMEOUT_S = 1.0
MAX_TIMEOUT_S = 60.0
#: Well-known public anycast resolvers (IPv4 and IPv6) on 443, and a name to resolve.
DEFAULT_INTERNET: tuple[tuple[str, int], ...] = (
    ("1.1.1.1", 443),
    ("9.9.9.9", 443),
    ("2606:4700:4700::1111", 443),
    ("2620:fe::fe", 443),
)
DEFAULT_DNS_NAME = "example.com"
#: The usual home-router address, used only with ``--allow-default-lan``.
DEFAULT_LAN: tuple[str, ...] = ("192.168.1.1",)
#: Ports tried on the host gateway: SSH, HTTP(S), the Docker API, Postgres, the APIs.
HOST_PORTS: tuple[int, ...] = (22, 80, 443, 2375, 5432, 8000)
LAN_PORTS: tuple[int, ...] = (80, 443)
DEFAULT_ROUTE_FILE = "/proc/net/route"


class Category(StrEnum):
    """What a destination stands for; all are must-fail except ``reach``."""

    INTERNET = "internet"
    HOST = "host"
    LAN = "lan"
    REACH = "reach"

    @property
    def must_reach(self) -> bool:
        return self is Category.REACH


#: Every category must be covered for a report to count as contained.
ALL_CATEGORIES: frozenset[Category] = frozenset(Category)


class Kind(StrEnum):
    TCP = "tcp"
    DNS = "dns"


class Outcome(StrEnum):
    REACHABLE = "reachable"
    REFUSED = "refused"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"


#: Outcomes that show a must-fail destination was *not* reached.
_CONTAINED_OUTCOMES = frozenset({Outcome.UNREACHABLE, Outcome.TIMEOUT})

#: errnos meaning "no path": routing failure or a firewall verdict on the way out.
#: (``EACCES`` and ``EADDRNOTAVAIL`` are local conditions and fall through to ERROR.)
_UNREACHABLE_ERRNOS = frozenset(
    {
        errno_mod.ENETUNREACH,
        errno_mod.EHOSTUNREACH,
        errno_mod.EHOSTDOWN,
        errno_mod.ENETDOWN,
        errno_mod.EPERM,
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
    #: Set when the destination could not be determined (e.g. no host gateway):
    #: probing it yields ``error`` with this text, so the category fails closed.
    unavailable: str | None = None

    @property
    def label(self) -> str:
        target = self.target or "?"
        target = f"[{target}]" if ":" in target else target
        where = target if self.port is None else f"{target}:{self.port}"
        return f"{self.category}:{self.kind}:{where}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "category": str(self.category),
            "kind": str(self.kind),
            "target": self.target,
            "port": self.port,
            "must_reach": self.category.must_reach,
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

    @property
    def ok(self) -> bool:
        """Must-reach: ``reachable``. Must-fail: ``unreachable`` or ``timeout``."""
        if self.destination.category.must_reach:
            return self.outcome is Outcome.REACHABLE
        return self.outcome in _CONTAINED_OUTCOMES

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.destination.to_dict(),
            "ok": self.ok,
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
    def missing_categories(self) -> frozenset[Category]:
        """Categories without a covering result: a **tcp** result, for every category."""
        covered = {r.destination.category for r in self.results if r.destination.kind is Kind.TCP}
        return ALL_CATEGORIES - covered

    @property
    def breaches(self) -> tuple[ProbeResult, ...]:
        """Must-fail results that break containment (reached, refused or untestable)."""
        return tuple(r for r in self.results if not r.destination.category.must_reach and not r.ok)

    @property
    def reach_failures(self) -> tuple[ProbeResult, ...]:
        """Must-reach results that did not reach: the probe's network is not proven."""
        return tuple(r for r in self.results if r.destination.category.must_reach and not r.ok)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contained": self.contained,
            "required_categories": sorted(str(c) for c in ALL_CATEGORIES),
            "missing_categories": sorted(str(c) for c in self.missing_categories),
            "timeout_s": self.timeout_s,
            "started_at": self.started_at,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def is_contained(report: ContainmentReport) -> bool:
    """True only if all four categories are covered and every result is ``ok``.

    A ``reachable`` or ``refused`` must-fail destination (internet, host or LAN) is a
    critical failure; an ``error`` fails closed (an untested destination proves
    nothing); a must-reach destination that was not reached means the probe's network
    is unproven; a category with no covering tcp result fails too.
    """
    return (
        bool(report.results) and not report.missing_categories and all(r.ok for r in report.results)
    )


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


_RTF_UP, _RTF_GATEWAY = 0x1, 0x2


def default_gateways(route_file: str = DEFAULT_ROUTE_FILE) -> list[str]:
    """Every distinct IPv4 default-route gateway in ``/proc/net/route``, lowest metric first.

    A Docker ``internal`` network has no default route, so inside a cell this is
    usually empty: pass ``--host-gateway`` (the cell network's bridge address).
    """
    try:
        with open(route_file, encoding="ascii") as fh:
            lines = fh.read().splitlines()[1:]
    except (OSError, UnicodeDecodeError):
        return []
    found: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            dest, gateway, flags, metric, mask = (int(fields[i], 16) for i in (1, 2, 3, 6, 7))
        except ValueError:
            continue
        if dest == 0 and mask == 0 and flags & _RTF_UP and flags & _RTF_GATEWAY and gateway:
            # The kernel prints the network-order address as a host-order integer.
            addr = str(ipaddress.IPv4Address(gateway.to_bytes(4, sys.byteorder)))
            found.append((metric, index, addr))
    ordered: list[str] = []
    for _metric, _index, addr in sorted(found):
        if addr not in ordered:
            ordered.append(addr)
    return ordered


def default_gateway(route_file: str = DEFAULT_ROUTE_FILE) -> str | None:
    """The lowest-metric IPv4 default-route gateway, or ``None``."""
    gateways = default_gateways(route_file)
    return gateways[0] if gateways else None


# --------------------------------------------------------------------- probing


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


_Address = ipaddress.IPv4Address | ipaddress.IPv6Address
_LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def _legacy_v4(text: str) -> ipaddress.IPv4Address | None:
    """A non-standard IPv4 form ``inet_aton`` accepts (``127.1``, ``0x7f.1``, ``2130706433``)."""
    if _ip(text) is not None:
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(text))
    except (OSError, ValueError):
        return None


def _forms(addr: _Address) -> list[_Address]:
    """``addr`` plus the IPv4 address an IPv4-mapped or IPv4-compatible IPv6 one carries."""
    forms: list[_Address] = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            forms.append(addr.ipv4_mapped)
        elif int(addr) < 2**32:
            forms.append(ipaddress.IPv4Address(int(addr)))
    return forms


def _never_a_path(addr: _Address) -> str | None:
    """Why ``addr`` can never stand for a network path (it fails or succeeds locally)."""
    for form in _forms(addr):
        if form.is_loopback:
            return "loopback"
        if form.is_unspecified:
            return "unspecified"
        if form.is_multicast:
            return "multicast"
        if isinstance(form, ipaddress.IPv4Address) and (
            form == _LIMITED_BROADCAST or form.is_reserved
        ):
            return "broadcast or reserved"
    return None


#: Ranges no real path leads to (documentation, test, discard-only): a must-fail target
#: there proves nothing whatever it reads.
_NO_PATH_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
        "100::/64",
    )
)


def _must_fail_problem(target: str) -> str | None:
    """Why ``target`` cannot be a must-fail tcp target, or ``None`` if it can.

    It must be an IP literal that is not loopback, unspecified, multicast, broadcast or
    reserved: those fail (or succeed) instantly without testing any path, so they
    would "cover" a category with a meaningless ``unreachable``. Nor may it be scoped
    or IPv6 link-local (``fe80::1%lo`` fails instantly with ``ENETUNREACH``), or in a
    documentation/test/discard range (:data:`_NO_PATH_NETWORKS`). IPv4 link-local stays
    allowed: ``169.254.169.254`` is the metadata service, a real breakout path.
    """
    addr = _ip(target)
    if addr is None:
        return "is not an IP literal"
    reason = _never_a_path(addr)
    if reason:
        return f"is {reason}"
    if isinstance(addr, ipaddress.IPv6Address) and (addr.scope_id or addr.is_link_local):
        return "is IPv6 link-local or scoped"
    for form in _forms(addr):
        if any(form in net for net in _NO_PATH_NETWORKS):
            return "is in a documentation, test or discard range"
    return None


def _reach_problem(target: str) -> str | None:
    """Why ``target`` (an IP or a name) can never prove the probe's network, if it can't.

    Static checks only; :func:`_binds_locally` adds the probe's own addresses.
    """
    name = target.lower().rstrip(".")
    if name == "localhost" or name.endswith(".localhost"):
        return "is localhost"
    if _legacy_v4(target) is not None:
        return "is a non-standard numeric address (use a dotted quad or a name)"
    addr = _ip(target)
    if addr is None:
        return None  # a name: checked again once resolved
    reason = _never_a_path(addr)
    if reason:
        return f"is {reason}"
    if any(form.is_link_local for form in _forms(addr)):
        return "is link-local"
    return None


def _binds_locally(ip: str) -> bool:
    """True if ``ip`` is one of this machine's own addresses (a ``bind`` to it works).

    A connect to the probe's own address never leaves the container, so it proves
    nothing about the network.
    """
    addr = _ip(ip)
    if addr is None:
        return False
    family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((ip, 0))
    except OSError:
        return False
    return True


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


def _classify(kind: Kind, exc: BaseException) -> tuple[Outcome, str | None]:
    """Map an exception from the connector or resolver to an outcome and errno name."""
    if isinstance(exc, socket.gaierror):
        # DNS: resolution failed (no such name, resolver unreachable...): nothing reached.
        # TCP: a hostname did not resolve, so no address was tried: untested, an error.
        return (Outcome.UNREACHABLE if kind is Kind.DNS else Outcome.ERROR), _gai_name(exc)
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


class _Untestable(Exception):
    """The destination cannot be tested as specified (reported as ``error``)."""


def _reach_address(dest: Destination, resolve: Resolver, timeout: float) -> tuple[str, ...]:
    """The addresses a must-reach tcp destination stands for.

    Never loopback, unspecified, multicast, broadcast, reserved, link-local or one of
    the probe's own addresses, whether given directly or resolved from a name.
    """
    problem = _reach_problem(dest.target)
    if problem:
        raise _Untestable(f"reach target {dest.target!r} {problem}")
    if _ip(dest.target) is not None:
        answers: tuple[str, ...] = (dest.target,)
    else:
        answers = tuple(resolve(dest.target, timeout))
        if not answers:
            raise _Untestable(f"reach target {dest.target!r} resolved to no address")
    for answer in answers:
        problem = "is not an address" if _ip(answer) is None else _reach_problem(answer)
        if problem is None and _binds_locally(answer):
            problem = "is one of the probe's own addresses"
        if problem:
            via = "" if answer == dest.target else f" resolves to {answer}, which"
            raise _Untestable(f"reach target {dest.target!r}{via} {problem}")
    return answers


def _probe_one(
    dest: Destination, connect: Connector, resolve: Resolver, timeout: float
) -> ProbeResult:
    start = time.monotonic()

    def elapsed() -> float:
        return (time.monotonic() - start) * 1000.0

    if dest.unavailable is not None:
        return ProbeResult(dest, Outcome.ERROR, dest.unavailable, elapsed())
    answers: tuple[str, ...] = ()
    try:
        if dest.kind is Kind.TCP:
            if dest.port is None:
                raise _Untestable(f"tcp destination {dest.label} has no port")
            address = dest.target
            if dest.category.must_reach:
                answers = _reach_address(dest, resolve, timeout)
                address = answers[0]
            elif problem := _must_fail_problem(dest.target):
                raise _Untestable(f"must-fail tcp target {dest.target!r} {problem}")
            connect(address, dest.port, timeout)
            return ProbeResult(
                dest, Outcome.REACHABLE, "tcp handshake completed", elapsed(), answers=answers
            )
        if dest.category.must_reach:
            raise _Untestable("a reach destination must be tcp: a DNS answer needs no network")
        answers = tuple(resolve(dest.target, timeout))
    except _Untestable as exc:
        return ProbeResult(dest, Outcome.ERROR, str(exc), elapsed(), answers=answers)
    except Exception as exc:  # reported, never raised: that is the probe's contract
        outcome, code = _classify(dest.kind, exc)
        gai = code if isinstance(exc, socket.gaierror) else None
        detail = _describe(exc) if gai is None else f"{gai}: {exc}"
        return ProbeResult(dest, outcome, detail, elapsed(), errno_name=code, answers=answers)

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
    """Probe every destination in order; never raises because of a destination.

    Raises :class:`ValueError` if ``timeout`` is outside
    [:data:`MIN_TIMEOUT_S`, :data:`MAX_TIMEOUT_S`].
    """
    if not MIN_TIMEOUT_S <= timeout <= MAX_TIMEOUT_S:
        raise ValueError(
            f"timeout must be within {MIN_TIMEOUT_S}-{MAX_TIMEOUT_S}s, got {timeout!r}"
        )
    results = tuple(_probe_one(d, connect, resolve, timeout) for d in destinations)
    return ContainmentReport(results=results, timeout_s=timeout)


# --------------------------------------------------------------------- destinations


def default_destinations(
    *,
    host_gateway: str | None = None,
    lan: Sequence[str] | None = None,
    sinkhole: Sequence[str] = (),
    reach: Sequence[tuple[str, int]] = (),
    route_file: str = DEFAULT_ROUTE_FILE,
) -> list[Destination]:
    """The standard set: public IPv4/IPv6 on 443, a public name, host, LAN and reach.

    * host: ``host_gateway``, else every :func:`default_gateways` entry, else one
      ``error`` result;
    * LAN: ``lan`` must be given; ``None`` yields one ``error`` result, never a guess;
    * reach: one must-reach tcp destination per ``(host, port)``; with none, the
      ``reach`` category is missing and the report is not contained.
    """
    dests = [Destination(Category.INTERNET, Kind.TCP, ip, port) for ip, port in DEFAULT_INTERNET]
    dests.append(
        Destination(Category.INTERNET, Kind.DNS, DEFAULT_DNS_NAME, sinkhole=tuple(sinkhole))
    )
    gateways = [host_gateway] if host_gateway else default_gateways(route_file)
    for gateway in gateways:
        dests += [Destination(Category.HOST, Kind.TCP, gateway, p) for p in HOST_PORTS]
    if not gateways:
        why = f"no host gateway: none given and no default route in {route_file}"
        dests.append(Destination(Category.HOST, Kind.TCP, "", unavailable=why))
    if lan is None:
        why = "no home-LAN address given (--lan, or --allow-default-lan)"
        dests.append(Destination(Category.LAN, Kind.TCP, "", unavailable=why))
    else:
        for addr in lan:
            dests += [Destination(Category.LAN, Kind.TCP, addr, p) for p in LAN_PORTS]
    dests += [Destination(Category.REACH, Kind.TCP, host, port) for host, port in reach]
    return dests


def _bad(spec: str, why: str) -> ValueError:
    return ValueError(f"bad destination {spec!r}: {why}")


def _split_host_port(spec: str, rest: str) -> tuple[str, int]:
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
    return host, int(port_s)


def _reach_spec(spec: str, rest: str) -> tuple[str, int]:
    host, port = _split_host_port(spec, rest)
    if problem := _reach_problem(host):
        raise _bad(spec, f"a reach target {problem}")
    return host, port


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
        if category.must_reach:
            raise _bad(spec, "a reach destination must be tcp")
        if not rest or ":" in rest:
            raise _bad(spec, "dns takes a name and no port")
        return Destination(category, kind, rest, sinkhole=tuple(sinkhole))

    if category.must_reach:
        host, port = _reach_spec(spec, rest)
    else:
        host, port = _split_host_port(spec, rest)
        if problem := _must_fail_problem(host):
            raise _bad(spec, f"a must-fail tcp target {problem}")
    return Destination(category, kind, host, port)


# --------------------------------------------------------------------- CLI


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m cell.probe.containment",
        description=(
            "Try destinations that must be unreachable from a run cell (and ones that "
            "must be reachable); print a JSON report; exit 0 if contained, 1 if not."
        ),
    )
    p.add_argument(
        "--dest",
        action="append",
        default=[],
        metavar="CATEGORY:KIND:TARGET[:PORT]",
        help="a destination, e.g. internet:tcp:1.1.1.1:443, internet:dns:example.com, "
        "host:tcp:172.30.0.1:22, lan:tcp:192.168.1.1:80, reach:tcp:tap:8080 (repeatable)",
    )
    p.add_argument(
        "--defaults",
        action="store_true",
        help="also probe the default set (implied when no --dest is given)",
    )
    p.add_argument(
        "--host-gateway",
        help="the cell network's bridge gateway (default: every default-route gateway)",
    )
    p.add_argument(
        "--lan",
        action="append",
        default=None,
        help="home-LAN address for the default set (repeatable; required with the "
        "default set unless --allow-default-lan)",
    )
    p.add_argument(
        "--allow-default-lan",
        action="store_true",
        help=f"use {list(DEFAULT_LAN)} as the home LAN when no --lan is given",
    )
    p.add_argument(
        "--reach",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="a must-reach tcp destination proving the probe's network works (the tap, "
        "the target; never loopback); without one the cell is never contained (repeatable)",
    )
    p.add_argument(
        "--sinkhole",
        action="append",
        default=[],
        help="an address the cell's resolver answers every name with (the catcher)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"seconds per probe ({MIN_TIMEOUT_S}-{MAX_TIMEOUT_S})",
    )
    p.add_argument("--route-file", default=DEFAULT_ROUTE_FILE, help=argparse.SUPPRESS)
    return p


def main(
    argv: Sequence[str] | None = None,
    *,
    connect: Connector = tcp_connect,
    resolve: Resolver = dns_resolve,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not MIN_TIMEOUT_S <= args.timeout <= MAX_TIMEOUT_S:
        parser.error(f"--timeout must be within {MIN_TIMEOUT_S}-{MAX_TIMEOUT_S}")
    try:
        dests = [parse_destination(s, sinkhole=args.sinkhole) for s in args.dest]
        reach = [_reach_spec(f"reach:tcp:{r}", r) for r in args.reach]
    except ValueError as exc:
        parser.error(str(exc))
    for flag, values in (("--host-gateway", [args.host_gateway]), ("--lan", args.lan)):
        for value in values or ():
            if value is not None and (problem := _must_fail_problem(value)):
                parser.error(f"{flag} {value!r} {problem}")
    if args.defaults or not dests:
        if args.lan is None and not args.allow_default_lan:
            parser.error("the default set needs --lan ADDR (or --allow-default-lan)")
        dests += default_destinations(
            host_gateway=args.host_gateway,
            lan=args.lan if args.lan is not None else DEFAULT_LAN,
            sinkhole=args.sinkhole,
            route_file=args.route_file,
        )
    dests += [Destination(Category.REACH, Kind.TCP, host, port) for host, port in reach]
    report = probe(dests, connect=connect, resolve=resolve, timeout=args.timeout)
    sys.stdout.write(report.to_json() + "\n")
    sys.stdout.flush()
    return 0 if report.contained else 1


if __name__ == "__main__":
    sys.exit(main())
