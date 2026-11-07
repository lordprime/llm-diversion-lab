"""Containment probe: every must-fail destination is reported, never raised.

The connector and resolver are injected, so no test touches the network except the
loopback tests, which use a listener (and a closed port) on 127.0.0.1 as a must-fail
destination (a must-reach destination may never be loopback).
"""

from __future__ import annotations

import errno
import json
import socket
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from cell.probe.containment import (
    ALL_CATEGORIES,
    DEFAULT_INTERNET,
    MIN_TIMEOUT_S,
    Category,
    ContainmentReport,
    Destination,
    Kind,
    Outcome,
    default_destinations,
    default_gateway,
    default_gateways,
    is_contained,
    main,
    parse_destination,
    probe,
    tcp_connect,
)

TAP_IP = "10.88.0.10"
ANY_V4 = "0.0.0.0"  # noqa: S104 -- an address under test, nothing binds to it
INTERNET = Destination(Category.INTERNET, Kind.TCP, "1.1.1.1", 443)
INTERNET_V6 = Destination(Category.INTERNET, Kind.TCP, "2606:4700:4700::1111", 443)
INTERNET_DNS = Destination(Category.INTERNET, Kind.DNS, "example.com")
HOST = Destination(Category.HOST, Kind.TCP, "172.30.0.1", 22)
LAN = Destination(Category.LAN, Kind.TCP, "192.168.1.1", 80)
REACH = Destination(Category.REACH, Kind.TCP, "tap", 8080)
MUST_FAIL = [INTERNET, INTERNET_V6, INTERNET_DNS, HOST, LAN]
ALL = [*MUST_FAIL, REACH]

_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"


def _gw_hex(ip: str) -> str:
    """An IPv4 address as /proc/net/route prints it (host byte order)."""
    return f"{int.from_bytes(socket.inet_aton(ip), sys.byteorder):08X}"


def _default_route(ip: str, metric: int, iface: str = "eth0") -> str:
    return f"{iface}\t00000000\t{_gw_hex(ip)}\t0003\t0\t0\t{metric}\t00000000\t0\t0\t0\n"


ROUTE_WITH_DEFAULT = (
    _HEADER
    + _default_route("172.17.0.1", 0)
    + "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
)
# An internal Docker network: only the link route, no gateway.
ROUTE_INTERNAL = _HEADER + "eth0\t00001EAC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"


def _raising(exc: BaseException) -> Callable[..., None]:
    def connect(host: str, port: int, timeout: float) -> None:
        raise exc

    return connect


def _ok_connect(host: str, port: int, timeout: float) -> None:
    return None


def _failing_resolve(name: str, timeout: float) -> list[str]:
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def _resolve_tap(name: str, timeout: float) -> list[str]:
    """The cell's service names resolve; everything else does not."""
    if name == "tap":
        return [TAP_IP]
    return _failing_resolve(name, timeout)


def _only_reach(host: str, port: int, timeout: float) -> None:
    """A contained cell: only the must-reach destination (the tap) answers."""
    if (host, port) == (TAP_IP, 8080):
        return
    raise TimeoutError("timed out")


def _outcomes(report: ContainmentReport) -> dict[str, Outcome]:
    return {r.destination.label: r.outcome for r in report.results}


def _contained_probe(dests: list[Destination]) -> ContainmentReport:
    return probe(dests, connect=_only_reach, resolve=_resolve_tap)


@pytest.fixture
def route_file(tmp_path: Path) -> Callable[[str], str]:
    def write(text: str) -> str:
        path = tmp_path / "route"
        path.write_text(text)
        return str(path)

    return write


@pytest.fixture
def listener() -> Iterator[int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        yield s.getsockname()[1]


# --------------------------------------------------------------------- outcomes


@pytest.mark.parametrize(
    ("exc", "outcome"),
    [
        (OSError(errno.ENETUNREACH, "Network is unreachable"), Outcome.UNREACHABLE),
        (OSError(errno.EHOSTUNREACH, "No route to host"), Outcome.UNREACHABLE),
        (OSError(errno.EPERM, "Operation not permitted"), Outcome.UNREACHABLE),
        (TimeoutError("timed out"), Outcome.TIMEOUT),
        (OSError(errno.ETIMEDOUT, "Connection timed out"), Outcome.TIMEOUT),
    ],
)
def test_unreachable_destination_is_reported_not_raised(
    exc: BaseException, outcome: Outcome
) -> None:
    report = probe([INTERNET, HOST, LAN], connect=_raising(exc), resolve=_failing_resolve)

    assert [r.outcome for r in report.results] == [outcome] * 3
    assert all(not r.reached and r.ok for r in report.results)
    assert report.breaches == ()


@pytest.mark.parametrize(
    "code",
    [errno.EACCES, errno.EADDRNOTAVAIL],
    ids=["EACCES", "EADDRNOTAVAIL"],
)
def test_local_conditions_are_errors_not_unreachable(code: int) -> None:
    """EACCES / EADDRNOTAVAIL are about this host, not the path: they prove nothing."""
    report = probe([INTERNET], connect=_raising(OSError(code, "local")))
    assert report.results[0].outcome is Outcome.ERROR
    assert not report.results[0].ok


def test_failed_dns_resolution_is_unreachable() -> None:
    report = probe([INTERNET_DNS], resolve=_failing_resolve)

    (result,) = report.results
    assert result.outcome is Outcome.UNREACHABLE
    assert "EAI_NONAME" in result.detail or "not known" in result.detail
    assert result.ok


def test_dns_answers_only_from_the_sinkhole_are_not_a_breach() -> None:
    """The cell's resolver is the callback catcher, which answers every name."""
    dest = Destination(Category.INTERNET, Kind.DNS, "example.com", sinkhole=("10.88.0.53",))
    report = probe([dest], resolve=lambda name, timeout: ["10.88.0.53"])

    (result,) = report.results
    assert result.outcome is Outcome.UNREACHABLE
    assert result.answers == ("10.88.0.53",)
    assert result.ok


def test_a_dead_destination_in_the_real_connector_is_reported() -> None:
    """The real connector against a closed loopback port: refused, never raised."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # bound but not listening: connections are refused
        dest = Destination(Category.HOST, Kind.TCP, "127.0.0.1", port)
        report = probe([dest], timeout=1.0)

    (result,) = report.results
    assert result.outcome is Outcome.REFUSED
    assert result.errno_name == "ECONNREFUSED"


def test_ipv6_unreachable_on_a_v4_only_cell_is_ok() -> None:
    report = probe(
        [INTERNET_V6], connect=_raising(OSError(errno.ENETUNREACH, "Network is unreachable"))
    )
    assert report.results[0].outcome is Outcome.UNREACHABLE
    assert report.results[0].ok


def test_reachable_destination_is_reported_as_success(listener: int) -> None:
    dest = Destination(Category.LAN, Kind.TCP, "127.0.0.1", listener)
    report = probe([dest], connect=tcp_connect, timeout=1.0)

    (result,) = report.results
    assert result.outcome is Outcome.REACHABLE
    assert result.reached
    assert result.elapsed_ms >= 0
    assert not result.ok
    assert not is_contained(report)


def test_dns_resolving_to_a_real_address_is_reachable() -> None:
    dest = Destination(Category.INTERNET, Kind.DNS, "example.com", sinkhole=("10.88.0.53",))
    report = probe([dest], resolve=lambda name, timeout: ["10.88.0.53", "93.184.215.14"])

    (result,) = report.results
    assert result.outcome is Outcome.REACHABLE
    assert not result.ok


# --------------------------------------------------------------------- is_contained


def test_fully_covered_contained_cell_is_contained() -> None:
    report = _contained_probe(ALL)

    assert report.missing_categories == frozenset()
    assert is_contained(report)
    assert report.breaches == ()
    assert report.reach_failures == ()
    reach = report.results[-1]
    assert reach.outcome is Outcome.REACHABLE
    assert reach.answers == (TAP_IP,)


@pytest.mark.parametrize("breached", MUST_FAIL, ids=lambda d: d.label)
def test_any_reachable_must_fail_destination_breaks_containment(breached: Destination) -> None:
    """Critical: one reachable internet, host or LAN destination is a containment failure."""

    def connect(host: str, port: int, timeout: float) -> None:
        if breached.kind is Kind.TCP and (host, port) == (breached.target, breached.port):
            return
        _only_reach(host, port, timeout)

    def resolve(name: str, timeout: float) -> list[str]:
        if breached.kind is Kind.DNS and name == breached.target:
            return ["93.184.215.14"]
        return _resolve_tap(name, timeout)

    report = probe(ALL, connect=connect, resolve=resolve)

    assert _outcomes(report)[breached.label] is Outcome.REACHABLE
    assert sum(r.reached for r in report.results) == 2  # the breach and the reach control
    assert is_contained(report) is False
    assert report.contained is False
    assert [r.destination for r in report.breaches] == [breached]


def test_refused_connection_breaks_containment() -> None:
    """The lab drops cell egress, never rejects it: a refusal means something answered."""
    report = probe(
        [*ALL, Destination(Category.HOST, Kind.TCP, "172.30.0.1", 80)],
        connect=lambda h, p, t: (
            _raising(ConnectionRefusedError(errno.ECONNREFUSED, "x"))(h, p, t)
            if (h, p) == ("172.30.0.1", 80)
            else _only_reach(h, p, t)
        ),
        resolve=_resolve_tap,
    )
    assert report.results[-1].outcome is Outcome.REFUSED
    assert not is_contained(report)


def test_error_is_distinct_from_timeout_and_fails_closed() -> None:
    timed_out = probe([INTERNET], connect=_raising(TimeoutError("timed out")))
    errored = probe([INTERNET], connect=_raising(RuntimeError("probe bug")))

    assert timed_out.results[0].outcome is Outcome.TIMEOUT
    assert errored.results[0].outcome is Outcome.ERROR
    assert "RuntimeError" in errored.results[0].detail
    assert timed_out.results[0].ok
    assert not errored.results[0].ok, "a destination the probe could not test proves nothing"


def test_empty_report_is_not_containment() -> None:
    assert not is_contained(probe([]))


@pytest.mark.parametrize("missing", sorted(ALL_CATEGORIES), ids=str)
def test_every_category_must_be_probed(missing: Category) -> None:
    """A category with no destination is untested: never reported as contained."""
    report = _contained_probe([d for d in ALL if d.category is not missing])

    assert all(r.ok for r in report.results)
    assert report.missing_categories == {missing}
    assert not is_contained(report)
    assert report.to_dict()["missing_categories"] == [str(missing)]


@pytest.mark.parametrize("category", ["internet", "host", "lan"])
def test_dns_alone_does_not_cover_a_must_fail_category(category: str) -> None:
    """A failed lookup proves nothing about IP reachability: a TCP result is required."""
    cat = Category(category)
    dests = [d for d in ALL if d.category is not cat]
    dests.append(Destination(cat, Kind.DNS, "nx.invalid"))
    report = _contained_probe(dests)

    assert all(r.ok for r in report.results)
    assert report.missing_categories == {cat}
    assert not is_contained(report)


def test_dns_only_categories_with_loopback_reach_never_pass(
    listener: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reviewer's reproducer: DNS-only categories plus a loopback reach control."""
    with pytest.raises(SystemExit) as exc:
        main(
            ["--dest", "internet:dns:nx.invalid", "--dest", "host:dns:nx.invalid",
             "--dest", "lan:dns:nx.invalid", "--dest", f"reach:tcp:127.0.0.1:{listener}"]
        )  # fmt: skip
    assert exc.value.code == 2  # loopback reach is a usage error

    code = main(
        ["--dest", "internet:dns:nx.invalid", "--dest", "host:dns:nx.invalid",
         "--dest", "lan:dns:nx.invalid", "--reach", "tap:8080"],
        connect=_only_reach,
        resolve=_resolve_tap,
    )  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["missing_categories"] == ["host", "internet", "lan"]


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("timed out"),
        OSError(errno.ENETUNREACH, "Network is unreachable"),
        ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
    ],
)
def test_failed_must_reach_destination_breaks_containment(exc: BaseException) -> None:
    """No working network at all must not read as 'contained'."""
    report = probe(ALL, connect=_raising(exc), resolve=_resolve_tap)

    assert not is_contained(report)
    assert [r.destination for r in report.reach_failures] == [REACH]
    reach = report.to_dict()["results"][-1]
    assert reach["must_reach"] is True
    assert reach["ok"] is False


@pytest.mark.parametrize(
    "target", ["127.0.0.1", "127.8.9.10", "::1", ANY_V4, "::"], ids=lambda t: t
)
def test_loopback_or_unspecified_reach_ip_is_an_error(target: str) -> None:
    dest = Destination(Category.REACH, Kind.TCP, target, 8080)
    called: list[str] = []

    def connect(host: str, port: int, timeout: float) -> None:
        called.append(host)

    report = probe([*MUST_FAIL, dest], connect=connect, resolve=_failing_resolve)
    assert called[-1:] != [target]
    assert report.results[-1].outcome is Outcome.ERROR
    assert "loopback" in report.results[-1].detail or "unspecified" in report.results[-1].detail
    assert not is_contained(report)


@pytest.mark.parametrize("answers", [["127.0.0.1"], ["10.88.0.10", "::1"], [ANY_V4]])
def test_reach_name_resolving_to_loopback_is_an_error(answers: list[str]) -> None:
    report = probe(
        [*MUST_FAIL, REACH],
        connect=_ok_connect,
        resolve=lambda n, t: answers if n == "tap" else _failing_resolve(n, t),
    )
    assert report.results[-1].outcome is Outcome.ERROR
    assert not is_contained(report)


def test_reach_connects_to_the_resolved_address() -> None:
    seen: list[tuple[str, int]] = []

    def connect(host: str, port: int, timeout: float) -> None:
        seen.append((host, port))

    probe([REACH], connect=connect, resolve=_resolve_tap)
    assert seen == [(TAP_IP, 8080)]


def test_reach_dns_destination_is_an_error() -> None:
    """``reach`` must be TCP: a DNS answer (even 10.9.9.9) needs no network at all."""
    dest = Destination(Category.REACH, Kind.DNS, "10.9.9.9")
    report = probe([dest], resolve=lambda n, t: ["10.9.9.9"])
    assert report.results[0].outcome is Outcome.ERROR
    assert not report.results[0].ok


def test_must_fail_tcp_hostname_is_an_error_not_unreachable() -> None:
    """A hostname target that does not resolve was never tried: it must not pass."""
    dest = Destination(Category.INTERNET, Kind.TCP, "one.one.one.one", 443)
    called: list[str] = []

    def connect(host: str, port: int, timeout: float) -> None:
        called.append(host)

    report = probe([dest], connect=connect)

    assert called == []
    assert report.results[0].outcome is Outcome.ERROR
    assert "IP literal" in report.results[0].detail


def test_unresolvable_reach_hostname_is_an_error() -> None:
    report = probe([REACH], connect=_ok_connect, resolve=_failing_resolve)
    assert report.results[0].outcome is Outcome.ERROR
    assert not report.results[0].ok


def test_probe_never_raises_even_on_odd_exceptions_from_the_connector() -> None:
    report = probe([INTERNET], connect=_raising(OSError("weird")))
    assert report.results[0].outcome is Outcome.ERROR


# --------------------------------------------------------------------- timeout


def test_timeout_is_passed_to_the_connector() -> None:
    seen: list[float] = []

    def connect(host: str, port: int, timeout: float) -> None:
        seen.append(timeout)
        raise TimeoutError

    probe([INTERNET, LAN], connect=connect, timeout=1.5)
    assert seen == [1.5, 1.5]


@pytest.mark.parametrize("timeout", [0.0, 0.001, 0.5, 0.999])
def test_timeout_below_the_floor_is_refused(timeout: float) -> None:
    """A tiny timeout would turn every reachable destination into 'timeout' = contained."""
    assert MIN_TIMEOUT_S == 1.0
    with pytest.raises(ValueError, match="timeout"):
        probe([INTERNET], connect=_ok_connect, timeout=timeout)


@pytest.mark.parametrize("value", ["0.001", "0.5", "0", "-1"])
def test_cli_timeout_below_the_floor_is_a_usage_error(value: str) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--dest", "internet:tcp:192.0.2.1:443", "--timeout", value])
    assert exc.value.code == 2


# --------------------------------------------------------------------- defaults


def test_default_internet_covers_ipv4_and_ipv6() -> None:
    addrs = {ip for ip, _ in DEFAULT_INTERNET}
    assert {"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111", "2620:fe::fe"} <= addrs


def test_default_gateway_from_proc_net_route(route_file: Callable[[str], str]) -> None:
    assert default_gateway(route_file(ROUTE_WITH_DEFAULT)) == "172.17.0.1"
    assert default_gateway(route_file(ROUTE_INTERNAL)) is None
    assert default_gateway("/nonexistent/route") is None
    assert default_gateways("/nonexistent/route") == []


def test_default_gateways_by_metric_and_distinct(route_file: Callable[[str], str]) -> None:
    table = (
        _HEADER
        + _default_route("10.0.0.1", 600, "wlan0")
        + _default_route("172.17.0.1", 100)
        + _default_route("10.0.0.1", 700, "wlan1")
        + "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    )
    path = route_file(table)
    assert default_gateways(path) == ["172.17.0.1", "10.0.0.1"]
    assert default_gateway(path) == "172.17.0.1"


def test_every_default_gateway_is_probed(route_file: Callable[[str], str]) -> None:
    table = _HEADER + _default_route("172.17.0.1", 100) + _default_route("10.0.0.1", 600)
    dests = default_destinations(lan=["192.168.1.1"], route_file=route_file(table))
    assert {d.target for d in dests if d.category is Category.HOST} == {"172.17.0.1", "10.0.0.1"}


def test_default_destinations_with_everything_given(route_file: Callable[[str], str]) -> None:
    dests = default_destinations(
        host_gateway="172.30.0.1", lan=["10.0.0.1"], reach=[("tap", 8080)],
        route_file=route_file(ROUTE_INTERNAL),
    )  # fmt: skip
    assert {d.category for d in dests} == ALL_CATEGORIES
    assert any(d.kind is Kind.DNS for d in dests)
    assert {d.target for d in dests if d.category is Category.HOST} == {"172.30.0.1"}
    assert {d.target for d in dests if d.category is Category.LAN} == {"10.0.0.1"}
    assert {d.target for d in dests if d.category is Category.INTERNET} >= {"2620:fe::fe"}
    assert all(d.unavailable is None for d in dests)


def test_missing_host_gateway_and_lan_are_errors_not_silence(
    route_file: Callable[[str], str],
) -> None:
    dests = default_destinations(reach=[("tap", 8080)], route_file=route_file(ROUTE_INTERNAL))
    report = _contained_probe(dests)

    by_cat = {r.destination.category: r for r in report.results if r.outcome is Outcome.ERROR}
    assert set(by_cat) == {Category.HOST, Category.LAN}
    assert "host gateway" in by_cat[Category.HOST].detail
    assert "--lan" in by_cat[Category.LAN].detail
    assert not is_contained(report)


def test_defaults_without_reach_are_not_contained(route_file: Callable[[str], str]) -> None:
    dests = default_destinations(
        host_gateway="172.30.0.1", lan=["10.0.0.1"], route_file=route_file(ROUTE_INTERNAL)
    )
    report = probe(dests, connect=_raising(TimeoutError()), resolve=_failing_resolve)
    assert report.missing_categories == {Category.REACH}
    assert not is_contained(report)


def test_full_default_set_with_reach_is_contained(route_file: Callable[[str], str]) -> None:
    dests = default_destinations(
        host_gateway="172.30.0.1", lan=["192.168.1.1"], reach=[("tap", 8080)],
        route_file=route_file(ROUTE_INTERNAL),
    )  # fmt: skip
    assert is_contained(_contained_probe(dests))


# --------------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("internet:tcp:1.1.1.1:443", INTERNET),
        ("internet:tcp:[2606:4700:4700::1111]:443", INTERNET_V6),
        ("internet:dns:example.com", INTERNET_DNS),
        ("host:tcp:172.30.0.1:22", HOST),
        ("lan:tcp:192.168.1.1:80", LAN),
        ("lan:tcp:[fd00::1]:443", Destination(Category.LAN, Kind.TCP, "fd00::1", 443)),
        ("lan:tcp:127.0.0.1:80", Destination(Category.LAN, Kind.TCP, "127.0.0.1", 80)),
        ("reach:tcp:tap:8080", REACH),
        ("reach:tcp:10.88.0.10:8080", Destination(Category.REACH, Kind.TCP, TAP_IP, 8080)),
    ],
)
def test_parse_destination(spec: str, expected: Destination) -> None:
    assert parse_destination(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "internet:tcp:1.1.1.1",  # no port
        "internet:tcp:1.1.1.1:0",
        "internet:tcp:1.1.1.1:70000",
        "moon:tcp:1.1.1.1:443",
        "internet:udp:1.1.1.1:53",
        "internet:dns:",
        "internet:dns:example.com:53",
        "lan:tcp:fd00::1:443",  # IPv6 without brackets is ambiguous
        "lan:tcp:[not-v6]:443",
        "internet:tcp:one.one.one.one:443",  # must-fail tcp needs an IP literal
        "host:tcp:host.docker.internal:22",
        "reach:dns:target",  # reach must be tcp
        "reach:dns:localhost",
        "reach:tcp:127.0.0.1:8080",  # reach may not be loopback
        "reach:tcp:[::1]:8080",
        "reach:tcp:0.0.0.0:8080",
        "reach:tcp:localhost:8080",
        "reach:tcp:tap.localhost:8080",
    ],
)
def test_parse_destination_rejects_bad_specs(spec: str) -> None:
    with pytest.raises(ValueError, match="destination"):
        parse_destination(spec)


# --------------------------------------------------------------------- report and CLI


def test_report_serialises_to_json() -> None:
    report = probe([INTERNET, INTERNET_DNS], connect=_ok_connect, resolve=_failing_resolve)
    doc = json.loads(report.to_json())

    assert doc["contained"] is False
    assert doc["required_categories"] == ["host", "internet", "lan", "reach"]
    assert doc["missing_categories"] == ["host", "lan", "reach"]
    assert [r["outcome"] for r in doc["results"]] == ["reachable", "unreachable"]
    first = doc["results"][0]
    assert first["category"] == "internet"
    assert first["kind"] == "tcp"
    assert first["target"] == "1.1.1.1"
    assert first["port"] == 443
    assert first["must_reach"] is False
    assert first["ok"] is False


#: Every category given explicitly, on TEST-NET addresses (RFC 5737).
FULL_CLI = [
    "--dest", "internet:tcp:192.0.2.1:443",
    "--dest", "host:tcp:192.0.2.2:22",
    "--dest", "lan:tcp:192.0.2.3:80",
    "--reach", "tap:8080",
]  # fmt: skip


def test_main_exits_zero_when_contained(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(FULL_CLI, connect=_only_reach, resolve=_resolve_tap)

    doc = json.loads(capsys.readouterr().out)
    must_fail = [r for r in doc["results"] if not r["must_reach"]]
    assert {r["outcome"] for r in must_fail} == {"timeout"}
    assert doc["missing_categories"] == []
    assert code == 0
    assert doc["contained"] is True


def test_main_prints_report_and_exits_nonzero_when_not_contained(
    listener: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real loopback listener as a reachable must-fail destination."""

    def connect(host: str, port: int, timeout: float) -> None:
        if host == "127.0.0.1":
            tcp_connect(host, port, timeout)
        else:
            _only_reach(host, port, timeout)

    code = main(
        [*FULL_CLI, "--dest", f"lan:tcp:127.0.0.1:{listener}"],
        connect=connect,
        resolve=_resolve_tap,
    )
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["contained"] is False
    assert [r["outcome"] for r in doc["results"] if r["target"] == "127.0.0.1"] == ["reachable"]


def test_main_without_reach_is_never_contained(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(FULL_CLI[:-2], connect=_only_reach, resolve=_resolve_tap)
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["missing_categories"] == ["reach"]


def test_main_defaults_require_an_explicit_lan() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--defaults", "--reach", "tap:8080"])
    assert exc.value.code == 2


def test_main_defaults_without_a_gateway_report_an_error(
    route_file: Callable[[str], str], capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["--defaults", "--allow-default-lan", "--reach", "tap:8080",
         "--route-file", route_file(ROUTE_INTERNAL)],
        connect=_only_reach,
        resolve=_resolve_tap,
    )  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    host = [r for r in doc["results"] if r["category"] == "host"]
    assert [r["outcome"] for r in host] == ["error"]
    assert code == 1
    lan = {r["target"] for r in doc["results"] if r["category"] == "lan"}
    assert lan == {"192.168.1.1"}


@pytest.mark.parametrize(
    "argv",
    [
        ["--dest", "moon:tcp:1.1.1.1:443"],
        ["--dest", "internet:tcp:example.com:443"],
        ["--reach", "tap"],
        ["--reach", "127.0.0.1:8080"],
        ["--reach", "localhost:8080"],
        ["--timeout", "0"],
    ],
)
def test_main_rejects_bad_arguments_with_usage_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_module_entry_point_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "cell.probe.containment", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "--dest" in proc.stdout
    assert "--reach" in proc.stdout
    assert "--allow-default-lan" in proc.stdout
