"""Containment probe: every must-fail destination is reported, never raised.

The connector and resolver are injected, so no test touches the network except the
two loopback tests, which use a listener (and a closed port) on 127.0.0.1.
"""

from __future__ import annotations

import errno
import json
import socket
import subprocess
import sys
from collections.abc import Callable, Iterator

import pytest

from cell.probe.containment import (
    Category,
    ContainmentReport,
    Destination,
    Kind,
    Outcome,
    default_destinations,
    is_contained,
    main,
    parse_destination,
    probe,
    tcp_connect,
)

INTERNET = Destination(Category.INTERNET, Kind.TCP, "1.1.1.1", 443)
INTERNET_DNS = Destination(Category.INTERNET, Kind.DNS, "example.com")
HOST = Destination(Category.HOST, Kind.TCP, "172.30.0.1", 22)
LAN = Destination(Category.LAN, Kind.TCP, "192.168.1.1", 80)
ALL = [INTERNET, INTERNET_DNS, HOST, LAN]


def _raising(exc: BaseException) -> Callable[..., None]:
    def connect(host: str, port: int, timeout: float) -> None:
        raise exc

    return connect


def _ok_connect(host: str, port: int, timeout: float) -> None:
    return None


def _failing_resolve(name: str, timeout: float) -> list[str]:
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def _outcomes(report: ContainmentReport) -> dict[str, Outcome]:
    return {r.destination.label: r.outcome for r in report.results}


# --------------------------------------------------------------------- unreachable


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
    assert all(not r.reached for r in report.results)
    assert is_contained(report)
    assert report.contained


def test_failed_dns_resolution_is_unreachable() -> None:
    report = probe([INTERNET_DNS], connect=_ok_connect, resolve=_failing_resolve)

    (result,) = report.results
    assert result.outcome is Outcome.UNREACHABLE
    assert "EAI_NONAME" in result.detail or "not known" in result.detail
    assert is_contained(report)


def test_dns_answers_only_from_the_sinkhole_are_not_a_breach() -> None:
    """The cell's resolver is the callback catcher, which answers every name."""
    dest = Destination(Category.INTERNET, Kind.DNS, "example.com", sinkhole=("10.88.0.53",))
    report = probe([dest], resolve=lambda name, timeout: ["10.88.0.53"])

    (result,) = report.results
    assert result.outcome is Outcome.UNREACHABLE
    assert result.answers == ("10.88.0.53",)
    assert is_contained(report)


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


# --------------------------------------------------------------------- reachable


@pytest.fixture
def listener() -> Iterator[int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        yield s.getsockname()[1]


def test_reachable_destination_is_reported_as_success(listener: int) -> None:
    dest = Destination(Category.LAN, Kind.TCP, "127.0.0.1", listener)
    report = probe([dest], connect=tcp_connect, timeout=1.0)

    (result,) = report.results
    assert result.outcome is Outcome.REACHABLE
    assert result.reached
    assert result.elapsed_ms >= 0
    assert not is_contained(report)


def test_dns_resolving_to_a_real_address_is_reachable() -> None:
    dest = Destination(Category.INTERNET, Kind.DNS, "example.com", sinkhole=("10.88.0.53",))
    report = probe([dest], resolve=lambda name, timeout: ["10.88.0.53", "93.184.215.14"])

    (result,) = report.results
    assert result.outcome is Outcome.REACHABLE
    assert not is_contained(report)


# --------------------------------------------------------------------- is_contained


@pytest.mark.parametrize("breached", ALL, ids=lambda d: d.label)
def test_any_reachable_must_fail_destination_breaks_containment(breached: Destination) -> None:
    """Critical: one reachable internet, host or LAN destination is a containment failure."""

    def connect(host: str, port: int, timeout: float) -> None:
        if breached.kind is Kind.TCP and (host, port) == (breached.target, breached.port):
            return
        raise TimeoutError("timed out")

    def resolve(name: str, timeout: float) -> list[str]:
        if breached.kind is Kind.DNS and name == breached.target:
            return ["93.184.215.14"]
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    report = probe(ALL, connect=connect, resolve=resolve)

    assert _outcomes(report)[breached.label] is Outcome.REACHABLE
    assert sum(r.reached for r in report.results) == 1
    assert is_contained(report) is False
    assert report.contained is False
    assert [r.destination for r in report.breaches] == [breached]


def test_refused_connection_breaks_containment() -> None:
    """The lab drops cell egress, never rejects it: a refusal means something answered."""
    report = probe([HOST], connect=_raising(ConnectionRefusedError(errno.ECONNREFUSED, "x")))

    assert report.results[0].outcome is Outcome.REFUSED
    assert not is_contained(report)


def test_error_is_distinct_from_timeout_and_fails_closed() -> None:
    timed_out = probe([INTERNET], connect=_raising(TimeoutError("timed out")))
    errored = probe([INTERNET], connect=_raising(RuntimeError("probe bug")))

    assert timed_out.results[0].outcome is Outcome.TIMEOUT
    assert errored.results[0].outcome is Outcome.ERROR
    assert "RuntimeError" in errored.results[0].detail
    assert is_contained(timed_out)
    assert not is_contained(errored), "a destination the probe could not test proves nothing"


def test_empty_report_is_not_containment() -> None:
    assert not is_contained(probe([]))


def test_probe_never_raises_even_on_base_exceptions_from_the_connector() -> None:
    report = probe([INTERNET], connect=_raising(OSError("weird")))
    assert report.results[0].outcome is Outcome.ERROR


def test_timeout_is_passed_to_the_connector() -> None:
    seen: list[float] = []

    def connect(host: str, port: int, timeout: float) -> None:
        seen.append(timeout)
        raise TimeoutError

    probe([INTERNET, LAN], connect=connect, timeout=0.5)
    assert seen == [0.5, 0.5]


# --------------------------------------------------------------------- report and CLI


def test_report_serialises_to_json() -> None:
    report = probe([INTERNET, INTERNET_DNS], connect=_ok_connect, resolve=_failing_resolve)
    doc = json.loads(report.to_json())

    assert doc["contained"] is False
    assert [r["outcome"] for r in doc["results"]] == ["reachable", "unreachable"]
    first = doc["results"][0]
    assert first["category"] == "internet"
    assert first["kind"] == "tcp"
    assert first["target"] == "1.1.1.1"
    assert first["port"] == 443


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("internet:tcp:1.1.1.1:443", INTERNET),
        ("internet:dns:example.com", INTERNET_DNS),
        ("host:tcp:172.30.0.1:22", HOST),
        ("lan:tcp:192.168.1.1:80", LAN),
        ("lan:tcp:[fd00::1]:443", Destination(Category.LAN, Kind.TCP, "fd00::1", 443)),
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
    ],
)
def test_parse_destination_rejects_bad_specs(spec: str) -> None:
    with pytest.raises(ValueError, match="destination"):
        parse_destination(spec)


def test_default_destinations_cover_internet_and_lan_and_optionally_the_host() -> None:
    assert {d.category for d in default_destinations()} == {Category.INTERNET, Category.LAN}
    with_host = default_destinations(host_gateway="172.30.0.1", lan=["10.0.0.1"])
    assert {d.category for d in with_host} == set(Category)
    assert any(d.kind is Kind.DNS for d in with_host)
    assert {d.target for d in with_host if d.category is Category.HOST} == {"172.30.0.1"}
    assert {d.target for d in with_host if d.category is Category.LAN} == {"10.0.0.1"}


def test_main_prints_report_and_exits_nonzero_when_not_contained(
    listener: int, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--dest", f"lan:tcp:127.0.0.1:{listener}", "--timeout", "1"])

    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["contained"] is False
    assert doc["results"][0]["outcome"] == "reachable"


def test_main_exits_zero_when_contained(capsys: pytest.CaptureFixture[str]) -> None:
    # TEST-NET-1 (RFC 5737) is never routed; with a tiny timeout this is a timeout or
    # an unreachable, never a success.
    code = main(["--dest", "internet:tcp:192.0.2.1:443", "--timeout", "0.2"])

    doc = json.loads(capsys.readouterr().out)
    assert doc["results"][0]["outcome"] in {"timeout", "unreachable"}
    assert code == 0
    assert doc["contained"] is True


def test_main_rejects_a_bad_destination_with_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--dest", "moon:tcp:1.1.1.1:443"])
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
