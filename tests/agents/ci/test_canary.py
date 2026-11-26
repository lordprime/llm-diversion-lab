"""The egress canary: which frames count as connection attempts, and its DNS answers.

The raw socket and the servers only run in CI (the agent lane's self-check proves them end
to end); here the frame reader and the resolver are driven with hand-built packets.
"""

from __future__ import annotations

import io
import ipaddress
import json
import socket
import struct
from types import SimpleNamespace
from typing import Any

import pytest
from dnslib import QTYPE, RCODE, DNSRecord  # type: ignore[import-untyped]

from agents.ci.canary.canary import CanaryResolver, ConnectionSniffer, EgressLog, _allowed
from agents.ci.stub_model.server import RequestRecorder

OWN = ipaddress.ip_address("172.18.0.3")
STUB = ipaddress.ip_address("172.18.0.2")
AGENT = "172.18.0.4"
HOST, BROADCAST, MULTICAST, OUTGOING = 0, 1, 2, 4


class Canary:
    def __init__(self) -> None:
        self.stream = io.StringIO()
        self.log = EgressLog(RequestRecorder(self.stream))
        self.sniffer = ConnectionSniffer(OWN, self.log)
        self.resolver = CanaryResolver(OWN, self.log, {"tap": STUB})

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]


@pytest.fixture
def canary() -> Canary:
    return Canary()


def ipv4(proto: int, src: str, dst: str, payload: bytes, ihl: int = 5) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        20 + len(payload),
        0,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    options = b"\x00" * ((ihl - 5) * 4)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + header + options + payload


def ipv6(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(payload), proto, 64)
    header += socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x86\xdd" + header + payload


def tcp(dport: int, flags: int = 0x02, sport: int = 40000) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0)


def udp(dport: int, sport: int = 50000) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8, 0)


def test_a_syn_to_any_address_is_recorded(canary: Canary) -> None:
    record = canary.sniffer.inspect(ipv4(6, AGENT, "93.184.216.34", tcp(443)), HOST, "eth0")
    assert record is not None
    assert {k: record[k] for k in ("kind", "src", "dst", "dport", "qname")} == {
        "kind": "tcp",
        "src": AGENT,
        "dst": "93.184.216.34",
        "dport": 443,
        "qname": None,
    }
    assert canary.records() == [record]


@pytest.mark.parametrize("flags", [0x10, 0x12, 0x18, 0x11, 0x04, 0x00])
def test_only_the_opening_syn_counts(canary: Canary, flags: int) -> None:
    assert canary.sniffer.inspect(ipv4(6, AGENT, str(OWN), tcp(80, flags)), HOST, "eth0") is None


def test_udp_is_recorded_once_per_flow(canary: Canary) -> None:
    frame = ipv4(17, AGENT, "8.8.8.8", udp(53))
    assert canary.sniffer.inspect(frame, HOST, "eth0") is not None
    assert canary.sniffer.inspect(frame, HOST, "eth0") is None
    assert canary.sniffer.inspect(ipv4(17, AGENT, "8.8.8.8", udp(53, 50001)), HOST, "eth0")
    assert [r["kind"] for r in canary.records()] == ["udp", "udp"]


def test_dns_to_the_canary_itself_is_left_to_the_resolver(canary: Canary) -> None:
    assert canary.sniffer.inspect(ipv4(17, AGENT, str(OWN), udp(53)), HOST, "eth0") is None
    assert canary.sniffer.inspect(ipv4(6, AGENT, str(OWN), tcp(53)), HOST, "eth0") is None
    # DNS to any other server is an escape attempt
    assert canary.sniffer.inspect(ipv4(17, AGENT, "1.1.1.1", udp(53)), HOST, "eth0")


@pytest.mark.parametrize(
    ("pkttype", "ifname"),
    [(BROADCAST, "eth0"), (MULTICAST, "eth0"), (OUTGOING, "eth0"), (HOST, "lo")],
)
def test_frames_not_addressed_to_the_canary_are_ignored(
    canary: Canary, pkttype: int, ifname: str
) -> None:
    assert canary.sniffer.inspect(ipv4(6, AGENT, str(OWN), tcp(80)), pkttype, ifname) is None
    assert canary.records() == []


def test_ipv6_and_ip_options_are_read(canary: Canary) -> None:
    record = canary.sniffer.inspect(ipv6(6, "fd00::4", "2001:db8::1", tcp(22)), HOST, "eth0")
    assert record is not None and (record["dst"], record["dport"]) == ("2001:db8::1", 22)
    record = canary.sniffer.inspect(ipv4(6, AGENT, "10.9.9.9", tcp(8080), ihl=7), HOST, "eth0")
    assert record is not None and record["dport"] == 8080


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\x00" * 13,
        b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28,  # ARP
        b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 10,  # IPv4 header cut short
        b"\x00" * 12 + b"\x08\x00" + b"\x65" + b"\x00" * 30,  # version 6 under IPv4
        b"\x00" * 12 + b"\x86\xdd" + b"\x60" + b"\x00" * 20,  # IPv6 header cut short
    ],
)
def test_short_and_foreign_frames_are_ignored(canary: Canary, frame: bytes) -> None:
    assert canary.sniffer.inspect(frame, HOST, "eth0") is None


def test_icmp_and_cut_transport_headers_are_ignored(canary: Canary) -> None:
    assert canary.sniffer.inspect(ipv4(1, AGENT, "8.8.8.8", b"\x08\x00" * 4), HOST, "eth0") is None
    assert canary.sniffer.inspect(ipv4(6, AGENT, "8.8.8.8", tcp(443)[:10]), HOST, "eth0") is None
    assert canary.sniffer.inspect(ipv4(17, AGENT, "8.8.8.8", udp(53)[:6]), HOST, "eth0") is None


# --------------------------------------------------------------------------- DNS


def _handler() -> Any:
    return SimpleNamespace(client_address=(AGENT, 5353))


def _ask(canary: Canary, name: str, qtype: str = "A") -> Any:
    return canary.resolver.resolve(DNSRecord.question(name, qtype), _handler())


@pytest.mark.parametrize("name", ["tap", "TAP.", "tap."])
def test_tap_resolves_to_the_stub_and_is_not_recorded(canary: Canary, name: str) -> None:
    reply = _ask(canary, name)
    assert [str(rr.rdata) for rr in reply.rr] == [str(STUB)]
    assert canary.records() == []


@pytest.mark.parametrize("name", ["api.openai.com", "tap.evil.test", "xtap", "localhost"])
def test_every_other_name_resolves_to_the_canary_and_is_recorded(canary: Canary, name: str) -> None:
    reply = _ask(canary, name)
    assert [str(rr.rdata) for rr in reply.rr] == [str(OWN)]
    (record,) = canary.records()
    assert (record["kind"], record["qname"], record["qtype"], record["src"]) == (
        "dns",
        f"{name}.",
        "A",
        AGENT,
    )


def test_other_record_types_get_an_empty_answer_but_are_recorded(canary: Canary) -> None:
    reply = _ask(canary, "example.com", "AAAA")
    assert reply.rr == [] and reply.header.rcode == RCODE.NOERROR
    assert canary.records()[0]["qtype"] == "AAAA"
    assert _ask(canary, "example.com", "TXT").rr == []


def test_a_packet_mixing_tap_with_another_name_is_recorded(canary: Canary) -> None:
    request = DNSRecord.question("tap")
    request.add_question(DNSRecord.question("example.com").q)
    canary.resolver.resolve(request, _handler())
    assert [r["qname"] for r in canary.records()] == ["tap.", "example.com."]


def test_an_unparsable_question_is_still_recorded(canary: Canary) -> None:
    packet = (
        struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
        + b"\x03\xffab\x04test\x00"
        + b"\x00\x01\x00\x01"
    )
    reply = canary.resolver.reply_unparsable(packet, _handler())
    assert reply is not None and DNSRecord.parse(reply).header.rcode == RCODE.FORMERR
    (record,) = canary.records()
    assert record["qname"] == "\\255ab.test." and record["qtype"] == QTYPE[1]


def test_allow_list_parsing() -> None:
    assert _allowed(["tap=172.18.0.2", "x=fd00::1"]) == {
        "tap": STUB,
        "x": ipaddress.ip_address("fd00::1"),
    }
    for bad in (["tap"], ["=1.2.3.4"], ["tap=not-an-ip"]):
        with pytest.raises(ValueError):
            _allowed(bad)
