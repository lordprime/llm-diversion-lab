"""The egress canary of a smoke run: anything that reaches it is an escape attempt.

In a smoke run every DNS name except ``tap`` resolves to the canary, and the agent's
default route points at it, so whatever the agent tries to reach outside the stub model
ends up here. The canary writes one JSON line per attempt and never answers anything but
DNS:

* ``kind: dns``: a DNS question (UDP or TCP) for any name other than the allowed ones.
  It is answered with the canary's own address (the catcher's resolver code,
  :class:`cell.catcher.dns_server.CatcherResolver`, does the answering, including for
  packets dnslib can't parse), so the agent's next step, a connection, also lands here.
  Allowed names (``--allow tap=<stub ip>``) are answered with their address and not
  recorded.
* ``kind: tcp``: a TCP connection attempt (a SYN) to any address and port, seen on the
  wire with a raw packet socket, so a closed port is still caught (the kernel then
  refuses the connection, and the agent fails fast).
* ``kind: udp``: the first UDP datagram of each flow, to any address and port.

DNS sent to the canary itself is left to the resolver, which records the question
rather than the packet. Broadcast and multicast frames are ignored.

Each record has ``seq``, ``ts``, ``kind``, ``src``, ``dst``, ``dport``, ``qname`` and
``qtype`` (the last two only for ``dns``). An empty file means no egress was attempted.

Run as root, with only NET_RAW (the packet socket) and NET_BIND_SERVICE (port 53)::

    python -m agents.ci.canary.canary --record /tmp/canary.jsonl --allow tap=172.18.0.2
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import signal
import socket
import struct
import sys
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from dnslib.server import DNSLogger, DNSServer  # type: ignore[import-untyped]

from agents.ci.stub_model.server import RequestRecorder
from cell.catcher.dns_server import CatcherIp, CatcherResolver, LenientDNSHandler, answer

__all__ = ["CanaryResolver", "ConnectionSniffer", "main"]

_ETH_P_ALL: Final = 0x0003
_ETH_IPV4: Final = 0x0800
_ETH_IPV6: Final = 0x86DD
#: ``sll_pkttype`` of a frame addressed to this host (not broadcast, multicast or ours).
_PACKET_HOST: Final = 0
_TCP: Final = 6
_UDP: Final = 17
_SYN: Final = 0x02
_ACK: Final = 0x10
_DNS_PORT: Final = 53
#: Flows remembered for de-duplication; past this, every packet is recorded again.
_MAX_FLOWS: Final = 100_000


class EgressLog:
    """The canary's JSON lines, written through the stub's own line recorder."""

    def __init__(self, recorder: RequestRecorder) -> None:
        self._recorder = recorder

    def record(
        self,
        kind: str,
        src: str | None,
        dst: str | None,
        dport: int | None,
        qname: str | None = None,
        qtype: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "seq": self._recorder.next_seq(),
            "ts": datetime.now(UTC).isoformat(),
            "kind": kind,
            "src": src,
            "dst": dst,
            "dport": dport,
            "qname": qname,
            "qtype": qtype,
        }
        self._recorder.write(event)
        return event


class CanaryResolver(CatcherResolver):
    """The catcher's resolver, recording to the canary log and letting a few names through.

    It reuses the catcher's answering (every name -> one address, empty ``NOERROR`` for
    other record types) and its handling of packets dnslib refuses to parse; only where a
    question is recorded, and the allowed names, differ. The catcher's run evidence
    (manifest, tokens) does not exist in a smoke run, so its constructor is not used.
    """

    def __init__(self, own_ip: CatcherIp, log: EgressLog, allowed: Mapping[str, CatcherIp]) -> None:
        self._ip = own_ip
        self._egress = log
        self._allowed = {self.bare(name): ip for name, ip in allowed.items()}

    @staticmethod
    def bare(qname: str) -> str:
        return qname.lower().rstrip(".")

    def record_question(  # type: ignore[override]
        self, qname: str, qtype: str, source_ip: str | None, ts: datetime
    ) -> dict[str, Any]:
        return self._egress.record("dns", source_ip, str(self._ip), _DNS_PORT, qname, qtype)

    def resolve(self, request: Any, handler: Any) -> Any:
        names = {self.bare(str(q.qname)) for q in request.questions}
        if len(names) == 1 and (allowed := self._allowed.get(names.pop())) is not None:
            return answer(request, allowed)
        return super().resolve(request, handler)


class ConnectionSniffer:
    """Watches every frame that reaches the canary and records connection attempts."""

    def __init__(self, own_ip: CatcherIp, log: EgressLog) -> None:
        self._own = str(own_ip)
        self._log = log
        self._flows: set[tuple[str, str, int, int, int]] = set()

    def inspect(self, frame: bytes, pkttype: int, ifname: str) -> dict[str, Any] | None:
        """Record ``frame`` if it is a connection attempt; return the record, else ``None``."""
        if pkttype != _PACKET_HOST or ifname == "lo" or len(frame) < 14:
            return None
        parsed = self.parse(frame)
        if parsed is None:
            return None
        proto, src, dst, sport, dport, flags = parsed
        if proto == _TCP and (flags & (_SYN | _ACK)) != _SYN:
            return None  # only the opening SYN of a connection
        if dst == self._own and dport == _DNS_PORT:
            return None  # the resolver records the question itself
        flow = (src, dst, sport, dport, proto)
        if flow in self._flows:
            return None
        if len(self._flows) < _MAX_FLOWS:
            self._flows.add(flow)
        return self._log.record("tcp" if proto == _TCP else "udp", src, dst, dport)

    @staticmethod
    def parse(frame: bytes) -> tuple[int, str, str, int, int, int] | None:
        """``(protocol, src, dst, sport, dport, tcp_flags)`` of a TCP or UDP frame, or ``None``."""
        (ethertype,) = struct.unpack("!H", frame[12:14])
        packet = frame[14:]
        if ethertype == _ETH_IPV4 and len(packet) >= 20 and packet[0] >> 4 == 4:
            proto = packet[9]
            src, dst = (
                socket.inet_ntop(socket.AF_INET, packet[12:16]),
                socket.inet_ntop(socket.AF_INET, packet[16:20]),
            )
            payload = packet[(packet[0] & 0x0F) * 4 :]
        elif ethertype == _ETH_IPV6 and len(packet) >= 40 and packet[0] >> 4 == 6:
            proto = packet[6]
            src, dst = (
                socket.inet_ntop(socket.AF_INET6, packet[8:24]),
                socket.inet_ntop(socket.AF_INET6, packet[24:40]),
            )
            payload = packet[40:]
        else:
            return None
        if proto == _TCP and len(payload) >= 14:
            sport, dport = struct.unpack("!HH", payload[:4])
            return proto, src, dst, sport, dport, payload[13]
        if proto == _UDP and len(payload) >= 8:
            sport, dport = struct.unpack("!HH", payload[:4])
            return proto, src, dst, sport, dport, 0
        return None

    def run(self, raw: socket.socket) -> None:  # pragma: no cover - needs a raw socket
        """Read frames for ever; if that fails, the canary dies loudly instead of going blind."""
        try:
            while True:
                frame, address = raw.recvfrom(65535)
                self.inspect(frame, address[2], address[0])
        except BaseException as exc:
            print(f"canary: packet capture stopped: {exc!r}", file=sys.stderr, flush=True)
            os._exit(3)

    @staticmethod
    def open() -> socket.socket:  # pragma: no cover - needs NET_RAW
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(_ETH_P_ALL))


def _allowed(values: list[str]) -> dict[str, CatcherIp]:
    allowed: dict[str, CatcherIp] = {}
    for value in values:
        name, sep, ip = value.partition("=")
        if not sep or not name:
            raise ValueError(f"--allow wants name=ip, got {value!r}")
        allowed[name] = ipaddress.ip_address(ip)
    return allowed


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - CI only
    parser = argparse.ArgumentParser(description="Smoke-run egress canary.")
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--ready", type=Path, help="file created once the canary listens")
    parser.add_argument("--allow", action="append", default=[], metavar="NAME=IP")
    parser.add_argument("--ip", help="own address (default: what the hostname resolves to)")
    args = parser.parse_args(argv)
    try:
        own = ipaddress.ip_address(args.ip or socket.gethostbyname(socket.gethostname()))
        allowed = _allowed(args.allow)
    except (ValueError, OSError) as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return 2
    with args.record.open("a", encoding="utf-8") as stream:
        log = EgressLog(RequestRecorder(stream))
        resolver = CanaryResolver(own, log, allowed)
        quiet = DNSLogger("-request,-reply")
        for tcp in (False, True):
            DNSServer(
                resolver, port=_DNS_PORT, logger=quiet, tcp=tcp, handler=LenientDNSHandler
            ).start_thread()
        sniffer = ConnectionSniffer(own, log)
        threading.Thread(target=sniffer.run, args=(sniffer.open(),), daemon=True).start()
        if args.ready:
            args.ready.write_text(f"{own}\n", encoding="utf-8")
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        stop.wait()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
