"""DNS callback catcher: a dnslib resolver that answers every name with one fixed IP.

Every agent container in the cell resolves through the catcher (Docker's embedded DNS
still answers cell service names first). For every question it records, on stream
``catcher-dns`` (:mod:`cell.catcher.callback_log`), one :class:`Callback` with the
qname exactly as received (case kept, trailing dot), the qtype name (``A``,
``AAAA``, ``TXT``, ``TYPE65``...) and the source IP, and only then answers:

* an ``A`` (or ``ANY``) question with ``LAB_CATCHER_IP`` if it is IPv4, an ``AAAA``
  (or ``ANY``) question with it if it is IPv6, TTL 0;
* any other question with an empty ``NOERROR``;
* a packet with no question with ``FORMERR`` (nothing to record);
* a packet dnslib refuses to parse (e.g. a label that is not valid UTF-8, such as
  ``\\xff.cb.lab.test``) with ``FORMERR`` carrying the request id, after
  :class:`LenientDNSHandler` has parsed its first question leniently from the wire
  (:func:`lenient_question`; non-printable bytes rendered as ``\\DDD``, dnslib's own
  escaping) and recorded it. Only packets without even a readable first question
  (truncated header or name, compression pointer in the name, no qtype) stay
  unrecorded; dnslib logs those as errors.

The token is extracted from any label after lowercasing the qname, because resolvers
may randomise case (0x20 encoding); it is set only if it verifies against the run's
manifest. If the event cannot be stored the resolver prints
``catcher: cannot record DNS question ...`` to stderr
(:func:`~cell.catcher.callback_log.report_record_failure`) and raises, and no answer
is sent; the runner marks the run ``RECORDING_FAILED``, so evidence loss is loud.

DNS over TCP is bounded: a connection must deliver its query within
:data:`TCP_TIMEOUT_S` or it is dropped, and at most :data:`MAX_TCP_CONNECTIONS` are
served at once (more are closed at once), so idle connections cannot pile up threads
until the container's ``pids_limit`` stops every new lookup.

Run (one process per cell; UDP and TCP share one resolver and one ``seq`` counter)::

    python -m cell.catcher.dns_server

with the :class:`~cell.catcher.callback_log.CatcherConfig` variables plus
``LAB_CATCHER_IP`` (required), ``LAB_CATCHER_DNS_PORT`` (default ``53``) and
``LAB_CATCHER_BIND`` (default all interfaces).
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import threading
from datetime import UTC, datetime
from functools import partial
from typing import Any, Final

from dnslib import (  # type: ignore[import-untyped]
    AAAA,
    QTYPE,
    RCODE,
    RR,
    A,
    DNSError,
    DNSHeader,
    DNSLabel,
    DNSRecord,
)
from dnslib.buffer import BufferError as DNSBufferError  # type: ignore[import-untyped]
from dnslib.server import DNSHandler, DNSLogger, DNSServer  # type: ignore[import-untyped]

from cell.catcher.callback_log import (
    CATCHER_DNS_STREAM,
    DNS_EVENTS_FILE,
    CallbackLog,
    CatcherConfig,
    parse_port,
    report_record_failure,
)
from cell.catcher.classify import TokenIndex
from control.core.models import Callback, CallbackChannel

__all__ = [
    "DNS_TTL",
    "MAX_TCP_CONNECTIONS",
    "TCP_TIMEOUT_S",
    "CatcherIp",
    "CatcherResolver",
    "LenientDNSHandler",
    "answer",
    "dns_callback",
    "lenient_question",
    "main",
    "parse_catcher_ip",
]

#: TTL of every answer: 0, so each lookup reaches the catcher again.
DNS_TTL: Final = 0
#: Seconds a DNS-over-TCP client has for each read and write before it is dropped.
TCP_TIMEOUT_S: float = 5.0
#: DNS-over-TCP connections served at once; more are closed without an answer.
MAX_TCP_CONNECTIONS: int = 32

CatcherIp = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_catcher_ip(value: str | None) -> CatcherIp:
    """Parse ``LAB_CATCHER_IP``: the one address every name resolves to."""
    if not value or not value.strip():
        raise ValueError("LAB_CATCHER_IP: not set")
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError(f"LAB_CATCHER_IP: not an IP address: {value!r}") from None


def qtype_name(qtype: int) -> str:
    """The mnemonic of a numeric qtype (``TYPE<n>`` when dnslib has none)."""
    return str(QTYPE[qtype])


def answer(request: Any, catcher_ip: CatcherIp) -> Any:
    """The reply to ``request`` (a dnslib ``DNSRecord``): every name -> ``catcher_ip``."""
    reply = request.reply()
    if not request.questions:
        reply.header.rcode = RCODE.FORMERR
        return reply
    if catcher_ip.version == 4:
        wanted, rtype, rdata = (QTYPE.A, QTYPE.ANY), QTYPE.A, A(str(catcher_ip))
    else:
        wanted, rtype, rdata = (QTYPE.AAAA, QTYPE.ANY), QTYPE.AAAA, AAAA(str(catcher_ip))
    for question in request.questions:
        if question.qtype in wanted:
            reply.add_answer(RR(question.qname, rtype, rdata=rdata, ttl=DNS_TTL))
    return reply


def lenient_question(data: bytes) -> tuple[int, str, int] | None:
    """``(id, qname, qtype)`` of a packet's first question, read straight from the wire.

    Unlike dnslib it accepts any label bytes; the qname is rendered with dnslib's own
    escaping (printable ASCII kept, every other byte as ``\\DDD``) and a trailing dot.
    Returns ``None`` if there is no question or it cannot be read: a short header, a
    truncated name or qtype, or a compression pointer (never valid in a first question).
    """
    if len(data) < 12:
        return None
    qid, _flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount == 0:
        return None
    labels: list[bytes] = []
    offset = 12
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        label = data[offset : offset + length]
        if len(label) < length:
            return None
        labels.append(label)
        offset += length
    if offset + 2 > len(data):
        return None
    (qtype,) = struct.unpack("!H", data[offset : offset + 2])
    return qid, str(DNSLabel(labels)), qtype


def dns_callback(
    seq: int,
    *,
    run_id: str,
    ts: datetime,
    qname: str,
    qtype: str,
    source_ip: str | None,
    tokens: TokenIndex,
) -> Callback:
    """The :class:`Callback` event for one question (pure). ``qname`` is kept as received."""
    match = tokens.find([qname.lower()])
    return Callback(
        run_id=run_id,
        stream=CATCHER_DNS_STREAM,
        seq=seq,
        ts=ts,
        channel=CallbackChannel.DNS,
        source_ip=source_ip,
        token=match[0] if match else None,
        placement_id=match[1] if match else None,
        qname=qname,
        qtype=qtype,
    )


def _source_ip(handler: Any) -> str | None:
    address = getattr(handler, "client_address", None)
    if isinstance(address, tuple) and address:
        return str(address[0])
    return None


class CatcherResolver:
    """dnslib resolver (duck-typed ``resolve``): record every question, then answer."""

    def __init__(
        self, config: CatcherConfig, catcher_ip: CatcherIp, log: CallbackLog | None = None
    ) -> None:
        self._config = config
        self._ip = catcher_ip
        self._log = log or CallbackLog(
            config.run_id, CATCHER_DNS_STREAM, config.evidence_dir / DNS_EVENTS_FILE
        )

    @property
    def log(self) -> CallbackLog:
        return self._log

    def record_question(
        self, qname: str, qtype: str, source_ip: str | None, ts: datetime
    ) -> Callback:
        """Record one question on the ``catcher-dns`` stream.

        If it cannot, prints the recording-failure marker and raises.
        """
        build = partial(
            dns_callback,
            run_id=self._config.run_id,
            ts=ts,
            qname=qname,
            qtype=qtype,
            source_ip=source_ip,
            tokens=self._config.tokens,
        )
        try:
            return self._log.record(build)
        except Exception as exc:
            report_record_failure("DNS question", exc)
            raise

    def resolve(self, request: Any, handler: Any) -> Any:
        ts = datetime.now(UTC)
        source_ip = _source_ip(handler)
        for question in request.questions:
            self.record_question(str(question.qname), qtype_name(question.qtype), source_ip, ts)
        return answer(request, self._ip)

    def reply_unparsable(self, data: bytes, handler: Any) -> bytes | None:
        """Record a packet dnslib cannot parse and return a ``FORMERR`` for it.

        ``None`` if not even its first question can be read (nothing is recorded).
        """
        parsed = lenient_question(data)
        if parsed is None:
            return None
        qid, qname, qtype = parsed
        self.record_question(qname, qtype_name(qtype), _source_ip(handler), datetime.now(UTC))
        reply = DNSRecord(DNSHeader(id=qid, qr=1, aa=1, ra=1, rcode=RCODE.FORMERR))
        packed: bytes = reply.pack()
        return packed


class LenientDNSHandler(DNSHandler):  # type: ignore[misc]
    """dnslib request handler that also records packets dnslib refuses to parse.

    dnslib rejects any label that is not valid UTF-8 before the resolver runs; this
    handler catches that, records the question via
    :meth:`CatcherResolver.reply_unparsable` and answers ``FORMERR``.

    TCP connections get a socket timeout (:data:`TCP_TIMEOUT_S`) and one of
    :data:`MAX_TCP_CONNECTIONS` slots; without a free slot a connection is closed at
    once. A timed-out connection is dropped quietly.
    """

    _tcp_slots: threading.BoundedSemaphore = threading.BoundedSemaphore(MAX_TCP_CONNECTIONS)

    def handle(self) -> None:
        if self.server.socket_type != socket.SOCK_STREAM:
            super().handle()
            return
        slots = type(self)._tcp_slots
        if not slots.acquire(blocking=False):
            return  # over the cap: the connection is closed without an answer
        try:
            self.request.settimeout(TCP_TIMEOUT_S)
            super().handle()
        except TimeoutError:
            return  # a client that did not send (or read) in time: drop it
        finally:
            slots.release()

    def get_reply(self, data: bytes) -> bytes:
        try:
            DNSRecord.parse(data)
        except (DNSError, DNSBufferError):
            resolver = self.server.resolver
            if isinstance(resolver, CatcherResolver):
                reply = resolver.reply_unparsable(data, self)
                if reply is not None:
                    return reply
            raise
        packed: bytes = super().get_reply(data)
        return packed


# --------------------------------------------------------------------------- entrypoint


def main() -> None:  # pragma: no cover - exercised in the cell, not in unit tests

    config = CatcherConfig.from_env(os.environ)
    ip = parse_catcher_ip(os.environ.get("LAB_CATCHER_IP"))
    port = parse_port(os.environ.get("LAB_CATCHER_DNS_PORT", "53"), "LAB_CATCHER_DNS_PORT")
    bind = os.environ.get("LAB_CATCHER_BIND", "")
    resolver = CatcherResolver(config, ip)
    logger = DNSLogger("-request,-reply")  # the JSONL is the record; keep errors
    tcp = DNSServer(
        resolver, port=port, address=bind, logger=logger, tcp=True, handler=LenientDNSHandler
    )
    udp = DNSServer(resolver, port=port, address=bind, logger=logger, handler=LenientDNSHandler)
    tcp.start_thread()
    udp.start()


if __name__ == "__main__":  # pragma: no cover
    main()
