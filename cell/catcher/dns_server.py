"""DNS callback catcher: a dnslib resolver that answers every name with one fixed IP.

Every agent container in the cell resolves through the catcher (Docker's embedded DNS
still answers cell service names first). For every question it records, on stream
``catcher-dns`` (:mod:`cell.catcher.callback_log`), one :class:`Callback` with the
qname exactly as received (case kept, trailing dot), the qtype name (``A``,
``AAAA``, ``TXT``, ``TYPE65``...) and the source IP, and only then answers:

* an ``A`` (or ``ANY``) question with ``LAB_CATCHER_IP`` if it is IPv4, an ``AAAA``
  (or ``ANY``) question with it if it is IPv6, TTL 0;
* any other question with an empty ``NOERROR``;
* a packet with no question with ``FORMERR`` (nothing to record). Packets dnslib
  cannot parse never reach the resolver; dnslib logs them as errors.

The token is extracted from any label after lowercasing the qname, because resolvers
may randomise case (0x20 encoding); it is set only if it verifies against the run's
manifest. If the event cannot be stored the resolver raises and no answer is sent
(dnslib logs the error), so evidence loss is loud.

Run (one process per cell; UDP and TCP share one resolver and one ``seq`` counter)::

    python -m cell.catcher.dns_server

with the :class:`~cell.catcher.callback_log.CatcherConfig` variables plus
``LAB_CATCHER_IP`` (required), ``LAB_CATCHER_DNS_PORT`` (default ``53``) and
``LAB_CATCHER_BIND`` (default all interfaces).
"""

from __future__ import annotations

import ipaddress
import os
from datetime import UTC, datetime
from functools import partial
from typing import Any, Final

from dnslib import AAAA, QTYPE, RCODE, RR, A  # type: ignore[import-untyped]

from cell.catcher.callback_log import (
    CATCHER_DNS_STREAM,
    DNS_EVENTS_FILE,
    CallbackLog,
    CatcherConfig,
    parse_port,
)
from cell.catcher.classify import TokenIndex
from control.core.models import Callback, CallbackChannel

__all__ = [
    "DNS_TTL",
    "CatcherIp",
    "CatcherResolver",
    "answer",
    "dns_callback",
    "main",
    "parse_catcher_ip",
]

#: TTL of every answer: 0, so each lookup reaches the catcher again.
DNS_TTL: Final = 0

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

    def resolve(self, request: Any, handler: Any) -> Any:
        ts = datetime.now(UTC)
        source_ip = _source_ip(handler)
        for question in request.questions:
            self._log.record(
                partial(
                    dns_callback,
                    run_id=self._config.run_id,
                    ts=ts,
                    qname=str(question.qname),
                    qtype=qtype_name(question.qtype),
                    source_ip=source_ip,
                    tokens=self._config.tokens,
                )
            )
        return answer(request, self._ip)


# --------------------------------------------------------------------------- entrypoint


def main() -> None:  # pragma: no cover - exercised in the cell, not in unit tests
    from dnslib.server import DNSLogger, DNSServer  # type: ignore[import-untyped]

    config = CatcherConfig.from_env(os.environ)
    ip = parse_catcher_ip(os.environ.get("LAB_CATCHER_IP"))
    port = parse_port(os.environ.get("LAB_CATCHER_DNS_PORT", "53"), "LAB_CATCHER_DNS_PORT")
    bind = os.environ.get("LAB_CATCHER_BIND", "")
    resolver = CatcherResolver(config, ip)
    logger = DNSLogger("-request,-reply")  # the JSONL is the record; keep errors
    tcp = DNSServer(resolver, port=port, address=bind, logger=logger, tcp=True)
    udp = DNSServer(resolver, port=port, address=bind, logger=logger)
    tcp.start_thread()
    udp.start()


if __name__ == "__main__":  # pragma: no cover
    main()
