"""The gateway's configuration: where it listens, where Ollama is, and its limits.

:meth:`GatewayConfig.from_env` reads ``LAB_OLLAMA_URL``, ``LAB_GATEWAY_LISTEN`` (the
cell-facing address), ``LAB_GATEWAY_ADMIN_LISTEN`` (a control-plane address),
``LAB_GATEWAY_ADMIN_SECRET`` and the optional limits, each read from
``LAB_GATEWAY_<FIELD NAME IN CAPITALS>`` (``LAB_GATEWAY_MAX_INFLIGHT_PER_RUN``...). The
configuration refuses to exist with both listeners on one address and port, with the
admin listener on the cell-facing address, or with either on a wildcard address: the
admin API must never answer on the interface the cells reach.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any, Final
from urllib.parse import urlsplit

__all__ = [
    "LARGE_BODY_BYTES",
    "MIN_SECRET_CHARS",
    "GatewayConfig",
    "GatewayConfigError",
    "Listener",
]

MIN_SECRET_CHARS: Final = 32
#: A body above this size is "large": it counts against the large-body caps.
LARGE_BODY_BYTES: Final = 1 << 20


class GatewayConfigError(ValueError):
    """A gateway configuration that is missing, malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class Listener:
    """An IP address and port to listen on."""

    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def parse(cls, raw: str, name: str) -> Listener:
        """``<IPv4>:<port>``, as the deploy files write it."""
        host, colon, port = raw.rpartition(":")
        try:
            ipaddress.IPv4Address(host)
            number = int(port)
        except ValueError:
            raise GatewayConfigError(f"{name}: expected <IPv4>:<port>, got {raw!r}") from None
        if not colon or not 1 <= number <= 65535:
            raise GatewayConfigError(f"{name}: expected <IPv4>:<port>, got {raw!r}")
        return cls(host, number)

    def is_wildcard(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_unspecified
        except ValueError:
            return True  # not an IP literal: never a safe, single address


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Everything the gateway needs; refuses an unsafe combination at construction."""

    upstream: str
    listen: Listener
    admin_listen: Listener
    admin_secret: str = field(repr=False)
    #: The largest request body. Real agent traffic stays well below it: a 128k-token
    #: context is about 0.5 MB of text, and even a long history with tool output and a
    #: few base64 screenshots is a few MB. 16 MiB leaves room for that and keeps the
    #: memory the caps below allow small enough to size the container.
    max_body_bytes: int = 16 << 20
    #: How many large (over 1 MiB) bodies one run, and the whole gateway, may hold in
    #: memory at once. A 128k-token context is about 0.5 MB, so a large body is rare.
    #: Worst case held: 4 x 16 MiB plus 1 MiB for every other call (see the compose
    #: file for the measured memory).
    max_large_bodies_per_run: int = 2
    max_large_bodies: int = 4
    #: Calls one run may have open at once (an agent with a few sub-agents needs a
    #: handful); more get 429.
    max_inflight_per_run: int = 8
    #: Calls the whole gateway may have open at once, which is also the size of the
    #: connection pool to Ollama, so the pool never queues; more get 503.
    max_upstream_connections: int = 64
    #: Open connections on the cell-facing listener (idle ones included), in all and
    #: per peer address; more get the gateway's JSON 503. Each cell's tap is one peer,
    #: so 256 holds 8 cells at their full 32 (one runner per host runs one cell at a
    #: time); the per-peer cap must stay below the total.
    max_connections: int = 256
    max_connections_per_peer: int = 32
    #: A new or kept-alive connection must deliver a complete request head this fast.
    header_timeout_s: float = 10.0
    #: The request body must arrive within this time.
    body_timeout_s: float = 60.0
    #: Ollama must accept the connection in 5 s, send something at least every 10 min
    #: (a long prompt can take minutes before the first token) and finish in an hour.
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 600.0
    max_request_s: float = 3600.0

    def __post_init__(self) -> None:
        if self.admin_listen == self.listen:
            raise GatewayConfigError(
                f"the admin listener shares the proxy's address and port ({self.listen})"
            )
        if self.admin_listen.is_wildcard() or self.listen.is_wildcard():
            raise GatewayConfigError(
                "the proxy and the admin listener must each bind one IP address, never a "
                "wildcard: the admin API would then answer on the cell-facing interface"
            )
        if self.admin_listen.host == self.listen.host:
            raise GatewayConfigError(
                f"the admin listener must not be on the cell-facing address {self.listen.host}"
            )
        if len(self.admin_secret) < MIN_SECRET_CHARS:
            raise GatewayConfigError(
                f"the admin secret must have at least {MIN_SECRET_CHARS} characters"
            )
        parts = urlsplit(self.upstream)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            raise GatewayConfigError(
                f"the upstream must be a bare http(s)://host:port URL, got {self.upstream!r}"
            )
        for limit in self._limits():
            value = getattr(self, limit.name)
            if not math.isfinite(value) or value <= 0:
                raise GatewayConfigError(f"{limit.name} must be a positive, finite number")
        if self.max_inflight_per_run > self.max_upstream_connections:
            raise GatewayConfigError("max_inflight_per_run exceeds max_upstream_connections")
        if self.max_large_bodies_per_run > min(self.max_large_bodies, self.max_inflight_per_run):
            raise GatewayConfigError("max_large_bodies_per_run exceeds the other caps")
        if self.max_connections_per_peer >= self.max_connections:
            # one peer could then fill every slot again
            raise GatewayConfigError("max_connections_per_peer must be below max_connections")

    @classmethod
    def _limits(cls) -> list[Any]:
        """The numeric fields: every limit and timeout."""
        return [f for f in fields(cls) if f.type in ("int", "float")]

    @property
    def upstream_base(self) -> str:
        return self.upstream.rstrip("/")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GatewayConfig:
        def need(name: str) -> str:
            value = env.get(name, "")
            if not value:
                raise GatewayConfigError(f"{name} is not set")
            return value

        limits: dict[str, Any] = {}
        for limit in cls._limits():
            name = f"LAB_GATEWAY_{limit.name.upper()}"
            raw = env.get(name, "")
            if not raw:
                continue
            try:
                limits[limit.name] = int(raw) if limit.type == "int" else float(raw)
            except ValueError:
                raise GatewayConfigError(f"{name}: not a number: {raw!r}") from None
        return cls(
            upstream=need("LAB_OLLAMA_URL"),
            listen=Listener.parse(need("LAB_GATEWAY_LISTEN"), "LAB_GATEWAY_LISTEN"),
            admin_listen=Listener.parse(
                need("LAB_GATEWAY_ADMIN_LISTEN"), "LAB_GATEWAY_ADMIN_LISTEN"
            ),
            admin_secret=need("LAB_GATEWAY_ADMIN_SECRET"),
            **limits,
        )
