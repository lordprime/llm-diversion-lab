"""The gateway's configuration: where it listens, where Ollama is, and its limits.

:meth:`GatewayConfig.from_env` reads ``LAB_OLLAMA_URL``, ``LAB_GATEWAY_LISTEN`` (the
cell-facing address), ``LAB_GATEWAY_ADMIN_LISTEN`` (a control-plane address),
``LAB_GATEWAY_ADMIN_SECRET`` and the optional ``LAB_GATEWAY_*`` limits. The
configuration refuses to exist with both listeners on one address and port, with the
admin listener on the cell-facing address, or with either on a wildcard address: the
admin API must never answer on the interface the cells reach.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlsplit

__all__ = [
    "DEFAULT_BODY_TIMEOUT_S",
    "DEFAULT_CONNECT_TIMEOUT_S",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_REQUEST_S",
    "DEFAULT_READ_TIMEOUT_S",
    "MIN_SECRET_CHARS",
    "GatewayConfig",
    "GatewayConfigError",
    "Listener",
]

MIN_SECRET_CHARS: Final = 32
#: Defaults of the limits (LAB_GATEWAY_*): a 32 MiB body received within a minute;
#: Ollama must connect in 5 s, send something at least every 10 min (a long prompt
#: can take minutes before the first token) and finish within the hour.
DEFAULT_MAX_BODY_BYTES: Final = 32 << 20
DEFAULT_BODY_TIMEOUT_S: Final = 60.0
DEFAULT_CONNECT_TIMEOUT_S: Final = 5.0
DEFAULT_READ_TIMEOUT_S: Final = 600.0
DEFAULT_MAX_REQUEST_S: Final = 3600.0


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
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    body_timeout_s: float = DEFAULT_BODY_TIMEOUT_S
    connect_timeout_s: float = DEFAULT_CONNECT_TIMEOUT_S
    read_timeout_s: float = DEFAULT_READ_TIMEOUT_S
    max_request_s: float = DEFAULT_MAX_REQUEST_S

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
        numbers = (
            self.max_body_bytes,
            self.body_timeout_s,
            self.connect_timeout_s,
            self.read_timeout_s,
            self.max_request_s,
        )
        if any(n <= 0 for n in numbers):
            raise GatewayConfigError("limits and timeouts must be positive")

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

        def number(name: str, kind: Callable[[str], Any], default: Any) -> Any:
            raw = env.get(name, "")
            try:
                return kind(raw) if raw else default
            except ValueError:
                raise GatewayConfigError(f"{name}: not a number: {raw!r}") from None

        return cls(
            upstream=need("LAB_OLLAMA_URL"),
            listen=Listener.parse(need("LAB_GATEWAY_LISTEN"), "LAB_GATEWAY_LISTEN"),
            admin_listen=Listener.parse(
                need("LAB_GATEWAY_ADMIN_LISTEN"), "LAB_GATEWAY_ADMIN_LISTEN"
            ),
            admin_secret=need("LAB_GATEWAY_ADMIN_SECRET"),
            max_body_bytes=number("LAB_GATEWAY_MAX_BODY_BYTES", int, DEFAULT_MAX_BODY_BYTES),
            body_timeout_s=number("LAB_GATEWAY_BODY_TIMEOUT_S", float, DEFAULT_BODY_TIMEOUT_S),
            connect_timeout_s=number(
                "LAB_GATEWAY_CONNECT_TIMEOUT_S", float, DEFAULT_CONNECT_TIMEOUT_S
            ),
            read_timeout_s=number("LAB_GATEWAY_READ_TIMEOUT_S", float, DEFAULT_READ_TIMEOUT_S),
            max_request_s=number("LAB_GATEWAY_MAX_REQUEST_S", float, DEFAULT_MAX_REQUEST_S),
        )
