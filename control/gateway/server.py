"""The gateway process: each listener in its own uvicorn server, in one event loop.

The proxy and the admin API never share a connection budget: cells can fill the
proxy's connection slots without the runner losing its admin API (grants, revokes,
the health check). Each app is also pinned to the address it listens on and answers
404 anywhere else, so the admin routes never exist on the cell-facing address.

The proxy's server closes any connection that does not deliver a complete request
head within ``header_timeout_s`` of opening or of its previous response: idle or
dripping sockets cannot hold its slots for long. (uvicorn's own keep-alive timeout is
cancelled by the first byte that arrives, so it does not cover a head that drips.)

Both servers ignore signals themselves; :meth:`Gateway.serve` stops both on SIGTERM
or SIGINT, and stops the other when one of them ends.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import socket
import threading
from collections.abc import Iterator
from typing import Any

import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol

from control.gateway.admin import AdminApi
from control.gateway.app import ModelProxy
from control.gateway.asgi import Refused
from control.gateway.config import GatewayConfig, Listener
from control.gateway.keys import RunKeys

__all__ = ["ADMIN_MAX_CONNECTIONS", "Gateway", "HeadDeadlineProtocol"]

log = logging.getLogger(__name__)

#: Open connections the admin listener takes: the runner needs a handful.
ADMIN_MAX_CONNECTIONS = 32


class HeadDeadlineProtocol(H11Protocol):
    """uvicorn's h11 protocol, plus a deadline for receiving each request head."""

    head_timeout_s: float = 10.0

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self._head_timer: asyncio.TimerHandle | None = None
        self._waiting_for: object = None
        super().connection_made(transport)
        self._arm()

    def _arm(self) -> None:
        """Start waiting for the next request head (after connecting or a response)."""
        self._disarm()
        self._waiting_for = self.cycle
        self._head_timer = self.loop.call_later(self.head_timeout_s, self._expire)

    def _disarm(self) -> None:
        if self._head_timer is not None:
            self._head_timer.cancel()
            self._head_timer = None

    def _expire(self) -> None:
        self._head_timer = None
        if not self.transport.is_closing():
            self.transport.close()

    def data_received(self, data: bytes) -> None:
        super().data_received(data)
        if self._head_timer is not None and self.cycle is not self._waiting_for:
            self._disarm()  # a complete head arrived: a new request cycle began

    def on_response_complete(self) -> None:
        super().on_response_complete()
        idle = self.cycle is None or self.cycle.response_complete
        if idle and not self.transport.is_closing():
            self._arm()

    def connection_lost(self, exc: Exception | None) -> None:
        self._disarm()
        super().connection_lost(exc)


class _Pinned:
    """Serves ``app`` only to connections that arrived on ``listener``."""

    def __init__(self, app: ASGIApp, listener: Listener) -> None:
        self._app = app
        self._listener = listener

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        server = scope.get("server")
        local = Listener(str(server[0]), int(server[1])) if server else None
        if scope["type"] == "lifespan" or local == self._listener:
            await self._app(scope, receive, send)
        elif scope["type"] == "http":
            await Refused(404, "no such listener").response()(scope, receive, send)


class _QuietServer(uvicorn.Server):
    """A uvicorn server that leaves signal handling to :class:`Gateway`."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


class Gateway:
    """The proxy and the admin API, each in its own server with its own budget."""

    def __init__(self, config: GatewayConfig, keys: RunKeys) -> None:
        self._config = config
        protocol = type(
            "ProxyProtocol", (HeadDeadlineProtocol,), {"head_timeout_s": config.header_timeout_s}
        )
        self._servers = (
            self._server(
                _Pinned(ModelProxy(config, keys), config.listen),
                limit_concurrency=config.max_connections,
                http=protocol,
            ),
            self._server(
                _Pinned(AdminApi(config, keys), config.admin_listen),
                limit_concurrency=ADMIN_MAX_CONNECTIONS,
            ),
        )

    @staticmethod
    def _server(app: ASGIApp, **options: Any) -> uvicorn.Server:
        return _QuietServer(
            uvicorn.Config(
                app,
                lifespan="on",
                log_config=None,
                access_log=False,  # the gateway logs each call itself, without headers
                proxy_headers=False,
                server_header=False,
                date_header=False,
                timeout_keep_alive=5,
                timeout_graceful_shutdown=10,
                **options,
            )
        )

    @property
    def started(self) -> bool:
        return all(server.started for server in self._servers)

    def stop(self) -> None:
        for server in self._servers:
            server.should_exit = True

    def sockets(self) -> list[socket.socket]:
        """Bind both listeners (IPv4, one address each): the proxy's, then the admin's."""
        return [
            socket.create_server((listener.host, listener.port), family=socket.AF_INET)
            for listener in (self._config.listen, self._config.admin_listen)
        ]

    async def serve(self, sockets: list[socket.socket] | None = None) -> None:
        proxy_socket, admin_socket = sockets if sockets is not None else self.sockets()
        if threading.current_thread() is threading.main_thread():
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self.stop)
        log.info(
            "gateway: proxy on %s, admin on %s, upstream %s",
            self._config.listen,
            self._config.admin_listen,
            self._config.upstream_base,
        )
        proxy, admin = self._servers
        tasks = [
            asyncio.create_task(proxy.serve(sockets=[proxy_socket])),
            asyncio.create_task(admin.serve(sockets=[admin_socket])),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            self.stop()  # one server ending (or failing) ends the other
            await asyncio.gather(*tasks)

    def run(self, sockets: list[socket.socket] | None = None) -> None:
        asyncio.run(self.serve(sockets))
