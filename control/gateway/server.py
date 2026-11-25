"""The gateway process: both listeners in one uvicorn server.

Each connection is routed by the local address it arrived on, so the admin routes do
not exist on the cell-facing address at all, whatever path a client asks for.
"""

from __future__ import annotations

import logging
import socket

import uvicorn
from starlette.types import Receive, Scope, Send

from control.gateway.admin import AdminApi
from control.gateway.app import ModelProxy
from control.gateway.asgi import Refused, serve_lifespan
from control.gateway.config import GatewayConfig, Listener
from control.gateway.keys import RunKeys

__all__ = ["Gateway"]

log = logging.getLogger(__name__)


class Gateway:
    """Both listeners in one uvicorn server, each connection routed by its local address."""

    def __init__(self, config: GatewayConfig, keys: RunKeys) -> None:
        self._config = config
        self._proxy = ModelProxy(config, keys)
        self._admin = AdminApi(config, keys)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await serve_lifespan(receive, send, self._proxy.startup, self._proxy.shutdown)
            return
        server = scope.get("server")
        local = Listener(str(server[0]), int(server[1])) if server else None
        if local == self._config.listen:
            await self._proxy(scope, receive, send)
        elif local == self._config.admin_listen:
            await self._admin(scope, receive, send)
        elif scope["type"] == "http":
            await Refused(404, "no such listener").response()(scope, receive, send)

    def sockets(self) -> list[socket.socket]:
        """Bind both listeners (IPv4, one address each)."""
        return [
            socket.create_server((listener.host, listener.port), family=socket.AF_INET)
            for listener in (self._config.listen, self._config.admin_listen)
        ]

    def server(self) -> uvicorn.Server:
        return uvicorn.Server(
            uvicorn.Config(
                self,
                lifespan="on",
                log_config=None,
                access_log=False,  # the gateway logs each call itself, without headers
                proxy_headers=False,
                server_header=False,
                date_header=False,
                timeout_keep_alive=5,
                limit_concurrency=256,
                timeout_graceful_shutdown=10,
            )
        )

    def run(self, sockets: list[socket.socket] | None = None) -> None:
        bound = sockets if sockets is not None else self.sockets()
        log.info(
            "gateway: proxy on %s, admin on %s, upstream %s",
            self._config.listen,
            self._config.admin_listen,
            self._config.upstream_base,
        )
        self.server().run(sockets=bound)
