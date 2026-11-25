"""The whole gateway in a process of its own, for timing tests.

A test that measures how long the gateway's event loop stalls cannot share a process
(and a GIL) with its own clients or with the fake Ollama: their threads would stall
the measurement too, and in production Ollama is another process as well. Run as
``python -m tests.gateway.serve_gateway <upstream URL> <run_id>=<key>...``; it prints
one JSON line with the proxy and admin URLs, then serves until its stdin closes.
"""

from __future__ import annotations

import json
import secrets
import socket
import sys
import threading
from datetime import UTC, datetime, timedelta

from control.gateway.config import GatewayConfig, Listener
from control.gateway.keys import RunKeys, key_sha256
from control.gateway.server import Gateway

MODEL = "qwen3:14b"


def main(argv: list[str]) -> int:
    upstream, runs = argv[0], [arg.partition("=") for arg in argv[1:]]
    proxy_sock = socket.create_server(("127.0.0.1", 0))
    admin_sock = socket.create_server(("127.0.0.2", 0))
    config = GatewayConfig(
        upstream=upstream,
        listen=Listener("127.0.0.1", proxy_sock.getsockname()[1]),
        admin_listen=Listener("127.0.0.2", admin_sock.getsockname()[1]),
        admin_secret=secrets.token_urlsafe(32),
        max_request_s=60,
    )
    keys = RunKeys()
    for run_id, _, key in runs:
        keys.register(run_id, key_sha256(key), [MODEL], datetime.now(UTC) + timedelta(hours=1))
    gateway = Gateway(config, keys)
    thread = threading.Thread(target=gateway.run, args=([proxy_sock, admin_sock],))
    thread.start()
    while not gateway.started:
        if not thread.is_alive():
            return 1
        threading.Event().wait(0.01)
    urls = {"proxy": f"http://{config.listen}", "admin": f"http://{config.admin_listen}"}
    print(json.dumps(urls), flush=True)
    sys.stdin.read()  # until the test closes our stdin
    gateway.stop()
    thread.join(15)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
