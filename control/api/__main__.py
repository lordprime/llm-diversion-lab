"""The Collector process: ``python -m control.api [--host H] [--port P]``.

:func:`~control.core.logging.configure_logging` runs **before** uvicorn, and uvicorn
runs with ``log_config=None``, so uvicorn's own and its access-log lines go through
the one redacting JSON handler (see control/core/logging.py, "Running under
uvicorn"). The database comes from ``$DATABASE_URL`` (libpq's ``PGPASSWORD`` can hold
the password, so it never has to sit in the URL).

Defaults to ``127.0.0.1:8000``; the control-plane compose file runs it on
``0.0.0.0:8000`` inside the container and publishes it on the host's loopback only.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

import uvicorn

from control.api.app import create_app
from control.core.logging import configure_logging

__all__ = ["main"]


def _port(value: str) -> int:
    port = int(value)
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError(f"not a TCP port: {value}")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m control.api", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    parser.add_argument("--port", type=_port, default=8000, help="listen port (default 8000)")
    parser.add_argument("--log-level", default="INFO", help="root log level (default INFO)")
    args = parser.parse_args(argv)

    configure_logging(level=args.log_level)
    uvicorn.run(
        create_app(),
        host=args.host,
        port=args.port,
        log_config=None,
        proxy_headers=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
