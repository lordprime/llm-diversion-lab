"""The model gateway process: ``python -m control.gateway``.

Configuration comes from the environment (:meth:`GatewayConfig.from_env`):
``LAB_OLLAMA_URL``, ``LAB_GATEWAY_LISTEN`` (the cell-facing address),
``LAB_GATEWAY_ADMIN_LISTEN`` (a control-plane address), ``LAB_GATEWAY_ADMIN_SECRET``
(from lab.env) and the optional limits. Grants are mirrored to ``$DATABASE_URL`` and
reloaded at start, so a restart keeps the running runs' grants. The redacted JSON
logging is configured before anything else. Exit 2 on a bad configuration, 1 when the
grant store cannot be read.
"""

from __future__ import annotations

import argparse
import logging
import os
from collections.abc import Sequence

from control.core.logging import configure_logging
from control.db.engine import create_db_engine
from control.gateway.config import GatewayConfig, GatewayConfigError
from control.gateway.keys import PostgresGrantStore, RunKeys
from control.gateway.server import Gateway

__all__ = ["main"]

log = logging.getLogger("control.gateway")

#: libpq connect timeout of the grant store.
CONNECT_TIMEOUT_S = 5


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m control.gateway", description=__doc__)
    parser.add_argument("--log-level", default="INFO", help="root log level (default INFO)")
    args = parser.parse_args(argv)
    configure_logging(level=args.log_level)
    try:
        config = GatewayConfig.from_env(os.environ)
    except GatewayConfigError as exc:
        log.error("gateway: refusing to start: %s", exc)
        return 2
    try:
        engine = create_db_engine(connect_args={"connect_timeout": CONNECT_TIMEOUT_S})
        keys = RunKeys(PostgresGrantStore(engine))
        live = keys.load()
    except Exception:
        log.exception("gateway: cannot read the grant store; refusing to start")
        return 1
    log.info("gateway: %d live grants reloaded", live)
    Gateway(config, keys).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
