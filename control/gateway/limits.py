"""How many calls the gateway holds open at once: per run and in total.

One run must never be able to take what the others need: its open calls are capped
(429 beyond), and so are the large bodies it may hold in memory. The gateway-wide cap
on open calls equals the size of the connection pool to Ollama, so a call that gets
in always has a connection and the pool never queues (503 beyond).

Everything here runs on the event loop's thread, so plain counters suffice.
"""

from __future__ import annotations

from collections import Counter

from control.gateway.asgi import Refused
from control.gateway.config import GatewayConfig

__all__ = ["Call", "CallLimits"]


class Call:
    """One open call's share of the limits; :meth:`close` gives it back (idempotent)."""

    def __init__(self, limits: CallLimits, run_id: str) -> None:
        self._limits = limits
        self.run_id = run_id
        self.large = False
        self._open = True

    def hold_large(self) -> None:
        """Count this call's body as large, or refuse it with 429 or 503."""
        if not self.large:
            self._limits.take_large(self.run_id)
            self.large = True

    def close(self) -> None:
        if self._open:
            self._open = False
            self._limits.give_back(self)


class CallLimits:
    """The open-call and large-body counters, per run and gateway-wide."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._open: Counter[str] = Counter()
        self._large: Counter[str] = Counter()

    def open(self, run_id: str) -> Call:
        """Admit one more call of ``run_id``, or refuse it."""
        if self._open.total() >= self._config.max_upstream_connections:
            raise Refused(503, "the model gateway is busy; retry shortly")
        if self._open[run_id] >= self._config.max_inflight_per_run:
            raise Refused(
                429, f"this run already has {self._config.max_inflight_per_run} calls in flight"
            )
        self._open[run_id] += 1
        return Call(self, run_id)

    def take_large(self, run_id: str) -> None:
        if self._large.total() >= self._config.max_large_bodies:
            raise Refused(503, "the model gateway holds too many large bodies; retry shortly")
        if self._large[run_id] >= self._config.max_large_bodies_per_run:
            raise Refused(
                429,
                f"this run already has {self._config.max_large_bodies_per_run} large "
                "request bodies in flight",
            )
        self._large[run_id] += 1

    def give_back(self, call: Call) -> None:
        self._open[call.run_id] -= 1
        if self._open[call.run_id] <= 0:
            del self._open[call.run_id]
        if call.large:
            self._large[call.run_id] -= 1
            if self._large[call.run_id] <= 0:
                del self._large[call.run_id]
