"""Structured JSON logging for the control plane (docs/ENGINEERING_STANDARDS.md).

Call :func:`configure_logging` once at process start. After that, both structlog
loggers (:func:`get_logger`) and plain ``logging`` loggers (the existing modules,
uvicorn, libraries) emit **one JSON object per line** through a single root handler:
``event``, ``level``, ``logger``, ``timestamp`` (ISO 8601, UTC), any bound fields, and
``exception`` when there is one.

Run scope
---------
Inside ``with run_scope(run_id=..., experiment_id=..., component=...):`` every line,
from either kind of logger, carries those three fields (they live in contextvars, so
they follow the current thread / asyncio task). Scopes nest and restore the outer
values on exit. :func:`bind_component` tags lines outside a run.

Redaction
---------
:func:`redact`, the last processor before rendering, rewrites every string in the
event (the message, bound fields, nested dicts/lists, the rendered traceback):

* any match of :data:`REDACTION_PATTERNS` becomes ``[REDACTED:<pattern name>]``
  (for bearer tokens the ``Bearer`` scheme is kept);
* the value of any field whose name is in :data:`SENSITIVE_KEYS` (``api_key``,
  ``authorization``, ``password``...) becomes ``[REDACTED]`` whatever it looks like.

``token`` is deliberately *not* a sensitive key: in this project it is the callback
token, which is evidence.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Callable, Iterator, MutableMapping
from contextlib import contextmanager
from typing import IO, Any

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

__all__ = [
    "REDACTED",
    "REDACTION_PATTERNS",
    "SENSITIVE_KEYS",
    "bind_component",
    "configure_logging",
    "get_logger",
    "redact",
    "redact_text",
    "run_scope",
]

REDACTED = "[REDACTED]"

#: ``(name, pattern)``, applied in order (specific shapes before generic ones). A match
#: becomes ``[REDACTED:<name>]``; text captured by a group named ``keep`` (the
#: ``Bearer`` scheme) is kept in front of it.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}")),
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
        ),
    ),
    ("bearer", re.compile(r"(?i)\b(?P<keep>bearer\s+)[A-Za-z0-9\-._~+/]+=*")),
)

#: Field names (lowercased, ``-`` read as ``_``) whose values are always masked.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "x_api_key",
        "authorization",
        "proxy_authorization",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "private_key",
        "cookie",
        "set_cookie",
    }
)

#: The context fields every line inside a run's scope carries.
RUN_FIELDS = ("run_id", "experiment_id", "component")
#: Marks the root handler installed by :func:`configure_logging`.
_HANDLER_FLAG = "_lab_structlog_handler"


def redact_text(text: str) -> str:
    """``text`` with every provider-key-shaped substring masked."""
    for name, pattern in REDACTION_PATTERNS:
        mask = f"[REDACTED:{name}]"
        if "keep" in pattern.groupindex:
            text = pattern.sub(_keep_then(mask), text)
        else:
            text = pattern.sub(mask, text)
    return text


def _keep_then(mask: str) -> Callable[[re.Match[str]], str]:
    def replace(match: re.Match[str]) -> str:
        return match.group("keep") + mask

    return replace


def _is_sensitive(key: object) -> bool:
    return isinstance(key, str) and key.lower().replace("-", "_") in SENSITIVE_KEYS


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, dict):
        return {k: REDACTED if _is_sensitive(k) else _scrub(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub(v) for v in value]
    # Anything else would be rendered with repr()/str() by the JSON renderer: render it
    # here so the text is scrubbed too.
    return redact_text(str(value))


def redact(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor: mask secrets anywhere in the event (see the module doc)."""
    return {k: REDACTED if _is_sensitive(k) else _scrub(v) for k, v in event_dict.items()}


# --------------------------------------------------------------------- configuration


def _shared_processors() -> list[Processor]:
    """Run for every line, structlog-native or stdlib, before the formatter."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]


def configure_logging(*, level: int | str = "INFO", stream: IO[str] | None = None) -> None:
    """Send all logging, structlog and stdlib, to ``stream`` (default stderr) as JSON.

    Idempotent: calling it again replaces the handler it installed before (other root
    handlers, e.g. pytest's, are left alone).
    """
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    setattr(handler, _HANDLER_FLAG, True)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_shared_processors(),
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.format_exc_info,
                redact,
                structlog.processors.JSONRenderer(sort_keys=True),
            ],
        )
    )

    root = logging.getLogger()
    root.handlers[:] = [h for h in root.handlers if not getattr(h, _HANDLER_FLAG, False)]
    root.addHandler(handler)
    root.setLevel(level.upper() if isinstance(level, str) else level)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *_shared_processors(),
            structlog.processors.StackInfoRenderer(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """A structlog logger named ``name`` (rendered as the ``logger`` field)."""
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger


# --------------------------------------------------------------------- context


def _require(fields: MutableMapping[str, str]) -> None:
    for key, value in fields.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a non-empty string, got {value!r}")


@contextmanager
def run_scope(*, run_id: str, experiment_id: str, component: str) -> Iterator[None]:
    """Bind ``run_id``, ``experiment_id`` and ``component`` to every line in the block."""
    fields = {"run_id": run_id, "experiment_id": experiment_id, "component": component}
    _require(fields)
    with structlog.contextvars.bound_contextvars(**fields):
        yield


@contextmanager
def bind_component(component: str) -> Iterator[None]:
    """Bind only ``component`` (for work outside any run)."""
    _require({"component": component})
    with structlog.contextvars.bound_contextvars(component=component):
        yield
