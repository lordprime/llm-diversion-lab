"""Structured JSON logging for the control plane (docs/ENGINEERING_STANDARDS.md).

Call :func:`configure_logging` once at process start. After that, every log line,
from structlog loggers (:func:`get_logger`), plain ``logging`` loggers (the existing
modules, libraries) and uvicorn's own loggers, goes through **one** root handler and
comes out as **one redacted JSON object per line**: ``event``, ``level``, ``logger``,
``timestamp`` (ISO 8601, UTC), any bound fields, and ``exception`` when there is one.

:func:`configure_logging` therefore *replaces* every root handler, strips the handlers
off the ``uvicorn*`` loggers and makes them propagate, and warns (as a JSON line) about
any other logger that still has a handler of its own, since that logger's lines bypass
redaction.

Running under uvicorn
---------------------
``uvicorn.run(...)`` and the ``uvicorn`` CLI apply their own ``log_config`` (plain-text
handlers on ``uvicorn``, ``uvicorn.error`` and ``uvicorn.access``, ``propagate=False``)
**before** importing the app. So either call :func:`configure_logging` and then
``uvicorn.run(app, log_config=None)``, or (with the CLI, which cannot disable it) call
:func:`configure_logging` at app import time, which runs after uvicorn's config and so
wins. Access-log lines then go through the redaction below (``?api_key=...`` masked).

Run scope
---------
Inside ``with run_scope(run_id=..., experiment_id=..., component=...):`` every line,
from any logger, carries those three fields (they live in contextvars, so they follow
the current thread / asyncio task). Scopes nest and restore the outer values on exit.
:func:`bind_component` tags lines outside a run.

Redaction
---------
:func:`redact`, the last processor before rendering, rewrites every value in the event
(the message, bound fields, nested dicts/lists/tuples, bytes, the rendered traceback):

* any match of :data:`REDACTION_PATTERNS` becomes ``[REDACTED:<pattern name>]``; text
  in a group named ``keep`` (an auth scheme, ``://``, ``?api_key=``, ``password=``) is
  kept in front of the mask;
* the value of any field whose *name* is sensitive (:func:`is_sensitive_key`) becomes
  ``[REDACTED]`` whatever it looks like. This applies to dict keys at any depth (str or
  bytes) and to ``(name, value)`` pairs in lists, the shape of raw header lists.

A name is sensitive if, lowercased with ``-`` read as ``_``, it *contains* one of
:data:`SENSITIVE_KEY_PARTS` (``password``, ``secret``, ``api_key``, ``authorization``,
``cookie``, ``credential``...) or *ends with* ``_token``, unless it is in
:data:`NON_SECRET_KEYS`: ``token`` and ``callback_token`` are the run's callback token,
which is evidence the analysis relies on (it is an HMAC of the run id, not a
credential), so it stays readable. ``*_url`` / ``*_dsn`` values are not masked as a
whole (they are useful), but their ``user:password@`` part is, by the
``url_userinfo`` pattern, wherever it appears.

AWS secret access keys (40 base64-ish characters with no fixed prefix) are only matched
after an AWS/secret context (``aws_secret_access_key=``, ``secret access key:``...), so
40-hex SHA-1 / git object ids elsewhere are never masked.
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
    "NON_SECRET_KEYS",
    "REDACTED",
    "REDACTION_PATTERNS",
    "RUN_FIELDS",
    "SENSITIVE_KEY_PARTS",
    "bind_component",
    "configure_logging",
    "get_logger",
    "is_sensitive_key",
    "redact",
    "redact_text",
    "run_scope",
]

REDACTED = "[REDACTED]"

_SENSITIVE_NAME = r"[\w-]*(?:password|passwd|secret|api[_-]?key|private[_-]?key|credential)[\w-]*"

#: ``(name, pattern)``, applied in order (specific shapes before generic ones). A match
#: becomes ``[REDACTED:<name>]``, preceded by the text of a group named ``keep``.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
        ),
    ),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}")),
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_\-]{16,}")),
    ("stripe", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}")),
    ("xai", re.compile(r"\bxai-[A-Za-z0-9]{20,}")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?i)(?P<keep>(?:aws[_\- ]?secret(?:[_\- ]?access)?(?:[_\- ]?key)?"
            r"|secret[_\- ]?access[_\- ]?key)[\"']?\s*[:=]\s*[\"']?)"
            r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # ``scheme://user:password@host``: mask the userinfo, keep the scheme and host.
    # Greedy up to the *last* ``@`` before the path, so a password containing ``@``
    # is masked whole.
    ("url_userinfo", re.compile(r"(?P<keep>://)[^\s/:@]+:[^\s/]+(?=@)")),
    # ``?api_key=...`` / ``&token=...`` in URLs and access-log request lines.
    (
        "query_param",
        re.compile(
            r"(?i)(?P<keep>[?&;](?:[\w-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token"
            r"|id[_-]?token|secret|password|passwd|signature|credential)[\w-]*"
            r"|key|sig|token|auth|code)=)[^&;#\s\"']+"
        ),
    ),
    # ``Authorization: Bearer|Basic|Token|Digest <credential>``: keep the scheme.
    ("auth_scheme", re.compile(r"(?i)\b(?P<keep>(?:bearer|basic|token|digest)\s+)\S+")),
    # ``DB_PASSWORD=...`` / ``"client_secret": "..."`` in free text (env dumps, reprs).
    (
        "assignment",
        re.compile(
            rf"(?i)(?P<keep>\b{_SENSITIVE_NAME}[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED)[^\s\"',;&]+"
        ),
    ),
)

#: A field name containing any of these (lowercased, ``-`` read as ``_``) is sensitive.
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "credential",
    "session_key",
)
#: Field names that look sensitive but are evidence (the callback token), never masked.
NON_SECRET_KEYS: frozenset[str] = frozenset({"token", "callback_token"})

#: The context fields every line inside a run's scope carries.
RUN_FIELDS = ("run_id", "experiment_id", "component")
#: Marks the root handler installed by :func:`configure_logging`.
_HANDLER_FLAG = "_lab_structlog_handler"


def redact_text(text: str) -> str:
    """``text`` with every secret-shaped substring masked."""
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


def _as_text(value: bytes | bytearray | memoryview) -> str:
    return bytes(value).decode("utf-8", errors="replace")


def is_sensitive_key(key: object) -> bool:
    """Whether a field named ``key`` (str or bytes) always has its value masked."""
    if isinstance(key, bytes | bytearray | memoryview):
        key = _as_text(key)
    if not isinstance(key, str):
        return False
    name = key.strip().lower().replace("-", "_")
    if name in NON_SECRET_KEYS:
        return False
    return name.endswith("_token") or any(part in name for part in SENSITIVE_KEY_PARTS)


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return redact_text(_as_text(value))
    if isinstance(value, dict):
        return {_key(k): REDACTED if is_sensitive_key(k) else _scrub(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        if len(value) == 2 and is_sensitive_key(value[0]):
            # A ``(name, value)`` pair, e.g. one raw header.
            return [_scrub(value[0]), REDACTED]
        return [_scrub(v) for v in value]
    if isinstance(value, set | frozenset):
        return [_scrub(v) for v in value]
    # Anything else would be rendered with repr()/str() by the JSON renderer: render it
    # here so the text is scrubbed too.
    return redact_text(str(value))


def _key(key: Any) -> Any:
    """Dict keys as JSON can render them: bytes decoded, text scrubbed."""
    if isinstance(key, bytes | bytearray | memoryview):
        return redact_text(_as_text(key))
    return redact_text(key) if isinstance(key, str) else key


def redact(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor: mask secrets anywhere in the event (see the module doc)."""
    return {k: REDACTED if is_sensitive_key(k) else _scrub(v) for k, v in event_dict.items()}


# --------------------------------------------------------------------- configuration


def _shared_processors() -> list[Processor]:
    """Run for every line, structlog-native or stdlib, before the formatter."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]


def _is_uvicorn(name: str) -> bool:
    return name == "uvicorn" or name.startswith("uvicorn.")


def configure_logging(*, level: int | str = "INFO", stream: IO[str] | None = None) -> None:
    """Send all logging (structlog, stdlib, uvicorn) to ``stream`` as redacted JSON.

    ``stream`` defaults to stderr. Replaces every root handler (idempotent), routes the
    ``uvicorn*`` loggers through the root, and warns about any other logger that keeps
    a handler of its own (its lines would bypass redaction).
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
    root.handlers[:] = [handler]
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

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name)  # make sure they exist, so the sweep below covers them
    bypassing: list[str] = []
    for name, logger in list(root.manager.loggerDict.items()):
        if not isinstance(logger, logging.Logger):  # a PlaceHolder: no handlers
            continue
        if _is_uvicorn(name):
            logger.handlers[:] = []
            logger.propagate = True
        elif any(not isinstance(h, logging.NullHandler) for h in logger.handlers):
            bypassing.append(name)
    if bypassing:
        logging.getLogger(__name__).warning(
            "loggers with their own handlers bypass JSON redaction: %s",
            ", ".join(sorted(bypassing)),
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
