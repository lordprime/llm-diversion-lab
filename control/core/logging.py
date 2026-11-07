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

Never leaking on failure
------------------------
Redaction and rendering never raise. If either fails (an object whose ``str()``
raises, a message whose ``%`` args do not fit...), the handler writes a fixed line
``{"event": "log_render_error", "level": ..., "logger": ..., "timestamp": ...}``
carrying **no** value from the record. :func:`configure_logging` also sets
``logging.raiseExceptions = False``, so a failing stream never makes ``logging`` print
the raw record to stderr.

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
(the message, bound fields, nested mappings/lists/tuples, bytes, the rendered
traceback):

* every string is first cut to :data:`MAX_TEXT_CHARS` (16 KiB) with a
  :data:`TRUNCATED` marker; then any match of :data:`REDACTION_PATTERNS` becomes
  ``[REDACTED:<pattern name>]``; text in a group named ``keep`` (an auth scheme,
  ``://``, ``?api_key=``, ``password=``, ``Set-Cookie:``) is kept in front of the mask.
  Every pattern is linear: bounded or possessive quantifiers only, and name-dependent
  patterns match any name and then check it in Python (no nested unbounded runs);
* the value of any field whose *name* is sensitive (:func:`is_sensitive_key`) becomes
  ``[REDACTED]`` whatever it looks like. This applies to the keys of any mapping
  (``dict``, ``MappingProxyType``, Starlette ``Headers``...) at any depth (str or bytes
  keys; other keys are stringified) and to ``(name, value)`` pairs in lists, the shape
  of raw header lists;
* nesting deeper than :data:`MAX_DEPTH` becomes ``"[depth]"`` and a container that
  contains itself becomes ``"[cycle]"``.

A name is sensitive if, with camelCase split (``accessToken`` → ``access_token``),
lowercased and ``-`` read as ``_``, it *contains* one of :data:`SENSITIVE_KEY_PARTS`
(``password``, ``secret``, ``api_key``, ``authorization``, ``cookie``, ``credential``...)
or *ends with* ``_token``, unless it is in :data:`NON_SECRET_KEYS`: ``token`` and
``callback_token`` are the run's callback token, which is evidence the analysis relies
on (it is an HMAC of the run id, not a credential), so it stays readable. ``*_url`` /
``*_dsn`` values are not masked as a whole (they are useful), but their
``user:password@`` part is, by the ``url_userinfo`` pattern, wherever it appears.

AWS secret access keys (40 base64-ish characters with no fixed prefix) are only matched
after an AWS/secret context (``aws_secret_access_key=``, ``secret access key:``...), so
40-hex SHA-1 / git object ids elsewhere are never masked.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from typing import IO, Any

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

__all__ = [
    "MAX_DEPTH",
    "MAX_TEXT_CHARS",
    "NON_SECRET_KEYS",
    "REDACTED",
    "REDACTION_PATTERNS",
    "RENDER_ERROR_EVENT",
    "RUN_FIELDS",
    "SENSITIVE_KEY_PARTS",
    "TRUNCATED",
    "bind_component",
    "configure_logging",
    "get_logger",
    "is_sensitive_key",
    "redact",
    "redact_text",
    "run_scope",
]

REDACTED = "[REDACTED]"
#: Every string is cut to this many characters before the patterns run.
MAX_TEXT_CHARS = 16 * 1024
TRUNCATED = "[truncated]"
#: Containers nested deeper than this are replaced by ``"[depth]"``.
MAX_DEPTH = 32
#: The ``event`` of the fixed line written when a record cannot be rendered safely.
RENDER_ERROR_EVENT = "log_render_error"

#: ``(name, pattern)``, applied in order (specific shapes before generic ones). A match
#: becomes ``[REDACTED:<name>]``, preceded by the text of a group named ``keep``.
#: All quantifiers are bounded or possessive, so every pattern runs in linear time.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----.*?"
            r"(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)",
            re.S,
        ),
    ),
    # ``Cookie:`` / ``Set-Cookie:`` header text: the rest of the line.
    (
        "cookie_header",
        re.compile(r"(?i)(?P<keep>\b(?:set-)?cookie[ \t]{0,8}+:[ \t]{0,8}+)[^\r\n]++"),
    ),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}+")),
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_\-]{16,}+")),
    ("stripe", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}+")),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}+")),
    ("xai", re.compile(r"\bxai-[A-Za-z0-9]{20,}+")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}+")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?i)(?P<keep>(?:aws[_\- ]?secret(?:[_\- ]?access)?(?:[_\- ]?key)?"
            r"|secret[_\- ]?access[_\- ]?key)[\"']?[ \t]{0,8}+[:=][ \t]{0,8}+[\"']?)"
            r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}+|github_pat_[A-Za-z0-9_]{22,}+)"),
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}+")),
    # Anchored on "not after a token character", so a run of ``eyJ-eyJ-...`` is
    # scanned once, not once per ``eyJ``.
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}+\.[A-Za-z0-9_\-]{8,}+\.[A-Za-z0-9_\-]{8,}+"
        ),
    ),
    # ``scheme://user:password@host``: mask the userinfo (up to the last ``@`` within
    # 256 characters), keep the scheme and host.
    ("url_userinfo", re.compile(r"(?P<keep>://)[^\s/:@]{1,256}+:[^\s/]{1,256}(?=@)")),
    # ``?name=value`` / ``&name=value``: any name, checked by ``_query_name_is_secret``.
    (
        "query_param",
        re.compile(r"(?P<keep>[?&;](?P<qname>[\w.\-]{1,64}+)=)(?P<value>[^&;#\s\"']++)"),
    ),
    # ``Authorization: Bearer|Basic|Token|Digest <credential>``: keep the scheme.
    (
        "auth_scheme",
        re.compile(r"(?i)\b(?P<keep>(?:bearer|basic|token|digest)[ \t]{1,16}+)\S++"),
    ),
    # ``NAME=value`` / ``"name": "value"``: any name, checked by ``_assigned_is_secret``.
    (
        "assignment",
        re.compile(
            r"(?P<keep>(?<![\w-])(?P<aname>[\w-]{1,128}+)[\"']?[ \t]{0,8}+[:=][ \t]{0,8}+[\"']?)"
            r"(?P<value>[^\s\"',;&]++)"
        ),
    ),
)

#: Compact (no ``_``/``-``, lowercased) name parts that make an assigned value secret.
_ASSIGNMENT_PARTS = ("password", "passwd", "secret", "apikey", "privatekey", "credential")
#: Compact query-parameter name parts, and exact names, that make a value secret.
_QUERY_PARTS = (
    "apikey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "secret",
    "password",
    "passwd",
    "signature",
    "credential",
)
_QUERY_NAMES = frozenset({"key", "sig", "token", "auth", "code"})


def _compact(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "").replace(".", "")


def _assigned_is_secret(match: re.Match[str]) -> bool:
    name = _compact(match.group("aname"))
    return any(p in name for p in _ASSIGNMENT_PARTS)


def _query_name_is_secret(match: re.Match[str]) -> bool:
    name = match.group("qname").lower()
    compact = _compact(name)
    return name in _QUERY_NAMES or any(p in compact for p in _QUERY_PARTS)


#: Patterns that match any name and then decide in Python whether it is secret.
_GUARDS: dict[str, Callable[[re.Match[str]], bool]] = {
    "assignment": _assigned_is_secret,
    "query_param": _query_name_is_secret,
}

#: A field name containing any of these (snake-cased, lowercased) is sensitive.
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
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def redact_text(text: str) -> str:
    """``text`` cut to :data:`MAX_TEXT_CHARS`, with every secret-shaped substring masked."""
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + TRUNCATED
    for name, pattern in REDACTION_PATTERNS:
        text = pattern.sub(_replacer(name, pattern), text)
    return text


def _replacer(name: str, pattern: re.Pattern[str]) -> Callable[[re.Match[str]], str]:
    mask = f"[REDACTED:{name}]"
    guard = _GUARDS.get(name)
    has_keep = "keep" in pattern.groupindex
    has_value = "value" in pattern.groupindex

    def replace(match: re.Match[str]) -> str:
        if guard is not None and not guard(match):
            return match.group(0)
        if has_value and match.group("value").startswith("[REDACTED"):
            return match.group(0)  # already masked by a more specific pattern
        return (match.group("keep") if has_keep else "") + mask

    return replace


def _as_text(value: bytes | bytearray | memoryview) -> str:
    return bytes(value).decode("utf-8", errors="replace")


def is_sensitive_key(key: object) -> bool:
    """Whether a field named ``key`` (str or bytes) always has its value masked."""
    if isinstance(key, bytes | bytearray | memoryview):
        key = _as_text(key)
    if not isinstance(key, str):
        return False
    name = _CAMEL_BOUNDARY.sub("_", key[:256].strip()).lower().replace("-", "_")
    name = name.replace(" ", "_")
    if name in NON_SECRET_KEYS:
        return False
    return name.endswith("_token") or any(part in name for part in SENSITIVE_KEY_PARTS)


def _key(key: Any) -> str:
    """A mapping key as JSON can render it: always a str, scrubbed."""
    if isinstance(key, bytes | bytearray | memoryview):
        return redact_text(_as_text(key))
    return redact_text(key if isinstance(key, str) else str(key))


def _scrub(value: Any, depth: int, path: frozenset[int]) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return redact_text(_as_text(value))
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        if id(value) in path:
            return "[cycle]"
        if depth > MAX_DEPTH:
            return "[depth]"
        inner = path | {id(value)}
        if isinstance(value, Mapping):
            return {
                _key(k): REDACTED if is_sensitive_key(k) else _scrub(v, depth + 1, inner)
                for k, v in value.items()
            }
        if isinstance(value, list | tuple) and len(value) == 2 and is_sensitive_key(value[0]):
            # A ``(name, value)`` pair, e.g. one raw header.
            return [_scrub(value[0], depth + 1, inner), REDACTED]
        return [_scrub(v, depth + 1, inner) for v in value]
    # Anything else would be rendered with repr()/str() by the JSON renderer: render it
    # here so the text is scrubbed too.
    return redact_text(str(value))


def redact(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor: mask secrets anywhere in the event (see the module doc)."""
    return {
        _key(k): REDACTED if is_sensitive_key(k) else _scrub(v, 1, frozenset())
        for k, v in event_dict.items()
    }


# --------------------------------------------------------------------- configuration


class _SafeFormatter(structlog.stdlib.ProcessorFormatter):
    """Never raises: a record that cannot be redacted and rendered becomes a fixed line."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            return super().format(record)
        except Exception:
            return _render_error_line(record)


def _render_error_line(record: logging.LogRecord) -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
    return json.dumps(
        {
            "event": RENDER_ERROR_EVENT,
            "level": str(record.levelname).lower(),
            "logger": str(record.name),
            "timestamp": f"{stamp}.{int(record.msecs):03d}Z",
        },
        sort_keys=True,
    )


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
    ``uvicorn*`` loggers through the root, warns about any other logger that keeps a
    handler of its own (its lines would bypass redaction), and sets
    ``logging.raiseExceptions = False`` so a failing write never echoes a raw record.
    """
    logging.raiseExceptions = False
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    setattr(handler, _HANDLER_FLAG, True)
    handler.setFormatter(
        _SafeFormatter(
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
