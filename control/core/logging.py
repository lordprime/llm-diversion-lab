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

* any match of :data:`REDACTION_PATTERNS` becomes ``[REDACTED:<pattern name>]``; text
  in a group named ``keep`` (an auth scheme, ``://``, ``?api_key=``, ``password=``,
  ``Set-Cookie:``) is kept in front of the mask. Every pattern is linear: bounded or
  possessive quantifiers only. The name-dependent ones (``assignment``,
  ``query_param``) match only *name + separator*, check the name in Python (the
  :func:`is_sensitive_key` rule for assignments) and consume the value only when the
  name is secret; a rejected match resumes right after its separator, so a value like
  ``DB_PASSWORD=x`` in ``msg=DB_PASSWORD=x`` is still scanned;
* redaction runs on the **whole** string before any cut (up to
  :data:`MAX_INPUT_CHARS`; beyond that, on a head and a tail window whose cut edges
  first drop their partial token), so a cut never splits a secret into a leaking
  prefix. The redacted string is then cut to :data:`HEAD_CHARS` +
  :data:`TRUNCATED` + :data:`TAIL_CHARS` (a traceback keeps its root cause and its
  final lines), dropping any token split at a cut;
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
    "HEAD_CHARS",
    "MAX_DEPTH",
    "MAX_INPUT_CHARS",
    "MAX_TEXT_CHARS",
    "NON_SECRET_KEYS",
    "REDACTED",
    "REDACTION_PATTERNS",
    "RENDER_ERROR_EVENT",
    "RUN_FIELDS",
    "SENSITIVE_KEY_PARTS",
    "TAIL_CHARS",
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
#: The patterns run on at most this much of a string: longer ones are redacted as a
#: head window and a tail window of half this size each (the timing tests prove every
#: pattern linear and fast at this size).
MAX_INPUT_CHARS = 64 * 1024
#: After redaction a string longer than this keeps its first :data:`HEAD_CHARS` and
#: last :data:`TAIL_CHARS` (so a traceback keeps its root cause and its final lines),
#: joined by :data:`TRUNCATED`. A token cut in half at either edge is dropped.
HEAD_CHARS = 12 * 1024
TAIL_CHARS = 4 * 1024
MAX_TEXT_CHARS = HEAD_CHARS + TAIL_CHARS
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
            r"|secret[_\- ]?access[_\- ]?key)[\"']?\s{0,64}+[:=]\s{0,64}+[\"']?)"
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
    # 1024 characters), keep the scheme and host.
    ("url_userinfo", re.compile(r"(?P<keep>://)[^\s/:@]{1,1024}+:[^\s/]{1,1024}(?=@)")),
    # Guarded patterns (see ``_GUARDED``): they match only ``name`` + separator, any
    # name; the name is checked in Python and only then is the value consumed. A
    # rejected name never consumes the value, so a secret inside it is still scanned.
    # ``?name=`` / ``&name=``:
    ("query_param", re.compile(r"(?P<keep>[?&;](?P<qname>[\w.\-]{1,256}+)=)")),
    # ``Authorization: Bearer|Basic|Token|Digest <credential>``: keep the scheme.
    (
        "auth_scheme",
        re.compile(r"(?i)\b(?P<keep>(?:bearer|basic|token|digest)[ \t]{1,64}+)\S++"),
    ),
    # ``NAME=`` / ``"name": "`` (whitespace, newlines included, around the separator):
    (
        "assignment",
        re.compile(
            r"(?P<keep>(?<![\w-])(?P<aname>[\w-]{1,256}+)[\"']?\s{0,64}+[:=]\s{0,64}+"
            r"(?P<quote>[\"']?))"
        ),
    ),
)

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
    """An assigned name is secret by the same rule as a field name."""
    return is_sensitive_key(match.group("aname"))


def _query_name_is_secret(match: re.Match[str]) -> bool:
    name = match.group("qname").lower()
    compact = _compact(name)
    return name in _QUERY_NAMES or any(p in compact for p in _QUERY_PARTS)


_UNQUOTED_VALUE = re.compile(r"[^\s\"',;&]++")
_QUOTED_VALUE = {q: re.compile(rf"[^{q}\r\n]{{1,4096}}+") for q in ("'", '"')}
_QUERY_VALUE = re.compile(r"[^&;#\s\"']++")
#: A value already masked by an earlier pattern, possibly behind its auth scheme.
_ALREADY_MASKED = re.compile(r"(?i)(?:(?:bearer|basic|token|digest)[ \t]{1,64}+)?\[REDACTED")


def _assignment_value(match: re.Match[str]) -> re.Pattern[str]:
    quote = match.group("quote")
    return _QUOTED_VALUE[quote] if quote else _UNQUOTED_VALUE


#: Patterns that match only ``name`` + separator: the check on the name, and the
#: pattern for the value that follows when the name is secret.
_GUARDED: dict[
    str,
    tuple[Callable[[re.Match[str]], bool], Callable[[re.Match[str]], re.Pattern[str]]],
] = {
    "assignment": (_assigned_is_secret, _assignment_value),
    "query_param": (_query_name_is_secret, lambda _match: _QUERY_VALUE),
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
    """``text`` with every secret-shaped substring masked, then cut to size.

    Redaction always runs before any cut that could split a secret: on the whole
    string up to :data:`MAX_INPUT_CHARS`, else on a head and a tail window of half that
    size whose cut edges first lose their partial token. The redacted result is then
    cut to :data:`HEAD_CHARS` + :data:`TRUNCATED` + :data:`TAIL_CHARS`, again dropping
    any token split at a cut.
    """
    if len(text) > MAX_INPUT_CHARS:
        half = MAX_INPUT_CHARS // 2
        text = _redact_all(_head(text, half)) + TRUNCATED + _redact_all(_tail(text, half))
    else:
        text = _redact_all(text)
    if len(text) <= MAX_TEXT_CHARS:
        return text
    return _head(text, HEAD_CHARS) + TRUNCATED + _tail(text, TAIL_CHARS)


def _head(text: str, size: int) -> str:
    """The first ``size`` characters, minus a token the cut splits."""
    if len(text) <= size:
        return text
    head = text[:size]
    if text[size].isspace() or head[-1].isspace():
        return head
    end = len(head)
    while end and not head[end - 1].isspace():
        end -= 1
    return head[:end]


def _tail(text: str, size: int) -> str:
    """The last ``size`` characters, minus a token the cut splits."""
    if len(text) <= size:
        return text
    tail = text[-size:]
    if text[-size - 1].isspace() or tail[0].isspace():
        return tail
    start = 0
    while start < len(tail) and not tail[start].isspace():
        start += 1
    return tail[start:]


def _redact_all(text: str) -> str:
    for name, pattern in REDACTION_PATTERNS:
        guarded = _GUARDED.get(name)
        if guarded is None:
            text = pattern.sub(_replacer(name, pattern), text)
        else:
            text = _scan_guarded(name, pattern, *guarded, text)
    return text


def _replacer(name: str, pattern: re.Pattern[str]) -> Callable[[re.Match[str]], str]:
    mask = f"[REDACTED:{name}]"
    has_keep = "keep" in pattern.groupindex

    def replace(match: re.Match[str]) -> str:
        return (match.group("keep") if has_keep else "") + mask

    return replace


def _scan_guarded(
    name: str,
    pattern: re.Pattern[str],
    is_secret: Callable[[re.Match[str]], bool],
    value_pattern: Callable[[re.Match[str]], re.Pattern[str]],
    text: str,
) -> str:
    """Mask the value after every secret ``name`` + separator match, in linear time.

    A match whose name is not secret is kept and the scan resumes right after its
    separator, so the value (which may itself hold ``secret=...``) is scanned too.
    """
    mask = f"[REDACTED:{name}]"
    out: list[str] = []
    pos = 0
    while (match := pattern.search(text, pos)) is not None:
        end = match.end()
        if is_secret(match) and not _ALREADY_MASKED.match(text, end):
            value = value_pattern(match).match(text, end)
            if value is not None and value.end() > end:
                out += (text[pos : match.start()], match.group("keep"), mask)
                pos = value.end()
                continue
        out.append(text[pos:end])
        pos = end
    out.append(text[pos:])
    return "".join(out)


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
