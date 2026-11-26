"""What the gateway lets through: which endpoints, and which model.

Both checks are pure and work on what the client actually sent, before anything is
forwarded:

* :class:`EndpointPolicy` compares the request's *raw* path, byte for byte, with a
  short allow-list. Nothing is decoded or normalised first, so ``/api/../api/pull``,
  ``//api/pull``, ``/api/%70ull``, ``/api/chat/`` or ``/API/CHAT`` simply do not match.
  The gateway then forwards to the allow-listed path itself, never the client's string.
* :class:`ModelPolicy` reads the JSON body the way Ollama's Go decoder would, and only
  lets the run's own model through. Go's ``encoding/json`` matches object keys without
  regard to case and keeps the last duplicate, so a body with a second spelling of
  ``model`` (``Model``, ``MODEL``, a repeated key) is refused outright: otherwise the
  gateway and Ollama could each see a different model. The model id must equal a
  granted one exactly. Nothing is stripped or normalised: Ollama reads
  ``ollama/qwen3:14b`` as the model ``qwen3:14b`` of a namespace ``ollama``, another
  model, and LiteLLM-based clients drop their ``ollama/`` routing prefix themselves.

The parse is bounded so it can run off the event loop without starving it. CPython's
JSON scanner keeps the GIL while it builds strings, keys, literals and numbers in C,
so a worker thread parsing a crafted body would still freeze the loop. A body may
therefore hold at most :data:`MAX_JSON_CONTAINERS` arrays and objects and
:data:`MAX_JSON_SEPARATORS` commas and colons (about one per value, two per object
member), and numbers go through a Python hook. Both are counted before parsing, in
two steps: raw counts of the bytes (milliseconds; over-counts, because the ones
inside strings count too), and only when one passes its cap, an exact count that
skips strings and stops at the caps. Minified JavaScript that an agent fetched sits
in its history as strings full of braces and commas; it must pass. A body really
over a cap raises :class:`BodyTooComplex`, which is not a model refusal.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, cast

__all__ = [
    "ALLOWED_ENDPOINTS",
    "MAX_JSON_CONTAINERS",
    "MAX_JSON_SEPARATORS",
    "BodyTooComplex",
    "Decision",
    "Endpoint",
    "EndpointPolicy",
    "Listing",
    "ModelPolicy",
    "ModelRefused",
    "Ruling",
]


class Decision(StrEnum):
    """What the gateway does with a request."""

    #: forwarded unchanged (an inference call)
    ALLOW = "allow"
    #: answered only for the run's own model (a model list, or one model's details)
    ALLOW_FILTERED = "allow_filtered"
    #: refused with 404
    DENY = "deny"


class Listing(StrEnum):
    """A model list the gateway narrows to the run's models."""

    OLLAMA_TAGS = "ollama_tags"
    OPENAI_MODELS = "openai_models"


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One allowed route. ``names_model``: the body must name a granted model."""

    method: str
    path: str
    decision: Decision
    names_model: bool
    listing: Listing | None = None
    #: allowed only for a run whose grant includes embeddings
    embeddings: bool = False


@dataclass(frozen=True, slots=True)
class Ruling:
    """The policy's answer for one request, with a reason fit to send to the client."""

    decision: Decision
    reason: str
    endpoint: Endpoint | None = None


ALLOWED_ENDPOINTS: Final = (
    Endpoint("POST", "/api/chat", Decision.ALLOW, names_model=True),
    Endpoint("POST", "/api/generate", Decision.ALLOW, names_model=True),
    Endpoint("POST", "/v1/chat/completions", Decision.ALLOW, names_model=True),
    Endpoint("POST", "/v1/messages", Decision.ALLOW, names_model=True),
    Endpoint("POST", "/api/show", Decision.ALLOW_FILTERED, names_model=True),
    Endpoint(
        "GET", "/api/tags", Decision.ALLOW_FILTERED, names_model=False, listing=Listing.OLLAMA_TAGS
    ),
    Endpoint(
        "GET",
        "/v1/models",
        Decision.ALLOW_FILTERED,
        names_model=False,
        listing=Listing.OPENAI_MODELS,
    ),
    Endpoint("POST", "/api/embed", Decision.ALLOW, names_model=True, embeddings=True),
    Endpoint("POST", "/api/embeddings", Decision.ALLOW, names_model=True, embeddings=True),
    Endpoint("POST", "/v1/embeddings", Decision.ALLOW, names_model=True, embeddings=True),
)

#: A query string is passed on as sent (the Anthropic client adds ``?beta=true``), so
#: it may hold only plain ``name=value`` pairs: no ``/``, ``#``, ``?``, spaces or
#: control characters that could change how the upstream URL is read.
_QUERY: Final = re.compile(r"[A-Za-z0-9._~%&=+-]{0,2048}")


class EndpointPolicy:
    """Decides a request from its method, raw path and raw query string."""

    def __init__(self, endpoints: tuple[Endpoint, ...] = ALLOWED_ENDPOINTS) -> None:
        self._routes = {(e.method, e.path): e for e in endpoints}
        self._paths = frozenset(e.path for e in endpoints)

    def decide(
        self, method: str, path: str, query: str = "", *, embeddings: bool = False
    ) -> Ruling:
        """``path`` is the raw request path exactly as received (no query string)."""
        endpoint = self._routes.get((method, path))
        if endpoint is None:
            what = "method" if path in self._paths else "endpoint"
            return Ruling(Decision.DENY, f"{what} not allowed through the model gateway")
        if endpoint.embeddings and not embeddings:
            return Ruling(Decision.DENY, "endpoint not allowed: embeddings are not granted")
        if not _QUERY.fullmatch(query):
            return Ruling(Decision.DENY, "query string not allowed through the model gateway")
        return Ruling(endpoint.decision, "allowed", endpoint)


# --------------------------------------------------------------------------- models


#: The most arrays and objects a request body may hold. A real agent request has a
#: few per message and tool: a 15 MiB history of fetched JavaScript has 152. Each one
#: costs the parser an allocation; the object hook is Python code, so the GIL is
#: handed over between objects (100,000 small objects: about 11 ms at most).
MAX_JSON_CONTAINERS: Final = 100_000
#: The most commas and colons a body may hold outside strings: about one per value and
#: two per object member. CPython's JSON scanner builds strings, keys and literals in C
#: and keeps the GIL while it does, so this, not the body's size, bounds how long a
#: parse holds it. Measured on this host (Ryzen 7 5800H, CPython 3.12) at 150,000:
#: the worst body under 16 MiB (75,000 members with 200-byte keys) holds the GIL for
#: 45-50 ms and peaks at 40 MiB (tracemalloc); 150,000 short strings 11 ms and 9 MiB.
#: One object of 1.15 million members held it for 425 ms and took 176 MiB. The
#: JavaScript history above has a few hundred: its bulk is inside strings.
MAX_JSON_SEPARATORS: Final = 150_000
#: One step of the exact count, within a window of the body: any number of plain runs
#: (no quote, bracket, comma or colon) and whole strings, then one opening bracket,
#: comma or colon (group 1), or the quote of a string that does not end inside the
#: window (group 2). Possessive, so a failed match never backtracks.
_STEP: Final = re.compile(rb'(?:[^"\[{,:]++|"(?:[^"\\]++|\\.)*+")*+(?:([\[{,:])|("))?', re.S)
#: The inside of a string, up to its closing quote or the end of the window.
_INSIDE: Final = re.compile(rb'(?:[^"\\]++|\\.)*+', re.S)
#: How much of the body one regex call may scan. The regex engine keeps the GIL for a
#: whole call, so this bounds how long the event loop can wait on the count (about a
#: millisecond); a window is also what keeps a long or unterminated string linear. It
#: must be at least 2 bytes, so an escape (a backslash and one byte) always fits.
_WINDOW: Final = 64 << 10
_QUOTE: Final = ord('"')
_OPENERS: Final = frozenset(b"[{")

#: The top-level body fields that select the model, per path. Ollama's /api/show
#: still honours the deprecated ``name`` when ``model`` is empty.
_MODEL_FIELDS: Final = {"/api/show": ("model", "name")}
_DEFAULT_MODEL_FIELDS: Final = ("model",)
#: How much of an agent-chosen model id a refusal reason quotes.
_QUOTE_CHARS: Final = 80


class ModelRefused(Exception):
    """The request body names no granted model, or names it ambiguously."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BodyTooComplex(Exception):
    """The body holds more arrays and objects, or more values, than the gateway parses
    (not a model refusal: the gateway answers it with 413)."""

    def __init__(self, what: str) -> None:
        self.reason = f"body_too_complex: more than {what}"
        super().__init__(self.reason)


class _Pairs(list[tuple[str, Any]]):
    """A JSON object kept as its raw key/value pairs, duplicates included."""


def _pairs(items: list[tuple[str, Any]]) -> _Pairs:
    return _Pairs(items)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _number(text: str) -> int:
    # numbers are never a model; a Python hook lets other threads run between them
    return 0


class ModelPolicy:
    """Checks that a request body names one of ``allowed``, and nothing else."""

    def __init__(self, allowed: frozenset[str]) -> None:
        self.allowed = allowed

    def lists(self, name: str) -> bool:
        """Whether a model list entry is a granted model. An untagged grant (``qwen3``)
        is the ``:latest`` tag to Ollama, so it also matches ``qwen3:latest``."""
        if name in self.allowed:
            return True
        base, _, tag = name.rpartition(":")
        return tag == "latest" and base in self.allowed

    def check(self, body: bytes, path: str) -> str | None:
        """The model id, or ``None`` when the body names no model.

        Raises :class:`BodyTooComplex` for a body with more arrays and objects than
        :data:`MAX_JSON_CONTAINERS`, or more commas and colons than
        :data:`MAX_JSON_SEPARATORS`.

        Raises :class:`ModelRefused` for a body that is not one JSON object, for a
        model field that is not a string, is spelt twice or in another case, and for
        any model outside the grant.
        """
        document = self._parse(body)
        fields = _MODEL_FIELDS.get(path, _DEFAULT_MODEL_FIELDS)
        named = [(key, value) for key, value in document if key.casefold() in fields]
        if not named:
            return None
        keys = [key for key, _ in named]
        if any(key not in fields for key in keys) or len(set(keys)) != len(keys):
            raise ModelRefused("the model is named more than once or in another case")
        models: list[str] = []
        for _, value in named:
            if not isinstance(value, str):
                raise ModelRefused("the model must be a string")
            if value not in self.allowed:
                raise ModelRefused(f"model {value[:_QUOTE_CHARS]!r} is not granted to this run")
            models.append(value)
        return models[0]

    @staticmethod
    def count_structure(
        body: bytes,
        containers_cap: int = MAX_JSON_CONTAINERS,
        separators_cap: int = MAX_JSON_SEPARATORS,
    ) -> tuple[int, int]:
        """The arrays and objects, and the commas and colons, in ``body`` outside
        strings; counting stops as soon as either passes its cap.

        Strings are skipped whole, so brackets and separators inside them do not count.
        The body is read one window at a time, so each regex call is short and other
        threads (the event loop) get the GIL in between; a stretch of whole strings
        and plain bytes takes one call per window. Linear: well under a second for
        16 MiB.
        """
        containers = separators = pos = 0
        end = len(body)
        while pos < end:
            # both patterns match at least the empty string, so never None
            step = cast(re.Match[bytes], _STEP.match(body, pos, pos + _WINDOW))
            pos = step.end()
            if step.lastindex == 1:  # an opening bracket, a comma or a colon
                if body[pos - 1] in _OPENERS:
                    containers += 1
                else:
                    separators += 1
                if containers > containers_cap or separators > separators_cap:
                    break
            elif step.lastindex == 2:  # a string that runs past the window
                while pos < end and body[pos] != _QUOTE:
                    inside = cast(re.Match[bytes], _INSIDE.match(body, pos, pos + _WINDOW))
                    if inside.end() == pos:
                        break  # a backslash that ends the body
                    pos = inside.end()
                pos += 1  # past the closing quote
        return containers, separators

    @staticmethod
    def _parse(body: bytes) -> _Pairs:
        # cheap over-counts first: brackets and separators inside strings count too
        if (
            body.count(b"[") + body.count(b"{") > MAX_JSON_CONTAINERS
            or body.count(b",") + body.count(b":") > MAX_JSON_SEPARATORS
        ):
            containers, separators = ModelPolicy.count_structure(body)
            if containers > MAX_JSON_CONTAINERS:
                raise BodyTooComplex(f"{MAX_JSON_CONTAINERS} arrays and objects")
            if separators > MAX_JSON_SEPARATORS:
                raise BodyTooComplex(f"{MAX_JSON_SEPARATORS} values and object members")
        try:
            document = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=_reject_constant,
                parse_int=_number,
                parse_float=_number,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ModelRefused("the request body is not one JSON object") from exc
        if not isinstance(document, _Pairs):
            raise ModelRefused("the request body is not one JSON object")
        return document
