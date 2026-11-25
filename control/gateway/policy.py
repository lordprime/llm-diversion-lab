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
  gateway and Ollama could each see a different model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "ALLOWED_ENDPOINTS",
    "LITELLM_PREFIXES",
    "Decision",
    "Endpoint",
    "EndpointPolicy",
    "Listing",
    "ModelPolicy",
    "ModelRefused",
    "Ruling",
    "normalise_model",
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


#: Prefixes LiteLLM-based clients put in front of an Ollama model id. Exactly one is
#: stripped before the comparison; nothing else is normalised.
LITELLM_PREFIXES: Final = ("ollama_chat/", "ollama/")

#: The top-level body fields that select the model, per path. Ollama's /api/show
#: still honours the deprecated ``name`` when ``model`` is empty.
_MODEL_FIELDS: Final = {"/api/show": ("model", "name")}
_DEFAULT_MODEL_FIELDS: Final = ("model",)
#: How much of an agent-chosen model id a refusal reason quotes.
_QUOTE_CHARS: Final = 80


def normalise_model(model: str) -> str:
    """Strip one LiteLLM prefix (``ollama/`` or ``ollama_chat/``); nothing else."""
    for prefix in LITELLM_PREFIXES:
        if model.startswith(prefix):
            return model.removeprefix(prefix)
    return model


class ModelRefused(Exception):
    """The request body names no granted model, or names it ambiguously."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Pairs(list[tuple[str, Any]]):
    """A JSON object kept as its raw key/value pairs, duplicates included."""


def _pairs(items: list[tuple[str, Any]]) -> _Pairs:
    return _Pairs(items)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


class ModelPolicy:
    """Checks that a request body names one of ``allowed``, and nothing else."""

    def __init__(self, allowed: frozenset[str]) -> None:
        self.allowed = frozenset(normalise_model(m) for m in allowed)

    def check(self, body: bytes, path: str) -> str | None:
        """The normalised model id, or ``None`` when the body names no model.

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
            model = normalise_model(value)
            if model not in self.allowed:
                raise ModelRefused(f"model {value[:_QUOTE_CHARS]!r} is not granted to this run")
            models.append(model)
        return models[0]

    @staticmethod
    def _parse(body: bytes) -> _Pairs:
        try:
            document = json.loads(
                body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ModelRefused("the request body is not one JSON object") from exc
        if not isinstance(document, _Pairs):
            raise ModelRefused("the request body is not one JSON object")
        return document
