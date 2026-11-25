"""The gateway's endpoint and model policy, as pure functions of method, path and body."""

from __future__ import annotations

import json

import pytest

from control.gateway.policy import (
    ALLOWED_ENDPOINTS,
    Decision,
    EndpointPolicy,
    ModelPolicy,
    ModelRefused,
    normalise_model,
)

POLICY = EndpointPolicy()
METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT")

#: Ollama's management and introspection routes (and the OpenAI-compatible ones that
#: are not inference): none may ever pass, with any method.
MANAGEMENT = (
    "/api/pull",
    "/api/push",
    "/api/create",
    "/api/copy",
    "/api/delete",
    "/api/ps",
    "/api/version",
    "/api/blobs/sha256:" + "0" * 64,
    "/api/embed",
    "/api/embeddings",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/models/qwen3:14b",
    "/v1/messages/count_tokens",
    "/",
    "",
    "/metrics",
    "/admin/grants",
)

#: Path tricks that a lax router could resolve to an inference or management route.
PATH_TRICKS = (
    "/api/../api/pull",
    "/api/./chat",
    "//api/pull",
    "//api/chat",
    "/api/chat/",
    "/api/chat//",
    "/API/CHAT",
    "/Api/Chat",
    "/api/%63hat",
    "/api%2fchat",
    "/api/chat%00",
    "/api/chat;x=1",
    "/api/chat%2f..%2fpull",
    "/%2e%2e/api/pull",
    "/api/chat\x00",
    "/api/chat ",
    " /api/chat",
    "\\api\\chat",
    "http://ollama:11434/api/pull",
    "http://ollama:11434/api/chat",
    "api/chat",
    "*",
)


# --------------------------------------------------------------------------- endpoints


@pytest.mark.parametrize("path", MANAGEMENT)
@pytest.mark.parametrize("method", METHODS)
def test_denies_management_endpoints(method: str, path: str) -> None:
    ruling = POLICY.decide(method, path)
    assert ruling.decision is Decision.DENY
    assert ruling.endpoint is None
    assert ruling.reason


@pytest.mark.parametrize("path", PATH_TRICKS)
@pytest.mark.parametrize("method", ("GET", "POST"))
def test_path_tricks_are_denied(method: str, path: str) -> None:
    assert POLICY.decide(method, path).decision is Decision.DENY


@pytest.mark.parametrize(
    ("method", "path", "decision"),
    [
        ("POST", "/api/chat", Decision.ALLOW),
        ("POST", "/api/generate", Decision.ALLOW),
        ("POST", "/v1/chat/completions", Decision.ALLOW),
        ("POST", "/v1/messages", Decision.ALLOW),
        ("GET", "/api/tags", Decision.ALLOW_FILTERED),
        ("POST", "/api/show", Decision.ALLOW_FILTERED),
        ("GET", "/v1/models", Decision.ALLOW_FILTERED),
    ],
)
def test_inference_endpoints_are_allowed_with_their_method_only(
    method: str, path: str, decision: Decision
) -> None:
    ruling = POLICY.decide(method, path)
    assert ruling.decision is decision
    assert ruling.endpoint is not None and ruling.endpoint.path == path
    for other in METHODS:
        if other != method:
            assert POLICY.decide(other, path).decision is Decision.DENY, other
    # methods are case-sensitive in HTTP: a lower-case one is another method
    assert POLICY.decide(method.lower(), path).decision is Decision.DENY


def test_the_allow_list_is_exactly_the_plans() -> None:
    assert {(e.method, e.path) for e in ALLOWED_ENDPOINTS if not e.embeddings} == {
        ("POST", "/api/chat"),
        ("POST", "/api/generate"),
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/messages"),
        ("GET", "/api/tags"),
        ("POST", "/api/show"),
        ("GET", "/v1/models"),
    }


@pytest.mark.parametrize("path", ["/api/embed", "/api/embeddings", "/v1/embeddings"])
def test_embeddings_only_when_the_run_is_granted_them(path: str) -> None:
    assert POLICY.decide("POST", path).decision is Decision.DENY
    ruling = POLICY.decide("POST", path, embeddings=True)
    assert ruling.decision is Decision.ALLOW
    assert ruling.endpoint is not None and ruling.endpoint.names_model
    assert POLICY.decide("GET", path, embeddings=True).decision is Decision.DENY
    # embeddings never open a management route
    assert POLICY.decide("POST", "/api/pull", embeddings=True).decision is Decision.DENY


@pytest.mark.parametrize("query", ["", "beta=true", "a=1&b=2", "x=%20y", "k=v~-._"])
def test_plain_query_strings_pass(query: str) -> None:
    assert POLICY.decide("POST", "/v1/messages", query).decision is Decision.ALLOW


@pytest.mark.parametrize(
    "query",
    ["a=1#frag", "a=1 b", "a=\x00", "a=\r\nX: y", "a=1?b", "path=/api/pull", "x=<y>", "a" * 2049],
)
def test_odd_query_strings_are_denied(query: str) -> None:
    assert POLICY.decide("POST", "/v1/messages", query).decision is Decision.DENY


# --------------------------------------------------------------------------- models


GRANT = ModelPolicy(frozenset({"qwen3:14b"}))


def _body(**fields: object) -> bytes:
    return json.dumps({"messages": [{"role": "user", "content": "hi"}], **fields}).encode()


@pytest.mark.parametrize("model", ["qwen3:14b", "ollama/qwen3:14b", "ollama_chat/qwen3:14b"])
def test_model_must_match_grant(model: str) -> None:
    assert GRANT.check(_body(model=model), "/api/chat") == "qwen3:14b"


@pytest.mark.parametrize(
    "model",
    [
        "qwen3:32b",  # same name, another tag
        "qwen3",  # no tag: Ollama reads it as qwen3:latest
        "qwen3:latest",
        "Qwen3:14b",
        "QWEN3:14B",
        " qwen3:14b",
        "qwen3:14b ",
        "qwen3:14b\n",
        "registry.ollama.ai/library/qwen3:14b",
        "library/qwen3:14b",
        "ollama/ollama/qwen3:14b",
        "ollama_chat/ollama/qwen3:14b",
        "openai/qwen3:14b",
        "OLLAMA/qwen3:14b",
        "llama3:8b",
        "",
        "qwen3:14b\x00",
        "qwen3:14b@sha256:" + "0" * 64,
    ],
)
def test_any_other_model_is_refused(model: str) -> None:
    with pytest.raises(ModelRefused, match="not granted"):
        GRANT.check(_body(model=model), "/api/chat")


def test_a_missing_model_field_returns_none() -> None:
    assert GRANT.check(_body(), "/api/chat") is None
    assert GRANT.check(b"{}", "/v1/messages") is None


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"{",
        b'{"model": "qwen3:14b"',
        b"[]",
        b'["qwen3:14b"]',
        b'"qwen3:14b"',
        b"null",
        b"42",
        b"\xff\xfe{}",
        b'{"model": "qwen3:14b", "x": "\xff"}',
        '{"model": "qwen3:14b"}'.encode("utf-16"),
        b"[" * 100_000 + b"]" * 100_000,
        b'{"model": "qwen3:14b"} {"model": "llama3"}',
        b'{"model": NaN}',
    ],
)
def test_a_body_that_is_not_one_json_object_is_refused(body: bytes) -> None:
    with pytest.raises(ModelRefused):
        GRANT.check(body, "/api/chat")


@pytest.mark.parametrize(
    "body",
    [
        b'{"model": "qwen3:14b", "model": "llama3"}',
        b'{"model": "llama3", "model": "qwen3:14b"}',
        b'{"model": "qwen3:14b", "Model": "llama3"}',
        b'{"model": "qwen3:14b", "MODEL": "llama3"}',
        b'{"Model": "qwen3:14b"}',
        b'{"model": "qwen3:14b", "mod\\u0065l": "llama3"}',
        b'{"model": "qwen3:14b", "MOD\\u0045L": "llama3"}',
    ],
)
def test_smuggled_second_model_fields_are_refused(body: bytes) -> None:
    # Go's encoding/json (Ollama) matches keys case-insensitively and keeps the last
    # duplicate, so any second spelling of "model" could pick the model it serves.
    with pytest.raises(ModelRefused):
        GRANT.check(body, "/api/chat")


@pytest.mark.parametrize("value", [None, 1, True, ["qwen3:14b"], {"name": "qwen3:14b"}])
def test_a_model_that_is_not_a_string_is_refused(value: object) -> None:
    with pytest.raises(ModelRefused):
        GRANT.check(_body(model=value), "/api/chat")


def test_show_also_checks_the_deprecated_name_field() -> None:
    # Ollama's /api/show falls back to "name" when "model" is empty
    assert GRANT.check(b'{"name": "qwen3:14b"}', "/api/show") == "qwen3:14b"
    assert GRANT.check(b'{"model": "qwen3:14b", "name": "qwen3:14b"}', "/api/show")
    for body in (
        b'{"name": "llama3"}',
        b'{"model": "qwen3:14b", "name": "llama3"}',
        b'{"model": "", "name": "llama3"}',
        b'{"NAME": "llama3", "model": "qwen3:14b"}',
    ):
        with pytest.raises(ModelRefused):
            GRANT.check(body, "/api/show")
    # on the chat routes "name" is not a model selector
    assert GRANT.check(_body(model="qwen3:14b", name="x"), "/api/chat") == "qwen3:14b"


def test_nested_model_fields_are_not_the_request_model() -> None:
    body = _body(model="qwen3:14b", options={"model": "llama3", "MODEL": "x"})
    assert GRANT.check(body, "/api/chat") == "qwen3:14b"


def test_the_grant_itself_is_normalised() -> None:
    policy = ModelPolicy(frozenset({"ollama/qwen3:14b"}))
    assert policy.check(_body(model="qwen3:14b"), "/api/chat") == "qwen3:14b"
    assert policy.allowed == frozenset({"qwen3:14b"})


def test_a_refusal_reason_names_the_model_but_stays_short() -> None:
    with pytest.raises(ModelRefused) as info:
        GRANT.check(_body(model="x" * 10_000), "/api/chat")
    assert len(info.value.reason) < 300


@pytest.mark.parametrize(
    ("raw", "normal"),
    [
        ("ollama/qwen3:14b", "qwen3:14b"),
        ("ollama_chat/qwen3:14b", "qwen3:14b"),
        ("qwen3:14b", "qwen3:14b"),
        ("ollama/ollama/x", "ollama/x"),
        ("ollama_chat/ollama_chat/x", "ollama_chat/x"),
        ("ollamax/x", "ollamax/x"),
    ],
)
def test_normalisation_strips_one_litellm_prefix_only(raw: str, normal: str) -> None:
    assert normalise_model(raw) == normal
