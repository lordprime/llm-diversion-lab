"""The gateway's endpoint and model policy, as pure functions of method, path and body."""

from __future__ import annotations

import json
import random
import threading
import time

import pytest

from control.gateway import policy as policy_module
from control.gateway.policy import (
    ALLOWED_ENDPOINTS,
    MAX_JSON_CONTAINERS,
    BodyTooComplex,
    Decision,
    EndpointPolicy,
    ModelPolicy,
    ModelRefused,
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


count_containers = ModelPolicy.count_containers
GRANT = ModelPolicy(frozenset({"qwen3:14b"}))


def _body(**fields: object) -> bytes:
    return json.dumps({"messages": [{"role": "user", "content": "hi"}], **fields}).encode()


def test_model_must_match_grant() -> None:
    assert GRANT.check(_body(model="qwen3:14b"), "/api/chat") == "qwen3:14b"


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
        # exact match only: Ollama reads "ollama/qwen3:14b" as namespace "ollama", another
        # model, and LiteLLM-based clients strip their routing prefix before sending
        "ollama/qwen3:14b",
        "ollama_chat/qwen3:14b",
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


def test_the_grant_is_compared_exactly_too() -> None:
    policy = ModelPolicy(frozenset({"ollama/qwen3:14b"}))
    with pytest.raises(ModelRefused):
        policy.check(_body(model="qwen3:14b"), "/api/chat")
    assert policy.check(_body(model="ollama/qwen3:14b"), "/api/chat") == "ollama/qwen3:14b"


def test_a_refusal_reason_names_the_model_but_stays_short() -> None:
    with pytest.raises(ModelRefused) as info:
        GRANT.check(_body(model="x" * 10_000), "/api/chat")
    assert len(info.value.reason) < 300


@pytest.mark.parametrize(
    "fill",
    [b"[]", b"{}", b'{"a":[]}', b"[[[]]]"],
)
def test_a_body_with_too_many_arrays_or_objects_is_too_complex(fill: bytes) -> None:
    # every container costs the parser an allocation the event loop's thread pays for
    # too (CPython's JSON scanner keeps the GIL); a body is bounded by their number
    count = MAX_JSON_CONTAINERS // fill.count(b"[" if b"[" in fill else b"{") + 10
    body = b'{"model": "qwen3:14b", "x": [' + b",".join([fill] * count) + b"]}"
    with pytest.raises(BodyTooComplex) as info:
        GRANT.check(body, "/api/chat")
    # not a model refusal: it must never read like a model swap
    assert not isinstance(info.value, ModelRefused)
    assert info.value.reason.startswith("body_too_complex")


#: Minified JavaScript, as an agent fetching a single-page app's bundles gets it: about
#: 95,000 ``[`` and ``{`` per MiB (real bundles hold 13,000 to 25,000).
MINIFIED_JS = 'function(e,t){return{a:[e,t],b:{c:e.d,f:"x"}}};var n={k:[1,{z:2}]};'


def js_history(target_bytes: int, model: str = "qwen3:14b") -> bytes:
    """An agent request whose history is tool results full of minified JavaScript."""
    script = MINIFIED_JS * 3_000
    messages: list[dict[str, object]] = []
    while sum(len(str(m["content"])) for m in messages) < target_bytes:
        messages.append({"role": "tool", "content": script})
        messages.append({"role": "assistant", "content": "ok", "tool_calls": []})
    return json.dumps({"model": model, "messages": messages}).encode()


def test_a_history_of_minified_javascript_passes() -> None:
    body = js_history(15 << 20)
    assert len(body) <= 16 << 20
    assert body.count(b"[") + body.count(b"{") > 5 * MAX_JSON_CONTAINERS  # raw over-count
    assert count_containers(body) < 1_000
    assert GRANT.check(body, "/api/chat") == "qwen3:14b"


def test_a_flood_of_strings_full_of_braces_passes() -> None:
    body = b'{"model": "qwen3:14b", "x": [' + b'"{",' * 3_900_000 + b'"[[{"]}'
    assert len(body) <= 16 << 20
    assert count_containers(body) == 2
    assert GRANT.check(body, "/api/chat") == "qwen3:14b"


@pytest.mark.parametrize(
    ("body", "count"),
    [
        (b'{"a":"{[\\"{","b":[{}]}', 3),
        (b'"\\\\"[{', 2),  # an escaped backslash ends the string
        (b'"\\\\"[[', 2),
        (b'"\\"[[', 0),  # an escaped quote does not: the rest is one open string
        (b'["' + b"x" * 5_000_000 + b'",[{]]', 3),  # a string longer than one window
        (b'["' + b"\\n" * 3_000_000 + b'",{}]', 2),  # escapes beyond one window
        # a window is 64 KiB from where a step starts: a short string across its edge,
        # an escaped backslash split by it, and plain runs longer than a window
        (b"[" + b"1," * 32_766 + b'"{[{[{[{",{', 2),
        (b"[" + b"1," * 32_766 + b'"ab\\\\"[', 2),
        (b"[" + b"1," * 32_766 + b'"ab\\"[",[', 2),
        (b"[" + b"1," * 100_000 + b'"[",[', 2),
        (b'["a\\', 1),  # a backslash ends the body inside a string
        (b"", 0),
        (b'"', 0),
        (b"\\", 0),
        (b"[\n{\t[", 3),
    ],
)
def test_the_exact_count_skips_strings(body: bytes, count: int) -> None:
    assert count_containers(body) == count


def _count_byte_by_byte(body: bytes) -> int:
    """The same count, the slow and obvious way."""
    count, index, in_string = 0, 0, False
    while index < len(body):
        byte = body[index : index + 1]
        if in_string and byte == b"\\":
            index += 2
            continue
        if byte == b'"':
            in_string = not in_string
        elif not in_string and byte in (b"[", b"{"):
            count += 1
        index += 1
    return count


def test_the_exact_count_agrees_with_a_byte_by_byte_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # tiny windows, so random bodies cross a window's edge everywhere: inside strings,
    # in escapes, on quotes and on brackets
    monkeypatch.setattr(policy_module, "_WINDOW", 7)
    rng = random.Random(20261126)  # noqa: S311 - reproducible test data, not secrets
    for _ in range(20_000):
        body = bytes(rng.choice(b'"\\[{a,]}\n') for _ in range(rng.randint(0, 50)))
        assert count_containers(body, cap=10**9) == _count_byte_by_byte(body), body


@pytest.mark.parametrize(
    "body",
    [
        b'"\\' * 5_000_000,  # quote, backslash: one unterminated string of escapes
        b'"' + b'\\"' * 5_000_000,
        b'"\\\n' * 4_000_000,
        b'{"x":"' + b"\\n" * 7_000_000 + b'"}',
        b'{"x":[' + b'"{",' * 4_000_000 + b'""]}',
        b"[" + b'"",' * 5_000_000 + b"]",
        b"[" + b'"\\n",' * 3_000_000 + b"]",
        # nothing to find for 14 MiB: one search over it held the GIL for 3 s
        b'{"s":"' + b"[" * (MAX_JSON_CONTAINERS + 5) + b'","x":[' + b"1," * 7_000_000 + b"1]}",
    ],
)
def test_the_exact_count_is_linear_on_hostile_strings(body: bytes) -> None:
    # an unbounded string pattern rescans to the end of the body from every quote of
    # an unterminated string (quadratic, hours for 16 MiB), and one regex call per
    # short string takes seconds for a flood of them; all of these take well under 1 s
    started = time.perf_counter()
    count_containers(body + b"[" * (MAX_JSON_CONTAINERS + 5))
    assert time.perf_counter() - started < 2.5


def test_the_exact_count_stops_past_the_cap() -> None:
    body = b"[" + b"[]," * 5_000_000
    assert count_containers(body) == MAX_JSON_CONTAINERS + 1


_BRACKETS_IN_A_STRING = b'{"s":"' + b"[" * (MAX_JSON_CONTAINERS + 5) + b'",'


@pytest.mark.parametrize(
    "body",
    [
        _BRACKETS_IN_A_STRING + b'"x":[' + b"1," * 8_000_000 + b"1]}",  # nothing to skip
        _BRACKETS_IN_A_STRING + b'"x":"' + b"y" * (16 << 20) + b'"}',  # one long string
        _BRACKETS_IN_A_STRING + b'"x":"' + b"\\n" * (8 << 20) + b'"}',  # all escapes
        _BRACKETS_IN_A_STRING + b'"x":[' + b'"{",' * 4_000_000 + b'""]}',
    ],
)
def test_the_exact_count_lets_other_threads_run(body: bytes) -> None:
    # The regex engine keeps the GIL for a whole call, and the count runs in a worker
    # thread next to the event loop: no single call may scan much. (One search across
    # 16 MiB with nothing to find held the GIL for about 0.13 s, far more on a busy
    # host.) This thread asks for the GIL every millisecond.
    worker = threading.Thread(target=count_containers, args=(body,))
    gaps: list[float] = []
    last = time.perf_counter()
    worker.start()  # the worker may take the GIL at once: this is already a gap
    while worker.is_alive():
        time.sleep(0.001)
        now = time.perf_counter()
        gaps.append(now - last)
        last = now
    worker.join()
    assert max(gaps) < 0.05, sorted(gaps)[-3:]


def test_a_realistic_large_body_is_well_inside_the_container_cap() -> None:
    history = [{"role": "user", "content": "x" * 16_000, "images": []} for _ in range(1000)]
    tools = [
        {"type": "function", "function": {"name": f"t{i}", "parameters": {}}} for i in range(200)
    ]
    body = json.dumps({"model": "qwen3:14b", "messages": history, "tools": tools}).encode()
    assert len(body) > 14 << 20
    assert GRANT.check(body, "/api/chat") == "qwen3:14b"
