"""Structured logging: JSON lines, run-scope context, secret redaction.

Key-shaped test values are assembled at runtime so no literal in this file looks like
a credential to a secret scanner.
"""

from __future__ import annotations

import collections
import copy
import io
import json
import logging
import logging.config
import re
import time
from collections.abc import Callable, Iterator
from types import MappingProxyType
from typing import Any

import pytest
import structlog
import uvicorn.config
from starlette.datastructures import Headers

from control.core.logging import (
    HEAD_CHARS,
    MAX_DEPTH,
    MAX_INPUT_CHARS,
    MAX_TEXT_CHARS,
    REDACTED,
    REDACTION_PATTERNS,
    TAIL_CHARS,
    TRUNCATED,
    bind_component,
    configure_logging,
    get_logger,
    is_sensitive_key,
    redact,
    redact_text,
    run_scope,
)

# Fake, key-shaped values (never real credentials), built so the source holds none.
ANTHROPIC_KEY = "sk-" + "ant-" + "api03-" + "A1b2C3d4E5f6G7h8I9j0" * 4
OPENAI_KEY = "sk-" + "proj-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2" * 2
AWS_KEY_ID = "AK" + "IA" + "IOSFODNN7EXAMPLE"
BEARER = "Bearer " + "eyJhbGciOiJIUzI1NiJ9" + ".e30." + "abc_DEF-123"
GOOGLE_KEY = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
GITHUB_TOKEN = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")
#: Lines ``configure_logging`` itself emits (the "bypassing handlers" warning).
SELF = "control.core.logging"


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved_uvicorn = {
        name: (logging.getLogger(name).handlers[:], logging.getLogger(name).propagate)
        for name in UVICORN_LOGGERS
    }
    saved_raise = logging.raiseExceptions
    buf = io.StringIO()
    configure_logging(stream=buf, level="DEBUG")
    try:
        yield buf
    finally:
        structlog.contextvars.clear_contextvars()
        structlog.reset_defaults()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        logging.raiseExceptions = saved_raise
        for name, (handlers, propagate) in saved_uvicorn.items():
            logging.getLogger(name).handlers[:] = handlers
            logging.getLogger(name).propagate = propagate


def _all_lines(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


def _lines(buf: io.StringIO) -> list[dict[str, Any]]:
    """The test's own lines (not configure_logging's warning about other loggers)."""
    return [line for line in _all_lines(buf) if line.get("logger") != SELF]


# --------------------------------------------------------------------- JSON output


def test_output_is_one_json_object_per_line(stream: io.StringIO) -> None:
    log = get_logger("test")
    log.info("first", n=1)
    log.warning("second", nested={"a": [1, 2]})

    lines = _lines(stream)
    assert [ln["event"] for ln in lines] == ["first", "second"]
    assert lines[0]["level"] == "info"
    assert lines[1]["level"] == "warning"
    assert lines[0]["n"] == 1
    assert lines[1]["nested"] == {"a": [1, 2]}
    assert lines[0]["logger"] == "test"
    assert lines[0]["timestamp"].endswith("Z")


def test_stdlib_logging_is_rendered_as_json_too(stream: io.StringIO) -> None:
    logging.getLogger("control.api.app").warning("readyz: database unavailable: %s", "X")

    (line,) = _lines(stream)
    assert line["event"] == "readyz: database unavailable: X"
    assert line["level"] == "warning"
    assert line["logger"] == "control.api.app"


def test_exceptions_are_rendered_inside_the_json(stream: io.StringIO) -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        get_logger("test").exception("failed")

    (line,) = _lines(stream)
    assert "ValueError: boom" in line["exception"]


def test_level_filter(stream: io.StringIO) -> None:
    configure_logging(stream=stream, level="WARNING")
    log = get_logger("test")
    log.info("hidden")
    log.warning("shown")
    assert [ln["event"] for ln in _lines(stream)] == ["shown"]


def test_reconfiguring_does_not_duplicate_lines(stream: io.StringIO) -> None:
    configure_logging(stream=stream, level="DEBUG")
    configure_logging(stream=stream, level="DEBUG")
    get_logger("test").info("once")
    assert len(_lines(stream)) == 1


# --------------------------------------------------------------------- run scope


def test_lines_in_run_scope_carry_run_id_experiment_id_and_component(
    stream: io.StringIO,
) -> None:
    log = get_logger("runner")
    log.info("before")
    with run_scope(run_id="run_01ABC", experiment_id="exp_01XYZ", component="runner"):
        log.info("inside")
        logging.getLogger("control.db.repo").info("stdlib inside")
    log.info("after")

    before, inside, stdlib_inside, after = _lines(stream)
    for line in (inside, stdlib_inside):
        assert line["run_id"] == "run_01ABC"
        assert line["experiment_id"] == "exp_01XYZ"
        assert line["component"] == "runner"
    for line in (before, after):
        assert "run_id" not in line
        assert "experiment_id" not in line


def test_nested_scope_restores_outer_context(stream: io.StringIO) -> None:
    log = get_logger("runner")
    with run_scope(run_id="run_A", experiment_id="exp_1", component="runner"):
        with run_scope(run_id="run_B", experiment_id="exp_1", component="collector"):
            log.info("inner")
        log.info("outer")

    inner, outer = _lines(stream)
    assert (inner["run_id"], inner["component"]) == ("run_B", "collector")
    assert (outer["run_id"], outer["component"]) == ("run_A", "runner")


def test_bind_component_outside_a_run(stream: io.StringIO) -> None:
    with bind_component("scheduler"):
        get_logger("x").info("tick")
    get_logger("x").info("untagged")

    tick, untagged = _lines(stream)
    assert tick["component"] == "scheduler"
    assert "component" not in untagged


@pytest.mark.parametrize("field", ["run_id", "experiment_id", "component"])
def test_run_scope_refuses_empty_fields(field: str) -> None:
    kwargs = {"run_id": "run_A", "experiment_id": "exp_1", "component": "runner", field: ""}
    with pytest.raises(ValueError, match=field), run_scope(**kwargs):
        pass


# --------------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "secret",
    [ANTHROPIC_KEY, OPENAI_KEY, AWS_KEY_ID, GOOGLE_KEY, GITHUB_TOKEN],
    ids=["anthropic", "openai", "aws", "google", "github"],
)
def test_key_shaped_strings_are_redacted(stream: io.StringIO, secret: str) -> None:
    log = get_logger("test")
    log.info(f"calling provider with {secret}", key=secret, headers={"x": [secret]})

    raw = stream.getvalue()
    assert secret not in raw
    (line,) = _lines(stream)
    assert "[REDACTED" in line["event"]
    assert "[REDACTED" in line["key"]
    assert "[REDACTED" in line["headers"]["x"][0]
    assert line["event"].startswith("calling provider with ")


def test_bearer_token_is_masked_but_scheme_kept(stream: io.StringIO) -> None:
    get_logger("test").info("request", header_line=f"Authorization: {BEARER}")

    raw = stream.getvalue()
    token = BEARER.removeprefix("Bearer ")
    assert token not in raw
    (line,) = _lines(stream)
    assert line["header_line"].startswith("Authorization: Bearer [REDACTED")


def test_sensitive_field_names_are_masked_whatever_the_value(stream: io.StringIO) -> None:
    fields = {
        "api_key": "hunter2-not-key-shaped",
        "password": "pw",
        "X-Api-Key": "v",
        "token": "tok123",
    }
    get_logger("test").info("cfg", **fields)
    (line,) = _lines(stream)
    assert line["api_key"] == line["password"] == line["X-Api-Key"] == "[REDACTED]"
    # ``token`` is the callback token in this project: evidence, not a secret.
    assert line["token"] == fields["token"]


def test_stdlib_lines_and_exceptions_are_redacted(stream: io.StringIO) -> None:
    logging.getLogger("lib").error("upstream said %s", AWS_KEY_ID)
    try:
        raise RuntimeError(f"bad key {ANTHROPIC_KEY}")
    except RuntimeError:
        get_logger("test").exception("failed")

    raw = stream.getvalue()
    assert AWS_KEY_ID not in raw
    assert ANTHROPIC_KEY not in raw
    assert len(_lines(stream)) == 2


def test_redact_text_leaves_ordinary_text_alone() -> None:
    text = "run_01J8Z3 skipped: task-oriented sk-ip mask AKIA-short Bearer"
    assert redact_text(text) == text


def test_redact_processor_walks_nested_structures() -> None:
    event = {"event": "x", "deep": {"list": [AWS_KEY_ID, ("t", OPENAI_KEY)], "n": 3}}
    out = redact(None, "info", event)
    assert AWS_KEY_ID not in json.dumps(out)
    assert OPENAI_KEY not in json.dumps(out)
    assert out["deep"]["n"] == 3


def test_patterns_are_named() -> None:
    names = {name for name, _ in REDACTION_PATTERNS}
    assert {
        "anthropic",
        "openai",
        "aws_access_key_id",
        "aws_secret_access_key",
        "auth_scheme",
        "url_userinfo",
        "query_param",
    } <= names


# --------------------------------------------------------------------- fix round 1


@pytest.mark.parametrize(
    "name",
    [
        "ANTHROPIC_API_KEY",
        "openai_api_key",
        "aws_secret_access_key",
        "db_password",
        "secret_key",
        "x-anthropic-api-key",
        "X-Api-Key",
        "client_secret",
        "access_token",
        "refresh_token",
        "session_token",
        "google_application_credentials",
        "Set-Cookie",
        "proxy-authorization",
        b"authorization",
        b"X-API-KEY",
    ],
)
def test_sensitive_names_match_by_substring_and_suffix(name: str | bytes) -> None:
    assert is_sensitive_key(name)
    out = redact(None, "info", {"event": "x", "nested": {name: "plain-looking-value"}})
    assert "plain-looking-value" not in json.dumps(out)


@pytest.mark.parametrize(
    "name",
    ["token", "callback_token", "run_id", "input_tokens", "max_tokens", "key", "database_url"],
)
def test_ordinary_names_are_not_sensitive(name: str) -> None:
    """``token`` / ``callback_token`` are the run's callback token: evidence, kept."""
    assert not is_sensitive_key(name)


def test_env_style_names_in_a_log_call_are_masked(stream: io.StringIO) -> None:
    fields = {"ANTHROPIC_API_KEY": "abc", "db_password": "pw", "secret_key": "s3"}
    get_logger("test").info("env", **fields)
    (line,) = _lines(stream)
    assert all(line[k] == "[REDACTED]" for k in fields)


def test_url_userinfo_is_masked_in_any_value(stream: io.StringIO) -> None:
    pw = "pa" + "ss@w0rd"
    url = f"postgresql+psycopg://lab:{pw}@db:5432/lab"
    get_logger("test").info(f"connecting to {url}", database_url=url)

    raw = stream.getvalue()
    assert pw not in raw
    assert "ss@w0rd" not in raw
    (line,) = _lines(stream)
    assert line["database_url"] == "postgresql+psycopg://[REDACTED:url_userinfo]@db:5432/lab"
    assert "@db:5432/lab" in line["event"]


@pytest.mark.parametrize(
    "query",
    [
        "?api_key=QWERTY123",
        "?apikey=QWERTY123",
        "?x=1&key=QWERTY123",
        "?access_token=QWERTY123",
        "?secret=QWERTY123",
        "?password=QWERTY123",
        "?sig=QWERTY123",
        "?token=QWERTY123",
        "?X-Amz-Signature=QWERTY123",
    ],
)
def test_secret_query_parameters_are_masked(query: str) -> None:
    out = redact_text(f"GET /v1/runs{query}&page=2 HTTP/1.1")
    assert "QWERTY123" not in out
    assert out.endswith("&page=2 HTTP/1.1")
    assert "[REDACTED:query_param]" in out


def test_aws_secret_access_key_is_masked_in_context_only() -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
    assert len(secret) == 40
    for text in (
        f"AWS_SECRET_ACCESS_KEY={secret}",
        f'"aws_secret_access_key": "{secret}"',
        f"secret access key: {secret}",
    ):
        assert secret not in redact_text(text), text


def test_40_hex_object_ids_are_not_masked() -> None:
    """SHA-1 / git ids carry no AWS context, so they stay readable."""
    sha1 = "3f786850e387550fdab836ed7e6dc881de23001b"
    text = f"commit {sha1} release {sha1.upper()} artifact sha1={sha1}"
    assert redact_text(text) == text


@pytest.mark.parametrize("scheme", ["Bearer", "Basic", "Token", "Digest", "bearer"])
def test_every_auth_scheme_is_masked_and_kept(scheme: str) -> None:
    cred = "dXNlcjpwYXNz" + "Zm9vYmFy"
    out = redact_text(f"Authorization: {scheme} {cred}")
    assert cred not in out
    assert out == f"Authorization: {scheme} [REDACTED:auth_scheme]"


def test_header_pairs_and_bytes_keys_are_masked(stream: io.StringIO) -> None:
    get_logger("test").info(
        "upstream",
        raw_headers=[(b"authorization", b"Basic abc123"), (b"x-api-key", b"plainvalue")],
        header_list=[["X-Api-Key", "plainvalue"], ["accept", "*/*"]],
        header_dict={b"authorization": "Digest plainvalue", b"accept": b"*/*"},
    )
    raw = stream.getvalue()
    assert "abc123" not in raw
    assert "plainvalue" not in raw
    (line,) = _lines(stream)
    assert line["header_list"][1] == ["accept", "*/*"]
    assert line["header_dict"]["accept"] == "*/*"
    assert line["raw_headers"][1] == ["x-api-key", "[REDACTED]"]


def test_configure_logging_replaces_foreign_root_handlers(stream: io.StringIO) -> None:
    foreign = io.StringIO()
    logging.getLogger().addHandler(logging.StreamHandler(foreign))
    configure_logging(stream=stream, level="DEBUG")

    logging.getLogger("lib").warning("key %s", AWS_KEY_ID)

    assert foreign.getvalue() == ""
    assert AWS_KEY_ID not in stream.getvalue()
    assert len(logging.getLogger().handlers) == 1


def test_uvicorn_loggers_are_routed_through_redacting_json(stream: io.StringIO) -> None:
    """Even after uvicorn's own dictConfig (plain text, propagate=False)."""
    plain = io.StringIO()
    uvicorn_config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    for handler in uvicorn_config["handlers"].values():
        handler["stream"] = plain
    logging.config.dictConfig(uvicorn_config)
    configure_logging(stream=stream, level="DEBUG")

    try:
        raise RuntimeError(f"upstream rejected {ANTHROPIC_KEY}")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("Exception in ASGI application")
    logging.getLogger("uvicorn.access").info(
        '%s - "%s %s HTTP/%s" %d',
        "10.0.0.5:51234",
        "GET",
        "/v1/runs?api_key=QWERTY123&page=2",
        "1.1",
        200,
    )

    assert plain.getvalue() == ""
    raw = stream.getvalue()
    assert ANTHROPIC_KEY not in raw
    assert "QWERTY123" not in raw
    error, access = _lines(stream)
    assert error["logger"] == "uvicorn.error"
    assert "[REDACTED:anthropic]" in error["exception"]
    assert access["logger"] == "uvicorn.access"
    assert "api_key=[REDACTED:query_param]&page=2" in access["event"]
    for name in UVICORN_LOGGERS:
        assert logging.getLogger(name).handlers == []
        assert logging.getLogger(name).propagate is True


def test_other_loggers_with_own_handlers_trigger_a_warning(stream: io.StringIO) -> None:
    lonely = logging.getLogger("tests.lonely")
    lonely.addHandler(logging.StreamHandler(io.StringIO()))
    try:
        configure_logging(stream=stream, level="DEBUG")
    finally:
        lonely.handlers.clear()

    warnings = [ln for ln in _all_lines(stream) if ln.get("logger") == SELF]
    assert warnings
    assert warnings[-1]["level"] == "warning"
    assert "tests.lonely" in warnings[-1]["event"]


# --------------------------------------------------------------------- fix round 2

SECRET = "hunter2-" + "SECRET"
_64K = 64 * 1024


def _fill(unit: str, prefix: str = "") -> str:
    return (prefix + unit * (_64K // len(unit) + 1))[:_64K]


#: Inputs built to make backtracking regexes blow up (one per risky shape).
ADVERSARIAL = {
    "assignment_name_run": _fill("password-"),
    "assignment_no_sep": _fill("a", "x_password") + " ",
    "assignment_repeat": _fill("password="),
    "assignment_spaces": "password" + " " * (_64K - 9) + "x",
    "query_secret_run": _fill("secret", "?"),
    "query_dash_run": _fill("-", "?x"),
    "query_amp_run": _fill("&"),
    "query_eq_run": _fill("?key="),
    "userinfo_run": _fill("://a:"),
    "userinfo_long": "://" + "a" * 100 + ":" + "b" * (_64K - 110),
    "jwt_run": _fill("eyJ-"),
    "jwt_dots": "eyJ" + _fill("aaaaaaaa."),
    "auth_spaces": "bearer" + " " * (_64K - 6),
    "auth_run": _fill("bearer "),
    "aws_spaces": "aws secret" + " " * (_64K - 11) + ":",
    "aws_run": _fill("aws_secret_access_key="),
    "private_key_run": _fill("A ", "-----BEGIN "),
    "private_key_begins": _fill("-----BEGIN RSA PRIVATE KEY-----"),
    "cookie_spaces": "cookie" + " " * (_64K - 6),
    "cookie_run": _fill("set-cookie:"),
    "sk_run": _fill("sk-"),
    "word_run": _fill("a"),
    "dash_run": _fill("-"),
}


def _best_time(fn: Callable[[], object], runs: int = 3) -> float:
    """The fastest of ``runs`` timings of ``fn()``, in seconds (robust to load)."""
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def _assert_fast(fn: Callable[[], object], limit: float = 3.0) -> None:
    """``fn()`` finishes within ``limit`` seconds (the fastest of 3 runs).

    A generous absolute bound: catastrophic backtracking on 64 KiB takes minutes, so it
    still trips this, while a loaded CI machine does not.
    """
    elapsed = _best_time(fn)
    assert elapsed < limit, f"took {elapsed:.2f}s (limit {limit}s)"


def _assert_scales_linearly(run: Callable[[str], object], text: str) -> None:
    """4x the input takes less than 10x the time (fastest of 3 runs each).

    Measured below :data:`MAX_INPUT_CHARS`, where nothing is windowed; a 1 ms floor
    on the small input absorbs timer noise. Quadratic work would take ~16x.
    """
    # Inputs a few characters over the ceiling would switch the big run to the windowed
    # path (more work per character), so the ratio would compare two code paths.
    text = text[:MAX_INPUT_CHARS]
    small = text[: len(text) // 4]
    ratios = []
    # Load on a shared machine only ever slows a run down, so one clean attempt out of
    # three is enough; real super-linear work fails all three.
    for _ in range(3):
        t_small = max(_best_time(lambda: run(small)), 1e-3)
        t_big = _best_time(lambda: run(text))
        ratios.append(t_big / t_small)
        if t_big < 10 * t_small:
            return
    raise AssertionError(f"4x input took {min(ratios):.1f}x the time (best of 3 attempts)")


def _drain(pattern: re.Pattern[str]) -> Callable[[str], object]:
    return lambda text: collections.deque(pattern.finditer(text), maxlen=0)


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
@pytest.mark.parametrize("name", [n for n, _ in REDACTION_PATTERNS])
def test_every_pattern_is_linear_on_adversarial_64k_input(name: str, shape: str) -> None:
    """No pattern backtracks catastrophically, even without the input cap."""
    run = _drain(dict(REDACTION_PATTERNS)[name])
    text = ADVERSARIAL[shape]
    assert len(text) >= _64K - 16
    _assert_fast(lambda: run(text))
    _assert_scales_linearly(run, text)


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
def test_redact_text_is_fast_on_adversarial_input(shape: str) -> None:
    _assert_fast(lambda: redact_text(ADVERSARIAL[shape]))
    _assert_scales_linearly(redact_text, ADVERSARIAL[shape])


def test_long_strings_keep_head_and_tail_after_redaction() -> None:
    assert MAX_TEXT_CHARS == HEAD_CHARS + TAIL_CHARS == 16 * 1024
    words = " ".join(f"w{i:05d}" for i in range(8000))  # ~56 KiB of short words
    out = redact_text(words)
    head, marker, tail = out.partition(TRUNCATED)
    assert marker == TRUNCATED
    assert words.startswith(head)
    assert words.endswith(tail)
    assert len(head) <= HEAD_CHARS
    assert len(tail) <= TAIL_CHARS
    assert head.endswith(" ") or head.endswith(head.split()[-1])
    assert head.split()[-1] in words.split()  # no word cut in half at the cut
    assert tail.split()[0] in words.split()
    short = "a" * MAX_TEXT_CHARS
    assert redact_text(short) == short


# --------------------------------------------------------------------- fix round 3

#: The reviewer's R1 shapes: a rejected name must never swallow a following secret.
SWALLOW = [
    "ValueError: password=hunter2",
    "db error: password=hunter2",
    "msg=DB_PASSWORD=hunter2",
    '{"detail": "client_secret=hunter2"}',
    "GET /login?next=/cb?api_key=hunter2 HTTP/1.1",
    "GET /a?redirect_uri=https://x/cb?access_token=hunter2",
    "env: AWS_SECRET=hunter2",
    "a=b=c=d=password=hunter2",
    "x: y: z: secret: hunter2",
    "?a=1&b=2&c=/x?d=4&password=hunter2",
    "note=see client_secret=hunter2",
]


@pytest.mark.parametrize("text", SWALLOW)
def test_rejected_names_never_swallow_a_following_secret(text: str) -> None:
    out = redact_text(text)
    assert "hunter2" not in out, out
    assert "[REDACTED:" in out


def test_secret_in_a_rendered_traceback_is_masked(stream: io.StringIO) -> None:
    secret = "hun" + "ter2"  # not literal: the traceback quotes this source line
    try:
        raise ValueError(f"password={secret}")
    except ValueError:
        get_logger("test").exception("failed")
    out = stream.getvalue()
    assert "hunter2" not in out
    assert "ValueError: password=[REDACTED:assignment]" in out


def _cut_at_limit(prefix_secret: str) -> str:
    """Pad so that ``prefix_secret`` ends exactly at :data:`MAX_TEXT_CHARS`."""
    pad = "x " * ((MAX_TEXT_CHARS - len(prefix_secret)) // 2)
    pad += "x" * (MAX_TEXT_CHARS - len(prefix_secret) - len(pad))
    return pad + prefix_secret


@pytest.mark.parametrize(
    ("before", "after", "secret"),
    [
        ("AWS secret access key: " + "A" * 39, "A" + " tail", "A" * 39),
        ("db=postgres://admin:hunter2-SECRET", "@db:5432/x", "hunter2-SECRET"),
        ("key sk-proj-ABCDEFGHIJKLMNO", "PQRSTUVWXYZ123456", "ABCDEFGHIJKLMNO"),
    ],
    ids=["aws", "dsn", "openai"],
)
def test_a_secret_straddling_the_cut_is_masked(before: str, after: str, secret: str) -> None:
    """Reviewer's R2 shapes: patterns run on the full text before any cut."""
    out = redact_text(_cut_at_limit(before) + after + " end" * 2000)
    assert secret not in out


@pytest.mark.parametrize("where", ["head_edge", "tail_edge", "middle"])
def test_inputs_above_the_ceiling_never_leak_at_a_window_edge(where: str) -> None:
    dsn_line = "db=postgres://admin:" + "hunter2-SECRET" + "@db:5432/x"
    half = MAX_INPUT_CHARS // 2
    if where == "head_edge":
        text = "x " * ((half - 20) // 2) + dsn_line + " y" * 60000
    elif where == "tail_edge":
        text = "x " * 60000 + dsn_line + " y" * ((half - 20) // 2)
    else:
        text = "x " * 60000 + dsn_line + " y" * 60000
    assert len(text) > MAX_INPUT_CHARS
    out = redact_text(text)
    assert "hunter2" not in out
    assert TRUNCATED in out
    assert len(out) <= MAX_TEXT_CHARS + len(TRUNCATED)


def test_traceback_final_lines_survive_truncation(stream: io.StringIO) -> None:
    """Reviewer's r2_tb shape: a 60-deep chained exception keeps its last line."""

    def chain(n: int) -> None:
        try:
            if n == 0:
                raise KeyError("ROOT")
            chain(n - 1)
        except Exception as exc:
            raise RuntimeError(f"layer {n} " + "context " * 20) from exc

    try:
        chain(60)
    except RuntimeError:
        get_logger("s").exception("chained")
    (line,) = _lines(stream)
    assert TRUNCATED in line["exception"]
    assert "RuntimeError: layer 60 " in line["exception"]
    assert "KeyError: 'ROOT'" in line["exception"]  # the head keeps the root cause


@pytest.mark.parametrize(
    "text",
    [
        "DB_PASSWORD            = hunter2",
        "password:\n  hunter2",
        "password\t\t\t\t\t\t\t\t\t= hunter2",
        "password" + " " * 60 + "=" + " " * 60 + "hunter2",
        "x" * 129 + "_password=hunter2",
        "x" * 240 + "_password=hunter2",
        "postgres://u:" + "p" * 300 + "hunter2@h/db",
        "postgres://u:" + "p" * 1000 + "hunter2@h/db",
        "postgres://u:p@ss@hunter2@h/db?x=1",
        "?" + "a" * 70 + "_api_key=hunter2",
        "?" + "a" * 240 + "_api_key=hunter2",
        "Bearer" + " " * 20 + "hunter2",
        "Bearer" + " " * 60 + "hunter2",
        "Authorization: hunter2rawtoken",
        "access_token=hunter2",
        "api_token=hunter2",
        "accessToken: hunter2",
    ],
)
def test_round_one_cases_are_masked_with_raised_bounds(text: str) -> None:
    """Reviewer's R3 shapes (whitespace, long names, long passwords, long query names)."""
    assert "hunter2" not in redact_text(text)


def test_quoted_values_are_masked_whole() -> None:
    assert redact_text('{"password": "hunter 2"}') == '{"password": "[REDACTED:assignment]"}'
    assert redact_text("secret='a b c'") == "secret='[REDACTED:assignment]'"


def test_auth_scheme_mask_is_not_masked_again() -> None:
    assert redact_text("Authorization: Basic abc") == "Authorization: Basic [REDACTED:auth_scheme]"


#: Extra adversarial shapes for the scanning loop (rejected names back to back).
CHAINS = {
    "eq_chain": _fill("a="),
    "colon_chain": _fill("x: "),
    "query_chain": _fill("&a=1"),
    "quote_chain": _fill('"k": "'),
    "secret_chain": _fill("password=x "),
    "nested_query": _fill("?n=/"),
}


@pytest.mark.parametrize("shape", sorted(CHAINS))
def test_redact_text_is_fast_on_rejected_name_chains(shape: str) -> None:
    _assert_fast(lambda: redact_text(CHAINS[shape]))
    _assert_scales_linearly(redact_text, CHAINS[shape])


def test_bounded_patterns_still_mask_what_they_should() -> None:
    assert redact_text("DB_PASSWORD=" + SECRET) == "DB_PASSWORD=[REDACTED:assignment]"
    assert redact_text(f'{{"client_secret": "{SECRET}"}}') == (
        '{"client_secret": "[REDACTED:assignment]"}'
    )
    assert SECRET not in redact_text(f"GET /x?page=1&my_api_key={SECRET}&q=2")
    assert redact_text("GET /x?keyboard=qwerty&monkey=1") == "GET /x?keyboard=qwerty&monkey=1"
    assert redact_text("keyword=value passkey=1") == "keyword=value passkey=1"


def _boom() -> object:
    class Boom:
        def __str__(self) -> str:
            raise RuntimeError(f"cannot render {SECRET}")

        __repr__ = __str__

    return Boom()


def test_mixed_key_types_do_not_leak_the_secret(
    stream: io.StringIO, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reviewer's reproducer: ``sort_keys`` used to fail on int + str keys."""
    get_logger("test").info("x", data={1: "a", "password": SECRET})
    get_logger("test").info("y", data={("a", "b"): "v", "password": SECRET, None: 2})

    captured = capsys.readouterr()
    assert SECRET not in stream.getvalue()
    assert SECRET not in captured.err + captured.out
    first, second = _lines(stream)
    assert first["data"] == {"1": "a", "password": "[REDACTED]"}
    assert second["data"]["password"] == REDACTED
    assert second["data"]["None"] == 2


@pytest.mark.parametrize("via", ["structlog", "stdlib"])
def test_render_failure_emits_a_fixed_redacted_fallback_line(
    stream: io.StringIO, capsys: pytest.CaptureFixture[str], via: str
) -> None:
    if via == "structlog":
        get_logger("test").warning(f"about {SECRET}", obj=_boom())
    else:
        logging.getLogger("test").warning("about %s %s", SECRET, _boom())

    captured = capsys.readouterr()
    assert SECRET not in stream.getvalue()
    assert SECRET not in captured.err + captured.out
    (line,) = _lines(stream)
    assert line["event"] == "log_render_error"
    assert line["level"] == "warning"
    assert line["logger"] == "test"
    assert set(line) <= {"event", "level", "logger", "timestamp"}


def test_configure_logging_turns_off_raise_exceptions(stream: io.StringIO) -> None:
    assert logging.raiseExceptions is False


def test_a_failing_stream_never_prints_the_record(capsys: pytest.CaptureFixture[str]) -> None:
    class Broken(io.StringIO):
        def write(self, s: str) -> int:
            raise OSError("disk full")

    root = logging.getLogger()
    saved, saved_level, saved_raise = root.handlers[:], root.level, logging.raiseExceptions
    try:
        configure_logging(stream=Broken())
        logging.getLogger("lib").error("key is %s", SECRET)
        get_logger("lib").error("key", value=SECRET)
    finally:
        structlog.reset_defaults()
        root.handlers[:] = saved
        root.setLevel(saved_level)
        logging.raiseExceptions = saved_raise
    captured = capsys.readouterr()
    assert SECRET not in captured.err + captured.out


def test_cycles_are_cut_not_recursed(stream: io.StringIO) -> None:
    loop: dict[str, Any] = {"name": "a"}
    loop["self"] = loop
    items: list[Any] = [1]
    items.append(items)
    shared = {"k": 1}
    get_logger("test").info("x", loop=loop, items=items, twice=[shared, shared])

    (line,) = _lines(stream)
    assert line["loop"] == {"name": "a", "self": "[cycle]"}
    assert line["items"] == [1, "[cycle]"]
    assert line["twice"] == [{"k": 1}, {"k": 1}], "a repeat is not a cycle"


def test_deep_structures_are_cut_at_max_depth(stream: io.StringIO) -> None:
    deep: Any = SECRET
    for _ in range(5000):
        deep = [deep]
    get_logger("test").info("x", deep=deep)

    raw = stream.getvalue()
    assert SECRET not in raw
    (line,) = _lines(stream)
    node = line["deep"]
    depth = 0
    while isinstance(node, list):
        (node,) = node
        depth += 1
    assert node == "[depth]"
    assert depth <= MAX_DEPTH


@pytest.mark.parametrize(
    "name",
    ["accessToken", "apiToken", "refreshToken", "xApiKey", "clientSecret", "dbPassword",
     "AWSSecretAccessKey", "sessionToken"],
)  # fmt: skip
def test_camel_case_names_are_sensitive(name: str) -> None:
    assert is_sensitive_key(name)


@pytest.mark.parametrize("name", ["callbackToken", "inputTokens", "maxTokens", "runId"])
def test_camel_case_ordinary_names_are_not(name: str) -> None:
    assert not is_sensitive_key(name)


def test_any_mapping_keeps_key_masking(stream: io.StringIO) -> None:
    headers = Headers(headers={"x-api-key": "plainvalue", "accept": "*/*"})
    proxy = MappingProxyType({"authorization": "plainvalue", "n": 1})
    get_logger("test").info("req", headers=headers, proxy=proxy)

    assert "plainvalue" not in stream.getvalue()
    (line,) = _lines(stream)
    assert line["headers"] == {"x-api-key": "[REDACTED]", "accept": "*/*"}
    assert line["proxy"] == {"authorization": "[REDACTED]", "n": 1}


@pytest.mark.parametrize(
    "text",
    [
        "Set-Cookie: session=plainvalue; Path=/; HttpOnly",
        "cookie: a=plainvalue; b=plainvalue",
        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=plainvalue\r\nServer: x",
    ],
)
def test_cookie_header_text_is_masked(text: str) -> None:
    out = redact_text(text)
    assert "plainvalue" not in out
    assert "[REDACTED:cookie_header]" in out
    if "Server: x" in text:
        assert out.endswith("\r\nServer: x")


# --------------------------------------------------------------------- fix round 4

_WINDOW = MAX_INPUT_CHARS // 2
_FUZZ_SECRET = "hunter2" + "SECRETVALUE"
#: The reviewer's NEW-1 shapes: a name and a value a window cut can separate.
WINDOW_SHAPES = [
    "password: " + _FUZZ_SECRET,
    "Authorization: Bearer " + _FUZZ_SECRET,
    '"password": "correct horse ' + _FUZZ_SECRET + '"',
    "Cookie: a=1; b=" + _FUZZ_SECRET,
    "password:\n  " + _FUZZ_SECRET,
]


def _lorem(n: int) -> str:
    return ("lorem " * (n // 6 + 1))[:n]


def _sk_filler(n: int) -> str:
    """Maskable filler: one key-shaped token, redacted to a few characters."""
    return "sk-" + "A" * (n - 3)


def _pem_filler(n: int) -> str:
    body = ("QUJD" * 16 + "\n") * ((n - 60) // 65)
    return "-----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY-----"


SHRINKERS = {"sk_token": _sk_filler, "pem_block": _pem_filler}


@pytest.mark.parametrize("shrinker", sorted(SHRINKERS))
@pytest.mark.parametrize("shape", WINDOW_SHAPES)
def test_tail_window_cut_at_every_offset_never_leaks(shape: str, shrinker: str) -> None:
    """The tail window starts at every offset of the shape; maskable filler follows."""
    shrink = SHRINKERS[shrinker]
    for off in range(len(shape) + 1):
        rest = shape[off:] + " "
        tail = rest + shrink(_WINDOW - len(rest))
        tail += _lorem(_WINDOW - len(tail))
        assert len(tail) == _WINDOW
        text = _lorem(MAX_INPUT_CHARS) + " " + shape[:off] + tail
        out = redact_text(text)
        assert "SECRETVAL" not in out, (off, out[-200:])


@pytest.mark.parametrize("shrinker", sorted(SHRINKERS))
@pytest.mark.parametrize("shape", [*WINDOW_SHAPES, "db=postgres://admin:" + _FUZZ_SECRET + "@db"])
def test_head_window_cut_at_every_offset_never_leaks(shape: str, shrinker: str) -> None:
    """The head window ends at every offset of the shape; maskable filler precedes it."""
    shrink = SHRINKERS[shrinker]
    for off in range(len(shape) + 1):
        lead = shrink(_WINDOW - off - 1)
        lead += _lorem(_WINDOW - off - 1 - len(lead))
        text = lead + " " + shape + " " + _lorem(MAX_INPUT_CHARS)
        assert text[_WINDOW - off : _WINDOW - off + len(shape)] == shape
        out = redact_text(text)
        assert "SECRETVAL" not in out, (off, out[:200])


def test_the_tail_windows_leading_margin_never_reaches_the_output() -> None:
    margin = ("m" * 7 + " ") * (8 * 1024 // 8)  # exactly the 8 KiB lead-in margin
    for joint in ("\n", " ", "mmm\n", ""):
        tail = margin + joint
        tail += _sk_filler(_WINDOW - len(tail))
        text = _lorem(MAX_INPUT_CHARS).replace("m", "x") + " " + tail
        out = redact_text(text)
        emitted = out.rpartition(TRUNCATED)[2]
        assert "m" not in emitted, (repr(joint), emitted[:120])
        assert "[REDACTED:openai]" in emitted


def test_the_head_windows_trailing_margin_never_reaches_the_output() -> None:
    margin = ("m" * 7 + " ") * (8 * 1024 // 8)
    for joint in ("\n", " ", "\nmmm", ""):
        head = _sk_filler(_WINDOW - len(margin) - len(joint)) + joint + margin
        assert len(head) == _WINDOW
        text = head + " " + _lorem(MAX_INPUT_CHARS).replace("m", "x")
        out = redact_text(text)
        emitted = out.partition(TRUNCATED)[0]
        assert "m" not in emitted, (repr(joint), emitted[-120:])
        if joint:  # with no joint the key and the margin are one token: dropped whole
            assert emitted.startswith("[REDACTED:openai]")


def test_windows_cut_at_a_line_boundary_after_the_margin() -> None:
    from control.core import logging as lab_logging

    assert lab_logging.MARGIN_CHARS == 8 * 1024
    lines = "".join(f"line{i:05d} " + "w" * 40 + "\n" for i in range(700))
    window = lines[: MAX_INPUT_CHARS // 2]
    head = lab_logging._head_window(window)
    tail = lab_logging._tail_window(window)
    assert window.startswith(head) and head.endswith("\n")
    assert len(head) <= len(window) - lab_logging.MARGIN_CHARS
    assert len(head) > len(window) - lab_logging.MARGIN_CHARS - 60  # the nearest line end
    assert window.endswith(tail) and tail.startswith("line")
    assert len(tail) <= len(window) - lab_logging.MARGIN_CHARS
    assert len(tail) > len(window) - lab_logging.MARGIN_CHARS - 60
    flat = "word " * (len(window) // 5)  # no newline: cut at the margin, whole words
    assert flat.endswith(lab_logging._tail_window(flat))
    assert lab_logging._tail_window(flat).split()[0] == "word"
    assert flat.startswith(lab_logging._head_window(flat))


#: NEW-2: Python string prefixes and escaped (double-encoded) JSON.
PREFIXED_AND_ESCAPED = [
    "{'password': b'hunter2'}",
    "Creds(password=b'hunter2')",
    "{'password': r'hunter2'}",
    "{'password': rb'hunter2'}",
    "{'password': u\"hunter2\"}",
    'secret=B"hunter2"',
    '{"args": "{\\"password\\": \\"hunter2\\"}"}',
    'password=\\"hunter2\\"',
    "{\\'password\\': \\'hunter2\\'}",
    '{"args": "{\\"password\\": \\"a\\\\\\"hunter2\\"}"}',  # escaped quote, double-encoded
]


@pytest.mark.parametrize("text", PREFIXED_AND_ESCAPED)
def test_prefixed_and_escaped_quoted_values_are_masked(text: str) -> None:
    out = redact_text(text)
    assert "hunter2" not in out, out
    assert "[REDACTED:assignment]" in out


def test_prefixed_and_escaped_values_keep_their_quotes() -> None:
    assert redact_text("Creds(password=b'hunter2')") == ("Creds(password=b'[REDACTED:assignment]')")
    assert redact_text('{"args": "{\\"password\\": \\"hunter2\\"}"}') == (
        '{"args": "{\\"password\\": \\"[REDACTED:assignment]\\"}"}'
    )
    # a double-encoded value ending in a backslash: the next field is not swallowed
    assert redact_text('{"a": "{\\"password\\": \\"x\\\\\\\\\\", \\"n\\": \\"v\\"}"}') == (
        '{"a": "{\\"password\\": \\"[REDACTED:assignment]\\", \\"n\\": \\"v\\"}"}'
    )
    assert redact_text("password=bob") == "password=[REDACTED:assignment]"


#: NEW-3: the rest of a secret after an escape, a list, ``=>`` or a delimiter.
REST_OF_SECRET = [
    '"password": "a\\"hunter2"',
    "'password': 'it\\'shunter2'",
    '"password": ["hunter2"]',
    '"password": [ "hunter2", "x"]',
    "password => 'hunter2'",
    "password=>hunter2",
    "password=a,hunter2",
    "password=a;hunter2",
    "password=a&hunter2",
    "password=it'shunter2",
    'password=a"hunter2',
    "password=***;hunter2",
    "password: |\n  hunter2",
    "password: >-\n  hunter2",
    "password: |+\n  first\n\n  hunter2\n",
    "  db:\n    password: |2  # comment\n      line1\n      hunter2\n  next: 1",
    "- password: >\n    hunter2",
]


@pytest.mark.parametrize("text", REST_OF_SECRET)
def test_the_rest_of_a_secret_is_masked(text: str) -> None:
    out = redact_text(text)
    assert "hunter2" not in out, out


def test_yaml_block_scalars_stop_at_the_dedent() -> None:
    text = "auth:\n  password: |\n    hunter2\n    more\n\n  user: bob\nnext: 1"
    assert redact_text(text) == ("auth:\n  password: [REDACTED:assignment]\n\n  user: bob\nnext: 1")


def test_yaml_block_scalars_are_bounded() -> None:
    text = "password: |\n" + "".join(f"  l{i:03d}\n" for i in range(100))
    out = redact_text(text)
    assert "l000" not in out and "l063" not in out
    assert "l064" in out  # 64 lines at most


def test_query_parameters_still_stop_at_ampersand() -> None:
    assert redact_text("GET /cb?api_key=hunter2&page=2") == (
        "GET /cb?api_key=[REDACTED:query_param]&page=2"
    )


def test_assignment_values_run_to_whitespace() -> None:
    assert redact_text("password=a,b;c&d next") == "password=[REDACTED:assignment] next"
    assert redact_text("password=a\nnext") == "password=[REDACTED:assignment]\nnext"


#: Extra adversarial shapes for the round-4 value grammar and the windows.
ROUND4_ADVERSARIAL = {
    "yaml_indicator_run": _fill("password: |\n"),
    "yaml_block_lines": "password: |\n" + _fill("  x\n"),
    "yaml_blank_lines": "password: >-\n" + _fill(" \n"),
    "yaml_spaces": "password: |\n" + " " * (_64K - 13),
    "escaped_open_run": _fill('password=\\"'),
    "escaped_value": 'password=\\"' + _fill("\\\\\\"),
    "backslash_run": _fill("\\"),
    "quote_escape_run": 'password="' + _fill('\\"'),
    "prefix_run": _fill("password=b"),
    "prefix_quote_run": _fill("password=rb'"),
    "list_run": _fill("password: [ "),
    "list_spaces": "password: [" + " " * (_64K - 12),
    "arrow_run": _fill("password =>"),
    "escaped_name_run": _fill('\\"password\\": '),
    "newline_run": _fill("\n"),
}


@pytest.mark.parametrize("shape", sorted(ROUND4_ADVERSARIAL))
@pytest.mark.parametrize("name", [n for n, _ in REDACTION_PATTERNS])
def test_every_pattern_is_linear_on_round4_shapes(name: str, shape: str) -> None:
    run = _drain(dict(REDACTION_PATTERNS)[name])
    _assert_fast(lambda: run(ROUND4_ADVERSARIAL[shape]))
    _assert_scales_linearly(run, ROUND4_ADVERSARIAL[shape])


@pytest.mark.parametrize("shape", sorted(ROUND4_ADVERSARIAL))
def test_redact_text_is_fast_on_round4_shapes(shape: str) -> None:
    _assert_fast(lambda: redact_text(ROUND4_ADVERSARIAL[shape]))
    _assert_scales_linearly(redact_text, ROUND4_ADVERSARIAL[shape])


@pytest.mark.parametrize("shape", sorted({**ADVERSARIAL, **ROUND4_ADVERSARIAL, **CHAINS}))
def test_redact_text_is_fast_above_the_ceiling(shape: str) -> None:
    """Windowed redaction (two windows with their margins) on 4x the ceiling."""
    text = {**ADVERSARIAL, **ROUND4_ADVERSARIAL, **CHAINS}[shape] * 4
    assert len(text) > MAX_INPUT_CHARS
    _assert_fast(lambda: redact_text(text))


# --------------------------------------------------------------------- fix round 5

_X = "hunter2" + "SECRET"
#: LB-1: an unquoted value that runs into a following quoted secret's opening quote.
QUOTE_SWALLOW = [
    '{"password":null,"client_secret":"correct horse ' + _X + '"}',
    '{"password":123,"secret":"a ' + _X + '"}',
    'password=a;api_key="correct horse ' + _X + '"',
    "password=a,secret='x " + _X + "'",
    'DB_PASSWORD=x&API_KEY="y ' + _X + '"',
    '{\\"password\\":null,\\"secret\\":\\"a ' + _X + '\\"}',
    'password=x;api_key=\\"a ' + _X + '\\"',
    'password=it\'s,"secret":"a ' + _X + '"',
]


@pytest.mark.parametrize("text", QUOTE_SWALLOW)
def test_an_unquoted_value_never_strands_a_following_quoted_secret(text: str) -> None:
    out = redact_text(text)
    assert "SECRET" not in out, out
    assert "[REDACTED:assignment]" in out


def test_the_quote_extension_stops_at_the_closing_quote() -> None:
    assert redact_text('{"password":null,"secret":"a b","user":"bob"}') == (
        '{"password":[REDACTED:assignment]","user":"bob"}'
    )
    # a stray quote: the extension runs to the end of the line (at most 4096 characters)
    assert redact_text('password=x"y next\nline') == "password=[REDACTED:assignment]\nline"
    assert redact_text('password=a"b"c next') == "password=[REDACTED:assignment] next"


@pytest.mark.parametrize(
    "name", ["pass", "pwd", "passphrase", "DB_PASS", "db_pwd", "dbPass", "ssh_passphrase_file"]
)
def test_pass_pwd_and_passphrase_names_are_sensitive(name: str) -> None:
    assert is_sensitive_key(name)
    assert "hunter2" not in redact_text(f"{name}=hunter2")


@pytest.mark.parametrize("query", ["/login?pass=hunter2", "/login?pwd=hunter2&x=1"])
def test_pass_and_pwd_query_parameters_are_masked(query: str) -> None:
    assert "hunter2" not in redact_text(query)


@pytest.mark.parametrize(
    "name", ["passed", "bypass", "passthrough", "tests_passed", "compass", "passage", "pwdx"]
)
def test_words_containing_pass_stay_readable(name: str) -> None:
    """Evidence fields (``passed``, ``bypass``...) are never masked by a bare ``pass``."""
    assert not is_sensitive_key(name)
    assert redact_text(f"{name}=true") == f"{name}=true"
    out = redact(None, "info", {"event": "x", name: "true"})
    assert out[name] == "true"
    assert redact_text(f"/x?{name}=1") == f"/x?{name}=1"


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Key hunter2 more",
        "Authorization: ApiKey hunter2",
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/x, Signature=hunter2",
        "Proxy-Authorization: Custom a b hunter2",
    ],
)
def test_authorization_names_mask_to_end_of_line(text: str) -> None:
    out = redact_text(text + "\nnext: line")
    assert "hunter2" not in out, out
    assert out.endswith("\nnext: line")


#: Round-5 adversarial shapes for the quote extension and the to-end-of-line names.
ROUND5_ADVERSARIAL = {
    "unq_quote_run": _fill('password=a"'),
    "unq_quote_open": _fill('password=a" b '),
    "unq_esc_quote_run": _fill('password=a\\" '),
    "unq_sq_run": _fill("password=it's "),
    "auth_eol_run": _fill("authorization=x "),
    "auth_eol_long": "authorization: " + "x " * (_64K // 2 - 8),
}


@pytest.mark.parametrize("shape", sorted(ROUND5_ADVERSARIAL))
def test_redact_text_is_fast_on_round5_shapes(shape: str) -> None:
    for text in (ROUND5_ADVERSARIAL[shape], ROUND5_ADVERSARIAL[shape] * 4):
        _assert_fast(lambda text=text: redact_text(text))
    _assert_scales_linearly(redact_text, ROUND5_ADVERSARIAL[shape])


#: LB-A: a quote extension that stops on the next value's opening quote.
NEXT_SECRET_AFTER_OPEN_QUOTE = [
    "password=it's api_key='" + _X + "'",
    'password=p"w secret="' + _X + '"',
    "secret=it's;pwd=x y;password=\"it's " + _X + '"',
]


@pytest.mark.parametrize("text", NEXT_SECRET_AFTER_OPEN_QUOTE)
def test_a_quote_extension_never_strands_the_next_secret(text: str) -> None:
    out = redact_text(text)
    assert "SECRET" not in out, out


#: Nested secret names inside masked values (the scan resumes after each separator).
NESTED_ADVERSARIAL = {
    "nested_unquoted": _fill("password="),
    "nested_quoted": _fill('password="password='),
    "nested_auth": _fill("authorization=password="),
    "nested_query": _fill("?key="),
    "nested_open_quotes": _fill("password=it's secret='"),
}


@pytest.mark.parametrize("shape", sorted(NESTED_ADVERSARIAL))
def test_redact_text_is_linear_on_nested_secret_names(shape: str) -> None:
    _assert_fast(lambda: redact_text(NESTED_ADVERSARIAL[shape]))
    _assert_scales_linearly(redact_text, NESTED_ADVERSARIAL[shape])


# --------------------------------------------------------------------------- hardening H


@pytest.mark.parametrize(
    "name", ["passcode", "PASSCODE", "mfa_passcode", "userPasscode", "ssh-passcode"]
)
def test_passcode_names_are_sensitive(name: str) -> None:
    assert is_sensitive_key(name)
    assert "hunter2" not in redact_text(f"{name}=hunter2")
    assert redact(None, "info", {"event": "x", name: "hunter2"})[name] == REDACTED


def test_passcode_query_parameter_is_masked() -> None:
    assert "hunter2" not in redact_text("/login?passcode=hunter2&x=1")


def test_passcode_is_matched_exactly_or_as_a_suffix_only() -> None:
    assert not is_sensitive_key("passcodex")
    assert redact_text("passcodex=1") == "passcodex=1"


def test_short_name_suffixes_are_computed_once() -> None:
    from control.core import logging as lab_logging

    expected = tuple(f"_{name}" for name in lab_logging._SENSITIVE_SHORT_NAMES)
    assert expected == lab_logging._SENSITIVE_SHORT_SUFFIXES
    assert "passcode" in lab_logging._SENSITIVE_SHORT_NAMES


@pytest.mark.parametrize(
    "text",
    [
        "PWD=/home/u",
        "cwd PWD=/srv/lab/releases/v0.1.0 ok",
        '{"PWD": "/home/u", "HOME": "/home/u"}',
        "PWD='/tmp/x y'",
    ],
)
def test_the_shell_working_directory_stays_readable(text: str) -> None:
    assert redact_text(text) == text


def _as_str(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


def test_the_shell_working_directory_field_stays_readable() -> None:
    for key, value in (("PWD", "/home/u"), (b"PWD", b"/srv")):
        out = redact(None, "info", {"event": "x", key: value})
        assert out == {"event": "x", "PWD": _as_str(value)}
    env = redact(None, "info", {"event": "x", "env": {"PWD": "/home/u", "PASSWORD": "x"}})
    assert env["env"] == {"PWD": "/home/u", "PASSWORD": REDACTED}
    pairs = redact(None, "info", {"event": "x", "env": [("PWD", "/home/u")]})
    assert pairs["env"] == [["PWD", "/home/u"]]


@pytest.mark.parametrize(
    "text",
    [
        "pwd=hunter2",
        "PWD=hunter2",
        "pwd=/hunter2",  # only the shell variable's exact name is exempt
        "Pwd=/hunter2",
        "DB_PWD=/hunter2",
        'PWD="hunter2"',
        "PWD=hunter2/x",
    ],
)
def test_pwd_not_holding_a_working_directory_is_masked(text: str) -> None:
    assert "hunter2" not in redact_text(text), redact_text(text)


@pytest.mark.parametrize(
    ("key", "value"),
    [("pwd", "/hunter2"), ("pwd", "hunter2"), ("PWD", "hunter2"), ("db_pwd", "/x"), ("PWD", 1)],
)
def test_pwd_fields_not_holding_a_working_directory_are_masked(key: str, value: object) -> None:
    assert redact(None, "info", {"event": "x", key: value})[key] == REDACTED
    pairs = redact(None, "info", {"event": "x", "env": [(key, value)]})
    assert pairs["env"] == [[key, REDACTED]]


def test_a_readable_working_directory_is_still_scanned() -> None:
    out = redact_text(f"PWD=/srv/{ANTHROPIC_KEY} password=hunter2")
    assert ANTHROPIC_KEY not in out
    assert "hunter2" not in out
    assert out.startswith("PWD=/srv/")
    field = redact(None, "info", {"event": "x", "PWD": f"/srv/{ANTHROPIC_KEY}"})
    assert ANTHROPIC_KEY not in field["PWD"]
