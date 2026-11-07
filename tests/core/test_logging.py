"""Structured logging: JSON lines, run-scope context, secret redaction.

Key-shaped test values are assembled at runtime so no literal in this file looks like
a credential to a secret scanner.
"""

from __future__ import annotations

import copy
import io
import json
import logging
import logging.config
from collections.abc import Iterator
from typing import Any

import pytest
import structlog
import uvicorn.config

from control.core.logging import (
    REDACTION_PATTERNS,
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
    buf = io.StringIO()
    configure_logging(stream=buf, level="DEBUG")
    try:
        yield buf
    finally:
        structlog.contextvars.clear_contextvars()
        structlog.reset_defaults()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
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
