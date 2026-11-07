"""Structured logging: JSON lines, run-scope context, secret redaction.

Key-shaped test values are assembled at runtime so no literal in this file looks like
a credential to a secret scanner.
"""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
import structlog

from control.core.logging import (
    REDACTION_PATTERNS,
    bind_component,
    configure_logging,
    get_logger,
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


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    buf = io.StringIO()
    configure_logging(stream=buf, level="DEBUG")
    try:
        yield buf
    finally:
        structlog.contextvars.clear_contextvars()
        structlog.reset_defaults()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def _lines(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


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
    get_logger("test").info("request", authorization_header=f"Authorization: {BEARER}")

    raw = stream.getvalue()
    token = BEARER.removeprefix("Bearer ")
    assert token not in raw
    (line,) = _lines(stream)
    assert line["authorization_header"].startswith("Authorization: Bearer [REDACTED")


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
    assert {"anthropic", "openai", "aws_access_key_id", "bearer"} <= names
