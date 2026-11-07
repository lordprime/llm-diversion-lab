"""``python -m control.api``: the Collector process entry point.

It must configure the structured, redacted logging **before** uvicorn starts and run
uvicorn with ``log_config=None`` (control/core/logging.py, "Running under uvicorn"),
otherwise uvicorn's plain-text handlers bypass redaction.
"""

from __future__ import annotations

from typing import Any

import pytest

from control.api import __main__ as entry


def test_configures_logging_then_runs_uvicorn_without_its_log_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(entry, "configure_logging", lambda **kw: calls.append(("logging", kw)))
    monkeypatch.setattr(
        entry.uvicorn, "run", lambda app, **kw: calls.append(("uvicorn", (app, kw)))
    )

    assert entry.main(["--host", "0.0.0.0", "--port", "8123"]) == 0  # noqa: S104

    assert [name for name, _ in calls] == ["logging", "uvicorn"]
    app, kwargs = calls[1][1]
    assert kwargs["log_config"] is None
    assert kwargs["host"] == "0.0.0.0"  # noqa: S104
    assert kwargs["port"] == 8123
    assert app.title == "LLM Diversion Lab Collector API"


def test_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(entry, "configure_logging", lambda **kw: None)
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: seen.update(kw))

    entry.main([])

    assert seen["host"] == "127.0.0.1"
    assert seen["port"] == 8000


def test_bad_arguments_exit_with_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entry, "configure_logging", lambda **kw: None)
    with pytest.raises(SystemExit) as exc:
        entry.main(["--port", "not-a-port"])
    assert exc.value.code == 2
