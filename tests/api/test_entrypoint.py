"""``python -m control.api``: the Collector process entry point.

It must configure the structured, redacted logging **before** uvicorn starts and run
uvicorn with ``log_config=None`` (control/core/logging.py, "Running under uvicorn"),
otherwise uvicorn's plain-text handlers bypass redaction.
"""

from __future__ import annotations

from typing import Any

import pytest

from control.api import __main__ as entry


@pytest.fixture(autouse=True)
def _database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://lab@db:5432/lab")


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


def test_database_connections_time_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung database must not hang requests and scrapes on connect."""
    seen: dict[str, Any] = {}
    monkeypatch.setattr(entry, "configure_logging", lambda **kw: None)
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: seen.update(app=app))
    real = entry.create_db_engine

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen["kwargs"] = kwargs
        return real(*args, **kwargs)

    monkeypatch.setattr(entry, "create_db_engine", spy)

    entry.main([])

    assert seen["kwargs"]["connect_args"]["connect_timeout"] == entry.CONNECT_TIMEOUT_S == 5
    engine = seen["app"].state.engine
    assert engine is not None
    assert engine.url.host == "db"  # from $DATABASE_URL
