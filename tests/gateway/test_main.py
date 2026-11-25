"""``python -m control.gateway`` refuses to start on a bad configuration or store."""

from __future__ import annotations

import secrets

import pytest

from control.gateway import __main__ as entry

ENV = {
    "LAB_OLLAMA_URL": "http://ollama:11434",
    "LAB_GATEWAY_LISTEN": "172.31.232.10:4000",
    "LAB_GATEWAY_ADMIN_LISTEN": "172.31.231.20:4001",
    "LAB_GATEWAY_ADMIN_SECRET": secrets.token_urlsafe(32),
}


@pytest.fixture(autouse=True)
def quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    # keep pytest's own log capture: the real setup replaces every root handler
    monkeypatch.setattr(entry, "configure_logging", lambda **_: None)


def test_a_bad_configuration_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    assert entry.main([]) == 2
    for name, value in {**ENV, "LAB_GATEWAY_ADMIN_LISTEN": "172.31.232.10:4000"}.items():
        monkeypatch.setenv(name, value)
    assert entry.main([]) == 2  # both listeners on one address and port


def test_an_unreadable_grant_store_exits_1(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert entry.main([]) == 1
    assert ENV["LAB_GATEWAY_ADMIN_SECRET"] not in caplog.text


@pytest.mark.parametrize("served", [0, 1])
def test_the_exit_status_is_the_gateways(monkeypatch: pytest.MonkeyPatch, served: int) -> None:
    # 0 after SIGTERM or SIGINT, 1 when a server stopped by itself: the container's
    # restart policy and the operator must see the difference
    class Store:
        def __init__(self, engine: object) -> None:
            pass

    class Keys:
        def __init__(self, store: object) -> None:
            pass

        def load(self) -> int:
            return 0

    class Served:
        def __init__(self, config: object, keys: object) -> None:
            pass

        def run(self) -> int:
            return served

    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(entry, "create_db_engine", lambda **_: object())
    monkeypatch.setattr(entry, "PostgresGrantStore", Store)
    monkeypatch.setattr(entry, "RunKeys", Keys)
    monkeypatch.setattr(entry, "Gateway", Served)
    assert entry.main([]) == served
