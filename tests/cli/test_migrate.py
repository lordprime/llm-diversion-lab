"""``python -m control.cli.migrate``: the control-plane ``migrate`` one-shot.

It configures the redacted JSON logging first (Alembic's own ``fileConfig`` would
install plain-text handlers) and upgrades the database to ``head``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine

from control.cli import migrate
from control.cli.migrations import current_revisions, head_revisions
from control.db.engine import create_db_engine


def test_upgrades_an_empty_database_to_head(
    db_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    order: list[str] = []
    monkeypatch.setattr(migrate, "configure_logging", lambda **kw: order.append("logging"))
    monkeypatch.setenv("DATABASE_URL", db_url)

    assert migrate.main([]) == 0
    assert order == ["logging"]

    eng = create_db_engine(db_url)
    try:
        assert current_revisions(eng) == head_revisions()
    finally:
        eng.dispose()


def test_is_idempotent_at_head(
    db_url: str, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(migrate, "configure_logging", lambda **kw: None)
    monkeypatch.setenv("DATABASE_URL", db_url)
    assert migrate.main([]) == 0
    assert current_revisions(engine) == head_revisions()


def test_no_database_configured_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(migrate, "configure_logging", lambda **kw: None)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert migrate.main([]) == 1


def test_head_is_known_without_a_database() -> None:
    heads = head_revisions()
    assert len(heads) == 1
