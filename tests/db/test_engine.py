"""URL handling in control.db.engine (no database needed)."""

import pytest

from control.db.engine import DATABASE_URL_ENV, database_url


@pytest.mark.parametrize(
    "raw",
    [
        "postgresql://u:p@h:5432/d",
        "postgres://u:p@h:5432/d",
        "postgresql+psycopg://u:p@h:5432/d",
    ],
)
def test_postgres_urls_use_psycopg3(raw: str) -> None:
    assert database_url(raw) == "postgresql+psycopg://u:p@h:5432/d"


def test_password_is_kept_verbatim() -> None:
    assert database_url("postgresql://u:p%40ss@h/d") == "postgresql+psycopg://u:p%40ss@h/d"


@pytest.mark.parametrize("raw", ["sqlite:///x.db", "mysql://u@h/d"])
def test_non_postgres_backends_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="PostgreSQL is required"):
        database_url(raw)


def test_other_postgres_drivers_are_rejected() -> None:
    with pytest.raises(ValueError, match="psycopg"):
        database_url("postgresql+psycopg2://u@h/d")


def test_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DATABASE_URL_ENV, "postgresql://u@h/d")
    assert database_url() == "postgresql+psycopg://u@h/d"


def test_missing_url_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    with pytest.raises(RuntimeError, match=DATABASE_URL_ENV):
        database_url()
