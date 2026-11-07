"""Where labctl finds the lab: paths, the Collector URL and the database URL."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from control.cli.settings import (
    DB_NAME,
    DB_PASSWORD_VAR,
    DB_PORT,
    DB_USER,
    DEFAULT_COLLECTOR_URL,
    DEFAULT_LAB_ROOT,
    ConfigError,
    LabSettings,
    read_env_file,
)


def test_defaults_are_the_host_layout() -> None:
    s = LabSettings.from_environ({})
    assert s.lab_root == DEFAULT_LAB_ROOT == Path("/srv/lab")
    assert s.host_env_file == Path("/srv/lab/host.env")
    assert s.secrets_env_file == Path("/srv/lab/secrets/lab.env")
    assert s.release_file == Path("/srv/lab/current/RELEASE")
    assert s.collector_url == DEFAULT_COLLECTOR_URL == "http://127.0.0.1:8100"


def test_environment_overrides(tmp_path: Path) -> None:
    s = LabSettings.from_environ(
        {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://127.0.0.1:9999/"}
    )
    assert s.lab_root == tmp_path
    assert s.collector_url == "http://127.0.0.1:9999"


def test_read_env_file_parses_plain_assignments(tmp_path: Path) -> None:
    path = tmp_path / "x.env"
    path.write_text("# comment\n\nA=1\nB = two \nC=\nD=x=y\nnot a line\n", encoding="utf-8")
    assert read_env_file(path) == {"A": "1", "B": "two", "C": "", "D": "x=y"}


def test_database_url_from_the_environment_wins(tmp_path: Path) -> None:
    s = LabSettings.from_environ(
        {"LAB_ROOT": str(tmp_path), "DATABASE_URL": "postgresql://u:p@h:1/d"}
    )
    assert make_url(s.database_url()).host == "h"


def test_database_url_from_lab_env_on_the_host(tmp_path: Path) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    password = "p@ss/w:rd%zz"  # noqa: S105 -- test value; characters a URL must quote
    (secrets / "lab.env").write_text(f"OTHER=1\n{DB_PASSWORD_VAR}={password}\n", encoding="utf-8")

    url = make_url(LabSettings.from_environ({"LAB_ROOT": str(tmp_path)}).database_url())

    assert url.password == password
    assert (url.username, url.host, url.port, url.database) == (
        DB_USER,
        "127.0.0.1",
        DB_PORT,
        DB_NAME,
    )


def test_no_database_configured_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="DATABASE_URL") as exc:
        LabSettings.from_environ({"LAB_ROOT": str(tmp_path)}).database_url()
    assert DB_PASSWORD_VAR in str(exc.value)


def test_empty_password_is_not_accepted(tmp_path: Path) -> None:
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "lab.env").write_text(f"{DB_PASSWORD_VAR}=\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        LabSettings.from_environ({"LAB_ROOT": str(tmp_path)}).database_url()
