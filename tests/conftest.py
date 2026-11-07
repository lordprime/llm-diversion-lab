"""Postgres fixtures shared by the database and Collector API tests.

Server selection, in order:

1. ``DATABASE_URL`` if set. It must point at a *disposable* Postgres server whose role
   may ``CREATE DATABASE``: every test gets its own fresh database on that server.
2. Otherwise a throwaway ``postgres:17-alpine`` container started through the Docker
   API at ``DOCKER_HOST``, else the rootless Podman socket
   (``/run/user/<uid>/podman/podman.sock``), else ``/var/run/docker.sock``. Port 5432
   is published on a free port of 127.0.0.1 and the container is removed afterwards.
3. If neither is available the database tests are skipped, with the reason.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import Engine
from sqlalchemy.engine import make_url

from control.db.engine import create_db_engine

try:
    import docker
except ImportError:  # pragma: no cover - the dev group always installs it
    docker = None

POSTGRES_IMAGE = "docker.io/library/postgres:17-alpine"
READY_TIMEOUT_S = 60.0
REPO_ROOT = Path(__file__).resolve().parents[1]


def _docker_hosts() -> list[str]:
    if host := os.environ.get("DOCKER_HOST"):
        return [host]
    candidates = [
        Path(f"/run/user/{os.getuid()}/podman/podman.sock"),
        Path("/var/run/docker.sock"),
    ]
    return [f"unix://{p}" for p in candidates if p.exists()]


def _libpq_url(url: str, database: str | None = None) -> str:
    """Render ``url`` as a plain ``postgresql://`` URL psycopg can connect to."""
    u = make_url(url).set(drivername="postgresql")
    if database is not None:
        u = u.set(database=database)
    return u.render_as_string(hide_password=False)


def _wait_ready(url: str, deadline: float) -> None:
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(url, connect_timeout=2) as conn:
                conn.execute("SELECT 1")
            return
        except psycopg.OperationalError as exc:
            last = exc
            time.sleep(0.25)
    raise TimeoutError(f"postgres at {make_url(url)!r} not ready: {last}")


def _start_container() -> Iterator[str]:
    if docker is None:  # pragma: no cover - the dev group always installs it
        pytest.skip("DB tests need DATABASE_URL or the `docker` SDK (dev dependency)")

    hosts = _docker_hosts()
    if not hosts:
        pytest.skip("DB tests need DATABASE_URL or a Docker/Podman socket; found neither")

    client: Any = None
    errors: list[str] = []
    for host in hosts:
        try:
            candidate = docker.DockerClient(base_url=host, timeout=30)
            candidate.ping()
        except Exception as exc:  # any failure means: try the next socket
            errors.append(f"{host}: {exc}")
            continue
        client = candidate
        break
    if client is None:
        pytest.skip(f"DB tests need DATABASE_URL or a reachable container API ({errors})")

    try:
        client.images.get(POSTGRES_IMAGE)
    except docker.errors.ImageNotFound:
        client.images.pull(POSTGRES_IMAGE)

    password = uuid.uuid4().hex
    container = client.containers.run(
        POSTGRES_IMAGE,
        detach=True,
        environment={
            "POSTGRES_USER": "lab",
            "POSTGRES_PASSWORD": password,
            "POSTGRES_DB": "lab",
        },
        ports={"5432/tcp": ("127.0.0.1", None)},
        labels={"llm-diversion-lab.purpose": "pytest-db"},
    )
    try:
        deadline = time.monotonic() + READY_TIMEOUT_S
        port = None
        while port is None:
            container.reload()
            bindings = (container.attrs["NetworkSettings"]["Ports"] or {}).get("5432/tcp")
            if bindings and bindings[0].get("HostPort"):
                port = int(bindings[0]["HostPort"])
            elif time.monotonic() > deadline:
                raise TimeoutError("postgres container published no port for 5432/tcp")
            else:
                time.sleep(0.1)
        url = f"postgresql://lab:{password}@127.0.0.1:{port}/lab"
        try:
            _wait_ready(url, deadline)
        except TimeoutError as exc:
            logs = container.logs(tail=50).decode(errors="replace")
            raise TimeoutError(f"{exc}\n--- container logs ---\n{logs}") from exc
        yield url
    finally:
        container.remove(force=True)
        client.close()


@pytest.fixture(scope="session")
def pg_server_url() -> Iterator[str]:
    """URL of a Postgres server that tests may create and drop databases on."""
    if url := os.environ.get("DATABASE_URL"):
        yield _libpq_url(url)
        return
    yield from _start_container()


@pytest.fixture
def db_url(pg_server_url: str) -> Iterator[str]:
    """URL of a brand-new, empty database, dropped after the test."""
    name = f"test_{uuid.uuid4().hex}"
    with psycopg.connect(pg_server_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield _libpq_url(pg_server_url, database=name)
    finally:
        with psycopg.connect(pg_server_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def alembic_config(url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


@pytest.fixture
def engine(db_url: str) -> Iterator[Engine]:
    """Engine on a fresh database migrated to ``head`` with Alembic."""
    command.upgrade(alembic_config(db_url), "head")
    eng = create_db_engine(db_url)
    try:
        yield eng
    finally:
        eng.dispose()
