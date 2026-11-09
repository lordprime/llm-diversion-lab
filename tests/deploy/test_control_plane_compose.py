"""``deploy/compose/control-plane.yml``: the contract release.sh and labctl rely on.

* compose project ``lab``, used with ``--env-file /srv/lab/secrets/lab.env``;
* services ``db`` (PostgreSQL >= 13, pinned by the digest in ``deploy/images.lock``),
  ``migrate`` (one-shot ``alembic upgrade head``, ``restart: "no"``) and ``collector``;
* ``POSTGRES_DB`` / ``POSTGRES_USER`` set explicitly (release.sh's pg_dump and restore
  use them inside the db container);
* every published port binds 127.0.0.1, and the control-plane network stays out of
  the run-cell range 10.231.0.0/16;
* every image is pinned by digest or built from the release (``--allow-build``), and
  the Dockerfile's base images are pinned by digest.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from control.cli.settings import COLLECTOR_PORT, DB_NAME, DB_PASSWORD_VAR, DB_PORT, DB_USER

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "compose" / "control-plane.yml"
DOCKERFILE = ROOT / "deploy" / "compose" / "control.Dockerfile"
LOCK = ROOT / "deploy" / "images.lock"
ENV_EXAMPLE = ROOT / ".env.example"
RELEASE_SH = ROOT / "deploy" / "remote" / "release.sh"
BASE_DEFAULTS = ROOT / "deploy" / "ansible" / "roles" / "base" / "defaults" / "main.yml"
RELEASE_IMAGE = "lab/control:${LAB_RELEASE_TAG:?LAB_RELEASE_TAG is not set (release.sh sets it)}"

DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
CELL_RANGE = ipaddress.ip_network("10.231.0.0/16")
# Docker's address pools for other networks (group_vars docker_default_address_pools),
# the home LAN and Twingate/CGNAT: an explicit control-plane subnet overlaps none.
AVOID = [
    CELL_RANGE,
    ipaddress.ip_network("172.20.0.0/14"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _compose() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _services() -> dict[str, dict[str, Any]]:
    services = _compose()["services"]
    assert isinstance(services, dict)
    return services


def _lock() -> dict[str, dict[str, Any]]:
    return {e["name"]: e for e in yaml.safe_load(LOCK.read_text(encoding="utf-8"))["images"]}


def _env(service: dict[str, Any]) -> dict[str, str]:
    env = service.get("environment", {})
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {str(k): str(v) for k, v in env.items()}


# --------------------------------------------------------------------- structure


def test_project_and_services() -> None:
    assert _compose()["name"] == "lab"
    assert {"db", "migrate", "collector"} <= set(_services())


def test_db_is_pinned_postgres_from_images_lock() -> None:
    db = _services()["db"]
    entries = [e for e in _lock().values() if e["image"] == "docker.io/library/postgres"]
    assert len(entries) == 1, "images.lock must pin exactly one postgres image"
    entry = entries[0]
    assert db["image"] == f"{entry['image']}@{entry['digest']}"
    major = int(re.match(r"postgres-(\d+)", entry["name"]).group(1))  # type: ignore[union-attr]
    assert major >= 13, "release.sh's rollback needs DROP DATABASE ... WITH (FORCE)"
    assert "build" not in db


def test_images_lock_says_the_postgres_digest_changes_only_in_reviewed_commits() -> None:
    text = LOCK.read_text(encoding="utf-8")
    block = text[text.index("name: postgres-") - 600 : text.index("name: postgres-")]
    assert "reviewed commit" in block


def test_db_names_user_and_database_explicitly() -> None:
    env = _env(_services()["db"])
    assert env["POSTGRES_DB"] == DB_NAME == "lab"
    assert env["POSTGRES_USER"] == DB_USER == "lab"
    # the password comes from lab.env and the stack refuses to start without it
    assert re.fullmatch(rf"\$\{{{DB_PASSWORD_VAR}:\?[^}}]+\}}", env["POSTGRES_PASSWORD"])


def _base_dirs() -> dict[str, str]:
    base = yaml.safe_load(BASE_DEFAULTS.read_text(encoding="utf-8"))
    return {d["path"]: d["mode"] for d in base["base_lab_dirs"]}


def test_db_data_is_its_own_mount() -> None:
    """The data directory itself is the mount, at the image's default PGDATA.

    /srv/lab/db is lab:lab 0700. Mounting it as PGDATA's parent fails on a real host:
    the entrypoint chowns only $PGDATA, then runs initdb as uid 999, which cannot enter
    the 0700 parent. Mounting /srv/lab/db/pgdata *as* the data directory lets the
    entrypoint chown the mount point itself.
    """
    db = _services()["db"]
    assert db["volumes"] == ["/srv/lab/db/pgdata:/var/lib/postgresql/data"]
    assert "PGDATA" not in _env(db), "the image's default PGDATA is the mount point"


def test_db_data_directory_is_not_managed_by_ansible() -> None:
    """The base role owns /srv/lab/db (lab, 0700); it must never re-own pgdata (uid 999)."""
    dirs = _base_dirs()
    assert dirs["db"] == "0700"
    assert not [p for p in dirs if p.startswith("db/")], "pgdata belongs to postgres (uid 999)"


def test_every_host_bind_mount_has_a_creator() -> None:
    """Each host path is created by the base role, or (pgdata) by release.sh."""
    dirs = _base_dirs()
    for name, service in _services().items():
        for volume in service.get("volumes", []):
            source = str(volume).split(":", 1)[0]
            assert source.startswith("/srv/lab/"), f"{name}: {source}"
            rel = source.removeprefix("/srv/lab/")
            if rel == "db/pgdata":
                assert "db/pgdata" in RELEASE_SH.read_text(encoding="utf-8")
            else:
                assert rel in dirs, f"{name}: the base role does not create {source}"
    assert dirs["state"] == "0755", "the collector (uid 10001) reads the self-test status"


def test_migrate_is_a_one_shot_alembic_upgrade() -> None:
    migrate = _services()["migrate"]
    assert migrate["restart"] == "no"
    assert migrate["command"] == ["python", "-m", "control.cli.migrate"]
    assert migrate["depends_on"]["db"]["condition"] == "service_healthy"


def test_collector_runs_the_logging_entry_point_after_migrate() -> None:
    collector = _services()["collector"]
    assert collector["command"][:3] == ["python", "-m", "control.api"]
    assert collector["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert collector["depends_on"]["db"]["condition"] == "service_healthy"
    assert "healthcheck" in collector
    assert "readyz" in " ".join(collector["healthcheck"]["test"])
    # the self-test status file, read-only
    assert "/srv/lab/state:/srv/lab/state:ro" in collector["volumes"]


def test_app_services_reach_the_db_without_a_password_in_the_url() -> None:
    for name in ("migrate", "collector"):
        env = _env(_services()[name])
        url = env["DATABASE_URL"]
        assert url == f"postgresql+psycopg://{DB_USER}@db:5432/{DB_NAME}", name
        assert env["PGPASSWORD"] == f"${{{DB_PASSWORD_VAR}:?{DB_PASSWORD_VAR} is not set}}"


def test_db_and_app_services_have_healthchecks_and_restart_policies() -> None:
    services = _services()
    assert "pg_isready" in " ".join(services["db"]["healthcheck"]["test"])
    assert services["db"]["restart"] == "unless-stopped"
    assert services["collector"]["restart"] == "unless-stopped"


# --------------------------------------------------------------------- network exposure


def _published(service: dict[str, Any]) -> list[tuple[str, int, int]]:
    out = []
    for port in service.get("ports", []):
        if isinstance(port, dict):
            out.append((port.get("host_ip", ""), int(port["published"]), int(port["target"])))
            continue
        parts = str(port).split(":")
        assert len(parts) == 3, f"port {port!r} must name its host IP"
        out.append((parts[0], int(parts[1]), int(parts[2])))
    return out


def test_every_published_port_binds_loopback_only() -> None:
    seen = []
    for name, service in _services().items():
        assert service.get("network_mode") != "host", name
        for host_ip, _, _ in _published(service):
            assert host_ip == "127.0.0.1", f"{name} publishes on {host_ip!r}"
            seen.append(name)
    assert "db" in seen and "collector" in seen


def test_published_ports_match_labctl_defaults() -> None:
    services = _services()
    assert _published(services["db"]) == [("127.0.0.1", DB_PORT, 5432)]
    assert _published(services["collector"]) == [("127.0.0.1", COLLECTOR_PORT, 8000)]
    assert "ports" not in services["migrate"]


def test_control_plane_network_stays_out_of_the_cell_range() -> None:
    networks = _compose()["networks"]
    assert networks, "the control plane declares its network explicitly"
    for name, net in networks.items():
        configs = net["ipam"]["config"]
        assert configs, name
        for cfg in configs:
            subnet = ipaddress.ip_network(cfg["subnet"])
            assert subnet.is_private
            for avoid in AVOID:
                assert not subnet.overlaps(avoid), f"{name}: {subnet} overlaps {avoid}"
    for name, service in _services().items():
        assert set(service["networks"]) <= set(networks), name


def test_no_privileged_service_and_no_docker_socket() -> None:
    for name, service in _services().items():
        assert not service.get("privileged"), name
        assert not service.get("cap_add"), name
        for volume in service.get("volumes", []):
            assert "docker.sock" not in str(volume), name


# --------------------------------------------------------------------- image pinning


def test_every_image_is_pinned_or_built_from_the_release() -> None:
    """release.sh compose-pull: pulled images must be pinned; only built ones may not."""
    for name, service in _services().items():
        if "build" in service:
            build = service["build"]
            assert build["context"] == "../.."
            assert build["dockerfile"] == "deploy/compose/control.Dockerfile"
        else:
            assert DIGEST_REF.match(service["image"]), f"{name}: {service['image']} not pinned"


def test_built_image_is_tagged_per_release() -> None:
    """A rollback must start the previous release's own image, never the new one's.

    With one shared tag, `up --no-build` after a rollback would start the failed
    release's migrate on the restored database and re-apply the failed migration.
    """
    for name in ("migrate", "collector"):
        assert _services()[name]["image"] == RELEASE_IMAGE, name


def test_dockerfile_base_images_are_pinned() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", text, re.M)
    stages = set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", text, re.M | re.I))
    copies = [r for r in re.findall(r"^COPY\s+--from=(\S+)", text, re.M) if r not in stages]
    assert froms
    assert copies, "uv comes from its pinned image"
    for ref in froms + copies:
        assert DIGEST_REF.match(ref), f"{ref} is not pinned by digest"
    assert "# syntax=" not in text, "a syntax directive pulls an unpinned frontend image"


def test_dockerfile_runs_unprivileged_and_installs_from_the_lock() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"^USER\s+(?!root|0\b)\S+", text, re.M)
    assert "--frozen" in text
    assert "--no-dev" in text


def test_build_context_sends_only_what_the_image_copies() -> None:
    ignore = DOCKERFILE.with_name(DOCKERFILE.name + ".dockerignore").read_text(encoding="utf-8")
    rules = [line for line in ignore.splitlines() if line and not line.startswith("#")]
    assert rules[0] == "*"
    assert {"!pyproject.toml", "!uv.lock", "!control/"} <= set(rules)
    assert all(r == "*" or r.startswith("!") or r.startswith("**/") for r in rules)


# --------------------------------------------------------------------- lab.env


def test_db_password_is_host_generated_not_operator_supplied() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    # not a NAME= line: secrets.sh never prompts for it nor sends it
    assert not re.search(rf"^{DB_PASSWORD_VAR}=", text, re.M)
    header = text.split("\n\n# ---", 1)[0]
    assert DB_PASSWORD_VAR in header
    assert "bootstrap.sh" in header


# --------------------------------------------------------------------- docker compose config


def _docker_compose() -> list[str] | None:
    docker = shutil.which("docker")
    if docker is None:
        return None
    probe = subprocess.run(  # noqa: S603 -- fixed argv
        [docker, "compose", "version"], capture_output=True, text=True, check=False
    )
    return [docker, "compose"] if probe.returncode == 0 else None


@pytest.fixture
def compose_cmd() -> list[str]:
    cmd = _docker_compose()
    if cmd is None:
        pytest.skip("docker compose is not installed")
    return cmd


def _config(
    compose_cmd: list[str], env_file: Path, *extra: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed argv
        [
            *compose_cmd,
            "--project-name",
            "lab",
            "--env-file",
            str(env_file),
            "-f",
            str(COMPOSE),
            "config",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
    )


TAG = {"LAB_RELEASE_TAG": "v0.1.0"}


def test_compose_config_is_valid(compose_cmd: list[str], tmp_path: Path) -> None:
    env_file = tmp_path / "lab.env"
    env_file.write_text(f"{DB_PASSWORD_VAR}=correct-horse-battery\n", encoding="utf-8")
    result = _config(compose_cmd, env_file, "--services", env=TAG)
    assert result.returncode == 0, result.stderr
    # release.sh's migrate step looks for exactly these names
    assert {"db", "migrate", "collector"} <= set(result.stdout.split())
    images = _config(compose_cmd, env_file, "--images", env=TAG).stdout
    assert "correct-horse-battery" not in images


def test_rendered_image_follows_the_release_tag(compose_cmd: list[str], tmp_path: Path) -> None:
    env_file = tmp_path / "lab.env"
    env_file.write_text(f"{DB_PASSWORD_VAR}=correct-horse-battery\n", encoding="utf-8")
    images = {}
    for tag in ("v0.1.0", "v0.0.9"):
        result = _config(compose_cmd, env_file, "--images", env={"LAB_RELEASE_TAG": tag})
        assert result.returncode == 0, result.stderr
        images[tag] = set(result.stdout.split())
    assert "lab/control:v0.1.0" in images["v0.1.0"]
    assert "lab/control:v0.0.9" in images["v0.0.9"]
    assert "lab/control:v0.1.0" not in images["v0.0.9"]


def test_compose_refuses_to_run_without_the_release_tag(
    compose_cmd: list[str], tmp_path: Path
) -> None:
    env_file = tmp_path / "lab.env"
    env_file.write_text(f"{DB_PASSWORD_VAR}=correct-horse-battery\n", encoding="utf-8")
    result = _config(compose_cmd, env_file)
    assert result.returncode != 0
    assert "LAB_RELEASE_TAG" in result.stderr


def test_compose_refuses_to_run_without_the_db_password(
    compose_cmd: list[str], tmp_path: Path
) -> None:
    env_file = tmp_path / "lab.env"
    env_file.write_text("LAB_BUDGET_USD=10\n", encoding="utf-8")
    result = _config(compose_cmd, env_file, env=TAG)
    assert result.returncode != 0
    assert DB_PASSWORD_VAR in result.stderr
