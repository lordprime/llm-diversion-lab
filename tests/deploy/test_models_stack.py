"""The GPU host's model stack: ``deploy/compose/models.yml`` and the ``nvidia`` role.

* ``ollama`` is pinned by digest (the one in ``deploy/images.lock``), runs on the
  NVIDIA runtime and joins only the internal ``models`` network: no published port,
  no route to the internet, no cell network;
* the ``nvidia`` role installs a pinned NVIDIA Container Toolkit, registers the
  ``nvidia`` runtime in Docker, and refuses (with a clear message) on a host with no
  working NVIDIA driver: the driver is the operator's decision, never installed here;
* ``gpu: true`` in hosts.yml is what switches all of it on.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "compose" / "models.yml"
CONTROL = ROOT / "deploy" / "compose" / "control-plane.yml"
LOCK = ROOT / "deploy" / "images.lock"
ROLE = ROOT / "deploy" / "ansible" / "roles" / "nvidia"
DOCKER_ROLE = ROOT / "deploy" / "ansible" / "roles" / "docker"
SITE = ROOT / "deploy" / "ansible" / "site.yml"
HOSTS_EXAMPLE = ROOT / "deploy" / "hosts.example.yml"
LIB = ROOT / "deploy" / "lib.sh"

DIGEST_REF = re.compile(r"^docker\.io/ollama/ollama@sha256:[0-9a-f]{64}$")


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _ollama() -> dict[str, Any]:
    service = _load(COMPOSE)["services"]["ollama"]
    assert isinstance(service, dict)
    return service


def _env(service: dict[str, Any]) -> dict[str, str]:
    env = service["environment"]
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {str(k): str(v) for k, v in env.items()}


def _lock_entry() -> dict[str, Any]:
    entries = [e for e in _load(LOCK)["images"] if e["image"] == "docker.io/ollama/ollama"]
    assert len(entries) == 1, "images.lock must pin exactly one ollama image"
    return entries[0]


# --------------------------------------------------------------------- the compose file


def test_only_the_ollama_service_is_defined_here() -> None:
    # the gateway lives in control-plane.yml and joins `models`; it is never defined here
    assert set(_load(COMPOSE)["services"]) == {"ollama"}
    assert _load(COMPOSE)["name"] == "lab"


def test_the_image_is_the_digest_in_images_lock() -> None:
    entry = _lock_entry()
    assert entry["role"] == "infra"
    assert "ollama" in entry["expect_tools"]
    pinned = f"{entry['image']}@{entry['digest']}"
    assert DIGEST_REF.match(pinned)
    # the compose default is that exact ref; OLLAMA_IMAGE may override it, but only with
    # another digest (release.sh refuses an unpinned image)
    assert _ollama()["image"] == f"${{OLLAMA_IMAGE:-{pinned}}}"
    assert "build" not in _ollama()


def test_images_lock_documents_the_ollama_pin() -> None:
    text = LOCK.read_text(encoding="utf-8")
    block = text[text.index("name: ollama") - 900 : text.index("name: ollama")]
    assert "registry API" in block and "reviewed commit" in block


def test_ollama_runs_on_the_nvidia_runtime_with_every_gpu() -> None:
    service = _ollama()
    assert service["runtime"] == "nvidia"
    env = _env(service)
    assert env["NVIDIA_VISIBLE_DEVICES"] == "all"
    assert "compute" in env["NVIDIA_DRIVER_CAPABILITIES"]


def test_ollama_listens_inside_its_network_and_keeps_one_model_warm() -> None:
    env = _env(_ollama())
    assert env["OLLAMA_HOST"] == "0.0.0.0:11434"
    assert env["OLLAMA_KEEP_ALIVE"] == "-1"


def test_parallelism_and_context_come_from_host_config() -> None:
    env = _env(_ollama())
    assert re.fullmatch(r"\$\{OLLAMA_NUM_PARALLEL:-[0-9]+\}", env["OLLAMA_NUM_PARALLEL"])
    assert re.fullmatch(r"\$\{OLLAMA_CONTEXT_LENGTH:-[0-9]+\}", env["OLLAMA_CONTEXT_LENGTH"])


def test_no_published_ports_and_no_other_way_onto_the_host() -> None:
    service = _ollama()
    assert "ports" not in service
    for key in ("network_mode", "privileged", "pid", "ipc", "devices", "extra_hosts", "cap_add"):
        assert key not in service, key
    assert not any("docker.sock" in str(v) for v in service.get("volumes", []))


def test_ollama_joins_only_the_models_network_and_it_is_internal() -> None:
    doc = _load(COMPOSE)
    assert list(_ollama()["networks"]) == ["models"]
    models = doc["networks"]["models"]
    assert models["internal"] is True
    assert set(doc["networks"]) == {"models"}


def test_the_models_network_is_clear_of_the_cell_range_and_the_control_network() -> None:
    subnet = ipaddress.ip_network(
        _load(COMPOSE)["networks"]["models"]["ipam"]["config"][0]["subnet"]
    )
    avoid = [
        "10.231.0.0/16",
        "172.20.0.0/14",
        "192.168.0.0/16",
        "100.64.0.0/10",
        _load(CONTROL)["networks"]["control"]["ipam"]["config"][0]["subnet"],
    ]
    for other in avoid:
        assert not subnet.overlaps(ipaddress.ip_network(other)), other


def test_models_live_on_a_named_volume_the_host_can_rename() -> None:
    service = _ollama()
    assert service["volumes"] == ["ollama_models:/root/.ollama"]
    volume = _load(COMPOSE)["volumes"]["ollama_models"]
    assert re.fullmatch(r"\$\{OLLAMA_MODELS_VOLUME:-[a-z0-9_]+\}", volume["name"])


def test_ollama_restarts_and_reports_health() -> None:
    service = _ollama()
    assert service["restart"] == "unless-stopped"
    assert service["healthcheck"]["test"][0] == "CMD"
    assert "no-new-privileges:true" in service["security_opt"]


# --------------------------------------------------------------------- rendered by compose


@pytest.fixture
def compose_cmd() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker compose is not installed")
    probe = subprocess.run(  # noqa: S603 -- fixed argv
        [docker, "compose", "version"], capture_output=True, text=True, check=False
    )
    if probe.returncode != 0:
        pytest.skip("docker compose is not installed")
    return [docker, "compose"]


def _render(
    compose_cmd: list[str], *files: Path, env: dict[str, str] | None = None
) -> dict[str, Any]:
    argv = [*compose_cmd, "--project-name", "lab"]
    for f in files:
        argv += ["-f", str(f)]
    result = subprocess.run(  # noqa: S603 -- fixed argv
        [*argv, "config", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
    )
    assert result.returncode == 0, result.stderr
    doc = json.loads(result.stdout)
    assert isinstance(doc, dict)
    return doc


def test_rendered_service_has_no_ports_and_an_internal_network(compose_cmd: list[str]) -> None:
    doc = _render(compose_cmd, COMPOSE)
    ollama = doc["services"]["ollama"]
    assert not ollama.get("ports")
    assert list(ollama["networks"]) == ["models"]
    assert doc["networks"]["models"]["internal"] is True
    assert DIGEST_REF.match(ollama["image"])
    assert doc["networks"]["models"]["name"] == "lab_models"


def test_rendered_defaults_and_host_overrides(compose_cmd: list[str]) -> None:
    default = _render(compose_cmd, COMPOSE)["services"]["ollama"]["environment"]
    assert default["OLLAMA_CONTEXT_LENGTH"] == "65536"
    assert default["OLLAMA_NUM_PARALLEL"] == "1"
    custom = _render(
        compose_cmd,
        COMPOSE,
        env={
            "OLLAMA_NUM_PARALLEL": "4",
            "OLLAMA_CONTEXT_LENGTH": "32768",
            "OLLAMA_MODELS_VOLUME": "cispa_models",
        },
    )
    assert custom["services"]["ollama"]["environment"]["OLLAMA_NUM_PARALLEL"] == "4"
    assert custom["services"]["ollama"]["environment"]["OLLAMA_CONTEXT_LENGTH"] == "32768"
    assert custom["volumes"]["ollama_models"]["name"] == "cispa_models"


def test_it_merges_with_the_control_plane_file(compose_cmd: list[str]) -> None:
    doc = _render(
        compose_cmd,
        CONTROL,
        COMPOSE,
        env={"LAB_RELEASE_TAG": "v0.1.0", "LAB_DB_PASSWORD": "correct-horse-battery"},
    )
    assert {"db", "migrate", "collector", "ollama"} <= set(doc["services"])
    # nothing from the control plane leaks onto the models network, except a gateway
    members = {n for n, s in doc["services"].items() if "models" in (s.get("networks") or {})}
    assert members <= {"ollama", "gateway"}


# --------------------------------------------------------------------- the nvidia role


def _tasks(name: str) -> list[dict[str, Any]]:
    tasks = _load(ROLE / "tasks" / f"{name}.yml")
    assert isinstance(tasks, list)
    return tasks


def _module(task: dict[str, Any]) -> str:
    return next(k for k in task if k.startswith("ansible.builtin."))


def test_the_role_has_the_usual_layout() -> None:
    for part in ("tasks/main.yml", "defaults/main.yml", "templates/models.env.j2"):
        assert (ROLE / part).is_file(), part


def test_the_driver_is_checked_first_and_the_failure_says_what_to_do() -> None:
    tasks = _tasks("main")
    smi = next(i for i, t in enumerate(tasks) if "nvidia-smi" in json.dumps(t))
    install = next(i for i, t in enumerate(tasks) if _module(t) == "ansible.builtin.apt")
    assert smi < install, "the driver is checked before anything is installed"
    text = json.dumps(tasks)
    assert "nvidia-smi" in text and "driver" in text
    fail = next(t for t in tasks if "assert" in _module(t) and "driver" in json.dumps(t))
    message = fail["ansible.builtin.assert"]["fail_msg"]
    assert "driver" in message and "install" in message.lower()
    assert "never installs" in message or "does not install" in message


def test_the_role_never_installs_a_driver() -> None:
    for task in _tasks("main"):
        names = task.get("ansible.builtin.apt", {}).get("name", [])
        for name in [names] if isinstance(names, str) else names:
            assert not re.search(r"driver|cuda|dkms", str(name)), name


def test_the_toolkit_is_installed_at_a_pinned_version() -> None:
    defaults = _load(ROLE / "defaults" / "main.yml")
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-1", defaults["nvidia_toolkit_version"])
    assert re.fullmatch(r"[0-9A-F]{40}", defaults["nvidia_apt_key_fingerprint"])
    # all four packages move together: a mixed set breaks the runtime hook
    assert len(defaults["nvidia_toolkit_packages"]) == 4
    install = next(
        t
        for t in _tasks("main")
        if "nvidia_toolkit_packages" in str(t.get("ansible.builtin.apt", {}).get("name"))
    )
    apt = install["ansible.builtin.apt"]
    assert "nvidia_toolkit_version" in apt["name"]
    assert apt["install_recommends"] is False
    assert apt["allow_downgrade"] is True


def test_the_toolkit_packages_are_held() -> None:
    held = [t for t in _tasks("main") if "dpkg_selections" in _module(t)]
    assert held and held[0]["ansible.builtin.dpkg_selections"]["selection"] == "hold"


def test_the_apt_key_is_checked_before_it_is_trusted() -> None:
    tasks = _tasks("main")
    download = next(i for i, t in enumerate(tasks) if "get_url" in _module(t))
    assert (
        tasks[download]["ansible.builtin.get_url"]["dest"]
        != "/etc/apt/keyrings/nvidia-container-toolkit.asc"
    )
    check = next(
        i for i, t in enumerate(tasks) if "fingerprint" in json.dumps(t) and "assert" in _module(t)
    )
    trust = next(
        i
        for i, t in enumerate(tasks)
        if t.get("ansible.builtin.copy", {}).get("dest")
        == "/etc/apt/keyrings/nvidia-container-toolkit.asc"
    )
    assert download < check < trust


def test_docker_is_pointed_at_the_runtime_with_nvidia_ctk_only_when_it_is_missing() -> None:
    tasks = _tasks("main")
    configure = next(
        t for t in tasks if "nvidia-ctk" in json.dumps(t) and "configure" in json.dumps(t)
    )
    argv = configure["ansible.builtin.command"]["argv"]
    assert argv[:3] == ["nvidia-ctk", "runtime", "configure"] and "--runtime=docker" in argv
    assert "when" in configure, "idempotent: it runs only if the runtime is not registered"
    assert "Restart Docker" in json.dumps(configure["notify"])


def test_the_role_ends_by_checking_the_runtime_and_a_gpu() -> None:
    text = json.dumps(_tasks("main"))
    assert "docker" in text and "Runtimes" in text
    assert "nvidia-smi" in text


def test_the_role_refuses_to_run_in_an_lxc() -> None:
    text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "virtualization_type" in text and "lxc" in text


def test_models_env_carries_the_host_config_for_compose() -> None:
    template = (ROLE / "templates" / "models.env.j2").read_text(encoding="utf-8")
    for name in ("OLLAMA_NUM_PARALLEL", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_MODELS_VOLUME"):
        assert name in template
    defaults = _load(ROOT / "deploy" / "ansible" / "group_vars" / "all.yml")
    assert int(defaults["ollama_num_parallel"]) >= 1
    assert int(defaults["ollama_context_length"]) >= 2048
    assert re.fullmatch(r"[a-z0-9_]+", defaults["ollama_models_volume"])


def test_docker_role_keeps_a_registered_nvidia_runtime_when_it_rewrites_daemon_json() -> None:
    # Without this, every docker-role run would erase what `nvidia-ctk` wrote.
    text = (DOCKER_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "runtimes" in text
    assert text.index("runtimes") < text.index("Write /etc/docker/daemon.json")


# --------------------------------------------------------------------- site and hosts


def test_site_runs_the_nvidia_role_after_docker_on_gpu_hosts_only() -> None:
    roles = _load(SITE)[0]["roles"]
    names = [r["role"] for r in roles]
    entry = roles[names.index("nvidia")]
    assert entry["when"] == "gpu | bool"
    assert names.index("docker") < names.index("nvidia") < names.index("caddy")


def test_site_checks_gpu_is_a_boolean_and_not_in_an_lxc() -> None:
    text = SITE.read_text(encoding="utf-8")
    assert "gpu is boolean" in text
    assert "not gpu | bool or isolation == 'sysbox'" in text


def test_hosts_example_documents_the_gpu_keys() -> None:
    text = HOSTS_EXAMPLE.read_text(encoding="utf-8")
    assert _load(HOSTS_EXAMPLE)["lab1"]["gpu"] is False
    assert "gpu: true" in text and "ollama_models_volume" in text
    assert "ollama_num_parallel" in text and "ollama_context_length" in text


def _inventory(tmp_path: Path, host: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(yaml.safe_dump({"gpu1": host}), encoding="utf-8")
    out = tmp_path / "inv.json"
    return subprocess.run(  # noqa: S603 -- fixed argv
        [
            "/bin/bash",
            "-c",
            f'source "{LIB}"; lab_python -c "$LAB__HOSTS_PY" "{hosts}" gpu1 inventory "{out}"',
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LAB_PYTHON": _python(), "LAB_HOSTS_FILE": str(hosts)},
    )


def _python() -> str:
    import sys

    return sys.executable


BASE_HOST = {
    "address": "192.0.2.20",
    "ssh_user": "admin",
    "isolation": "sysbox",
    "access": "ssh-tunnel",
}


def test_gpu_is_a_known_boolean_host_key(tmp_path: Path) -> None:
    ok = _inventory(tmp_path, {**BASE_HOST, "gpu": True, "vars": {"ollama_models_volume": "m"}})
    assert ok.returncode == 0, ok.stderr
    inventory = json.loads((tmp_path / "inv.json").read_text(encoding="utf-8"))
    hostvars = inventory["all"]["hosts"]["gpu1"]
    assert hostvars["gpu"] is True and hostvars["ollama_models_volume"] == "m"
    default = _inventory(tmp_path, BASE_HOST)
    assert default.returncode == 0
    assert (
        json.loads((tmp_path / "inv.json").read_text(encoding="utf-8"))["all"]["hosts"]["gpu1"][
            "gpu"
        ]
        is False
    )


@pytest.mark.parametrize("value", ["yes", 1, None, "true"])
def test_gpu_must_be_a_real_boolean(tmp_path: Path, value: Any) -> None:
    bad = _inventory(tmp_path, {**BASE_HOST, "gpu": value})
    assert bad.returncode != 0
    assert "gpu" in bad.stderr


def test_host_env_records_the_gpu_flag_for_labctl_and_release() -> None:
    template = (ROOT / "deploy" / "ansible" / "templates" / "host.env.j2").read_text(
        encoding="utf-8"
    )
    assert "LAB_GPU={{ 'true' if gpu | bool else 'false' }}" in template


def test_the_models_bridge_has_no_host_side_gateway_address() -> None:
    # Docker 28+; the docker role pins 29.8 (checked against a local 29.9 daemon: a
    # second container on the network still reaches Ollama's name and port)
    opts = _load(COMPOSE)["networks"]["models"]["driver_opts"]
    assert opts["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    assert int(_load(DOCKER_ROLE / "defaults" / "main.yml")["docker_ce_minor"].split(".")[0]) >= 28


def test_release_pulls_the_ollama_image_only_for_a_gpu_host() -> None:
    text = (ROOT / "deploy" / "release.sh").read_text(encoding="utf-8")
    filter_at = text.index("docker.io/ollama/ollama@")
    assert text.index("$HOST_GPU != true") < filter_at < text.index("release.sh pull")
    assert filter_at > text.index('lab_load_host "$host"')


def test_release_guards_the_empty_image_list_for_set_u() -> None:
    text = (ROOT / "deploy" / "release.sh").read_text(encoding="utf-8")
    assert 'image_refs=("${kept[@]+"${kept[@]}"}")' in text
