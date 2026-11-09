"""Rendering one run's cell: the Compose project, its networks and its per-run files.

Pure: nothing here starts a container. Every option a Docker host relies on is
asserted on the rendered document (Docker semantics), whatever engine runs the tests.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from agents.scripted.agent import AgentScript
from cell.catcher.callback_log import CatcherConfig
from cell.injector.serve_log import InjectorConfig
from control.core.models import Arm, RunManifest
from control.core.tokens import TAG_PATTERN
from control.runner.cell_spec import (
    AGENT_SPECS,
    CELL_NAME_PREFIX,
    AgentSpec,
    CellError,
    CellSecrets,
    CellSettings,
    ComposeProject,
    Engine,
    allocate_subnets,
    bridge_name,
    project_name,
    render_cell,
)
from control.runner.experiment import Experiment, load_experiment
from control.runner.render import render_manifest
from control.runner.schedule import ScheduledRun, build_schedule

REPO_ROOT = Path(__file__).resolve().parents[2]
SELFTEST = REPO_ROOT / "experiments" / "selftest.yaml"
KEY = hashlib.sha256(b"cell-spec-test-lab-key").digest()
WHEN = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
POOL = ipaddress.IPv4Network("10.231.0.0/16")
IMAGES = {
    "lab-cell": "ghcr.io/lordprime/lab-cell@sha256:" + "a" * 64,
    "goat-dvga": "ghcr.io/lordprime/goat-dvga@sha256:" + "b" * 64,
}
SECRET_FILES = {
    ("secret_admin_password", "admin_password"),
    ("secret_outbound_service_request_canary", "outbound_service_request_canary"),
    ("secret_rce_canary", "rce_canary"),
    ("secret_attack_success_canary", "attack_success_canary"),
}
INFRA = ("goat", "injector", "tap", "stub-llm", "catcher", "agent")


@pytest.fixture(scope="module")
def experiment() -> Experiment:
    return load_experiment(SELFTEST)


@pytest.fixture(scope="module")
def schedule(experiment: Experiment) -> list[ScheduledRun]:
    return build_schedule(experiment)


def _settings(**over: Any) -> CellSettings:
    doc: dict[str, Any] = {"images": IMAGES, "cell_networks": (POOL,)}
    doc.update(over)
    return CellSettings(**doc)


def _render(
    experiment: Experiment,
    schedule: list[ScheduledRun],
    arm: Arm,
    *,
    settings: CellSettings | None = None,
    **kwargs: Any,
) -> tuple[ScheduledRun, RunManifest, ComposeProject]:
    run = next(r for r in schedule if r.arm is arm)
    manifest = render_manifest(run, experiment, KEY, created_at=WHEN)
    project = render_cell(
        run,
        manifest,
        experiment=experiment,
        settings=settings or _settings(),
        subnets=allocate_subnets((POOL,), []),
        **kwargs,
    )
    return run, manifest, project


@pytest.fixture(scope="module")
def control(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> tuple[ScheduledRun, RunManifest, ComposeProject]:
    return _render(experiment, schedule, Arm.CONTROL)


@pytest.fixture(scope="module")
def injected(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> tuple[ScheduledRun, RunManifest, ComposeProject]:
    return _render(experiment, schedule, Arm.INJECTED)


def _both(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> Iterator[tuple[ScheduledRun, RunManifest, ComposeProject]]:
    yield control
    yield injected


def _file(project: ComposeProject, volume: str, name: str) -> bytes:
    (match,) = [f for f in project.files if (f.volume, f.name) == (volume, name)]
    return match.content


def _services(project: ComposeProject) -> dict[str, Any]:
    services: dict[str, Any] = project.document["services"]
    return services


def _env(project: ComposeProject, service: str) -> dict[str, str]:
    env: dict[str, str] = _services(project)[service].get("environment", {})
    return env


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list | tuple):
        for item in node:
            yield from _strings(item)


# --------------------------------------------------------------------------- arms


def test_control_arm_injector_plants_nothing_and_has_no_decoy(
    control: tuple[ScheduledRun, RunManifest, ComposeProject], tmp_path: Path
) -> None:
    run, manifest, project = control
    assert json.loads(_file(project, "cfg_injector", "payloads.json")) == {}
    shipped = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
    assert shipped == manifest and shipped.placements == [] and shipped.tag is None
    env = _env(project, "injector")
    assert env["LAB_SYNTHESIZE_ROBOTS"] == "1"  # arm parity: same robots base as treated
    assert _env(project, "tap")["LAB_TAGS"] == ""
    tokens = json.loads(_file(project, "cfg_catcher", "tokens.json"))
    assert tokens["tokens"] == [] and tokens["run_id"] == run.run_id

    # the real injector reads these inputs into a plan with no placement and no decoy
    (tmp_path / "manifest.json").write_bytes(_file(project, "cfg_injector", "manifest.json"))
    (tmp_path / "payloads.json").write_bytes(_file(project, "cfg_injector", "payloads.json"))
    config = InjectorConfig.from_env(
        {
            **env,
            "LAB_MANIFEST": str(tmp_path / "manifest.json"),
            "LAB_PAYLOADS": str(tmp_path / "payloads.json"),
            "LAB_EVIDENCE_DIR": str(tmp_path / "ev"),
        }
    )
    assert config.contents == {} and config.synthesize_robots is True


def test_injected_arm_plants_p1_and_p7_with_the_tag(
    experiment: Experiment, injected: tuple[ScheduledRun, RunManifest, ComposeProject]
) -> None:
    run, manifest, project = injected
    payloads = json.loads(_file(project, "cfg_injector", "payloads.json"))
    surfaces = {p.surface.value: p for p in manifest.placements}
    assert set(surfaces) == {"P1", "P7"}
    assert set(payloads) == {p.placement_id for p in manifest.placements}
    assert run.tag is not None
    for text in payloads.values():
        assert run.tag in text
    assert _env(project, "tap")["LAB_TAGS"] == run.tag
    assert _env(project, "injector")["LAB_SYNTHESIZE_ROBOTS"] == "1"


def test_catcher_gets_only_the_token_file(
    tmp_path: Path, injected: tuple[ScheduledRun, RunManifest, ComposeProject]
) -> None:
    run, manifest, project = injected
    data = _file(project, "cfg_catcher", "tokens.json")
    assert run.tag is not None and run.tag.encode() not in data
    path = tmp_path / "tokens.json"
    path.write_bytes(data)
    env = _env(project, "catcher")
    assert "LAB_MANIFEST" not in env and env["LAB_TOKENS"] == "/etc/lab/catcher/tokens.json"
    config = CatcherConfig.from_env({"LAB_TOKENS": str(path), "LAB_RUN_ID": env["LAB_RUN_ID"]})
    assert {t for t, _ in config.tokens.entries} == {p.token for p in manifest.placements}
    assert {v for v, _ in project.document["volumes"].items() if v.startswith("cfg_")} == {
        "cfg_injector",
        "cfg_catcher",
        "cfg_agent",
    }


# --------------------------------------------------------------------------- containment


def test_agent_is_only_on_an_internal_network_and_reaches_the_llm_only_via_the_tap(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    for _run, _manifest, project in _both(control, injected):
        services = _services(project)
        agent = services["agent"]
        assert set(agent["networks"]) == {"agent"}
        networks = project.document["networks"]
        for name, net in networks.items():
            assert net["internal"] is True, name
            opts = net.get("driver_opts", {})
            # ruling (14b): no isolated gateway mode -- rpf needs the bridge's route
            assert "com.docker.network.bridge.gateway_mode_ipv4" not in opts
        env = _env(project, "agent")
        assert env["ANTHROPIC_BASE_URL"] == "http://tap:8080"
        # the LLM side is reachable only from the tap
        on_llm = {s for s, d in services.items() if "llm" in d.get("networks", {})}
        assert on_llm == {"tap", "stub-llm"}
        on_agent = {s for s, d in services.items() if "agent" in d.get("networks", {})}
        assert on_agent == {"agent", "injector", "tap", "catcher"}
        on_target = {s for s, d in services.items() if "target" in d.get("networks", {})}
        assert on_target == {"goat", "injector"}
        assert services["injector"]["networks"]["agent"]["aliases"] == ["target"]
        # the agent resolves through the catcher, which is pinned to a static address
        catcher_ip = services["catcher"]["networks"]["agent"]["ipv4_address"]
        assert agent["dns"] == [catcher_ip]
        assert _env(project, "catcher")["LAB_CATCHER_IP"] == catcher_ip
        # the agent finds the injector and the tap by pinned address, not by DNS
        injector_ip = services["injector"]["networks"]["agent"]["ipv4_address"]
        tap_ip = services["tap"]["networks"]["agent"]["ipv4_address"]
        assert agent["extra_hosts"] == [f"target:{injector_ip}", f"tap:{tap_ip}"]
        assert len({catcher_ip, injector_ip, tap_ip}) == 3


def test_networks_have_cell_subnets_bridge_names_and_labels(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    run, _, project = control
    subnets = []
    bridges = []
    for name, net in project.document["networks"].items():
        (config,) = net["ipam"]["config"]
        subnet = ipaddress.IPv4Network(config["subnet"])
        assert subnet.subnet_of(POOL), name
        gateway = ipaddress.IPv4Address(config["gateway"])
        assert gateway == next(subnet.hosts())  # a connected route: rpf works
        assert ipaddress.IPv4Network(config["ip_range"]).subnet_of(subnet)
        subnets.append(subnet)
        bridge = net["driver_opts"]["com.docker.network.bridge.name"]
        assert re.fullmatch(r"labc[a-z0-9]{1,11}", bridge) and len(bridge) <= 15
        bridges.append(bridge)
        assert net["labels"]["lab.run_id"] == run.run_id
        assert net["name"] == f"{project.name}_{name}"
    assert len(set(bridges)) == len(bridges)
    for i, a in enumerate(subnets):
        for b in subnets[i + 1 :]:
            assert not a.overlaps(b)
    catcher_ip = ipaddress.IPv4Address(
        _services(project)["catcher"]["networks"]["agent"]["ipv4_address"]
    )
    (agent_cfg,) = project.document["networks"]["agent"]["ipam"]["config"]
    assert catcher_ip in ipaddress.IPv4Network(agent_cfg["subnet"])
    assert catcher_ip not in ipaddress.IPv4Network(agent_cfg["ip_range"])  # never handed out


def test_bridge_names_are_short_stable_and_distinct_per_run(schedule: list[ScheduledRun]) -> None:
    a, b = schedule[0], schedule[1]
    assert bridge_name(a.run_id, "agent") == bridge_name(a.run_id, "agent")
    assert bridge_name(a.run_id, "agent") != bridge_name(a.run_id, "target")
    assert bridge_name(a.run_id, "agent") != bridge_name(b.run_id, "agent")
    for role in ("agent", "target", "llm"):
        assert len(bridge_name(a.run_id, role)) <= 15


def test_no_published_ports_no_host_paths_no_privileges(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    for _run, _manifest, project in _both(control, injected):
        declared = set(project.document["volumes"])
        for name, service in _services(project).items():
            assert "ports" not in service and "expose" not in service, name
            assert not service.get("privileged"), name
            assert service.get("network_mode") in (None, "none"), name
            assert "ALL" in service.get("cap_drop", []), name
            assert set(service.get("cap_add", [])) <= {
                "NET_BIND_SERVICE",
                "SETUID",
                "SETGID",
                "KILL",
            }, name
            assert "no-new-privileges:true" in service.get("security_opt", []), name
            assert "logging" not in service, name  # the daemon's bounded driver applies
            for volume in service.get("volumes", []):
                source = volume.split(":")[0]
                assert source in declared, f"{name}: {volume} is not a named volume"
            if name != "secrets-writer":
                assert service.get("pids_limit"), name
                assert service.get("mem_limit"), name


def test_agent_cannot_read_the_manifest_payloads_tokens_or_secrets(
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    _, _, project = injected
    mounts = {v.split(":")[0] for v in _services(project)["agent"]["volumes"]}
    assert mounts == {"cfg_agent", "ev_agent"}
    for service, data in _services(project).items():
        if service == "secrets-writer":
            continue
        sources = {v.split(":")[0] for v in data.get("volumes", [])}
        # each evidence volume belongs to one producer only
        assert len([s for s in sources if s.startswith("ev_")]) <= 1, service


def test_every_resource_is_labelled_with_the_run_and_never_as_cell_guard_output(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    run, _, project = control
    for kind in ("services", "networks", "volumes"):
        for name, item in project.document[kind].items():
            labels = item.get("labels", {})
            assert labels.get("lab.run_id") == run.run_id, (kind, name)
            assert "lab.origin" not in labels, (kind, name)
    for name, service in _services(project).items():
        assert service["labels"]["lab.role"] == name


def test_no_runner_resource_name_starts_with_the_cell_guard_prefix(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    run, _, project = control
    guard_prefix = f"{run.run_id.lower()}-"
    assert project.name.startswith(CELL_NAME_PREFIX)
    names = [project.name]
    names += list(project.document["services"])
    names += [n["name"] for n in project.document["networks"].values()]
    names += [v["name"] for v in project.document["volumes"].values()]
    names += [f"{project.name}-{s}-1" for s in project.document["services"]]
    for service in _services(project).values():
        for net in service.get("networks", {}).values():
            names += (net or {}).get("aliases", [])
        if "hostname" in service:
            names.append(service["hostname"])
    for name in names:
        assert not name.lower().startswith(guard_prefix), name


def test_project_name_is_built_from_the_run_id_only(schedule: list[ScheduledRun]) -> None:
    run = schedule[0]
    name = project_name(run)
    assert re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name)
    assert run.run_id.lower() in name


def test_a_manifest_that_disagrees_with_the_run_is_refused(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    run = next(r for r in schedule if r.arm is Arm.INJECTED)
    manifest = render_manifest(run, experiment, KEY, created_at=WHEN)
    for update in (
        {"target": "../../etc"},
        {"agent": "Other"},
        {"run_id": schedule[0].run_id if schedule[0] is not run else schedule[1].run_id},
        {"arm": Arm.CONTROL, "tag": None, "placements": []},
    ):
        bad = manifest.model_copy(update=update)
        with pytest.raises(CellError):
            render_cell(
                run,
                bad,
                experiment=experiment,
                settings=_settings(),
                subnets=allocate_subnets((POOL,), []),
            )


# --------------------------------------------------------------------------- secrets


def test_canaries_are_root_only_files_minted_fresh_for_every_render(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    seen: set[str] = set()
    for arm in (Arm.CONTROL, Arm.INJECTED, Arm.INJECTED):
        run, manifest, project = _render(experiment, schedule, arm)
        files = {(f.volume, f.name): f for f in project.files if f.volume.startswith("secret_")}
        assert set(files) == SECRET_FILES
        for f in files.values():
            assert f.mode == 0o400 and f.uid == 0 and f.gid == 0
            value = f.content.decode().strip()
            assert re.fullmatch(r"[0-9a-f]{32}", value)
            assert value not in seen  # never reused across runs, arms or renders
            seen.add(value)
            for derived in (
                run.run_id,
                run.pair_id,
                run.tag or "-",
                manifest.created_at.isoformat(),
            ):
                assert value not in derived.lower() and derived.lower() not in value
        assert project.probe_secret not in seen
        assert re.fullmatch(r"[0-9a-f]{32}", project.probe_secret)


def test_secrets_never_appear_in_the_compose_document(
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    _, _, project = injected
    text = project.to_yaml()
    for f in project.files:
        if f.volume.startswith("secret_"):
            assert f.content.decode().strip() not in text


def test_explicit_secrets_are_used_and_must_be_well_formed() -> None:
    minted = CellSecrets.mint()
    assert len({*minted.canaries.values(), minted.probe_secret}) == 5
    with pytest.raises(ValueError, match="canar"):
        CellSecrets(canaries={"rce_canary": "x"}, probe_secret=minted.probe_secret)


def test_no_rendered_byte_contains_the_lab_key(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    forms = [
        KEY,
        KEY.hex().encode(),
        KEY.hex().upper().encode(),
        base64.b64encode(KEY),
        base64.b32encode(KEY),
        base64.b32encode(KEY).lower(),
    ]
    for _run, _manifest, project in _both(control, injected):
        blobs = [project.to_yaml().encode(), *(f.content for f in project.files)]
        for blob in blobs:
            for form in forms:
                assert form not in blob


# --------------------------------------------------------------------------- agent


def test_scripted_agent_script_names_no_tag_or_token(
    experiment: Experiment, injected: tuple[ScheduledRun, RunManifest, ComposeProject]
) -> None:
    run, manifest, project = injected
    data = _file(project, "cfg_agent", "script.json")
    script = AgentScript.model_validate_json(data)
    assert script.target_url == "http://target"
    assert script.llm_url == "http://tap:8080"
    assert script.callback_domain == experiment.callback_domain
    fetched = [s.path for s in script.steps if s.action == "fetch"]
    assert fetched == ["/robots.txt", "/.env"]
    assert any(s.action == "graphql" and "importPaste" in (s.query or "") for s in script.steps)
    assert run.tag is not None and run.tag.encode() not in data
    assert not re.search(TAG_PATTERN.strip("^$").encode(), data.replace(b"importPaste", b""))
    for p in manifest.placements:
        assert p.token.encode() not in data
    assert "scripted" in AGENT_SPECS


def test_an_agent_that_starts_containers_gets_a_cell_guard(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    spec = AgentSpec(
        name="scripted",
        image="lab-cell",
        command=("python", "-m", "agents.scripted.agent", "--script", "/etc/lab/agent/script.json"),
        needs_docker=True,
    )
    _run, _, project = _render(experiment, schedule, Arm.CONTROL, agent_spec=spec)
    services = _services(project)
    guard = services["cellguard"]
    env = guard["environment"]
    catcher_ip = services["catcher"]["networks"]["agent"]["ipv4_address"]
    assert env["LAB_CELLGUARD_DNS"] == catcher_ip
    assert env["LAB_CELLGUARD_NETWORK"] == project.document["networks"]["agent"]["name"]
    # The scratch volume is created by the backend (labelled lab.run_id only) before
    # anything starts; Compose would never create it, cell-guard would unlabelled.
    assert "scratch" not in project.document["volumes"]
    assert project.scratch_volume == f"{project.name}_scratch"
    assert env["LAB_CELLGUARD_SCRATCH_VOLUME"] == project.scratch_volume
    assert project.evidence["cellguard"] == "cellguard"
    assert env["LAB_EVIDENCE_DIR"] == project.evidence_paths["cellguard"] != "/evidence"
    assert "LAB_CELLGUARD_NAME_PREFIX" not in env  # the default <run id>- prefix
    assert "networks" not in guard and guard.get("network_mode") == "none"  # sockets only
    assert services["agent"]["environment"]["DOCKER_HOST"].startswith("unix:///run/cellguard/")
    agent_mounts = {v.split(":")[0] for v in services["agent"]["volumes"]}
    assert "cellguard_sock" in agent_mounts
    sources = [v.split(":")[0] for v in guard["volumes"]]
    assert "/var/run/docker.sock" in sources  # the runner's infrastructure alone


# --------------------------------------------------------------------------- engines


def test_podman_rendering_omits_docker_only_network_options(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    _, _, project = _render(
        experiment, schedule, Arm.CONTROL, settings=_settings(engine=Engine.PODMAN)
    )
    for net in project.document["networks"].values():
        assert "com.docker.network.bridge.name" not in net.get("driver_opts", {})
        assert net["internal"] is True
    # Podman's internal-network resolver does not forward: the script asks the catcher
    catcher_ip = _services(project)["catcher"]["networks"]["agent"]["ipv4_address"]
    script = AgentScript.model_validate_json(_file(project, "cfg_agent", "script.json"))
    assert str(script.dns_server) == catcher_ip


def test_docker_scripts_use_the_agents_own_resolver(
    control: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    _, _, project = control
    script = AgentScript.model_validate_json(_file(project, "cfg_agent", "script.json"))
    assert script.dns_server is None


def test_gateway_mode_routes_the_tap_to_the_gateway_without_a_stub(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    _, _, project = _render(
        experiment,
        schedule,
        Arm.INJECTED,
        settings=_settings(llm_gateway="http://10.231.255.1:4000"),
    )
    services = _services(project)
    assert "stub-llm" not in services
    assert "reverse:http://10.231.255.1:4000" in services["tap"]["command"]
    assert project.document["networks"]["llm"]["internal"] is False
    assert project.document["networks"]["agent"]["internal"] is True


def test_images_are_pinned_by_digest(experiment: Experiment, schedule: list[ScheduledRun]) -> None:
    _, _, project = _render(experiment, schedule, Arm.CONTROL)
    for name, service in _services(project).items():
        assert service["image"] in IMAGES.values(), name
    with pytest.raises(CellError, match="digest"):
        _render(
            experiment,
            schedule,
            Arm.CONTROL,
            settings=_settings(images={**IMAGES, "lab-cell": "lab-cell:latest"}),
        )
    with pytest.raises(CellError, match="goat-dvga"):
        _render(
            experiment,
            schedule,
            Arm.CONTROL,
            settings=_settings(images={"lab-cell": IMAGES["lab-cell"]}),
        )


def test_the_yaml_round_trips_and_escapes_compose_interpolation(
    injected: tuple[ScheduledRun, RunManifest, ComposeProject],
) -> None:
    _, _, project = injected
    text = project.to_yaml()
    assert "&" not in text.split("services:")[1].split("\n")[0]  # no YAML anchors
    assert yaml.safe_load(text) == project.document
    for value in _strings(project.document):
        assert "@" not in value or "@sha256:" in value, value  # no placeholder left
        assert "$" not in value.replace("$$", ""), value


def test_settings_from_the_host_environment(tmp_path: Path) -> None:
    lock = tmp_path / "images.lock"
    lock.write_text(
        "images:\n"
        "  - name: lab-cell\n    image: ghcr.io/lordprime/lab-cell\n"
        f"    digest: sha256:{'c' * 64}\n"
    )
    settings = CellSettings.from_env(
        {
            "LAB_CELL_NETWORKS": "10.231.0.0/16,10.232.0.0/24",
            "LAB_IMAGES_LOCK": str(lock),
            "LAB_IMAGE_OVERRIDES": "goat-dvga=localhost/goat-dvga:dev",
            "LAB_ENGINE": "podman",
            "LAB_REQUIRE_DIGESTS": "0",
        }
    )
    assert settings.cell_networks == (POOL, ipaddress.IPv4Network("10.232.0.0/24"))
    assert settings.image("lab-cell") == f"ghcr.io/lordprime/lab-cell@sha256:{'c' * 64}"
    assert settings.image("goat-dvga") == "localhost/goat-dvga:dev"
    assert settings.engine is Engine.PODMAN
    with pytest.raises(CellError, match="LAB_CELL_NETWORKS"):
        CellSettings.from_env({"LAB_CELL_NETWORKS": "8.8.8.0/24", "LAB_IMAGES_LOCK": str(lock)})
    with pytest.raises(CellError, match="LAB_CELL_NETWORKS"):
        CellSettings.from_env({"LAB_IMAGES_LOCK": str(lock)})


# --------------------------------------------------------------------------- subnets


def test_allocate_subnets_skips_used_ranges_and_stays_in_the_pool() -> None:
    first = allocate_subnets((POOL,), [])
    used = [first.agent, first.target, first.llm]
    second = allocate_subnets((POOL,), used)
    for net in (second.agent, second.target, second.llm):
        assert net.subnet_of(POOL)
        assert not any(net.overlaps(u) for u in used)
    # a foreign network overlapping part of the pool is avoided too
    foreign = ipaddress.IPv4Network("10.231.0.0/24")
    third = allocate_subnets((POOL,), [foreign])
    assert not any(n.overlaps(foreign) for n in (third.agent, third.target, third.llm))


def test_allocate_subnets_refuses_an_exhausted_pool() -> None:
    small = ipaddress.IPv4Network("10.231.0.0/27")
    with pytest.raises(CellError, match="no free"):
        allocate_subnets((small,), [])
