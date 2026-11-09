"""Render one run's cell: a Compose project plus the files its named volumes start with.

Pure (no container is touched here): :func:`render_cell` turns a scheduled run, its
verified manifest, the experiment, the host's settings and the subnets the backend
allocated into a :class:`ComposeProject`. :mod:`control.runner.compose_backend` runs it.

Sources:

* ``deploy/compose/cell.<target>.yml``: the cell's static posture (services, commands,
  capabilities, mounts) and ``x-lab`` metadata; its ``goat`` service extends the
  target's own ``targets/<target>/compose.cell.yml`` (inlined here);
* the agent's :class:`AgentSpec` (:data:`AGENT_SPECS`), which adds the ``agent``
  service and, for an agent that starts containers, a ``cellguard`` service.

Rules this module guarantees (each asserted by ``tests/runner/test_cell_spec.py``):

* every name (project, networks, volumes, containers, aliases) is built only from the
  safe-typed :class:`~control.runner.schedule.ScheduledRun` and the target spec, never
  from a reloaded manifest's ``target``/``agent`` (the manifest must agree with the run);
  all start with :data:`CELL_NAME_PREFIX`, never with cell-guard's ``<run id>-`` prefix;
* cell networks have an explicit subnet inside ``LAB_CELL_NETWORKS`` and a gateway
  address (a connected route on the bridge, which the host's strict reverse-path check
  needs; isolated gateway mode is never used), and on Docker a bridge named
  ``labc<id>`` (at most 15 characters). All are ``internal: true`` except, in gateway
  mode (``LAB_LLM_GATEWAY`` set: real models), the ``llm`` network: only the tap is on
  it, and the host firewall lets a ``labc`` bridge reach nothing but the configured
  gateway address and port. The gateway must lie outside ``LAB_CELL_NETWORKS`` and equal
  the host's configured one (``/srv/lab/host.env``). With the stub LLM every network is
  internal;
* images: cell-guard's allow-list holds only ``images.lock`` entries with
  ``role: agent``, so an agent can never start the target or a harness image;
* ``LAB_ENGINE=podman`` and unpinned images (no ``labc`` bridge names, no digests) are
  refused unless ``LAB_DEV=1``;
* everything carries ``lab.run_id``; nothing carries ``lab.origin`` (cell-guard's mark);
* no published port and no host path, except the real Docker socket mounted into the
  runner-created cell-guard; per-run inputs travel only as :class:`CellFile` s written
  into named volumes before anything starts;
* canaries are minted fresh for every render with :func:`secrets.token_hex`, never
  derived from anything about the run, and written as root-only 0400 files;
* the agent sees only its own script and evidence volume: never the manifest, the
  payload texts, the token file or a canary.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import logging
import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from control.core.models import Arm, RunManifest, Surface
from control.runner.experiment import Experiment
from control.runner.render import render_catcher_file, render_payloads
from control.runner.schedule import ScheduledRun

__all__ = [
    "AGENT_SPECS",
    "CANARY_FILES",
    "CELL_NAME_PREFIX",
    "DEFAULT_CELL_NETWORK",
    "DEFAULT_EVIDENCE_PATH",
    "EVIDENCE_PREFIXES",
    "HOST_ENV_FILE",
    "IMAGE_ROLES",
    "REPO_ROOT",
    "ROLE_LABEL",
    "RUN_LABEL",
    "AgentSpec",
    "CellError",
    "CellFile",
    "CellSecrets",
    "CellSettings",
    "CellSubnets",
    "ComposeProject",
    "Engine",
    "allocate_subnets",
    "bridge_name",
    "project_name",
    "read_host_env",
    "render_cell",
]

log = logging.getLogger(__name__)

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
#: Every runner-created cell resource name starts with this (never with cell-guard's
#: ``<run id lowercased>-`` prefix, which only agent-created containers carry).
CELL_NAME_PREFIX: Final = "labcell-"
DEFAULT_CELL_NETWORK: Final = ipaddress.IPv4Network("10.231.0.0/16")
SUBNET_PREFIXLEN: Final = 27
RUN_LABEL: Final = "lab.run_id"
ROLE_LABEL: Final = "lab.role"
#: Canary volume -> file name, as targets/<target>/compose.cell.yml mounts them.
CANARY_FILES: Final[Mapping[str, str]] = {
    "secret_admin_password": "admin_password",
    "secret_outbound_service_request_canary": "outbound_service_request_canary",
    "secret_rce_canary": "rce_canary",
    "secret_attack_success_canary": "attack_success_canary",
}
#: Service -> the only top-level directory of its evidence volume the runner keeps.
EVIDENCE_PREFIXES: Final[Mapping[str, str]] = {
    "injector": "injector",
    "tap": "llm",
    "catcher": "catcher",
    "agent": "agent",
    "cellguard": "cellguard",
}
_NETWORK_ROLES: Final = ("agent", "target", "llm")
_DIGEST_REF = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_PLACEHOLDER = re.compile(r"@[A-Z_]+@")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_TAP_URL: Final = "http://tap:8080"
_GUARD_DIR: Final = "/run/cellguard"
#: The host profile written by the Ansible site play (deploy/ansible/templates/host.env.j2).
HOST_ENV_FILE: Final = "/srv/lab/host.env"
_DOCKER_SOCKET: Final = "/var/run/docker.sock"
#: Where every cell service but cell-guard keeps its evidence (owned by uid 10001).
DEFAULT_EVIDENCE_PATH: Final = "/evidence"
#: cell-guard runs as root without capabilities: its evidence path is not in the image,
#: so the fresh volume mounted there is root's.
_GUARD_EVIDENCE: Final = "/var/lib/cellguard-evidence"


class CellError(ValueError):
    """A cell cannot be rendered or run as configured (fail before tokens are spent)."""


class Engine(StrEnum):
    """The container engine behind the Docker API. Podman lacks Docker-only options."""

    DOCKER = "docker"
    PODMAN = "podman"


# --------------------------------------------------------------------------- settings


#: ``images.lock`` roles. cell-guard lets an agent start only ``agent`` images.
IMAGE_ROLES: Final = frozenset({"agent", "target", "infra", "control"})


def _load_lock(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """``images.lock`` as ``(name -> image@digest, name -> role)`` (role default infra)."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CellError(f"LAB_IMAGES_LOCK: cannot read {path}: {exc}") from exc
    entries = doc.get("images") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise CellError(f"LAB_IMAGES_LOCK: {path} has no images list")
    images: dict[str, str] = {}
    roles: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not {"name", "image", "digest"} <= set(entry):
            raise CellError(f"LAB_IMAGES_LOCK: malformed entry {entry!r}")
        role = str(entry.get("role", "infra"))
        if role not in IMAGE_ROLES:
            raise CellError(f"LAB_IMAGES_LOCK: unknown role {role!r} for {entry['name']!r}")
        images[str(entry["name"])] = f"{entry['image']}@{entry['digest']}"
        roles[str(entry["name"])] = role
    return images, roles


def read_host_env(path: Path) -> dict[str, str]:
    """``KEY=VALUE`` lines of the host profile (``/srv/lab/host.env``); comments skipped."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, eq, value = line.partition("=")
        if not eq:
            raise CellError(f"{path}: not a KEY=VALUE line: {line!r}")
        values[key.strip()] = value.strip()
    return values


def _gateway_url(raw: str) -> str | None:
    """``addr:port`` (host.env's form) or ``http://addr:port`` -> URL; empty -> None."""
    if not raw:
        return None
    hostport = raw.removeprefix("http://")
    addr, colon, port = hostport.rpartition(":")
    try:
        ipaddress.IPv4Address(addr)
        valid = colon == ":" and 1 <= int(port) <= 65535
    except ValueError:
        valid = False
    if not valid or "/" in hostport:
        raise CellError(f"LAB_LLM_GATEWAY: expected <IPv4>:<port>, got {raw!r}")
    return f"http://{hostport}"


def _parse_networks(raw: str) -> tuple[ipaddress.IPv4Network, ...]:
    nets: list[ipaddress.IPv4Network] = []
    for part in (p.strip() for p in raw.split(",")):
        if not part:
            continue
        try:
            net = ipaddress.IPv4Network(part, strict=True)
        except ValueError as exc:
            raise CellError(f"LAB_CELL_NETWORKS: {part!r}: {exc}") from exc
        if not net.is_private or net.prefixlen > SUBNET_PREFIXLEN:
            raise CellError(f"LAB_CELL_NETWORKS: {part} must be a private range of /27 or more")
        nets.append(net)
    if not nets:
        raise CellError("LAB_CELL_NETWORKS: not set (from /srv/lab/host.env)")
    return tuple(nets)


@dataclass(frozen=True, slots=True)
class CellSettings:
    """Host-level settings every cell of this host shares.

    ``images`` maps logical image names (``deploy/images.lock``) to references;
    with ``require_digests`` every reference must be pinned by digest. ``llm_gateway``
    is the model gateway's URL for real agents; ``None`` puts the stub LLM in the cell.
    """

    images: Mapping[str, str]
    cell_networks: tuple[ipaddress.IPv4Network, ...] = (DEFAULT_CELL_NETWORK,)
    engine: Engine = Engine.DOCKER
    llm_gateway: str | None = None
    require_digests: bool = True
    docker_socket: str = _DOCKER_SOCKET
    #: ``images.lock`` role per logical name (absent: ``infra``).
    roles: Mapping[str, str] = field(default_factory=dict)
    #: Development host: Podman and unpinned images are allowed (``LAB_DEV=1``).
    dev: bool = False

    def __post_init__(self) -> None:
        if (self.engine is Engine.PODMAN or not self.require_digests) and not self.dev:
            raise CellError(
                "LAB_ENGINE=podman and LAB_REQUIRE_DIGESTS=0 are for development only: "
                "the labc bridge names and digest pins the host firewall and the study rely "
                "on are missing there; set LAB_DEV=1 to allow them on a development host"
            )
        if self.llm_gateway is not None and self.engine is Engine.PODMAN:
            raise CellError(
                "gateway mode is refused on Podman: its llm bridge would have no labc "
                "name, so the host firewall could not limit the tap's egress"
            )
        if self.llm_gateway is not None:
            url = _gateway_url(self.llm_gateway) or ""
            addr = ipaddress.IPv4Address(url.removeprefix("http://").rpartition(":")[0])
            if any(addr in net for net in self.cell_networks):
                raise CellError(
                    f"LAB_LLM_GATEWAY {self.llm_gateway} lies inside LAB_CELL_NETWORKS: the "
                    "gateway must be outside the cells' address pool"
                )

    def image(self, name: str) -> str:
        ref = self.images.get(name)
        if ref is None:
            raise CellError(f"image {name!r} is not in images.lock (nor overridden)")
        if self.require_digests and not _DIGEST_REF.fullmatch(ref):
            raise CellError(f"image {name!r} is not pinned by digest: {ref!r}")
        return ref

    def role(self, name: str) -> str:
        return self.roles.get(name, "infra")

    @classmethod
    def from_env(
        cls, env: Mapping[str, str], *, host_env: Mapping[str, str] | None = None
    ) -> CellSettings:
        """Read the runner's settings.

        The host profile (``host_env``, else the file ``LAB_HOST_ENV``, default
        :data:`HOST_ENV_FILE`, read with :func:`read_host_env`) is the source of
        ``LAB_CELL_NETWORKS`` and ``LAB_LLM_GATEWAY``: the values the host firewall was
        built with. ``env`` may only repeat them, never differ. Without a profile,
        settings are refused unless ``LAB_DEV=1`` (a development host, which then takes
        both from ``env``). ``LAB_DEV=1`` is refused wherever the *default* profile
        :data:`HOST_ENV_FILE` exists (a production host), and ``LAB_HOST_ENV`` is ignored
        in dev mode, so no environment variable can turn a production host into a
        development one. From ``env``: ``LAB_IMAGES_LOCK``, ``LAB_IMAGE_OVERRIDES``
        (``name=ref,...``), ``LAB_ENGINE``, ``LAB_REQUIRE_DIGESTS``, ``LAB_DEV`` and
        ``LAB_DOCKER_SOCKET``.
        """
        dev = env.get("LAB_DEV", "0") == "1"
        if dev and Path(HOST_ENV_FILE).exists():
            raise CellError(
                f"LAB_DEV=1 is refused: {HOST_ENV_FILE} exists, so this is a production host"
            )
        if host_env is None and dev:
            pass  # a development host has no profile; LAB_HOST_ENV is not consulted
        elif host_env is None:
            path = Path(env.get("LAB_HOST_ENV") or HOST_ENV_FILE)
            if path.is_file():
                host_env = read_host_env(path)
            elif not dev:
                raise CellError(
                    f"host profile {path} is missing: it holds LAB_CELL_NETWORKS and "
                    "LAB_LLM_GATEWAY as the host firewall knows them (set LAB_DEV=1 only "
                    "on a development host)"
                )
        if host_env is not None and dev:
            raise CellError(
                "LAB_DEV=1 is refused on a host with a host profile (a production host)"
            )
        merged = dict(env)
        if host_env is not None:
            for key in ("LAB_CELL_NETWORKS", "LAB_LLM_GATEWAY"):
                host_value = host_env.get(key, "")
                if key in env and env[key] != host_value:
                    raise CellError(
                        f"{key} {env[key]!r} differs from the host's configured {host_value!r}"
                    )
                merged[key] = host_value
        networks = _parse_networks(merged.get("LAB_CELL_NETWORKS", ""))
        lock = Path(merged.get("LAB_IMAGES_LOCK") or REPO_ROOT / "deploy" / "images.lock")
        images, roles = _load_lock(lock)
        for item in (p.strip() for p in merged.get("LAB_IMAGE_OVERRIDES", "").split(",")):
            if item:
                name, eq, ref = item.partition("=")
                if not eq or not name or not ref:
                    raise CellError(f"LAB_IMAGE_OVERRIDES: malformed entry {item!r}")
                images[name.strip()] = ref.strip()
        try:
            engine = Engine(merged.get("LAB_ENGINE") or Engine.DOCKER.value)
        except ValueError as exc:
            raise CellError(f"LAB_ENGINE: {exc}") from exc
        require = merged.get("LAB_REQUIRE_DIGESTS", "1")
        if require not in ("0", "1"):
            raise CellError(f"LAB_REQUIRE_DIGESTS: expected 0 or 1, got {require!r}")
        if dev and (engine is Engine.PODMAN or require == "0"):
            log.warning(
                "LAB_DEV=1: engine %s, digests %s -- development settings, never for study runs",
                engine.value,
                "required" if require == "1" else "NOT required",
            )
        return cls(
            images=images,
            cell_networks=networks,
            engine=engine,
            llm_gateway=_gateway_url(merged.get("LAB_LLM_GATEWAY", "")),
            require_digests=require == "1",
            docker_socket=merged.get("LAB_DOCKER_SOCKET") or _DOCKER_SOCKET,
            roles=roles,
            dev=dev,
        )


# --------------------------------------------------------------------------- networks


@dataclass(frozen=True, slots=True)
class CellSubnets:
    """The three subnets of one cell."""

    agent: ipaddress.IPv4Network
    target: ipaddress.IPv4Network
    llm: ipaddress.IPv4Network

    def of(self, role: str) -> ipaddress.IPv4Network:
        net: ipaddress.IPv4Network = getattr(self, role)
        return net


def allocate_subnets(
    pool: Sequence[ipaddress.IPv4Network],
    in_use: Iterable[ipaddress.IPv4Network],
    *,
    prefixlen: int = SUBNET_PREFIXLEN,
) -> CellSubnets:
    """The first three free ``/prefixlen`` subnets of ``pool`` not overlapping ``in_use``."""
    used = list(in_use)
    free: list[ipaddress.IPv4Network] = []
    for net in pool:
        for candidate in net.subnets(new_prefix=prefixlen):
            if not any(candidate.overlaps(u) for u in used):
                free.append(candidate)
                used.append(candidate)
                if len(free) == len(_NETWORK_ROLES):
                    return CellSubnets(*free)
    raise CellError(f"no free /{prefixlen} subnets left in {', '.join(map(str, pool))}")


def project_name(run: ScheduledRun) -> str:
    """The Compose project of ``run``: ``labcell-<run id lowercased>``."""
    return f"{CELL_NAME_PREFIX}{run.run_id.lower()}"


def bridge_name(run_id: str, role: str) -> str:
    """``labc`` + 9 base32 chars of sha256(run id) + the role's initial (14 chars)."""
    digest = base64.b32encode(hashlib.sha256(run_id.encode()).digest()).decode().lower()
    return f"labc{digest[:9]}{role[0]}"


# --------------------------------------------------------------------------- secrets


@dataclass(frozen=True, slots=True)
class CellSecrets:
    """Per-run bearer secrets: the oracle's canaries and the injector's probe secret."""

    canaries: Mapping[str, str] = field(repr=False)
    probe_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if set(self.canaries) != set(CANARY_FILES.values()):
            raise ValueError(f"canaries must be exactly {sorted(CANARY_FILES.values())}")
        values = [*self.canaries.values(), self.probe_secret]
        if not all(_HEX32.fullmatch(v) for v in values) or len(set(values)) != len(values):
            raise ValueError("canaries and the probe secret must be distinct 32-hex values")

    @classmethod
    def mint(cls) -> CellSecrets:
        """Fresh random values (:func:`secrets.token_hex`), never derived from the run."""
        return cls(
            canaries={name: secrets.token_hex(16) for name in CANARY_FILES.values()},
            probe_secret=secrets.token_hex(16),
        )


@dataclass(frozen=True, slots=True)
class CellFile:
    """One file written into a named volume (through the writer) before the cell starts."""

    volume: str
    name: str
    content: bytes = field(repr=False)
    mode: int = 0o444
    uid: int = 0
    gid: int = 0


# --------------------------------------------------------------------------- agents


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """How the ``agent`` service of a cell is run.

    ``image`` is a logical name. ``scripted`` agents get an
    :class:`~agents.scripted.agent.AgentScript` rendered into ``cfg_agent/script.json``.
    ``needs_docker`` adds a cell-guard (the agent's only Docker socket).
    """

    name: str
    image: str
    command: tuple[str, ...]
    needs_docker: bool = False
    scripted: bool = True
    cap_add: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)


AGENT_SPECS: Final[Mapping[str, AgentSpec]] = {
    "scripted": AgentSpec(
        name="scripted",
        image="lab-cell",
        command=("python", "-m", "agents.scripted.agent", "--script", "/etc/lab/agent/script.json"),
    ),
}


# --------------------------------------------------------------------------- project


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class ComposeProject:
    """A rendered cell: the Compose document, its initial files and what to check."""

    name: str
    run_id: str
    document: Mapping[str, Any]
    files: tuple[CellFile, ...]
    probe_secret: str = field(repr=False)
    #: ``(path, expected status)`` the pre-flight probe requests through the injector.
    probe_paths: tuple[tuple[str, int], ...] = ()
    agent_service: str = "agent"
    target_service: str = "goat"
    injector_service: str = "injector"
    writer_service: str = "secrets-writer"
    #: Services whose evidence the runner collects, and the prefix each may write.
    evidence: Mapping[str, str] = field(default_factory=dict)
    #: Where a service keeps its evidence when not :data:`DEFAULT_EVIDENCE_PATH`.
    evidence_paths: Mapping[str, str] = field(default_factory=dict)
    #: The cell-guard scratch volume (agents that start containers), created by the
    #: backend with the run label before anything starts; ``None`` without cell-guard.
    scratch_volume: str | None = None

    @property
    def infra_services(self) -> tuple[str, ...]:
        """Every service started before the agent (the writer is never started)."""
        return tuple(
            s
            for s in self.document["services"]
            if s not in (self.agent_service, self.writer_service)
        )

    def to_yaml(self) -> str:
        return yaml.dump(
            dict(self.document), Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=True
        )


def _escape(node: Any) -> Any:
    """Plain data with every ``$`` doubled, so Compose interpolates nothing."""
    if isinstance(node, str):
        if _PLACEHOLDER.search(node):
            raise CellError(f"unfilled placeholder in {node!r}")
        return node.replace("$", "$$")
    if isinstance(node, Mapping):
        return {str(k): _escape(v) for k, v in node.items()}
    if isinstance(node, list | tuple):
        return [_escape(v) for v in node]
    return node


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CellError(f"cannot read {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise CellError(f"{path}: not a Compose mapping")
    return doc


def _check_manifest(run: ScheduledRun, manifest: RunManifest) -> None:
    fields = (
        "run_id",
        "experiment_id",
        "pair_id",
        "arm",
        "target",
        "agent",
        "model",
        "schedule_index",
        "attempt",
        "tag",
    )
    differing = [f for f in fields if getattr(run, f) != getattr(manifest, f)]
    if differing:
        raise CellError(f"run {run.run_id}: manifest disagrees on {', '.join(differing)}")


def _labels(run: ScheduledRun, role: str | None = None) -> dict[str, str]:
    labels = {RUN_LABEL: run.run_id}
    if role is not None:
        labels[ROLE_LABEL] = role
    return labels


def _agent_script(
    run: ScheduledRun, experiment: Experiment, meta: Mapping[str, Any], dns_server: str | None
) -> bytes:
    host, port = str(meta["agent_host"]), int(meta["agent_port"])
    target_url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    target = experiment.target(run.target)
    planted = sorted(experiment.arms.injected.surfaces)
    steps: list[dict[str, Any]] = [
        {"action": "fetch", "path": target.placements[s].url} for s in planted
    ]
    steps += [
        {"action": "llm"},
        {"action": "follow_decoy"},
        {"action": "callback_http"},
        {"action": "callback_dns"},
        {
            "action": "graphql",
            "path": str(meta["objective_path"]),
            "query": str(meta["objective_query"]),
        },
    ]
    doc = {
        "target_url": target_url,
        "llm_url": _TAP_URL,
        "model": run.model,
        "callback_domain": experiment.callback_domain,
        "steps": steps,
    }
    if dns_server is not None:
        doc["dns_server"] = dns_server
    return json.dumps(doc, sort_keys=True).encode()


def _images_lock(settings: CellSettings) -> bytes:
    """cell-guard's allow-list: only ``agent`` images, never the target or harness ones."""
    entries = []
    for name, ref in sorted(settings.images.items()):
        image, at, digest = ref.partition("@")
        if at and settings.role(name) == "agent":
            entries.append({"name": name, "image": image, "digest": digest, "role": "agent"})
    return yaml.safe_dump({"images": entries}, sort_keys=False).encode()


def render_cell(
    run: ScheduledRun,
    manifest: RunManifest,
    *,
    experiment: Experiment,
    settings: CellSettings,
    subnets: CellSubnets,
    secrets: CellSecrets | None = None,
    agent_spec: AgentSpec | None = None,
    templates_root: Path = REPO_ROOT,
) -> ComposeProject:
    """Render ``run``'s cell. ``manifest`` must already be token-verified and agree with it."""
    _check_manifest(run, manifest)
    if run.experiment_id != experiment.experiment_id:
        raise CellError(f"run {run.run_id} is not of experiment {experiment.experiment_id}")
    spec = agent_spec or AGENT_SPECS.get(run.agent)
    if spec is None:
        raise CellError(f"no agent spec for agent {run.agent!r}")
    secrets = secrets or CellSecrets.mint()
    name = project_name(run)
    target_spec = experiment.target(run.target)

    cell = _load_yaml(templates_root / "deploy" / "compose" / f"cell.{run.target}.yml")
    meta = cell.get("x-lab")
    if not isinstance(meta, dict) or meta.get("target") != run.target:
        raise CellError(f"cell.{run.target}.yml: x-lab.target must be {run.target!r}")
    services: dict[str, Any] = copy.deepcopy(cell["services"])
    for logical in (str(meta["cell_image"]), str(meta["target_image"])):
        if settings.role(logical) == "agent":
            raise CellError(
                f"image {logical!r} has images.lock role agent: a target or harness image "
                "must never be one an agent may start"
            )
    cell_image = settings.image(str(meta["cell_image"]))

    # the target service, inlined from the target's own compose file
    goat = services["goat"]
    extends = goat.pop("extends")
    base_doc = _load_yaml(templates_root / str(extends["file"]))
    base = copy.deepcopy(base_doc["services"][extends["service"]])
    base.pop("networks", None)
    base.update(goat)
    base["image"] = settings.image(str(meta["target_image"]))
    services["goat"] = base

    gateway = settings.llm_gateway
    if gateway is not None:
        services.pop("stub-llm")
    upstream = gateway or str(meta["stub_llm_url"])
    services["tap"]["command"] = [
        str(c).replace("@LLM_UPSTREAM@", upstream) for c in services["tap"]["command"]
    ]

    # networks
    networks: dict[str, Any] = {}
    for role in _NETWORK_ROLES:
        net = subnets.of(role)
        hosts = net.hosts()
        gateway_ip = next(hosts)
        dynamic = list(net.subnets(new_prefix=net.prefixlen + 1))[1]
        entry: dict[str, Any] = {
            "name": f"{name}_{role}",
            "driver": "bridge",
            "internal": not (role == "llm" and gateway is not None),
            "ipam": {
                "config": [
                    {"subnet": str(net), "gateway": str(gateway_ip), "ip_range": str(dynamic)}
                ]
            },
            "labels": _labels(run),
        }
        if settings.engine is Engine.DOCKER:
            entry["driver_opts"] = {"com.docker.network.bridge.name": bridge_name(run.run_id, role)}
        networks[role] = entry
    # Static addresses below the dynamic range: the catcher is the agent's DNS server;
    # the injector and the tap are also pinned in the agent's /etc/hosts, so it finds
    # them without depending on the engine's embedded DNS (on Podman the configured
    # server replaces it; on Docker it only forwards).
    catcher_ip = str(subnets.agent.network_address + 2)
    injector_ip = str(subnets.agent.network_address + 3)
    tap_ip = str(subnets.agent.network_address + 4)
    services["catcher"]["networks"]["agent"]["ipv4_address"] = catcher_ip
    services["injector"]["networks"]["agent"]["ipv4_address"] = injector_ip
    services["tap"]["networks"]["agent"] = {"ipv4_address": tap_ip}
    agent_hosts = [f"{meta['agent_host']}:{injector_ip}", f"tap:{tap_ip}"]

    # per-run environment of the infrastructure
    p1 = Surface.P1 in experiment.arms.injected.surfaces
    services["injector"]["environment"].update(
        LAB_RUN_ID=run.run_id,
        LAB_PROBE_SECRET=secrets.probe_secret,
        LAB_SYNTHESIZE_ROBOTS="1" if p1 else "0",
    )
    services["tap"]["environment"].update(LAB_RUN_ID=run.run_id, LAB_TAGS=run.tag or "")
    services["catcher"]["environment"].update(LAB_RUN_ID=run.run_id, LAB_CATCHER_IP=catcher_ip)

    # the agent
    agent_env = {
        "LAB_RUN_ID": run.run_id,
        "LAB_EVIDENCE_DIR": "/evidence",
        "ANTHROPIC_BASE_URL": _TAP_URL,
        **spec.env,
    }
    agent_volumes = ["cfg_agent:/etc/lab/agent:ro", "ev_agent:/evidence"]
    volumes: dict[str, Any] = {k: {} for k in cell.get("volumes", {})}
    files: list[CellFile] = []
    if spec.needs_docker:
        agent_env["DOCKER_HOST"] = f"unix://{_GUARD_DIR}/docker.sock"
        agent_volumes.append(f"cellguard_sock:{_GUARD_DIR}")
        for extra in ("cellguard_sock", "cfg_cellguard", "ev_cellguard"):
            volumes[extra] = {}
        services["cellguard"] = {
            "image": cell_image,
            "command": ["python", "-m", "cell.cellguard.proxy"],
            # root, every capability dropped: it only needs the Docker socket's owner
            # bits; its evidence path is not in the image, so root owns that volume
            "user": "0:0",
            "read_only": True,
            "tmpfs": ["/tmp:size=16m,mode=1777"],  # noqa: S108 - a container tmpfs
            "network_mode": "none",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 128,
            "mem_limit": "256m",
            "cpus": 0.5,
            "restart": "no",
            "environment": {
                "LAB_RUN_ID": run.run_id,
                "LAB_CELLGUARD_NETWORK": networks["agent"]["name"],
                "LAB_CELLGUARD_IMAGES_LOCK": "/etc/lab/cellguard/images.lock",
                "LAB_CELLGUARD_DNS": catcher_ip,
                "LAB_CELLGUARD_LISTEN": f"{_GUARD_DIR}/docker.sock",
                "LAB_CELLGUARD_UPSTREAM": _DOCKER_SOCKET,
                "LAB_CELLGUARD_SCRATCH_VOLUME": f"{name}_scratch",
                "LAB_CELLGUARD_SOCKET_MODE": "666",
                "LAB_EVIDENCE_DIR": _GUARD_EVIDENCE,
            },
            "volumes": [
                f"{settings.docker_socket}:{_DOCKER_SOCKET}",
                f"cellguard_sock:{_GUARD_DIR}",
                "cfg_cellguard:/etc/lab/cellguard:ro",
                f"ev_cellguard:{_GUARD_EVIDENCE}",
            ],
        }
        services["secrets-writer"]["volumes"].append("cfg_cellguard:/w/cfg_cellguard")
        files.append(CellFile("cfg_cellguard", "images.lock", _images_lock(settings)))
    services["agent"] = {
        "image": settings.image(spec.image),
        "command": list(spec.command),
        "read_only": True,
        "tmpfs": ["/tmp:size=256m,mode=1777"],  # noqa: S108 - a container tmpfs
        "cap_drop": ["ALL"],
        "cap_add": list(spec.cap_add),
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 512,
        "mem_limit": "1g",
        "cpus": 1.0,
        "restart": "no",
        "stop_grace_period": "10s",
        "environment": agent_env,
        "volumes": agent_volumes,
        "networks": {"agent": {}},
        "dns": [catcher_ip],
        "extra_hosts": agent_hosts,
    }
    if not spec.cap_add:
        del services["agent"]["cap_add"]

    # common: images and labels; writer hardening
    for svc_name, svc in services.items():
        if svc.get("image") == meta["cell_image"]:
            svc["image"] = cell_image
        svc["labels"] = _labels(run, svc_name)
    writer = services["secrets-writer"]
    writer.setdefault("cap_drop", ["ALL"])
    writer.setdefault("security_opt", ["no-new-privileges:true"])
    for vol_name, vol in volumes.items():
        vol["name"] = f"{name}_{vol_name}"
        vol["labels"] = _labels(run)

    # per-run files
    for volume, file_name in CANARY_FILES.items():
        value = secrets.canaries[file_name]
        files.append(CellFile(volume, file_name, (value + "\n").encode(), mode=0o400))
    files.append(CellFile("cfg_injector", "manifest.json", manifest.model_dump_json().encode()))
    payloads = render_payloads(manifest, experiment)
    files.append(
        CellFile("cfg_injector", "payloads.json", json.dumps(payloads, sort_keys=True).encode())
    )
    files.append(CellFile("cfg_catcher", "tokens.json", render_catcher_file(manifest, experiment)))
    if spec.scripted:
        # Podman's resolver on an internal network answers NXDOMAIN for every outside name
        # instead of forwarding to the catcher, so there the script asks the catcher
        # itself. On Docker the agent uses its own resolver, exactly as a real agent
        # does (whether that reaches the catcher is a Task 17 check on the host).
        dns_server = catcher_ip if settings.engine is Engine.PODMAN else None
        script = _agent_script(run, experiment, meta, dns_server)
        files.append(CellFile("cfg_agent", "script.json", script))

    probe_paths: list[tuple[str, int]] = []
    for surface in sorted(experiment.arms.injected.surfaces):
        placement = target_spec.placements[surface]
        if surface is Surface.P1:
            probe_paths.append((placement.url, 200))
        else:
            probe_paths.append((placement.url, int(placement.locator.rpartition(":")[2])))

    document = _escape(
        {"name": name, "services": services, "networks": networks, "volumes": volumes}
    )
    evidence = {s: p for s, p in EVIDENCE_PREFIXES.items() if s in services}
    if manifest.arm is Arm.CONTROL and manifest.placements:  # pragma: no cover - model forbids
        raise CellError("a control manifest cannot carry placements")
    return ComposeProject(
        name=name,
        run_id=run.run_id,
        document=document,
        files=tuple(files),
        probe_secret=secrets.probe_secret,
        probe_paths=tuple(probe_paths),
        evidence=evidence,
        evidence_paths={"cellguard": _GUARD_EVIDENCE} if spec.needs_docker else {},
        scratch_volume=f"{name}_scratch" if spec.needs_docker else None,
    )
