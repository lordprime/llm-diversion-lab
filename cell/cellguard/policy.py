"""cell-guard policy: the pure, deny-by-default decision for one Docker API request.

Binding policy: ``docs/DEPLOYMENT.md`` §0.3. :func:`evaluate` takes a parsed request
(:class:`DockerRequest`) and the cell it guards (:class:`CellContext`) and returns a
:class:`Decision`: allowed or denied, the rule that decided, and, when allowed, the
exact path and body to forward (rewrites and forced fields are part of the decision).
It does no I/O. Ownership of the object a request names (a container, an exec, a
network, a volume) is looked up by the proxy and passed in as :attr:`DockerRequest.target`.

What is allowed (everything else is denied):

* handshake: ``GET/HEAD /_ping``, ``GET /version``;
* ``POST /containers/create``: the image must be in the ``images.lock`` allow-list
  (by digest, or by a listed name, which is then pinned to its digest). Forced: the
  cell's network (``HostConfig.NetworkMode`` and ``NetworkingConfig``), the
  ``lab.run_id`` label, memory (no swap), CPU and PID limits (a lower request is kept).
  Denied: privileged; host or container network/PID/IPC/user/UTS/cgroup namespaces;
  devices; bind mounts outside the cell's scratch directory; named volumes other than
  the cell's scratch volume; volume driver options; capabilities beyond ``NET_RAW`` and
  ``NET_ADMIN``; any ``SecurityOpt`` except ``no-new-privileges`` (so no unconfined
  seccomp/AppArmor/SELinux/systempaths); published ports; ``VolumesFrom``; links;
  sysctls; runtimes; cgroup parents; masked/read-only path overrides; non-local log
  drivers; and any field this module does not know that is set to a non-zero value;
* start, stop, kill, wait, remove, inspect, logs, attach (incl. websocket), resize,
  exec create/start/resize/inspect: only on containers labelled with this cell's run;
  the path is pinned to the container's full id. A privileged exec is denied;
* container, network and volume lists: forced to the ``lab.run_id`` label filter;
* image list and inspect (read-only); pull, import, build, push, tag, export and
  remove are denied;
* network inspect: the cell's network or a network labelled with this run; volume
  inspect: the scratch volume or a volume labelled with this run;
* volume create: local driver without options, with the ``lab.run_id`` label forced.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode

import yaml

from control.core.ids import ID_PATTERN

__all__ = [
    "ALLOWED_CAPS",
    "DEFAULT_MEMORY_BYTES",
    "DEFAULT_NANO_CPUS",
    "DEFAULT_PIDS_LIMIT",
    "DIGEST_PATTERN",
    "RUN_LABEL",
    "AllowedImage",
    "CellContext",
    "Decision",
    "DockerRequest",
    "ImageRef",
    "Route",
    "Target",
    "evaluate",
    "load_images_lock",
    "match_image",
    "parse_image_ref",
    "route",
]

#: Label every container (and volume) the cell creates carries; ownership is this label.
RUN_LABEL: Final = "lab.run_id"
#: Label namespace reserved for the lab; an agent may not set other ``lab.*`` labels.
_LAB_PREFIX: Final = "lab."
#: Capabilities a created container may add.
ALLOWED_CAPS: Final = frozenset({"NET_RAW", "NET_ADMIN"})
DIGEST_PATTERN: Final = r"^sha256:[0-9a-f]{64}$"
#: Limits forced on created containers unless the cell configures others.
DEFAULT_MEMORY_BYTES: Final = 2 << 30
DEFAULT_NANO_CPUS: Final = 2_000_000_000
DEFAULT_PIDS_LIMIT: Final = 512

_DIGEST_RE = re.compile(DIGEST_PATTERN)
_ID_RE = re.compile(ID_PATTERN)
_REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)*$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_NAME_RE = re.compile(f"^{_NAME}$")
_IMAGE = r"[A-Za-z0-9][A-Za-z0-9_.:@/-]*"
_PATH_RE = re.compile(r"^/[A-Za-z0-9_.:@/-]*$")
_VERSION_RE = re.compile(r"^/v(?P<v>[0-9]+\.[0-9]+)(?P<rest>/.*)$")

MALFORMED: Final = "malformed"
UNKNOWN: Final = "unknown"


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True, slots=True)
class ImageRef:
    """A parsed image reference; ``repo`` is normalized (``alpine`` is
    ``docker.io/library/alpine``)."""

    repo: str
    tag: str | None
    digest: str | None


def _normalize_repo(name: str) -> str:
    first, sep, rest = name.partition("/")
    if not sep or ("." not in first and ":" not in first and first != "localhost"):
        first, rest = "docker.io", name
    if first in ("index.docker.io", "registry-1.docker.io"):
        first = "docker.io"
    if first == "docker.io" and "/" not in rest:
        rest = f"library/{rest}"
    return f"{first}/{rest}"


def parse_image_ref(ref: str) -> ImageRef | None:
    """Parse ``[registry/]repo[:tag][@sha256:...]``; ``None`` if it is not one."""
    name, at, digest = ref.partition("@")
    if at and not _DIGEST_RE.fullmatch(digest):
        return None
    tag: str | None = None
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
        if not _TAG_RE.fullmatch(tag):
            return None
    if not _REPO_RE.fullmatch(name):
        return None
    return ImageRef(_normalize_repo(name), tag, digest or None)


@dataclass(frozen=True, slots=True)
class AllowedImage:
    """One ``images.lock`` entry: the image ``name`` and the ``digest`` it is pinned to."""

    name: str
    digest: str
    expect_tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.digest):
            raise ValueError(f"images.lock: malformed digest {self.digest!r}")
        ref = parse_image_ref(self.name)
        if ref is None:
            raise ValueError(f"images.lock: malformed image name {self.name!r}")
        if ref.digest is not None and ref.digest != self.digest:
            raise ValueError(f"images.lock: {self.name!r} names another digest")

    @property
    def ref(self) -> ImageRef:
        ref = parse_image_ref(self.name)
        if ref is None:  # pragma: no cover - checked in __post_init__
            raise ValueError(f"images.lock: malformed image name {self.name!r}")
        return ref


def load_images_lock(
    source: Path | str | Sequence[Any] | Mapping[str, Any],
) -> tuple[AllowedImage, ...]:
    """Load the allow-list from an ``images.lock`` file (YAML or JSON) or parsed data.

    The document is a list of ``{name, digest, expect_tools}`` entries, or a mapping
    holding that list under ``images``. Anything malformed raises :class:`ValueError`.
    """
    data: Any = source
    if isinstance(source, Path | str):
        try:
            data = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"images.lock: cannot read {source!s}: {exc}") from exc
    if isinstance(data, Mapping):
        data = data.get("images")
    if not isinstance(data, list):
        raise ValueError("images.lock: expected a list of image entries")
    images: list[AllowedImage] = []
    for entry in data:
        if not isinstance(entry, Mapping):
            raise ValueError(f"images.lock: entry is not a mapping: {entry!r}")
        name, digest, tools = entry.get("name"), entry.get("digest"), entry.get("expect_tools", [])
        if not isinstance(name, str) or not name or not isinstance(digest, str):
            raise ValueError(f"images.lock: entry needs a name and a digest: {entry!r}")
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ValueError(f"images.lock: expect_tools must be a list of strings: {entry!r}")
        images.append(AllowedImage(name, digest, tuple(tools)))
    return tuple(images)


@dataclass(frozen=True, slots=True)
class CellContext:
    """The cell cell-guard protects: its run, network, allow-list, scratch and limits."""

    run_id: str
    network: str
    images: tuple[AllowedImage, ...]
    #: Named volume a created container may mount (the cell's scratch volume).
    scratch_volume: str | None = None
    #: Host directory under which bind mounts are allowed (the scratch volume's path).
    scratch_dir: str | None = None
    memory_bytes: int = DEFAULT_MEMORY_BYTES
    nano_cpus: int = DEFAULT_NANO_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.run_id):
            raise ValueError(f"malformed run id {self.run_id!r}")
        if not _NAME_RE.fullmatch(self.network):
            raise ValueError(f"malformed network name {self.network!r}")
        if self.scratch_volume is not None and not _NAME_RE.fullmatch(self.scratch_volume):
            raise ValueError(f"malformed scratch volume {self.scratch_volume!r}")
        if self.scratch_dir is not None and (
            not self.scratch_dir.startswith("/")
            or posixpath.normpath(self.scratch_dir) != self.scratch_dir
            or self.scratch_dir == "/"
        ):
            raise ValueError(f"scratch dir must be a normalized absolute path: {self.scratch_dir}")
        for limit in (self.memory_bytes, self.nano_cpus, self.pids_limit):
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise ValueError(f"limits must be positive integers, got {limit!r}")


@dataclass(frozen=True, slots=True)
class Target:
    """The object a request names, as the daemon reports it (resolved by the proxy).

    For an exec, ``labels`` are the labels of the container the exec runs in.
    """

    kind: str
    id: str
    name: str | None
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DockerRequest:
    """One HTTP request to the Docker API, as the agent sent it."""

    method: str
    #: Path and query, exactly as on the request line (``/v1.44/containers/create?...``).
    path: str
    body: bytes = b""
    #: The resolved object the path names, or ``None`` if none or not found.
    target: Target | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """The verdict on one request, and what to forward if it is allowed."""

    allowed: bool
    op: str
    #: Short identifier of the rule that decided (``create.privileged``, ``image.pull``...).
    rule: str
    reason: str
    #: Path and query to forward (rewritten if the decision pins or filters it).
    path: str
    #: Body to forward (rewritten if the decision forces fields).
    body: bytes
    #: Fields this decision forced or rewrote.
    forced: tuple[str, ...] = ()
    #: The request may hijack the connection (attach, exec start).
    upgrade: bool = False


# --------------------------------------------------------------------------- routing


@dataclass(frozen=True, slots=True)
class Route:
    """Where a request goes: the operation, its version prefix and the object it names."""

    op: str
    version: str | None
    base: str
    query: str
    target_kind: str | None = None
    ref: str | None = None
    ref_span: tuple[int, int] | None = None

    def with_ref(self, ident: str) -> str:
        """The request path with the object reference replaced by ``ident``."""
        base = self.base
        if self.ref_span is not None:
            start, end = self.ref_span
            base = base[:start] + ident + base[end:]
        return self.rebuild(base, self.query)

    def rebuild(self, base: str, query: str) -> str:
        prefix = f"/v{self.version}" if self.version else ""
        return f"{prefix}{base}" + (f"?{query}" if query else "")


_C = rf"/containers/(?P<ref>{_NAME})"
_E = rf"/exec/(?P<ref>{_NAME})"
_I = rf"/images/(?P<ref>{_IMAGE})"
_N = rf"/networks/(?P<ref>{_NAME})"
_V = rf"/volumes/(?P<ref>{_NAME})"

#: (methods, base path pattern, operation, kind of object the proxy must resolve).
#: Only operations that can be allowed name a target kind.
_ROUTES: Final[tuple[tuple[frozenset[str], re.Pattern[str], str, str | None], ...]] = tuple(
    (frozenset(methods.split()), re.compile(f"^{pattern}$"), op, kind)
    for methods, pattern, op, kind in [
        ("GET HEAD", r"/_ping", "system.ping", None),
        ("GET", r"/version", "system.version", None),
        ("GET", r"/info", "system.info", None),
        ("GET", r"/events", "system.events", None),
        ("GET", r"/system/df", "system.df", None),
        ("POST", r"/containers/create", "container.create", None),
        ("GET", r"/containers/json", "container.list", None),
        ("POST", r"/containers/prune", "container.prune", None),
        ("GET", rf"{_C}/json", "container.inspect", "container"),
        ("POST", rf"{_C}/start", "container.start", "container"),
        ("POST", rf"{_C}/stop", "container.stop", "container"),
        ("POST", rf"{_C}/kill", "container.kill", "container"),
        ("POST", rf"{_C}/wait", "container.wait", "container"),
        ("POST", rf"{_C}/resize", "container.resize", "container"),
        ("DELETE", _C, "container.remove", "container"),
        ("GET", rf"{_C}/logs", "container.logs", "container"),
        ("POST", rf"{_C}/attach", "container.attach", "container"),
        ("GET", rf"{_C}/attach/ws", "container.attach", "container"),
        ("POST", rf"{_C}/exec", "exec.create", "container"),
        ("POST", rf"{_E}/start", "exec.start", "exec"),
        ("POST", rf"{_E}/resize", "exec.resize", "exec"),
        ("GET", rf"{_E}/json", "exec.inspect", "exec"),
        ("GET", r"/images/json", "image.list", None),
        ("POST", r"/images/create", "image.pull", None),
        ("POST", r"/images/load", "image.import", None),
        ("GET", r"/images/get", "image.export", None),
        ("GET", r"/images/search", "image.search", None),
        ("POST", r"/images/prune", "image.prune", None),
        ("POST", r"/build(?:/prune)?", "image.build", None),
        ("POST", r"/commit", "image.commit", None),
        ("GET", rf"{_I}/json", "image.inspect", None),
        ("GET", rf"{_I}/history", "image.history", None),
        ("POST", rf"{_I}/push", "image.push", None),
        ("POST", rf"{_I}/tag", "image.tag", None),
        ("GET", rf"{_I}/get", "image.export", None),
        ("DELETE", _I, "image.remove", None),
        ("GET", r"/networks", "network.list", None),
        ("POST", r"/networks/create", "network.create", None),
        ("POST", r"/networks/prune", "network.prune", None),
        ("GET", _N, "network.inspect", "network"),
        ("POST", rf"{_N}/connect", "network.connect", None),
        ("POST", rf"{_N}/disconnect", "network.disconnect", None),
        ("DELETE", _N, "network.remove", None),
        ("GET", r"/volumes", "volume.list", None),
        ("POST", r"/volumes/create", "volume.create", None),
        ("POST", r"/volumes/prune", "volume.prune", None),
        ("GET", _V, "volume.inspect", "volume"),
        ("PUT", _V, "volume.update", None),
        ("DELETE", _V, "volume.remove", None),
    ]
)


def _path_ok(base: str) -> bool:
    if not _PATH_RE.fullmatch(base):
        return False
    return all(seg not in ("", ".", "..") for seg in base[1:].split("/"))


def route(method: str, path: str) -> Route:
    """Classify a request; ``op`` is ``"malformed"`` or ``"unknown"`` if it matches none."""
    raw, _, query = path.partition("?")
    version: str | None = None
    base = raw
    if match := _VERSION_RE.fullmatch(raw):
        version, base = match.group("v"), match.group("rest")
    if not _path_ok(base):
        return Route(MALFORMED, version, base, query)
    for methods, pattern, op, kind in _ROUTES:
        found = pattern.fullmatch(base)
        if found is None or method not in methods:
            continue
        if op == "image.pull" and any(k == "fromSrc" for k, _ in parse_qsl(query)):
            op = "image.import"
        if "ref" in pattern.groupindex:
            return Route(op, version, base, query, kind, found.group("ref"), found.span("ref"))
        return Route(op, version, base, query)
    return Route(UNKNOWN, version, base, query)


# --------------------------------------------------------------------------- helpers


class _Denied(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


def _json_object(raw: bytes, rule: str, *, empty_ok: bool = False) -> dict[str, Any]:
    if empty_ok and not raw.strip():
        return {}
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _Denied(rule, "body is not JSON") from None
    if not isinstance(doc, dict):
        raise _Denied(rule, "body is not a JSON object")
    return doc


def _encode(doc: Mapping[str, Any]) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _truthy(value: str) -> bool:
    return value.strip().lower() not in ("", "0", "false", "no")


def _mapping(value: Any, what: str, rule: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _Denied(rule, f"{what} is not an object")
    return value


def _strings(value: Any, what: str, rule: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _Denied(rule, f"{what} is not a list of strings")
    return value


def _reject_unknown(doc: Mapping[str, Any], known: frozenset[str], where: str, rule: str) -> None:
    """Deny any field outside ``known`` that is set to a non-zero value."""
    for key, value in doc.items():
        if key not in known and value:
            raise _Denied(rule, f"{where}{key} is not allowed")


def _labels(value: Any, ctx: CellContext, rule: str) -> dict[str, str]:
    labels = _mapping(value, "Labels", rule)
    for key, val in labels.items():
        if not isinstance(val, str):
            raise _Denied(rule, f"label {key!r} is not a string")
        if key.startswith(_LAB_PREFIX) and not (key == RUN_LABEL and val == ctx.run_id):
            raise _Denied(rule, f"label {key}={val!r} is reserved for the lab")
    return {**labels, RUN_LABEL: ctx.run_id}


def match_image(image: str, images: Sequence[AllowedImage]) -> str | None:
    """The reference to forward for ``image``, or ``None`` if it is not allowed.

    A reference with a digest is allowed if that digest is listed for the same
    repository and is forwarded unchanged. A reference without one is allowed if it
    names a listed entry (same repository and tag; an entry without a tag matches any
    tag) and is pinned to that entry's digest.
    """
    ref = parse_image_ref(image)
    if ref is None:
        return None
    if ref.digest is not None:
        ok = any(i.digest == ref.digest and i.ref.repo == ref.repo for i in images)
        return image if ok else None
    candidates = [i for i in images if i.ref.repo == ref.repo]
    chosen = [i for i in candidates if i.ref.tag is not None and i.ref.tag == (ref.tag or "latest")]
    if not chosen:
        chosen = [i for i in candidates if i.ref.tag is None]
    digests = {i.digest for i in chosen}
    if len(digests) != 1:
        return None
    return f"{ref.repo}@{digests.pop()}"


# --------------------------------------------------------------------------- container create

#: Container config fields that are harmless at any value.
_CONFIG_SAFE: Final = frozenset(
    {
        "Hostname",
        "Domainname",
        "User",
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "ExposedPorts",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "Env",
        "Cmd",
        "Healthcheck",
        "ArgsEscaped",
        "Volumes",
        "WorkingDir",
        "Entrypoint",
        "NetworkDisabled",
        "MacAddress",
        "OnBuild",
        "StopSignal",
        "StopTimeout",
        "Shell",
        # checked or forced below
        "Image",
        "Labels",
        "HostConfig",
        "NetworkingConfig",
    }
)

#: Host config fields that are harmless at any value, plus those checked or forced below.
#: Every other field must be unset or zero.
_HOST_KNOWN: Final = frozenset(
    {
        "CpuShares",
        "BlkioWeight",
        "CpusetCpus",
        "CpusetMems",
        "MemoryReservation",
        "MemorySwappiness",
        "OomKillDisable",
        "OomScoreAdj",
        "Init",
        "Ulimits",
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
        "RestartPolicy",
        "AutoRemove",
        "ConsoleSize",
        "CapDrop",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "GroupAdd",
        "ReadonlyRootfs",
        "Tmpfs",
        "ShmSize",
        "Isolation",
        # checked or forced below
        "Privileged",
        "NetworkMode",
        "PidMode",
        "IpcMode",
        "UsernsMode",
        "UTSMode",
        "CgroupnsMode",
        "CapAdd",
        "SecurityOpt",
        "Binds",
        "Mounts",
        "LogConfig",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "CpuPeriod",
        "CpuQuota",
        "PidsLimit",
        "MaskedPaths",
        "ReadonlyPaths",
    }
)

_NAMESPACE_MODES: Final[Mapping[str, frozenset[str]]] = {
    "PidMode": frozenset({""}),
    "IpcMode": frozenset({"", "private", "none", "shareable"}),
    "UsernsMode": frozenset({""}),
    "UTSMode": frozenset({""}),
    "CgroupnsMode": frozenset({"", "private"}),
}
_LOG_DRIVERS: Final = frozenset({"", "json-file", "local", "k8s-file", "journald", "none"})
_LOG_OPTIONS: Final = frozenset({"max-size", "max-file", "compress", "mode", "max-buffer-size"})
_BIND_OPTIONS: Final = frozenset(
    {"ro", "rw", "z", "Z", "nocopy", "private", "rprivate", "consistent", "cached", "delegated"}
)
_MOUNT_KEYS: Final = frozenset(
    {
        "Target",
        "Source",
        "Type",
        "ReadOnly",
        "Consistency",
        "BindOptions",
        "VolumeOptions",
        "TmpfsOptions",
    }
)


def _bind_source_ok(source: str, ctx: CellContext) -> bool:
    if ctx.scratch_dir is None or ".." in source.split("/"):
        return False
    path = posixpath.normpath(source)
    return path == ctx.scratch_dir or path.startswith(ctx.scratch_dir + "/")


def _volume_source_ok(source: str | None, ctx: CellContext) -> bool:
    return not source or source == ctx.scratch_volume


def _check_binds(value: Any, ctx: CellContext) -> None:
    for bind in _strings(value, "HostConfig.Binds", "create.mount"):
        parts = bind.split(":")
        if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
            raise _Denied("create.mount", f"malformed bind {bind!r}")
        source = parts[0]
        ok = (
            _bind_source_ok(source, ctx)
            if source.startswith("/")
            else _volume_source_ok(source, ctx)
        )
        if not ok:
            raise _Denied("create.mount", f"mount source {source!r} is outside the cell scratch")
        if len(parts) == 3 and not set(parts[2].split(",")) <= _BIND_OPTIONS:
            raise _Denied("create.mount", f"bind options {parts[2]!r} are not allowed")


def _check_mounts(value: Any, ctx: CellContext) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise _Denied("create.mount", "HostConfig.Mounts is not a list")
    for mount in value:
        if not isinstance(mount, dict):
            raise _Denied("create.mount", "mount is not an object")
        _reject_unknown(mount, _MOUNT_KEYS, "mount field ", "create.mount")
        kind, source = mount.get("Type"), mount.get("Source")
        if source is not None and not isinstance(source, str):
            raise _Denied("create.mount", "mount source is not a string")
        if kind == "bind":
            options = _mapping(mount.get("BindOptions"), "BindOptions", "create.mount")
            if not source or not _bind_source_ok(source, ctx):
                raise _Denied("create.mount", f"bind source {source!r} is outside the cell scratch")
            if options.get("Propagation") not in (None, "", "private", "rprivate"):
                raise _Denied("create.mount", "bind propagation is not allowed")
        elif kind == "volume":
            options = _mapping(mount.get("VolumeOptions"), "VolumeOptions", "create.mount")
            if not _volume_source_ok(source, ctx):
                raise _Denied("create.mount", f"volume {source!r} is not the cell scratch")
            if options.get("DriverConfig"):
                raise _Denied("create.mount", "volume driver options are not allowed")
            subpath = options.get("Subpath")
            if subpath is not None and (not isinstance(subpath, str) or ".." in subpath):
                raise _Denied("create.mount", "volume subpath is not allowed")
        elif kind != "tmpfs":
            raise _Denied("create.mount", f"mount type {kind!r} is not allowed")


def _check_paths(value: Any, what: str) -> None:
    """Keys of ``Volumes``/``Tmpfs`` must be plain container paths.

    Podman parses a ``Volumes`` key like a ``-v`` flag, so ``/host:/x`` would be a bind.
    """
    for path in _mapping(value, what, "create.mount"):
        if not path.startswith("/") or ":" in path or "," in path or ".." in path.split("/"):
            raise _Denied("create.mount", f"{what} entry {path!r} is not a container path")


def _check_host_config(host: dict[str, Any], ctx: CellContext) -> None:
    if host.get("Privileged"):
        raise _Denied("create.privileged", "HostConfig.Privileged is set")
    for key, allowed in _NAMESPACE_MODES.items():
        mode = host.get(key)
        if mode is not None and (not isinstance(mode, str) or mode not in allowed):
            raise _Denied("create.namespace", f"HostConfig.{key}={mode!r} is not allowed")
    for cap in _strings(host.get("CapAdd"), "HostConfig.CapAdd", "create.capabilities"):
        if cap.strip().upper().removeprefix("CAP_") not in ALLOWED_CAPS:
            raise _Denied("create.capabilities", f"capability {cap!r} is not allowed")
    for opt in _strings(host.get("SecurityOpt"), "HostConfig.SecurityOpt", "create.security_opt"):
        key, _, val = opt.strip().replace("=", ":", 1).partition(":")
        if key != "no-new-privileges" or val not in ("", "true"):
            raise _Denied("create.security_opt", f"security option {opt!r} is not allowed")
    _check_binds(host.get("Binds"), ctx)
    _check_paths(host.get("Tmpfs"), "HostConfig.Tmpfs")
    oom = host.get("OomScoreAdj")
    if oom is not None and (isinstance(oom, bool) or not isinstance(oom, int) or oom < 0):
        raise _Denied("create.field", "a negative HostConfig.OomScoreAdj is not allowed")
    _check_mounts(host.get("Mounts"), ctx)
    for key in ("MaskedPaths", "ReadonlyPaths"):
        if host.get(key) is not None:
            raise _Denied("create.field", f"HostConfig.{key} is not allowed")
    log = _mapping(host.get("LogConfig"), "HostConfig.LogConfig", "create.field")
    if log.get("Type") not in (None, *_LOG_DRIVERS):
        raise _Denied("create.field", f"log driver {log.get('Type')!r} is not allowed")
    log_options = _mapping(log.get("Config"), "HostConfig.LogConfig.Config", "create.field")
    if not set(log_options) <= _LOG_OPTIONS:
        raise _Denied("create.field", "log options are not allowed")
    _reject_unknown(log, frozenset({"Type", "Config"}), "HostConfig.LogConfig.", "create.field")
    _reject_unknown(host, _HOST_KNOWN, "HostConfig.", "create.field")


def _cap(value: Any, limit: int, what: str) -> int:
    if value is None:
        return limit
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Denied("create.field", f"{what} is not an integer")
    return value if 0 < value < limit else limit


def _force_network(body: dict[str, Any], host: dict[str, Any], ctx: CellContext) -> None:
    mode = host.get("NetworkMode")
    if mode not in (None, "", "default", "bridge", ctx.network):
        raise _Denied("create.network", f"HostConfig.NetworkMode={mode!r} is not allowed")
    host["NetworkMode"] = ctx.network
    networking = _mapping(body.get("NetworkingConfig"), "NetworkingConfig", "create.network")
    _reject_unknown(
        networking, frozenset({"EndpointsConfig"}), "NetworkingConfig.", "create.network"
    )
    endpoints = _mapping(networking.get("EndpointsConfig"), "EndpointsConfig", "create.network")
    endpoint: dict[str, Any] = {}
    for name, config in endpoints.items():
        if name != ctx.network:
            raise _Denied("create.network", f"network {name!r} is not the cell network")
        aliases = _strings(
            _mapping(config, "endpoint", "create.network").get("Aliases"),
            "Aliases",
            "create.network",
        )
        if aliases:
            endpoint["Aliases"] = aliases
    body["NetworkingConfig"] = {"EndpointsConfig": {ctx.network: endpoint}}


def _container_create(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    body = _json_object(req.body, "create.body")
    _reject_unknown(body, _CONFIG_SAFE, "", "create.field")
    _check_paths(body.get("Volumes"), "Volumes")
    image = body.get("Image")
    pinned = match_image(image, ctx.images) if isinstance(image, str) else None
    if pinned is None:
        raise _Denied("image.not_allowed", f"image {image!r} is not in images.lock")
    forced: list[str] = []
    if pinned != image:
        body["Image"] = pinned
        forced.append("Image")
    body["Labels"] = _labels(body.get("Labels"), ctx, "create.labels")
    host = _mapping(body.get("HostConfig"), "HostConfig", "create.body")
    _check_host_config(host, ctx)
    _force_network(body, host, ctx)
    memory = _cap(host.get("Memory"), ctx.memory_bytes, "HostConfig.Memory")
    host["Memory"] = host["MemorySwap"] = memory
    host["NanoCpus"] = _cap(host.get("NanoCpus"), ctx.nano_cpus, "HostConfig.NanoCpus")
    host["PidsLimit"] = _cap(host.get("PidsLimit"), ctx.pids_limit, "HostConfig.PidsLimit")
    host.pop("CpuPeriod", None)
    host.pop("CpuQuota", None)
    body["HostConfig"] = host
    forced += [
        "Labels",
        "HostConfig.NetworkMode",
        "NetworkingConfig",
        "HostConfig.Memory",
        "HostConfig.MemorySwap",
        "HostConfig.NanoCpus",
        "HostConfig.PidsLimit",
    ]
    return _allow(r, req, "container.create", body=_encode(body), forced=tuple(forced))


# --------------------------------------------------------------------------- other handlers

_EXEC_CREATE_KEYS: Final = frozenset(
    {
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "ConsoleSize",
        "DetachKeys",
        "Tty",
        "Env",
        "Cmd",
        "User",
        "WorkingDir",
        "Privileged",
        "Container",
    }
)
_EXEC_START_KEYS: Final = frozenset({"Detach", "Tty", "ConsoleSize"})
_UPGRADE_OPS: Final = frozenset({"container.attach", "exec.start"})


def _owned(target: Target | None, kind: str, ctx: CellContext) -> bool:
    if target is None or target.kind != kind:
        return False
    if target.labels.get(RUN_LABEL) == ctx.run_id:
        return True
    if kind == "network":
        return ctx.network in (target.name, target.id)
    if kind == "volume":
        return ctx.scratch_volume is not None and target.name == ctx.scratch_volume
    return False


def _targeted(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    """An operation on one existing object: allowed only if this cell owns it."""
    target = req.target
    if r.target_kind is None:  # pragma: no cover - only targeted routes get here
        raise _Denied("target.unknown", "route names no object")
    if target is None:
        raise _Denied("target.unknown", f"no such {r.target_kind} {r.ref!r}")
    if not _owned(target, r.target_kind, ctx):
        raise _Denied("target.not_owned", f"{r.target_kind} {r.ref!r} is not this cell's")
    if not _NAME_RE.fullmatch(target.id):
        raise _Denied("target.malformed", f"{r.target_kind} id {target.id!r} is malformed")
    body = req.body
    if r.op == "container.remove":
        if any(k == "link" and _truthy(v) for k, v in parse_qsl(r.query)):
            raise _Denied("remove.link", "removing links is not allowed")
    elif r.op == "exec.create":
        doc = _json_object(req.body, "exec.body")
        if doc.get("Privileged"):
            raise _Denied("exec.privileged", "a privileged exec is not allowed")
        # docker-py repeats the container in the body; it must be the one in the path.
        if doc.get("Container") not in (None, "", r.ref, target.id, target.name):
            raise _Denied("exec.field", "exec body names another container")
        _reject_unknown(doc, _EXEC_CREATE_KEYS, "exec field ", "exec.field")
    elif r.op == "exec.start":
        doc = _json_object(req.body, "exec.body", empty_ok=True)
        _reject_unknown(doc, _EXEC_START_KEYS, "exec start field ", "exec.field")
    return Decision(
        allowed=True,
        op=r.op,
        rule=r.op,
        reason=f"{r.target_kind} belongs to this cell",
        path=r.with_ref(target.id),
        body=body,
        upgrade=r.op in _UPGRADE_OPS,
    )


def _own_list(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    """A list, restricted to objects carrying this cell's run label."""
    pairs = parse_qsl(r.query, keep_blank_values=True)
    raw = [v for k, v in pairs if k == "filters"]
    if len(raw) > 1:
        raise _Denied("list.filters", "repeated filters parameter")
    filters: dict[str, list[str]] = {}
    if raw and raw[0]:
        try:
            doc = json.loads(raw[0])
        except ValueError:
            raise _Denied("list.filters", "filters is not JSON") from None
        if not isinstance(doc, dict):
            raise _Denied("list.filters", "filters is not an object")
        for key, value in doc.items():
            as_list = isinstance(value, list) and all(isinstance(v, str) for v in value)
            as_map = isinstance(value, dict) and all(v is True for v in value.values())
            if as_list or as_map:
                filters[key] = list(value)
            else:
                raise _Denied("list.filters", f"filter {key!r} is malformed")
    own = f"{RUN_LABEL}={ctx.run_id}"
    labels = filters.setdefault("label", [])
    if own not in labels:
        labels.append(own)
    query = urlencode(
        [(k, v) for k, v in pairs if k != "filters"]
        + [("filters", json.dumps(filters, separators=(",", ":")))]
    )
    return _allow(r, req, r.op, path=r.rebuild(r.base, query), forced=("filters.label",))


def _volume_create(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    body = _json_object(req.body, "volume.body")
    _reject_unknown(body, frozenset({"Name", "Driver", "Labels"}), "volume field ", "volume.field")
    name = body.get("Name")
    if name is not None and (not isinstance(name, str) or (name and not _NAME_RE.fullmatch(name))):
        raise _Denied("volume.field", f"volume name {name!r} is malformed")
    if body.get("Driver") not in (None, "", "local"):
        raise _Denied("volume.field", f"volume driver {body.get('Driver')!r} is not allowed")
    body["Labels"] = _labels(body.get("Labels"), ctx, "volume.labels")
    return _allow(r, req, r.op, body=_encode(body), forced=("Labels",))


def _plain(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    return _allow(r, req, r.op)


def _allow(
    r: Route,
    req: DockerRequest,
    rule: str,
    *,
    path: str | None = None,
    body: bytes | None = None,
    forced: tuple[str, ...] = (),
) -> Decision:
    return Decision(
        allowed=True,
        op=r.op,
        rule=rule,
        reason="allowed",
        path=req.path if path is None else path,
        body=req.body if body is None else body,
        forced=forced,
    )


_Handler = Callable[[Route, DockerRequest, CellContext], Decision]

_HANDLERS: Final[Mapping[str, _Handler]] = {
    "system.ping": _plain,
    "system.version": _plain,
    "container.create": _container_create,
    "container.list": _own_list,
    "container.inspect": _targeted,
    "container.start": _targeted,
    "container.stop": _targeted,
    "container.kill": _targeted,
    "container.wait": _targeted,
    "container.resize": _targeted,
    "container.remove": _targeted,
    "container.logs": _targeted,
    "container.attach": _targeted,
    "exec.create": _targeted,
    "exec.start": _targeted,
    "exec.resize": _targeted,
    "exec.inspect": _targeted,
    "image.list": _plain,
    "image.inspect": _plain,
    "network.list": _own_list,
    "network.inspect": _targeted,
    "volume.list": _own_list,
    "volume.inspect": _targeted,
    "volume.create": _volume_create,
}


# --------------------------------------------------------------------------- evaluate


def evaluate(request: DockerRequest, ctx: CellContext) -> Decision:
    """Decide one request for one cell. Pure: no I/O, no state."""
    r = route(request.method, request.path)

    def deny(rule: str, reason: str) -> Decision:
        return Decision(False, r.op, rule, reason, request.path, request.body)

    if r.op == MALFORMED:
        return deny("path.malformed", f"malformed path {request.path!r}")
    handler = _HANDLERS.get(r.op)
    if handler is None:
        if r.op == UNKNOWN:
            return deny("path.unmatched", f"{request.method} {r.base} is not allowed")
        return deny(r.op, f"{r.op} is not allowed")
    try:
        return handler(r, request, ctx)
    except _Denied as denied:
        return deny(denied.rule, denied.reason)
