"""cell-guard policy: the pure, deny-by-default decision for one Docker API request.

Binding policy: ``docs/DEPLOYMENT.md`` §0.3. :func:`evaluate` takes a parsed request
(:class:`DockerRequest`) and the cell it guards (:class:`CellContext`) and returns a
:class:`Decision`: allowed or denied, the rule that decided, and, when allowed, the
exact path and body to forward (rewrites and forced fields are part of the decision).
It does no I/O. Ownership of the object a request names (a container, an exec, a
network, a volume) is looked up by the proxy and passed in as :attr:`DockerRequest.target`.

**Bodies are rebuilt, never passed through.** Docker and Podman decode JSON with Go's
``encoding/json``, which matches object keys to struct fields case-insensitively (last
one wins), so ``"memory": 0`` after ``"Memory": 1`` would undo a forced limit. Every
forwarded body is therefore rebuilt from exact-key schemas: a key that is not exactly a
known field is denied whatever its value (a key whose Go-style case fold collides with
a known field is reported as ``body.shadow_key``), and only validated values are
re-encoded. Nested objects are rebuilt the same way. Operations that take no body must
send none, and API versions below 1.40 are denied.

Ownership: everything cell-guard creates carries two forced labels,
``lab.run_id=<run>`` and ``lab.origin=cellguard``; an object it may act on must carry
both. Runner infrastructure (the agent, target, oracle and cell-guard containers, the
scratch volume) is labelled with the run only and so is untouchable.

What is allowed (everything else is denied):

* handshake: ``GET/HEAD /_ping``, ``GET /version``;
* ``POST /containers/create``: the image must be in the ``images.lock`` allow-list (by
  logical name, by repository, or by ``repository@digest``) and is pinned to
  ``image@digest``. Forced: the cell's network (``HostConfig.NetworkMode`` and
  ``NetworkingConfig``), the cell's resolver (``HostConfig.Dns``), both ownership
  labels (also on volume mounts), memory (no swap), CPU and PID limits (a lower request
  is kept), and the cell's name prefix on ``?name=``. Every DNS name the container
  publishes on the cell network carries the cell prefix: network aliases and a
  non-empty ``Hostname`` must start with it (so none can be ``target``, ``tap`` or
  ``catcher``). Mounts: only the cell's scratch *named* volume (``<name>:/path[:ro]``
  or a ``volume`` mount without subpath), anonymous volumes via ``Mounts``
  (labelled on Docker; Podman ignores ``VolumeOptions.Labels``) and tmpfs; **no host
  path is ever mounted** (a symlink planted in a bind-mounted directory would reach
  any host path). Denied: privileged; host or container
  network/PID/IPC/user/UTS/cgroup namespaces; devices; bind mounts; other named
  volumes; volume subpaths and driver options; top-level ``Volumes`` (unlabelled
  anonymous volumes; an entry that only mirrors a ``Binds`` target is dropped);
  capabilities beyond ``NET_RAW``; any ``SecurityOpt`` except ``no-new-privileges``;
  published ports; ``VolumesFrom``; links; ``Domainname``; MAC/IP addresses; agent
  ``Dns``/``DnsSearch``/``DnsOptions``/``ExtraHosts``; sysctls; runtimes; cgroup
  parents; masked/read-only path overrides; any non-empty ``LogConfig`` (the daemon's
  log driver applies); restart policies other than ``no``; ulimits other than
  ``nofile``/``nproc`` within caps; ``GroupAdd`` ``keep-groups`` (Podman: the caller's
  supplementary groups); a ``Healthcheck`` ``Interval``/``Timeout``/``StartInterval``
  that is neither 0 (the default) nor at least 1 s; ``lab.*``, ``com.docker.*``,
  ``io.containers.*`` and ``io.podman.*`` labels and ``PODMAN_SYSTEMD_UNIT`` (Podman
  acts on them); and every other field set to a non-zero value;
* start, stop, kill, wait, remove, inspect, logs, attach (incl. websocket), resize,
  exec create/start/resize/inspect: only on containers carrying both ownership labels;
  the path is pinned to the container's full id. A privileged exec is denied;
* container and volume lists: forced to both ownership label filters; network list:
  forced to the ``lab.run_id`` filter;
* image list and inspect (read-only); pull, import, build, push, tag, export and
  remove are denied;
* network inspect: the cell's network only; volume inspect: the scratch volume or a
  volume carrying both ownership labels;
* volume create: local driver without options or query parameters; both ownership
  labels and the cell's name prefix are forced.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode

import yaml

__all__ = [
    "AGENT_ROLE",
    "ALLOWED_CAPS",
    "DEFAULT_MEMORY_BYTES",
    "DEFAULT_NANO_CPUS",
    "DEFAULT_PIDS_LIMIT",
    "DIGEST_PATTERN",
    "IMAGE_ROLES",
    "MIN_API_VERSION",
    "ORIGIN",
    "ORIGIN_LABEL",
    "RUN_ID_PATTERN",
    "RUN_LABEL",
    "ULIMIT_CAPS",
    "AllowedImage",
    "CellContext",
    "Decision",
    "DockerRequest",
    "ImageRef",
    "Route",
    "Target",
    "evaluate",
    "go_fold",
    "load_images_lock",
    "match_image",
    "parse_image_ref",
    "route",
]

#: Label every container (and volume) the cell creates carries; ownership is this label.
RUN_LABEL: Final = "lab.run_id"
#: Second ownership label: only objects cell-guard itself created carry it, so runner
#: infrastructure labelled with the run (agent, target, oracle, cell-guard) is untouchable.
ORIGIN_LABEL: Final = "lab.origin"
ORIGIN: Final = "cellguard"
#: Label namespaces an agent may not set (``lab.*`` is the lab's; ``com.docker.*`` would
#: spoof compose ownership; Podman acts on ``io.containers.*`` / ``io.podman.*``, e.g.
#: auto-update). Only the forced ``lab.*`` values themselves are accepted. Compared
#: case-insensitively.
_RESERVED_LABEL_PREFIXES: Final = ("lab.", "com.docker.", "io.containers.", "io.podman.")
#: Single label keys an agent may not set (casefolded): Podman ties a container
#: carrying ``PODMAN_SYSTEMD_UNIT`` to that systemd unit.
_RESERVED_LABEL_KEYS: Final = frozenset({"podman_systemd_unit"})
#: Healthcheck periods (ns) below this, other than 0 (the default), are denied: a 1 ms
#: interval would have the daemon exec the check a thousand times a second.
MIN_HEALTHCHECK_NS: Final = 1_000_000_000
#: Capabilities a created container may add.
#: NET_RAW is Docker's default and agents need raw scans; NET_ADMIN would let an agent
#: container take another container's address, so it is not allowed.
ALLOWED_CAPS: Final = frozenset({"NET_RAW"})
#: A canonical run id, as ``control.core.ids.new_id("run")`` makes it (``run_`` plus a
#: 26-character uppercase Crockford ULID). Nothing else is accepted, so one cell's name
#: prefix (``<run id lowercased>-``) can never be a prefix of another cell's.
RUN_ID_PATTERN: Final = r"^run_[0-9A-HJKMNP-TV-Z]{26}$"
#: Ulimits a created container may set, and the cap on each one's hard limit.
ULIMIT_CAPS: Final[Mapping[str, int]] = {"nofile": 65536, "nproc": 4096}
#: Oldest Docker API version accepted on a version-prefixed path.
MIN_API_VERSION: Final = (1, 40)
DIGEST_PATTERN: Final = r"^sha256:[0-9a-f]{64}$"
#: Limits forced on created containers unless the cell configures others.
DEFAULT_MEMORY_BYTES: Final = 2 << 30
DEFAULT_NANO_CPUS: Final = 2_000_000_000
DEFAULT_PIDS_LIMIT: Final = 512

_DIGEST_RE = re.compile(DIGEST_PATTERN)
_RUN_ID_RE = re.compile(RUN_ID_PATTERN)
_REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)*$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_LOGICAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$")
#: ``images.lock`` entry roles; cell-guard allows only ``agent`` images.
IMAGE_ROLES: Final = frozenset({"agent", "target", "infra", "control"})
AGENT_ROLE: Final = "agent"
_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_NAME_RE = re.compile(f"^{_NAME}$")
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9_.]*-$")
_IMAGE = r"[A-Za-z0-9][A-Za-z0-9_.:@/-]*"
_PATH_RE = re.compile(r"^/[A-Za-z0-9_.:@/-]*$")
_VERSION_RE = re.compile(r"^/v(?P<v>[0-9]{1,3}\.[0-9]{1,3})(?P<rest>/.*)$")
_PORT_RE = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:/(?:tcp|udp|sctp))?$")

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
    """One ``images.lock`` entry.

    ``name`` is a logical name (``python-3.10-bookworm``), ``image`` the repository
    (``docker.io/library/python``) and ``digest`` the manifest digest it is pinned to.
    """

    name: str
    image: str
    digest: str
    expect_tools: tuple[str, ...] = ()
    #: ``agent`` | ``target`` | ``infra`` | ``control``; only ``agent`` images may be
    #: started through cell-guard (:meth:`CellGuardConfig.from_env` filters on it).
    role: str = "infra"

    def __post_init__(self) -> None:
        if self.role not in IMAGE_ROLES:
            raise ValueError(f"images.lock: unknown role {self.role!r} for {self.name!r}")
        if not _LOGICAL_RE.fullmatch(self.name):
            raise ValueError(f"images.lock: malformed logical name {self.name!r}")
        if not _DIGEST_RE.fullmatch(self.digest):
            raise ValueError(f"images.lock: malformed digest {self.digest!r}")
        ref = parse_image_ref(self.image)
        if ref is None:
            raise ValueError(f"images.lock: malformed image {self.image!r}")
        if ref.digest is not None and ref.digest != self.digest:
            raise ValueError(f"images.lock: {self.image!r} names another digest")

    @property
    def repo(self) -> str:
        """The normalized repository."""
        ref = parse_image_ref(self.image)
        if ref is None:  # pragma: no cover - checked in __post_init__
            raise ValueError(f"images.lock: malformed image {self.image!r}")
        return ref.repo

    @property
    def pinned(self) -> str:
        """The reference forwarded to the daemon: ``image@digest``."""
        return f"{self.repo}@{self.digest}"


def load_images_lock(
    source: Path | str | Sequence[Any] | Mapping[str, Any],
) -> tuple[AllowedImage, ...]:
    """Load the allow-list from an ``images.lock`` file (YAML or JSON) or parsed data.

    The document maps ``images`` to a list of ``{name, image, digest, expect_tools,
    role}`` entries (a bare list is accepted too); ``expect_tools`` is optional and
    ``role`` defaults to ``infra``. Anything
    malformed raises :class:`ValueError`.
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
        name, image, digest = entry.get("name"), entry.get("image"), entry.get("digest")
        tools = entry.get("expect_tools", [])
        if not all(isinstance(v, str) and v for v in (name, image, digest)):
            raise ValueError(f"images.lock: entry needs a name, an image and a digest: {entry!r}")
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ValueError(f"images.lock: expect_tools must be a list of strings: {entry!r}")
        role = entry.get("role", "infra")
        if not isinstance(role, str):
            raise ValueError(f"images.lock: role must be a string: {entry!r}")
        images.append(AllowedImage(str(name), str(image), str(digest), tuple(tools), role))
    if len({i.name for i in images}) != len(images):
        raise ValueError("images.lock: duplicate logical name")
    return tuple(images)


@dataclass(frozen=True, slots=True)
class CellContext:
    """The cell cell-guard protects: its run, network, allow-list, scratch and limits."""

    run_id: str
    network: str
    images: tuple[AllowedImage, ...]
    #: The cell resolver (the catcher's DNS); forced as every created container's only
    #: nameserver, so callbacks cannot bypass the catcher.
    dns: str
    #: The one named volume a created container may mount (the cell's scratch volume).
    #: Host paths are never mounted.
    scratch_volume: str | None = None
    memory_bytes: int = DEFAULT_MEMORY_BYTES
    nano_cpus: int = DEFAULT_NANO_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT
    #: Prefix forced on container and volume names the agent chooses; default
    #: ``<run_id lowercased>-``. It ends with ``-`` and holds no other ``-``, and run
    #: ids hold none, so one cell's prefix is never a prefix of another's.
    name_prefix: str | None = None

    def __post_init__(self) -> None:
        if not _RUN_ID_RE.fullmatch(self.run_id):
            raise ValueError(f"malformed run id {self.run_id!r} (expected {RUN_ID_PATTERN})")
        try:
            ipaddress.ip_address(self.dns)
        except ValueError:
            raise ValueError(f"cell DNS must be an IP address, got {self.dns!r}") from None
        if not _NAME_RE.fullmatch(self.network):
            raise ValueError(f"malformed network name {self.network!r}")
        if self.scratch_volume is not None and not _NAME_RE.fullmatch(self.scratch_volume):
            raise ValueError(f"malformed scratch volume {self.scratch_volume!r}")
        if self.name_prefix is not None and not _PREFIX_RE.fullmatch(self.name_prefix):
            raise ValueError(
                f"malformed name prefix {self.name_prefix!r}: [a-z0-9][a-z0-9_.]* then one '-'"
            )
        for limit in (self.memory_bytes, self.nano_cpus, self.pids_limit):
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise ValueError(f"limits must be positive integers, got {limit!r}")

    @property
    def prefix(self) -> str:
        """The name prefix of this cell's containers and volumes."""
        return self.name_prefix or f"{self.run_id.lower()}-"

    def scoped(self, name: str) -> str:
        """``name`` with this cell's prefix (unchanged if it already has it)."""
        return name if name.startswith(self.prefix) else f"{self.prefix}{name}"


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
    #: Body to forward (rebuilt for operations that take one; empty otherwise).
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


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _json_object(raw: bytes, rule: str, *, empty_ok: bool = False) -> dict[str, Any]:
    if empty_ok and not raw.strip():
        return {}
    try:
        doc = json.loads(raw, parse_constant=_no_constants)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise _Denied(rule, "body is not JSON") from None
    if not isinstance(doc, dict):
        raise _Denied(rule, "body is not a JSON object")
    return doc


def _encode(doc: Mapping[str, Any]) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _truthy(value: str) -> bool:
    return value.strip().lower() not in ("", "0", "false", "no")


def go_fold(key: str) -> str:
    """Case fold as Go's ``encoding/json`` compares keys to field names.

    Lowercase plus Unicode simple folding; the long s (U+017F) folds to ``s`` and the Kelvin
    sign (U+212A) to ``k``, which ``str.casefold`` also does.
    """
    return key.casefold()


# --------------------------------------------------------------------------- body schemas
#
# A schema maps each exact field name to a validator ``(value, where, rule) -> value``.
# A validator returns the value to forward, or ``_OMIT`` to forward nothing; it raises
# ``_Denied`` to deny. ``_rebuild`` denies every key that is not exactly in the schema.

_OMIT: Final = object()
_Check = Callable[[Any, str, str], Any]
_Schema = Mapping[str, _Check]


def _rebuild(doc: Any, schema: _Schema, where: str, rule: str) -> dict[str, Any]:
    """Rebuild ``doc`` from ``schema``: exact keys only, every value validated."""
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise _Denied(rule, f"{where or 'body'} is not an object")
    folded = {go_fold(k): k for k in schema}
    out: dict[str, Any] = {}
    for key, value in doc.items():
        check = schema.get(key)
        if check is None:
            twin = folded.get(go_fold(key))
            if twin is not None:
                raise _Denied("body.shadow_key", f"{where}{key!r} shadows {where}{twin}")
            raise _Denied(rule, f"{where}{key} is not an allowed field")
        cleaned = check(value, f"{where}{key}", rule)
        if cleaned is not _OMIT:
            out[key] = cleaned
    return out


def _obj(schema: _Schema, rule: str | None = None) -> _Check:
    def check(value: Any, where: str, outer: str) -> Any:
        if value is None:
            return _OMIT
        return _rebuild(value, schema, f"{where}.", rule or outer)

    return check


def _bad(rule: str, where: str, what: str) -> _Denied:
    return _Denied(rule, f"{where} {what}")


def _str(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if not isinstance(value, str):
        raise _bad(rule, where, "is not a string")
    return value


def _bool(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if not isinstance(value, bool):
        raise _bad(rule, where, "is not a boolean")
    return value


def _int(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) >= 1 << 63:
        raise _bad(rule, where, "is not an integer")
    return value


def _uint(value: Any, where: str, rule: str) -> Any:
    value = _int(value, where, rule)
    if value is not _OMIT and value < 0:
        raise _bad(rule, where, "is negative")
    return value


def _strlist(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _bad(rule, where, "is not a list of strings")
    return list(value)


def _strslice(value: Any, where: str, rule: str) -> Any:
    """A string or a list of strings (Docker's ``StrSlice``)."""
    if isinstance(value, str):
        return value
    return _strlist(value, where, rule)


def _strmap(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
        raise _bad(rule, where, "is not a map of strings")
    return dict(value)


def _zero(rule: str | None = None) -> _Check:
    """The field may only be unset or zero; it is never forwarded."""

    def check(value: Any, where: str, outer: str) -> Any:
        if value:
            raise _bad(rule or outer, where, "is not allowed")
        return _OMIT

    return check


def _null(rule: str | None = None) -> _Check:
    """The field may only be absent or ``null`` (even ``[]`` changes behaviour)."""

    def check(value: Any, where: str, outer: str) -> Any:
        if value is not None:
            raise _bad(rule or outer, where, "is not allowed")
        return _OMIT

    return check


def _drop(value: Any, where: str, rule: str) -> Any:
    """A known field that is deliberately not forwarded (it is forced or irrelevant)."""
    return _OMIT


def _choice(allowed: frozenset[str], rule: str | None = None) -> _Check:
    def check(value: Any, where: str, outer: str) -> Any:
        if value is None:
            return _OMIT
        if not isinstance(value, str) or value not in allowed:
            raise _bad(rule or outer, where, f"={value!r} is not allowed")
        return value

    return check


def _list_of(item: _Check) -> _Check:
    def check(value: Any, where: str, rule: str) -> Any:
        if value is None:
            return _OMIT
        if not isinstance(value, list):
            raise _bad(rule, where, "is not a list")
        out = [item(v, f"{where}[{i}]", rule) for i, v in enumerate(value)]
        return [v for v in out if v is not _OMIT]

    return check


def _keys(pattern: re.Pattern[str] | Callable[[str], bool], rule: str | None = None) -> _Check:
    """A map whose keys are checked and whose values must be empty objects."""

    def ok(key: str) -> bool:
        return bool(pattern.fullmatch(key)) if isinstance(pattern, re.Pattern) else pattern(key)

    def check(value: Any, where: str, outer: str) -> Any:
        if value is None:
            return _OMIT
        if not isinstance(value, dict):
            raise _bad(rule or outer, where, "is not an object")
        for key, val in value.items():
            if not ok(key) or val not in (None, {}):
                raise _bad(rule or outer, where, f"entry {key!r} is not allowed")
        return {key: {} for key in value}

    return check


def _container_path(path: str) -> bool:
    """A plain absolute container path (Podman parses ``Volumes`` keys like ``-v``)."""
    return (
        path.startswith("/") and ":" not in path and "," not in path and ".." not in path.split("/")
    )


def _group_add(value: Any, where: str, rule: str) -> Any:
    """Supplementary groups; Podman's ``keep-groups`` (the caller's groups) is denied."""
    groups = _strlist(value, where, rule)
    if groups is not _OMIT and any(g.strip().casefold() == "keep-groups" for g in groups):
        raise _bad(rule, where, "keep-groups is not allowed")
    return groups


def _console_size(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not all(
            isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 16 for v in value
        )
    ):
        raise _bad(rule, where, "is not two sizes")
    return value


# --------------------------------------------------------------------------- create checks


def _privileged(rule: str) -> _Check:
    def check(value: Any, where: str, outer: str) -> Any:
        if value:
            raise _Denied(rule, f"{where} is set")
        return _OMIT

    return check


def _cap_add(value: Any, where: str, rule: str) -> Any:
    caps = _strlist(value, where, "create.capabilities")
    if caps is _OMIT:
        return _OMIT
    for cap in caps:
        if cap.strip().upper().removeprefix("CAP_") not in ALLOWED_CAPS:
            raise _Denied("create.capabilities", f"capability {cap!r} is not allowed")
    return caps


def _security_opt(value: Any, where: str, rule: str) -> Any:
    opts = _strlist(value, where, "create.security_opt")
    if opts is _OMIT:
        return _OMIT
    for opt in opts:
        key, _, val = opt.strip().replace("=", ":", 1).partition(":")
        if key != "no-new-privileges" or val not in ("", "true"):
            raise _Denied("create.security_opt", f"security option {opt!r} is not allowed")
    return opts


def _oom_score(value: Any, where: str, rule: str) -> Any:
    value = _int(value, where, rule)
    if value is not _OMIT and value < 0:
        raise _Denied("create.field", f"a negative {where} is not allowed")
    return value


def _swappiness(value: Any, where: str, rule: str) -> Any:
    value = _int(value, where, rule)
    if value is not _OMIT and not -1 <= value <= 100:
        raise _bad(rule, where, "is out of range")
    return value


def _tmpfs(value: Any, where: str, rule: str) -> Any:
    tmpfs = _strmap(value, where, "create.mount")
    if tmpfs is _OMIT:
        return _OMIT
    for path in tmpfs:
        if not _container_path(path):
            raise _Denied("create.mount", f"{where} entry {path!r} is not a container path")
    return tmpfs


_RESTART: Final[_Schema] = {
    "Name": _choice(frozenset({"", "no"}), "create.restart"),
    "MaximumRetryCount": _zero("create.restart"),
}

_ULIMIT: Final[_Schema] = {"Name": _str, "Soft": _int, "Hard": _int}


def _ulimits(value: Any, where: str, rule: str) -> Any:
    items = _list_of(_obj(_ULIMIT, "create.ulimits"))(value, where, "create.ulimits")
    if items is _OMIT:
        return _OMIT
    for item in items:
        name, soft, hard = item.get("Name"), item.get("Soft"), item.get("Hard")
        cap = ULIMIT_CAPS.get(name) if isinstance(name, str) else None
        if cap is None:
            raise _Denied("create.ulimits", f"ulimit {name!r} is not allowed")
        if not (isinstance(soft, int) and isinstance(hard, int) and 0 <= soft <= hard <= cap):
            raise _Denied(
                "create.ulimits", f"ulimit {name} must satisfy 0 <= Soft <= Hard <= {cap}"
            )
    return items


def _empty_log_type(value: Any, where: str, rule: str) -> Any:
    if value not in (None, "") or isinstance(value, bool):
        raise _bad("create.log", where, "must be empty (the daemon's log driver applies)")
    return _OMIT


def _empty_log_options(value: Any, where: str, rule: str) -> Any:
    if value is not None and value != {}:
        raise _bad("create.log", where, "must be empty (the daemon's log driver applies)")
    return _OMIT


_LOG_CONFIG: Final[_Schema] = {"Type": _empty_log_type, "Config": _empty_log_options}


def _log_config(value: Any, where: str, rule: str) -> Any:
    """``LogConfig`` may only be the zero struct (what the Docker CLI sends).

    The daemon's own driver with rotation applies (DEPLOYMENT.md §0.3): ``journald``
    would write agent text into the host journal, ``none`` would erase evidence, and
    driver options could lift rotation. Never forwarded.
    """
    if value is not None and not isinstance(value, dict):
        raise _bad("create.log", where, "is not an object")
    _obj(_LOG_CONFIG, "create.log")(value, where, "create.log")
    return _OMIT


def _period(value: Any, where: str, rule: str) -> Any:
    """A healthcheck period in ns: 0 (the daemon's default) or at least 1 s."""
    value = _uint(value, where, rule)
    if value is not _OMIT and 0 < value < MIN_HEALTHCHECK_NS:
        raise _bad(rule, where, f"={value} ns is below 1 s (use 0 for the default)")
    return value


_HEALTHCHECK: Final[_Schema] = {
    "Test": _strlist,
    "Interval": _period,
    "Timeout": _period,
    "StartPeriod": _uint,
    "StartInterval": _period,
    "Retries": _uint,
}

_VOLUME_OPTIONS: Final[_Schema] = {
    "NoCopy": _bool,
    "Labels": _strmap,
    "DriverConfig": _null("create.mount"),
    # A subpath would let a symlink planted in the volume reach any host path.
    "Subpath": _zero("create.mount"),
}
_TMPFS_OPTIONS: Final[_Schema] = {
    "SizeBytes": _uint,
    "Mode": _uint,
    "Options": _zero("create.mount"),
}
_MOUNT: Final[_Schema] = {
    "Type": _choice(frozenset({"volume", "tmpfs"}), "create.mount"),
    "Source": _str,
    "Target": _str,
    "ReadOnly": _bool,
    "Consistency": _str,
    "BindOptions": _null("create.mount"),
    "VolumeOptions": _obj(_VOLUME_OPTIONS, "create.mount"),
    "TmpfsOptions": _obj(_TMPFS_OPTIONS, "create.mount"),
    "ImageOptions": _zero("create.mount"),
    "ClusterOptions": _zero("create.mount"),
}
#: Options of a ``<scratch volume>:/path[:opts]`` bind (propagation is never accepted).
_BIND_FLAGS: Final = frozenset({"ro", "rw", "nocopy"})

_ENDPOINT: Final[_Schema] = {
    # Every alias must carry the cell prefix (checked against the cell after the rebuild).
    "Aliases": _strlist,
    # Names, addresses and options an agent could use to impersonate cell services or
    # clone an infrastructure container's address: must stay unset.
    **{
        key: _zero("create.network")
        for key in (
            "DNSNames",
            "Links",
            "MacAddress",
            "IPAMConfig",
            "IPAddress",
            "GlobalIPv6Address",
            "DriverOpts",
        )
    },
    # Read-only or advisory fields some clients echo back: accepted, never forwarded.
    **{
        key: _drop
        for key in (
            "NetworkID",
            "EndpointID",
            "Gateway",
            "IPPrefixLen",
            "IPv6Gateway",
            "GlobalIPv6PrefixLen",
            "GwPriority",
        )
    },
}


def _endpoints(value: Any, where: str, rule: str) -> Any:
    if value is None:
        return _OMIT
    if not isinstance(value, dict):
        raise _Denied("create.network", f"{where} is not an object")
    return {
        name: _rebuild(config, _ENDPOINT, f"{where}.{name}.", "create.network")
        for name, config in value.items()
    }


_NETWORKING: Final[_Schema] = {"EndpointsConfig": _endpoints}


def _namespace(allowed: frozenset[str]) -> _Check:
    return _choice(allowed, "create.namespace")


_HOST_CONFIG: Final[_Schema] = {
    # checked by the schema itself
    "Privileged": _privileged("create.privileged"),
    "PidMode": _namespace(frozenset({""})),
    "IpcMode": _namespace(frozenset({"", "private", "none", "shareable"})),
    "UsernsMode": _namespace(frozenset({""})),
    "UTSMode": _namespace(frozenset({""})),
    "CgroupnsMode": _namespace(frozenset({"", "private"})),
    "CapAdd": _cap_add,
    "CapDrop": _strlist,
    "SecurityOpt": _security_opt,
    "OomScoreAdj": _oom_score,
    "Tmpfs": _tmpfs,
    "RestartPolicy": _obj(_RESTART, "create.restart"),
    "Ulimits": _ulimits,
    "LogConfig": _log_config,
    "ConsoleSize": _console_size,
    "MaskedPaths": _null("create.field"),
    "ReadonlyPaths": _null("create.field"),
    # checked against the cell after the rebuild
    "Binds": _strlist,
    "Mounts": _list_of(_obj(_MOUNT, "create.mount")),
    "NetworkMode": _str,
    "Memory": _int,
    "MemorySwap": _int,
    "NanoCpus": _int,
    "PidsLimit": _int,
    "CpuPeriod": _drop,
    "CpuQuota": _drop,
    # harmless values
    "AutoRemove": _bool,
    "ReadonlyRootfs": _bool,
    "Init": _bool,
    "OomKillDisable": _bool,
    # The resolver is forced to the cell's; /etc/hosts entries could shadow cell names.
    "Dns": _zero("create.field"),
    "DnsOptions": _zero("create.field"),
    "DnsSearch": _zero("create.field"),
    "ExtraHosts": _zero("create.field"),
    "GroupAdd": _group_add,
    "ShmSize": _uint,
    "Isolation": _choice(frozenset({"", "default"})),
    "CpuShares": _uint,
    "CpusetCpus": _str,
    "CpusetMems": _str,
    "BlkioWeight": _uint,
    "MemoryReservation": _uint,
    "MemorySwappiness": _swappiness,
    "CpuCount": _uint,
    "CpuPercent": _uint,
    "IOMaximumIOps": _uint,
    "IOMaximumBandwidth": _uint,
    # known fields that must stay unset or zero
    **{
        key: _zero("create.field")
        for key in (
            "ContainerIDFile",
            "PortBindings",
            "PublishAllPorts",
            "VolumeDriver",
            "VolumesFrom",
            "Annotations",
            "Cgroup",
            "Links",
            "StorageOpt",
            "Sysctls",
            "Runtime",
            "CgroupParent",
            "BlkioWeightDevice",
            "BlkioDeviceReadBps",
            "BlkioDeviceWriteBps",
            "BlkioDeviceReadIOps",
            "BlkioDeviceWriteIOps",
            "CpuRealtimePeriod",
            "CpuRealtimeRuntime",
            "Devices",
            "DeviceCgroupRules",
            "DeviceRequests",
            "KernelMemory",
            "KernelMemoryTCP",
        )
    },
}


def _volumes(value: Any, where: str, rule: str) -> Any:
    """Top-level ``Volumes`` would create anonymous volumes without the cell's labels.

    Kept (for the check against ``Binds`` after the rebuild) but never forwarded.
    """
    return _keys(_container_path, "create.mount")(value, where, "create.mount")


def _check_volumes(volumes: Mapping[str, Any], binds: list[str]) -> None:
    """Every ``Volumes`` entry must mirror a ``Binds`` target (the Docker SDK sends
    both); such an entry creates nothing. Any other entry is an anonymous volume."""
    bound = {bind.split(":")[1] for bind in binds}
    for path in volumes:
        if path not in bound:
            raise _Denied(
                "create.mount", f"Volumes entry {path!r} is not allowed (use HostConfig.Mounts)"
            )


_CREATE: Final[_Schema] = {
    "Image": _str,
    "Labels": _strmap,
    "HostConfig": _obj(_HOST_CONFIG),
    "NetworkingConfig": _obj(_NETWORKING, "create.network"),
    # Published as a DNS name on the cell network: checked for the cell prefix.
    "Hostname": _str,
    "Domainname": _zero("create.name"),
    "User": _str,
    "AttachStdin": _bool,
    "AttachStdout": _bool,
    "AttachStderr": _bool,
    "ExposedPorts": _keys(_PORT_RE),
    "Tty": _bool,
    "OpenStdin": _bool,
    "StdinOnce": _bool,
    "Env": _strlist,
    "Cmd": _strslice,
    "Healthcheck": _obj(_HEALTHCHECK),
    "ArgsEscaped": _bool,
    "Volumes": _volumes,
    "WorkingDir": _str,
    "Entrypoint": _strslice,
    "NetworkDisabled": _bool,
    "MacAddress": _zero("create.network"),
    "StopSignal": _str,
    "StopTimeout": _int,
    "Shell": _strlist,
    "OnBuild": _zero(),
}


def _scratch_source_ok(source: str | None, ctx: CellContext) -> bool:
    """A volume source: anonymous, or exactly the cell's scratch volume (never a path)."""
    return not source or (ctx.scratch_volume is not None and source == ctx.scratch_volume)


def _check_binds(binds: list[str], ctx: CellContext) -> None:
    """Only ``<scratch volume>:/path[:opts]``; a host path is never bound (X1)."""
    for bind in binds:
        parts = bind.split(":")
        if len(parts) not in (2, 3) or not parts[0] or not _container_path(parts[1]):
            raise _Denied("create.mount", f"malformed bind {bind!r}")
        if "/" in parts[0] or not _scratch_source_ok(parts[0], ctx):
            raise _Denied("create.mount", f"mount source {parts[0]!r} is not the cell scratch")
        if len(parts) == 3 and not set(parts[2].split(",")) <= _BIND_FLAGS:
            raise _Denied("create.mount", f"bind options {parts[2]!r} are not allowed")


def _check_mounts(mounts: list[dict[str, Any]], ctx: CellContext) -> None:
    """Volume (anonymous or the scratch volume) and tmpfs mounts only.

    Volume mounts get the cell's ownership labels in ``VolumeOptions.Labels``: labelled
    on Docker, which applies them to a volume it creates for the mount (e.g. an
    anonymous one); Podman ignores them, so cleanup also goes by the run's mounts.
    """
    for mount in mounts:
        kind, source, target = mount.get("Type"), mount.get("Source"), mount.get("Target")
        if not isinstance(target, str) or not _container_path(target):
            raise _Denied("create.mount", f"mount target {target!r} is not a container path")
        if kind == "volume":
            if (source and "/" in source) or not _scratch_source_ok(source, ctx):
                raise _Denied("create.mount", f"volume {source!r} is not the cell scratch")
            options = mount.setdefault("VolumeOptions", {})
            options["Labels"] = _labels(options.get("Labels", {}), ctx, "create.mount")
        elif kind == "tmpfs":
            if source:
                raise _Denied("create.mount", "a tmpfs mount takes no source")
            if "VolumeOptions" in mount:
                raise _Denied("create.mount", "VolumeOptions on a tmpfs mount")
        else:
            raise _Denied("create.mount", f"mount type {kind!r} is not allowed")
        if "TmpfsOptions" in mount and kind != "tmpfs":
            raise _Denied("create.mount", f"TmpfsOptions on a {kind} mount")


def _cap(value: Any, limit: int) -> int:
    return value if isinstance(value, int) and 0 < value < limit else limit


def _forced_labels(ctx: CellContext) -> dict[str, str]:
    return {RUN_LABEL: ctx.run_id, ORIGIN_LABEL: ORIGIN}


def _labels(labels: Mapping[str, str], ctx: CellContext, rule: str) -> dict[str, str]:
    """``labels`` plus the forced ownership labels; reserved namespaces are denied."""
    forced = _forced_labels(ctx)
    for key, val in labels.items():
        folded = key.casefold()
        reserved = folded.startswith(_RESERVED_LABEL_PREFIXES) or folded in _RESERVED_LABEL_KEYS
        if reserved and forced.get(key) != val:
            raise _Denied(rule, f"label {key}={val!r} is reserved")
    return {**labels, **forced}


def _scoped_name(name: str, ctx: CellContext, rule: str) -> str:
    if not _NAME_RE.fullmatch(name):
        raise _Denied(rule, f"name {name!r} is malformed")
    return ctx.scoped(name)


def match_image(image: str, images: Sequence[AllowedImage]) -> str | None:
    """The pinned ``image@digest`` to forward for ``image``, or ``None`` if not allowed.

    ``image`` may be an entry's logical name, its repository (any tag, Docker defaults
    applied), or ``repository[:tag]@digest`` with the listed digest of that repository.
    A repository listed with several digests matches only by digest or logical name.
    """
    for entry in images:
        if image == entry.name:
            return entry.pinned
    ref = parse_image_ref(image)
    if ref is None:
        return None
    if ref.digest is not None:
        for entry in images:
            if entry.digest == ref.digest and entry.repo == ref.repo:
                return entry.pinned
        return None
    pinned = {entry.pinned for entry in images if entry.repo == ref.repo}
    return pinned.pop() if len(pinned) == 1 else None


def _force_network(body: dict[str, Any], host: dict[str, Any], ctx: CellContext) -> None:
    mode = host.get("NetworkMode")
    if mode not in (None, "", "default", "bridge", ctx.network):
        raise _Denied("create.network", f"HostConfig.NetworkMode={mode!r} is not allowed")
    host["NetworkMode"] = ctx.network
    endpoints = body.get("NetworkingConfig", {}).get("EndpointsConfig", {})
    endpoint: dict[str, Any] = {}
    for name, config in endpoints.items():
        if name != ctx.network:
            raise _Denied("create.network", f"network {name!r} is not the cell network")
        endpoint = config
    for alias in endpoint.get("Aliases", []):
        _check_dns_name(alias, ctx, "create.network", "alias")
    body["NetworkingConfig"] = {"EndpointsConfig": {ctx.network: endpoint}}


def _check_dns_name(name: str, ctx: CellContext, rule: str, what: str) -> None:
    """A name the container publishes in the cell network's DNS must carry the cell
    prefix, so it can never be a cell service name (``target``, ``tap``, ``catcher``)."""
    if not _NAME_RE.fullmatch(name) or not name.startswith(ctx.prefix):
        raise _Denied(rule, f"{what} {name!r} must start with {ctx.prefix!r}")


def _create_query(r: Route, ctx: CellContext) -> str:
    pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(r.query, keep_blank_values=True):
        if key == "name" and value:
            pairs.append((key, _scoped_name(value, ctx, "create.name")))
        elif key == "platform" or (key == "name" and not value):
            pairs.append((key, value))
        else:
            raise _Denied("create.query", f"query parameter {key!r} is not allowed")
    if len({k for k, _ in pairs}) != len(pairs):
        raise _Denied("create.query", "repeated query parameter")
    return urlencode(pairs)


def _container_create(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    body = _rebuild(_json_object(req.body, "create.body"), _CREATE, "", "create.field")
    image = body.get("Image")
    pinned = match_image(image, ctx.images) if isinstance(image, str) else None
    if pinned is None:
        raise _Denied("image.not_allowed", f"image {image!r} is not in images.lock")
    body["Image"] = pinned
    body["Labels"] = _labels(body.get("Labels", {}), ctx, "create.labels")
    host = body.setdefault("HostConfig", {})
    _check_binds(host.get("Binds", []), ctx)
    _check_volumes(body.pop("Volumes", {}), host.get("Binds", []))
    _check_mounts(host.get("Mounts", []), ctx)
    _force_network(body, host, ctx)
    host["Memory"] = host["MemorySwap"] = _cap(host.get("Memory"), ctx.memory_bytes)
    host["NanoCpus"] = _cap(host.get("NanoCpus"), ctx.nano_cpus)
    host["PidsLimit"] = _cap(host.get("PidsLimit"), ctx.pids_limit)
    host["Dns"] = [ctx.dns]
    if body.get("Hostname"):
        _check_dns_name(body["Hostname"], ctx, "create.name", "hostname")
    else:
        body.pop("Hostname", None)  # the daemon uses the short id
    query = _create_query(r, ctx)
    forced = (
        "Image",
        "Labels",
        "HostConfig.NetworkMode",
        "NetworkingConfig",
        "HostConfig.Memory",
        "HostConfig.MemorySwap",
        "HostConfig.NanoCpus",
        "HostConfig.PidsLimit",
        "HostConfig.Dns",
        "name",
    )
    return _allow(
        r, req, "container.create", path=r.rebuild(r.base, query), body=_encode(body), forced=forced
    )


# --------------------------------------------------------------------------- other handlers

_EXEC_CREATE: Final[_Schema] = {
    "Privileged": _privileged("exec.privileged"),
    "Container": _str,
    "User": _str,
    "Tty": _bool,
    "ConsoleSize": _console_size,
    "AttachStdin": _bool,
    "AttachStdout": _bool,
    "AttachStderr": _bool,
    "Detach": _bool,
    "DetachKeys": _str,
    "Env": _strlist,
    "WorkingDir": _str,
    "Cmd": _strlist,
}
_EXEC_START: Final[_Schema] = {"Detach": _bool, "Tty": _bool, "ConsoleSize": _console_size}
_VOLUME_CREATE: Final[_Schema] = {
    "Name": _str,
    "Driver": _choice(frozenset({"", "local"})),
    "DriverOpts": _zero(),
    "Labels": _strmap,
    "ClusterVolumeSpec": _zero(),
}
#: Operations that take a request body; every other operation must send none.
_BODY_OPS: Final = frozenset({"container.create", "exec.create", "exec.start", "volume.create"})
_UPGRADE_OPS: Final = frozenset({"container.attach", "exec.start"})


def _owned(target: Target | None, kind: str, ctx: CellContext) -> bool:
    """Whether this cell may act on ``target``.

    Containers, execs (via their container) and volumes must carry BOTH
    ``lab.run_id=<run>`` and ``lab.origin=cellguard``: only what this guard created.
    Runner infrastructure (labelled with the run alone) is untouchable. The cell
    network and the scratch volume are recognised by name or id (read-only inspect).
    """
    if target is None or target.kind != kind:
        return False
    if kind == "network":
        return ctx.network in (target.name, target.id)
    if kind == "volume" and ctx.scratch_volume is not None and target.name == ctx.scratch_volume:
        return True
    return all(target.labels.get(k) == v for k, v in _forced_labels(ctx).items())


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
    body = b""
    path = r.with_ref(target.id)
    forced: tuple[str, ...] = ()
    if r.op == "container.remove":
        pairs = parse_qsl(r.query, keep_blank_values=True)
        if any(k == "link" and _truthy(v) for k, v in pairs):
            raise _Denied("remove.link", "removing links is not allowed")
        # v=1 is forced: the container's anonymous (image VOLUME) volumes go with it,
        # so an agent never leaves unlabelled volumes behind (Podman labels none)
        kept = [(k, v) for k, v in pairs if k != "v"]
        query = urlencode([*kept, ("v", "1")])
        path = r.rebuild(path.partition("?")[0].removeprefix(f"/v{r.version}"), query)
        forced = ("v",)
    elif r.op == "exec.create":
        doc = _rebuild(_json_object(req.body, "exec.body"), _EXEC_CREATE, "", "exec.field")
        named = doc.pop("Container", None)
        names = {r.ref, target.id, target.name}
        if r.ref is not None:
            names.add(ctx.scoped(r.ref))
        if named not in (None, "", *names):
            raise _Denied("exec.field", "exec body names another container")
        body = _encode(doc)
    elif r.op == "exec.start":
        doc = _json_object(req.body, "exec.body", empty_ok=True)
        body = _encode(_rebuild(doc, _EXEC_START, "", "exec.field"))
    return Decision(
        allowed=True,
        op=r.op,
        rule=r.op,
        reason=f"{r.target_kind} belongs to this cell",
        path=path,
        body=body,
        forced=forced,
        upgrade=r.op in _UPGRADE_OPS,
    )


def _own_list(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    """A list, restricted to objects carrying this cell's ownership labels."""
    pairs = parse_qsl(r.query, keep_blank_values=True)
    raw = [v for k, v in pairs if k == "filters"]
    if len(raw) > 1:
        raise _Denied("list.filters", "repeated filters parameter")
    filters: dict[str, list[str]] = {}
    if raw and raw[0]:
        try:
            doc = json.loads(raw[0], parse_constant=_no_constants)
        except (ValueError, RecursionError):
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
    # Networks are created by the runner (labelled with the run only); containers and
    # volumes must also carry the origin label, so runner infrastructure is not listed.
    owned = {RUN_LABEL: ctx.run_id} if r.op == "network.list" else _forced_labels(ctx)
    labels = filters.setdefault("label", [])
    for key, value in owned.items():
        if f"{key}={value}" not in labels:
            labels.append(f"{key}={value}")
    query = urlencode(
        [(k, v) for k, v in pairs if k != "filters"]
        + [("filters", json.dumps(filters, separators=(",", ":")))]
    )
    return _allow(r, req, r.op, path=r.rebuild(r.base, query), forced=("filters.label",))


def _volume_create(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    if r.query:
        raise _Denied("volume.query", "volume create takes no query parameters")
    body = _rebuild(_json_object(req.body, "volume.body"), _VOLUME_CREATE, "", "volume.field")
    forced = ["Labels"]
    if body.get("Name"):
        body["Name"] = _scoped_name(body["Name"], ctx, "volume.field")
        forced.append("Name")
    body["Labels"] = _labels(body.get("Labels", {}), ctx, "volume.labels")
    return _allow(r, req, r.op, body=_encode(body), forced=tuple(forced))


def _plain(r: Route, req: DockerRequest, ctx: CellContext) -> Decision:
    return _allow(r, req, r.op)


def _allow(
    r: Route,
    req: DockerRequest,
    rule: str,
    *,
    path: str | None = None,
    body: bytes = b"",
    forced: tuple[str, ...] = (),
) -> Decision:
    return Decision(
        allowed=True,
        op=r.op,
        rule=rule,
        reason="allowed",
        path=req.path if path is None else path,
        body=body,
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
    if r.version is not None:
        major, minor = (int(part) for part in r.version.split("."))
        if (major, minor) < MIN_API_VERSION:
            return deny("api.version", f"API version {r.version} is below 1.40")
    handler = _HANDLERS.get(r.op)
    if handler is None:
        if r.op == UNKNOWN:
            return deny("path.unmatched", f"{request.method} {r.base} is not allowed")
        return deny(r.op, f"{r.op} is not allowed")
    if r.op not in _BODY_OPS and request.body:
        return deny("body.unexpected", f"{r.op} takes no request body")
    try:
        return handler(r, request, ctx)
    except _Denied as denied:
        return deny(denied.rule, denied.reason)
