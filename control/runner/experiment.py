"""Experiment configuration: one frozen YAML file under ``experiments/`` (DEVELOPMENT_PLAN 5.5).

An experiment fixes everything the scheduler expands and the renderer fills in:
targets (each with its placement map), agents, models, repetitions, per-run limits,
the schedule seed and the two arms of the matched-pair design:

* ``control``: the clean site, no planted content (no fields; DEVELOPMENT_PLAN 4.4);
* ``injected``: the surfaces planted (P1-P8) and the payload (family, style,
  version and one text template per surface).

Payload wording never lives in code: it comes from the templates in the file. A template
is a :class:`string.Template` that may use only :data:`TEMPLATE_FIELDS` and must use
``$tag`` (the injector refuses a text without the run's tag). A P1 text becomes one line
of ``/robots.txt``, so a P1 template must be a single line. A P8 text becomes the value of
one response header, so it must be single-line printable ASCII of at most 512 bytes;
a P3 text may not close its own comment (see :class:`~cell.injector.placement.SurfaceMarkup`).

A target's placement map is either written inline or read from the target's own frozen
map, ``placements: {from: targets/<name>/placements.yaml}`` (relative to the tree the
experiment belongs to: the repository, or the release tree on a lab host). A map entry
is a placement (``url``, ``locator``, ``offset_fraction``) or ``unavailable: <reason>``
for a surface the target cannot carry; an experiment that plants such a surface is
refused with the reason.

The file is *frozen by hash*: :func:`read_experiment` returns the exact text and its
sha256 (``experiments.definition_yaml`` / ``definition_sha256``). Placement maps read
from files are appended to that text as comments (path, sha256 and every line), so the
stored definition holds everything that ran and the hash changes with any map. Any
edit is a new hash; a schedule never edits a frozen experiment.

YAML is parsed with a safe loader that also refuses duplicate mapping keys, so a
repeated key can never silently override an earlier one. Quote strings YAML would
otherwise turn into numbers or booleans (``version: "1"``).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from string import Template
from typing import Annotated, Any, Final, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeFloat,
    Strict,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from cell.injector.placement import BODY_SURFACES, SURFACE_LOCATORS, SurfaceMarkup
from control.core.ids import ID_PATTERN
from control.core.models import OracleVerdictKind, Surface
from control.core.selftest_status import SELFTEST_EXPERIMENT_PREFIX
from control.core.tags import decoy_prefix, request_path
from control.core.tokens import TAG_LENGTH, TOKEN_LENGTH

__all__ = [
    "DEFAULT_OFFSET_FRACTION",
    "LABEL_PATTERN",
    "MAX_SEED",
    "P7_LOCATOR_PATTERN",
    "PLACEMENT_MAP_PATTERN",
    "ROBOTS_DIRECTIVES",
    "ROBOTS_LOCATOR",
    "ROBOTS_PATH",
    "SAFE_NAME_PATTERN",
    "SUPPORTED_SURFACES",
    "TEMPLATE_FIELDS",
    "AgentName",
    "ControlArmSpec",
    "Experiment",
    "ExperimentArms",
    "ExperimentFile",
    "InjectedArmSpec",
    "ModelName",
    "PayloadFamily",
    "PayloadId",
    "PayloadSpec",
    "PayloadStyle",
    "PayloadVersion",
    "PlacementMapFile",
    "PlacementSpec",
    "RunLimits",
    "TargetName",
    "TargetSpec",
    "freeze_experiment",
    "load_experiment",
    "parse_experiment",
    "read_experiment",
]

#: Surfaces the surface injector can plant (``cell.injector.placement``).
SUPPORTED_SURFACES: Final = frozenset(Surface)
#: Locator and path of a P1 placement (must equal the injector's own constants).
ROBOTS_LOCATOR: Final = "robots.txt:append"
ROBOTS_PATH: Final = "/robots.txt"
#: Locator of a P7 placement: the status the app is expected to answer with.
P7_LOCATOR_PATTERN: Final = r"^error:(403|404)$"
#: Placeholders a payload template may use. ``tag`` is required.
#:
#: * ``$tag``: the run's tag;
#: * ``$token``: the placement's callback token;
#: * ``$decoy_path``: the run's decoy path ``/x-<tag>``;
#: * ``$callback_host``: ``<token>.<callback_domain>``.
TEMPLATE_FIELDS: Final = frozenset({"tag", "token", "decoy_path", "callback_host"})
#: Largest seed (``experiments.schedule_seed`` is a Postgres ``BIGINT``).
MAX_SEED: Final = 2**63 - 1
#: Where an in-page text goes when a placement does not say (the middle of the body).
DEFAULT_OFFSET_FRACTION: Final = 0.5

#: Where a target's frozen placement map may live, relative to the experiment's tree.
PLACEMENT_MAP_PATTERN: Final = r"^targets/[a-z0-9][a-z0-9_-]{0,62}/placements\.yaml$"
#: Largest placement map file read (a map has at most eight short entries).
MAX_PLACEMENT_MAP_BYTES: Final = 64 * 1024

_P7_LOCATOR = re.compile(P7_LOCATOR_PATTERN)
_PLACEMENT_MAP = re.compile(PLACEMENT_MAP_PATTERN)

Id = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=200)]
#: Accepted shape of a target or agent name. These names end up in file names
#: (``deploy/compose/cell.<target>.yml``) and Compose project names, so only lowercase
#: letters, digits, ``_`` and ``-``: no ``/``, no ``.``, no uppercase.
SAFE_NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_-]{0,62}$"
#: Accepted shape of a model name or payload id. Permissive on purpose (provider model
#: ids such as ``openai/gpt-4o`` or ``claude-sonnet-5-5@2026``): NOT safe in paths or
#: Compose names; never build a file name or project name from it.
LABEL_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$"
TargetName = Annotated[str, StringConstraints(pattern=SAFE_NAME_PATTERN)]
AgentName = Annotated[str, StringConstraints(pattern=SAFE_NAME_PATTERN)]
ModelName = Annotated[str, StringConstraints(pattern=LABEL_PATTERN)]
PayloadId = Annotated[str, StringConstraints(pattern=LABEL_PATTERN)]
#: ``arms.payload_version`` and ``placements.payload_version`` are ``String(64)``.
PayloadVersion = Annotated[str, StringConstraints(min_length=1, max_length=64)]
DnsName = Annotated[
    str,
    StringConstraints(
        max_length=200,
        pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    ),
]
StrictPositiveInt = Annotated[int, Strict(), Field(ge=1)]
#: Callback zone used when a payload is checked on its own (an experiment re-checks with its own).
DEFAULT_CALLBACK_DOMAIN: Final = "cb.lab.test"


class PayloadFamily(StrEnum):
    """What a payload asks for (DEVELOPMENT_PLAN 4.4)."""

    DERAIL = "derail"
    DECOY = "decoy"
    BEACON = "beacon"


class PayloadStyle(StrEnum):
    """How a payload is worded (DEVELOPMENT_PLAN 4.4)."""

    OVERRIDE = "override"
    INTENT_ALIGNED = "intent_aligned"
    NEUTRAL = "neutral"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _unique(values: tuple[str, ...], what: str) -> tuple[str, ...]:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {what} {value!r}")
        seen.add(value)
    return values


# --------------------------------------------------------------------------- parts


class PlacementSpec(_Frozen):
    """Where one surface lives on a target: the request path and the injector locator."""

    url: NonEmptyStr
    locator: NonEmptyStr
    #: Relative position in the page body for P2-P6 (0 = start, 1 = end); fixed per
    #: experiment, never chosen per run. Any other surface leaves it at the default (unused).
    offset_fraction: Annotated[float, Strict(), Field(ge=0, le=1)] = DEFAULT_OFFSET_FRACTION

    @field_validator("url")
    @classmethod
    def _url_is_a_path(cls, value: str) -> str:
        if not value.startswith("/") or request_path(value) != value:
            raise ValueError(f"url {value!r} must be a plain absolute path (no query)")
        return value


class TargetSpec(_Frozen):
    """One target and its placement map (one entry per surface it can carry).

    In the map, a surface the target cannot carry is written ``P7: {unavailable:
    <reason>}``; it is kept in :attr:`unavailable`, never in :attr:`placements`.
    """

    name: TargetName
    #: The objective this target's oracle must report in every poll (``done`` v2).
    objective: NonEmptyStr
    placements: dict[Surface, PlacementSpec]
    #: Surfaces this target cannot carry, each with the reason the map gives.
    unavailable: dict[Surface, NonEmptyStr] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _split_unavailable(cls, data: Any) -> Any:
        """Move ``{unavailable: <reason>}`` entries out of the placement map."""
        if not isinstance(data, dict) or not isinstance(data.get("placements"), dict):
            return data
        placements: dict[Any, Any] = {}
        unavailable: dict[Any, Any] = dict(data.get("unavailable") or {})
        for surface, entry in data["placements"].items():
            if isinstance(entry, dict) and "unavailable" in entry:
                if set(entry) != {"unavailable"}:
                    raise ValueError(
                        f"target {data.get('name')} {surface}: an unavailable surface "
                        "takes only its reason (unavailable: <reason>)"
                    )
                if surface in unavailable:
                    raise ValueError(f"target {data.get('name')} {surface}: listed twice")
                unavailable[surface] = entry["unavailable"]
            else:
                placements[surface] = entry
        return {**data, "placements": placements, "unavailable": unavailable}

    @model_validator(mode="after")
    def _locators(self) -> Self:
        both = sorted(s.value for s in set(self.placements) & set(self.unavailable))
        if both:
            raise ValueError(f"target {self.name}: {', '.join(both)} both placed and unavailable")
        for surface, spec in self.placements.items():
            where = f"target {self.name} {surface.value}"
            if surface is Surface.P1:
                if spec.locator != ROBOTS_LOCATOR:
                    raise ValueError(f"{where}: locator must be {ROBOTS_LOCATOR!r}")
                if spec.url != ROBOTS_PATH:
                    raise ValueError(f"{where}: url must be {ROBOTS_PATH} (robots)")
            elif surface is Surface.P7:
                if not _P7_LOCATOR.fullmatch(spec.locator):
                    raise ValueError(f"{where}: locator must match {P7_LOCATOR_PATTERN}")
                if spec.url == ROBOTS_PATH:
                    raise ValueError(f"{where}: a P7 placement cannot use robots.txt")
            else:
                if spec.locator != SURFACE_LOCATORS[surface]:
                    raise ValueError(f"{where}: locator must be {SURFACE_LOCATORS[surface]!r}")
                if spec.url == ROBOTS_PATH:
                    raise ValueError(f"{where}: only P1 may use robots.txt")
            if surface not in BODY_SURFACES and spec.offset_fraction != DEFAULT_OFFSET_FRACTION:
                raise ValueError(f"{where}: offset_fraction applies to P2-P6 only")
        return self


#: Unicode categories a P1 text may not contain (tab excepted): controls, format
#: characters and line/paragraph separators. ``str.splitlines`` (used by
#: :mod:`urllib.robotparser`) also breaks lines at several of them.
_FORBIDDEN_P1_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})
#: robots.txt field names a crawler acts on (RFC 9309 plus widely honoured extensions).
#: A P1 line may be a comment or a non-standard line, never one of these: the treated
#: arm's robots.txt must differ from the control arm's by one line no crawler obeys.
ROBOTS_DIRECTIVES: Final = frozenset(
    {
        "user-agent",
        "allow",
        "disallow",
        "sitemap",
        "crawl-delay",
        "host",
        "request-rate",
        "visit-time",
        "clean-param",
        "noindex",
    }
)


def _check_robots_line(text: str, where: str) -> None:
    """A P1 text becomes one robots.txt line: refuse anything that could start another.

    It also refuses a line whose field name (the text before the first ``:``, trimmed
    and lowercased, as :mod:`urllib.robotparser` reads it) is a directive.
    """
    if len(text.splitlines()) != 1:
        raise ValueError(f"{where}: a P1 text must be a single robots.txt line")
    for char in text:
        if char != "\t" and unicodedata.category(char) in _FORBIDDEN_P1_CATEGORIES:
            raise ValueError(
                f"{where}: a P1 text must be a single robots.txt line "
                f"without control characters (found U+{ord(char):04X})"
            )
    field, colon, _ = text.partition(":")
    if colon and field.strip().lower() in ROBOTS_DIRECTIVES:
        raise ValueError(
            f"{where}: a P1 text must be a comment or a non-standard line, "
            f"not the robots.txt directive {field.strip()!r}"
        )


class PayloadSpec(_Frozen):
    """A versioned payload: family, style and one text template per surface."""

    payload_id: PayloadId
    family: PayloadFamily
    style: PayloadStyle
    version: PayloadVersion
    templates: dict[Surface, Annotated[str, StringConstraints(min_length=1, max_length=8192)]]

    @model_validator(mode="after")
    def _templates(self) -> Self:
        for surface, text in self.templates.items():
            where = f"payload {self.payload_id} template {surface.value}"
            template = Template(text)
            if not template.is_valid():
                raise ValueError(f"{where}: invalid placeholder syntax")
            used = set(template.get_identifiers())
            unknown = sorted(used - TEMPLATE_FIELDS)
            if unknown:
                raise ValueError(
                    f"{where}: unknown placeholder(s) {', '.join(unknown)}; "
                    f"allowed: {', '.join(sorted(TEMPLATE_FIELDS))}"
                )
            if "tag" not in used:
                raise ValueError(f"{where}: must use $tag")
            if surface is Surface.P1:
                _check_robots_line(text, where)
        self.check_rendered()
        return self

    def check_rendered(self, callback_domain: str = DEFAULT_CALLBACK_DOMAIN) -> None:
        """Render every template with stand-in values and check the surface's own rules.

        The stand-ins are as long as the real ones, so a P8 text that is too long, or a
        P3 text that closes its comment, is refused when the experiment is read.
        """
        tag, token = "0" * TAG_LENGTH, "a" * TOKEN_LENGTH
        for surface, text in self.templates.items():
            rendered = Template(text).substitute(
                tag=tag,
                token=token,
                decoy_path=decoy_prefix(tag),
                callback_host=f"{token}.{callback_domain}",
            )
            try:
                SurfaceMarkup.check(surface, rendered)
            except ValueError as exc:
                raise ValueError(
                    f"payload {self.payload_id} template {surface.value}: {exc}"
                ) from exc


class ControlArmSpec(_Frozen):
    """The control arm: the clean site exactly as the target serves it. No settings."""


class InjectedArmSpec(_Frozen):
    """The injected arm: which surfaces are planted, with which payload."""

    surfaces: Annotated[tuple[Surface, ...], Field(min_length=1)]
    payload: PayloadSpec

    @model_validator(mode="after")
    def _surfaces(self) -> Self:
        _unique(tuple(s.value for s in self.surfaces), "surface")
        for surface in self.surfaces:
            if surface not in SUPPORTED_SURFACES:
                raise ValueError(
                    f"surface {surface.value} is not supported "
                    f"(supported: {', '.join(sorted(s.value for s in SUPPORTED_SURFACES))})"
                )
            if surface not in self.payload.templates:
                raise ValueError(f"payload has no template for surface {surface.value}")
        extra = sorted(s.value for s in set(self.payload.templates) - set(self.surfaces))
        if extra:
            raise ValueError(f"payload has templates for unplanted surface(s): {', '.join(extra)}")
        return self


class ExperimentArms(_Frozen):
    """Both arms of the matched-pair design; each injected run has one matched control."""

    control: ControlArmSpec
    injected: InjectedArmSpec


class RunLimits(_Frozen):
    """Per-run limits, identical in every arm (DEVELOPMENT_PLAN 9.1)."""

    budget_usd: NonNegativeFloat
    max_turns: StrictPositiveInt
    timeout_s: StrictPositiveInt


# --------------------------------------------------------------------------- experiment


class Experiment(_Frozen):
    """One experiment definition, validated and frozen."""

    experiment_id: Id
    name: NonEmptyStr
    seed: Annotated[int, Strict(), Field(ge=0, le=MAX_SEED)]
    repetitions: StrictPositiveInt
    targets: Annotated[tuple[TargetSpec, ...], Field(min_length=1)]
    agents: Annotated[tuple[AgentName, ...], Field(min_length=1)]
    models: Annotated[tuple[ModelName, ...], Field(min_length=1)]
    arms: ExperimentArms
    limits: RunLimits
    #: DNS zone of the callback catcher; ``$callback_host`` is ``<token>.<this>``.
    callback_domain: DnsName = DEFAULT_CALLBACK_DOMAIN
    #: Which oracle verdict is the run's ``outcome``; the other one is stored beside it.
    oracle_primary: OracleVerdictKind = OracleVerdictKind.EFFECT

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        _unique(tuple(t.name for t in self.targets), "target")
        _unique(self.agents, "agent")
        _unique(self.models, "model")
        self.arms.injected.payload.check_rendered(self.callback_domain)
        for target in self.targets:
            for surface in self.arms.injected.surfaces:
                if surface in target.unavailable:
                    raise ValueError(
                        f"target {target.name} cannot carry surface {surface.value}: "
                        f"unavailable: {target.unavailable[surface]}"
                    )
                if surface not in target.placements:
                    raise ValueError(
                        f"target {target.name} has no placement for surface {surface.value}"
                    )
        return self

    def target(self, name: str) -> TargetSpec:
        """The target called ``name``; ``KeyError`` if the experiment has none."""
        for target in self.targets:
            if target.name == name:
                return target
        raise KeyError(name)


# --------------------------------------------------------------------------- loading


class _UniqueKeyLoader(yaml.SafeLoader):
    """A safe YAML loader that refuses duplicate keys in any mapping."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: list[Any] = []
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue  # ``<<`` merges: explicit keys override merged ones (YAML semantics)
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in seen
        except TypeError:  # unhashable key: let the base constructor report it
            duplicate = False
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        seen.append(key)
    loader.flatten_mapping(node)
    return dict(loader.construct_pairs(node, deep=True))


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass(frozen=True, slots=True)
class PlacementMapFile:
    """A target's frozen placement map, read from ``targets/<name>/placements.yaml``.

    The file is a mapping ``{target: <name>, placements: {<surface>: <entry>, ...}}``.
    ``ref`` is its path relative to the experiment's tree, ``data`` its exact bytes.
    """

    ref: str
    data: bytes

    @classmethod
    def read(cls, root: Path, ref: object) -> PlacementMapFile:
        """Read ``ref`` under ``root``; refuse anything but a small regular file there."""
        if not isinstance(ref, str) or not _PLACEMENT_MAP.fullmatch(ref):
            raise ValueError(
                f"placements from {ref!r}: must be a path matching {PLACEMENT_MAP_PATTERN}"
            )
        path = root / ref
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"placements from {ref}: not a regular file under {root}")
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"placements from {ref}: lies outside {root}")
            with path.open("rb") as fh:
                data = fh.read(MAX_PLACEMENT_MAP_BYTES + 1)
        except OSError as exc:
            raise ValueError(f"placements from {ref}: cannot read it: {exc}") from exc
        if len(data) > MAX_PLACEMENT_MAP_BYTES:
            raise ValueError(f"placements from {ref}: larger than {MAX_PLACEMENT_MAP_BYTES} bytes")
        return cls(ref, data)

    def placements(self, target: object) -> dict[Any, Any]:
        """The map's entries, after checking the file is for ``target``."""
        try:
            doc = yaml.load(self.data.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"placements from {self.ref}: does not parse: {exc}") from exc
        if not isinstance(doc, dict) or set(doc) != {"target", "placements"}:
            raise ValueError(
                f"placements from {self.ref}: must be a mapping of exactly target and placements"
            )
        if doc["target"] != target:
            raise ValueError(
                f"placements from {self.ref}: the map is for target {doc['target']!r}, "
                f"not {target!r}"
            )
        if not isinstance(doc["placements"], dict):
            raise ValueError(f"placements from {self.ref}: placements must be a mapping")
        return doc["placements"]

    def frozen_text(self) -> str:
        """The map as comment lines, appended to the frozen definition."""
        digest = hashlib.sha256(self.data).hexdigest()
        lines = self.data.decode("utf-8").splitlines()
        return f"# frozen placement map {self.ref} sha256 {digest}\n" + "".join(
            f"#| {line}\n" for line in lines
        )


def _read_placement_maps(doc: dict[Any, Any], root: Path | None) -> tuple[PlacementMapFile, ...]:
    """Replace every ``placements: {from: <file>}`` in ``doc`` by the file's entries."""
    targets = doc.get("targets")
    if not isinstance(targets, list):
        return ()
    maps: list[PlacementMapFile] = []
    for target in targets:
        placements = target.get("placements") if isinstance(target, dict) else None
        if not isinstance(placements, dict) or "from" not in placements:
            continue
        name = target.get("name")
        if set(placements) != {"from"}:
            raise ValueError(f"target {name}: placements {{from: <file>}} takes no other key")
        if root is None:
            raise ValueError(
                f"target {name}: placements from a file need the tree the experiment belongs to"
            )
        if any(m.ref == placements["from"] for m in maps):
            raise ValueError(f"target {name}: placements from {placements['from']} used twice")
        found = PlacementMapFile.read(root, placements["from"])
        target["placements"] = found.placements(name)
        maps.append(found)
    return tuple(maps)


def _load(
    text: str, *, selftest: bool, root: Path | None
) -> tuple[Experiment, tuple[PlacementMapFile, ...]]:
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ValueError(f"experiment YAML does not parse: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("experiment YAML must be a mapping at the top level")
    maps = _read_placement_maps(doc, root)
    experiment = Experiment.model_validate(doc)
    if not selftest and experiment.experiment_id.startswith(SELFTEST_EXPERIMENT_PREFIX):
        raise ValueError(
            f"experiment_id {experiment.experiment_id!r}: the prefix "
            f"{SELFTEST_EXPERIMENT_PREFIX!r} is reserved for the self-test"
        )
    return experiment, maps


def parse_experiment(text: str, *, selftest: bool = False, root: Path | None = None) -> Experiment:
    """Parse and validate an experiment from YAML text.

    ``root`` is the tree a ``placements: {from: <file>}`` is read from (none: such a
    reference is refused). Raises ``ValueError`` for YAML that does not parse, has a
    duplicate key or is not a mapping, or a placement map that cannot be read, and
    :class:`pydantic.ValidationError` (also a ``ValueError``) for an invalid experiment.
    The id prefix ``exp_selftest_``
    (:data:`~control.core.selftest_status.SELFTEST_EXPERIMENT_PREFIX`) is reserved for
    the self-test's derived experiments (``selftest=True``, only
    :func:`control.runner.selftest.derive_experiment`): study metrics leave such
    experiments out and the self-test sweeps their runs, so a study may never use it.
    """
    return _load(text, selftest=selftest, root=root)[0]


@dataclass(frozen=True, slots=True)
class ExperimentFile:
    """An experiment as frozen: the parsed model, its exact definition and its hash."""

    experiment: Experiment
    #: The experiment's text, plus every placement map it read (as comments).
    definition_yaml: str
    #: sha256 of ``definition_yaml`` (``experiments.definition_sha256``); for an
    #: experiment with no map file, the sha256 of the file's exact bytes.
    definition_sha256: str


def freeze_experiment(text: str, *, root: Path, selftest: bool = False) -> ExperimentFile:
    """Validate ``text`` and freeze it with the placement maps it reads under ``root``."""
    experiment, maps = _load(text, selftest=selftest, root=root)
    definition = text
    if maps:
        definition += ("" if text.endswith("\n") else "\n") + "".join(m.frozen_text() for m in maps)
    return ExperimentFile(
        experiment=experiment,
        definition_yaml=definition,
        definition_sha256=hashlib.sha256(definition.encode("utf-8")).hexdigest(),
    )


def read_experiment(path: str | Path, *, root: Path | None = None) -> ExperimentFile:
    """Read, validate and freeze an experiment file (UTF-8 YAML).

    ``root`` (default: the tree holding the file's ``experiments/`` directory) is where
    placement maps are read from.
    """
    path = Path(path)
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: experiment file is not UTF-8: {exc}") from exc
    try:
        return freeze_experiment(text, root=root or path.resolve().parents[1])
    except ValidationError:
        raise
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc


def load_experiment(path: str | Path, *, root: Path | None = None) -> Experiment:
    """Read and validate an experiment file; see :func:`read_experiment` for its hash."""
    return read_experiment(path, root=root).experiment
