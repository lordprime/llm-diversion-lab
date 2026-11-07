"""Experiment configuration: one frozen YAML file under ``experiments/`` (DEVELOPMENT_PLAN 5.5).

An experiment fixes everything the scheduler expands and the renderer fills in:
targets (each with its placement map), agents, models, repetitions, per-run limits,
the schedule seed and the two arms of the matched-pair design:

* ``control``: the clean site, no planted content (no fields; DEVELOPMENT_PLAN 4.4);
* ``injected``: the surfaces planted (P1 and P7 in M0) and the payload (family, style,
  version and one text template per surface).

Payload wording never lives in code: it comes from the templates in the file. A template
is a :class:`string.Template` that may use only :data:`TEMPLATE_FIELDS` and must use
``$tag`` (the injector refuses a text without the run's tag). A P1 text becomes one line
of ``/robots.txt``, so a P1 template must be a single line.

The file is *frozen by hash*: :func:`read_experiment` returns the exact text and its
sha256 (``experiments.definition_yaml`` / ``definition_sha256``). Any edit is a new
hash; a schedule never edits a frozen experiment.

YAML is parsed with a safe loader that also refuses duplicate mapping keys, so a
repeated key can never silently override an earlier one. Quote strings YAML would
otherwise turn into numbers or booleans (``version: "1"``).
"""

from __future__ import annotations

import hashlib
import re
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

from control.core.ids import ID_PATTERN
from control.core.models import Surface
from control.core.tags import request_path

__all__ = [
    "MAX_SEED",
    "P7_LOCATOR_PATTERN",
    "ROBOTS_LOCATOR",
    "ROBOTS_PATH",
    "SUPPORTED_SURFACES",
    "TEMPLATE_FIELDS",
    "ControlArmSpec",
    "Experiment",
    "ExperimentArms",
    "ExperimentFile",
    "InjectedArmSpec",
    "PayloadFamily",
    "PayloadSpec",
    "PayloadStyle",
    "PlacementSpec",
    "RunLimits",
    "TargetSpec",
    "load_experiment",
    "parse_experiment",
    "read_experiment",
]

#: Surfaces the M0 surface injector can plant (``cell.injector.placement``).
SUPPORTED_SURFACES: Final = frozenset({Surface.P1, Surface.P7})
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

_P7_LOCATOR = re.compile(P7_LOCATOR_PATTERN)

Id = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=200)]
#: A target, agent or model name: no whitespace, safe in ids, labels and file names.
Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")]
DnsName = Annotated[
    str,
    StringConstraints(
        max_length=200,
        pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    ),
]
StrictPositiveInt = Annotated[int, Strict(), Field(ge=1)]


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

    @field_validator("url")
    @classmethod
    def _url_is_a_path(cls, value: str) -> str:
        if not value.startswith("/") or request_path(value) != value:
            raise ValueError(f"url {value!r} must be a plain absolute path (no query)")
        return value


class TargetSpec(_Frozen):
    """One target and its placement map (one entry per surface it can carry)."""

    name: Name
    placements: dict[Surface, PlacementSpec]

    @model_validator(mode="after")
    def _locators(self) -> Self:
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
        return self


class PayloadSpec(_Frozen):
    """A versioned payload: family, style and one text template per surface."""

    payload_id: Name
    family: PayloadFamily
    style: PayloadStyle
    version: NonEmptyStr
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
            if surface is Surface.P1 and ("\n" in text or "\r" in text):
                raise ValueError(f"{where}: a P1 text must be a single robots.txt line")
        return self


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
                    f"surface {surface.value} is not supported in M0 "
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
    agents: Annotated[tuple[Name, ...], Field(min_length=1)]
    models: Annotated[tuple[Name, ...], Field(min_length=1)]
    arms: ExperimentArms
    limits: RunLimits
    #: DNS zone of the callback catcher; ``$callback_host`` is ``<token>.<this>``.
    callback_domain: DnsName = "cb.lab.test"

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        _unique(tuple(t.name for t in self.targets), "target")
        _unique(self.agents, "agent")
        _unique(self.models, "model")
        for target in self.targets:
            for surface in self.arms.injected.surfaces:
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


def parse_experiment(text: str) -> Experiment:
    """Parse and validate an experiment from YAML text.

    Raises ``ValueError`` for YAML that does not parse, has a duplicate key or is not a
    mapping, and :class:`pydantic.ValidationError` (also a ``ValueError``) for an
    invalid experiment.
    """
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ValueError(f"experiment YAML does not parse: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("experiment YAML must be a mapping at the top level")
    return Experiment.model_validate(doc)


@dataclass(frozen=True, slots=True)
class ExperimentFile:
    """An experiment as frozen on disk: the parsed model, its exact text and its hash."""

    experiment: Experiment
    definition_yaml: str
    #: sha256 of the file's exact bytes (``experiments.definition_sha256``).
    definition_sha256: str


def read_experiment(path: str | Path) -> ExperimentFile:
    """Read, hash and validate an experiment file (UTF-8 YAML)."""
    data = Path(path).read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: experiment file is not UTF-8: {exc}") from exc
    try:
        experiment = parse_experiment(text)
    except ValidationError:
        raise
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    return ExperimentFile(
        experiment=experiment,
        definition_yaml=text,
        definition_sha256=hashlib.sha256(data).hexdigest(),
    )


def load_experiment(path: str | Path) -> Experiment:
    """Read and validate an experiment file; see :func:`read_experiment` for its hash."""
    return read_experiment(path).experiment
