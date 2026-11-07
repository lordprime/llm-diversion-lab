"""The matched-pair scheduler: expand an experiment into an ordered list of runs.

For every *cell* ``(target, agent, model, rep)`` the schedule holds exactly one
injected run and one matched control run. The two share a ``pair_id`` and are
adjacent in the order, so they run interleaved, from fresh cells, in the same time
window (DEVELOPMENT_PLAN 9.4).

Order versus identity
---------------------
Planning the order and assigning identities are separate steps:

* :func:`plan_order` is pure: the order is a deterministic function of the
  experiment's ``seed`` and its cells only. Each pair's position is given by
  ``sha256(canonical JSON of [seed, "pair", target, agent, model, rep])`` (sorted
  ascending), and which arm of the pair goes first by the low bit of
  ``sha256([seed, "first", target, agent, model, rep])``. Treating sha256 as a random
  oracle this is a uniformly random permutation and a fair coin per pair, and unlike
  :mod:`random` it can never change across Python versions.
* :func:`build_schedule` takes that order and gives every run a fresh ``run_id``
  (``run_<ULID>``), every pair a fresh ``pair_id`` and every injected run a fresh tag.
  Ids are issued in schedule order from :func:`control.core.ids.new_id`, which is
  monotonic, so sorting runs by ``run_id`` gives the schedule order. Scheduling the
  same experiment twice gives the same order with new ids and tags: the runs of two
  schedules are never confused, and a resumed queue keeps the runs it already has.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated, NamedTuple, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    NonNegativeInt,
    StringConstraints,
    model_validator,
)

from control.core.ids import ID_PATTERN, new_id
from control.core.models import Arm
from control.core.tokens import TAG_PATTERN, new_tag
from control.runner.experiment import Experiment

__all__ = [
    "PairKey",
    "PlannedRun",
    "ScheduledRun",
    "build_schedule",
    "plan_order",
]

Id = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
Tag = Annotated[str, StringConstraints(pattern=TAG_PATTERN)]


class PairKey(NamedTuple):
    """The cell and repetition one matched pair belongs to."""

    target: str
    agent: str
    model: str
    rep: int


@dataclass(frozen=True, slots=True)
class PlannedRun:
    """One position of the planned order: a pair's cell and the arm run there."""

    key: PairKey
    arm: Arm


class ScheduledRun(BaseModel):
    """One run of a schedule: its identity, arm, cell, position and (injected) tag.

    ``rep`` counts from 0. A control run has no tag; an injected run has one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Id
    experiment_id: Id
    pair_id: Id
    arm: Arm
    target: str
    agent: str
    model: str
    rep: NonNegativeInt
    schedule_index: NonNegativeInt
    tag: Tag | None

    @model_validator(mode="after")
    def _tag_matches_arm(self) -> Self:
        if self.arm is Arm.CONTROL and self.tag is not None:
            raise ValueError("a control run must have no tag")
        if self.arm is Arm.INJECTED and self.tag is None:
            raise ValueError("an injected run requires a tag")
        return self

    @property
    def key(self) -> PairKey:
        return PairKey(self.target, self.agent, self.model, self.rep)


def _cells(experiment: Experiment) -> Iterator[PairKey]:
    for target in experiment.targets:
        for agent in experiment.agents:
            for model in experiment.models:
                for rep in range(experiment.repetitions):
                    yield PairKey(target.name, agent, model, rep)


def _digest(seed: int, purpose: str, key: PairKey) -> bytes:
    doc = [seed, purpose, key.target, key.agent, key.model, key.rep]
    return hashlib.sha256(json.dumps(doc, separators=(",", ":")).encode("utf-8")).digest()


def plan_order(experiment: Experiment) -> list[PlannedRun]:
    """The run order of ``experiment``: two adjacent entries per pair, seeded.

    Pure and deterministic: the same seed and cells always give the same order.
    """
    seed = experiment.seed
    cells = sorted(_cells(experiment), key=lambda k: (_digest(seed, "pair", k), k))
    order: list[PlannedRun] = []
    for key in cells:
        injected_first = _digest(seed, "first", key)[-1] & 1 == 1
        arms = (Arm.INJECTED, Arm.CONTROL) if injected_first else (Arm.CONTROL, Arm.INJECTED)
        order.extend(PlannedRun(key, arm) for arm in arms)
    return order


def build_schedule(experiment: Experiment) -> list[ScheduledRun]:
    """Expand ``experiment`` into its runs, in :func:`plan_order`, with fresh ids and tags."""
    runs: list[ScheduledRun] = []
    pair_ids: dict[PairKey, str] = {}
    tags: set[str] = set()
    for index, planned in enumerate(plan_order(experiment)):
        pair_id = pair_ids.get(planned.key)
        if pair_id is None:
            pair_id = pair_ids[planned.key] = new_id("pair")
        tag: str | None = None
        if planned.arm is Arm.INJECTED:
            tag = new_tag()
            while tag in tags:  # 64 random bits: practically never repeats
                tag = new_tag()
            tags.add(tag)
        runs.append(
            ScheduledRun(
                run_id=new_id("run"),
                experiment_id=experiment.experiment_id,
                pair_id=pair_id,
                arm=planned.arm,
                target=planned.key.target,
                agent=planned.key.agent,
                model=planned.key.model,
                rep=planned.key.rep,
                schedule_index=index,
                tag=tag,
            )
        )
    return runs
