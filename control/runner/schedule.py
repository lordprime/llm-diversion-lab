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

Attempts
--------
An invalid run is re-queued with the identical configuration (DEVELOPMENT_PLAN 5.4).
:func:`retry` gives the next attempt of a run the same pair, arm, cell and
``schedule_index``, ``attempt + 1``, a new ``run_id`` and, for an injected run, a new
tag, so every attempt's evidence is told apart in leak checks. Every attempt is kept:
a schedule is the list of all of them.

:func:`check_schedule` re-checks a schedule (for example one reloaded from the
database) before it is run or labelled.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Hashable, Iterator, Sequence
from dataclasses import dataclass
from typing import Annotated, NamedTuple, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    NonNegativeInt,
    PositiveInt,
    StringConstraints,
    model_validator,
)

from control.core.ids import ID_PATTERN, new_id
from control.core.models import Arm
from control.core.tokens import TAG_PATTERN, new_tag
from control.runner.experiment import AgentName, Experiment, ModelName, TargetName

__all__ = [
    "PairKey",
    "PlannedRun",
    "ScheduleError",
    "ScheduledRun",
    "build_schedule",
    "check_schedule",
    "plan_order",
    "retry",
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
    """One run of a schedule: its identity, arm, cell, position, attempt and tag.

    ``rep`` counts from 0, ``attempt`` from 1. A control run has no tag; an injected
    run has one. All attempts of a run share its ``pair_id``, arm, cell and
    ``schedule_index`` (see :func:`retry`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Id
    experiment_id: Id
    pair_id: Id
    arm: Arm
    target: TargetName
    agent: AgentName
    model: ModelName
    rep: NonNegativeInt
    schedule_index: NonNegativeInt
    attempt: PositiveInt = 1
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


def retry(run: ScheduledRun) -> ScheduledRun:
    """The next attempt of ``run``: same pair, arm, cell and position, ``attempt + 1``.

    It gets a new ``run_id`` and, for an injected run, a new tag. Add it to the
    schedule beside the earlier attempts; never replace them.
    """
    return run.model_copy(
        update={
            "run_id": new_id("run"),
            "attempt": run.attempt + 1,
            "tag": new_tag() if run.arm is Arm.INJECTED else None,
        }
    )


class ScheduleError(ValueError):
    """A schedule breaks the matched-pair design."""


def _unique_by(
    runs: Sequence[ScheduledRun], key: Callable[[ScheduledRun], Hashable], what: str
) -> None:
    seen: set[Hashable] = set()
    for run in runs:
        value = key(run)
        if value in seen:
            raise ScheduleError(f"duplicate {what} {value!r}")
        seen.add(value)


def _check_cells(runs: Sequence[ScheduledRun], experiment: Experiment) -> None:
    """Every run belongs to ``experiment`` and each of its cells holds exactly one pair."""
    wrong = sorted({r.experiment_id for r in runs} - {experiment.experiment_id})
    if wrong:
        raise ScheduleError(
            f"runs of experiment(s) {', '.join(wrong)}, not {experiment.experiment_id}"
        )
    cells = set(_cells(experiment))
    pairs_per_cell: dict[PairKey, set[str]] = defaultdict(set)
    for run in runs:
        if run.key not in cells:
            raise ScheduleError(f"run {run.run_id}: cell {tuple(run.key)} is not in the experiment")
        pairs_per_cell[run.key].add(run.pair_id)
    for key, pair_ids in pairs_per_cell.items():
        if len(pair_ids) > 1:
            raise ScheduleError(f"cell {tuple(key)} has more than one pair: {sorted(pair_ids)}")
    missing = sorted(cells - set(pairs_per_cell))
    if missing:
        shown = ", ".join(str(tuple(k)) for k in missing[:5])
        raise ScheduleError(f"{len(missing)} cell(s) of the experiment are missing: {shown}")


def check_schedule(runs: Sequence[ScheduledRun], *, experiment: Experiment | None = None) -> None:
    """Raise :class:`ScheduleError` unless ``runs`` is a well-formed matched-pair schedule.

    With ``experiment``, the schedule must also be *complete* for it: every run belongs
    to it, every run's cell ``(target, agent, model, rep)`` is one of its cells, and
    each cell holds exactly one pair (so a truncated schedule, or one with two pairs in
    a cell, is refused). Without it only the structure below is checked.

    Checked over all attempts:

    * ``run_id`` values and tags are unique; a control run has no tag and an injected
      run has one; all runs belong to one experiment;
    * ``(schedule_index, attempt)`` and ``(pair_id, arm, attempt)`` are unique (the
      database's own uniqueness rules);
    * each pair has both arms and all its runs share one cell; each arm's attempts are
      numbered ``1..n`` and share one ``schedule_index``, so the latest attempt of
      each arm is exactly one run;
    * pairs are adjacent: in ``schedule_index`` order pair *k* holds exactly the
      positions ``2k`` and ``2k + 1``, so positions run ``0..2*pairs - 1`` without gaps.
    """
    if experiment is not None:
        _check_cells(runs, experiment)
    if not runs:
        return
    experiments = {r.experiment_id for r in runs}
    if len(experiments) != 1:
        raise ScheduleError(f"runs of several experiments: {', '.join(sorted(experiments))}")
    _unique_by(runs, lambda r: r.run_id, "run_id")
    _unique_by(runs, lambda r: (r.schedule_index, r.attempt), "(schedule_index, attempt)")
    _unique_by(runs, lambda r: (r.pair_id, r.arm.value, r.attempt), "(pair_id, arm, attempt)")
    tags: set[str] = set()
    for run in runs:
        if run.arm is Arm.CONTROL and run.tag is not None:
            raise ScheduleError(f"control run {run.run_id} carries a tag")
        if run.arm is Arm.INJECTED and run.tag is None:
            raise ScheduleError(f"injected run {run.run_id} has no tag")
        if run.tag is not None:
            if run.tag in tags:
                raise ScheduleError(f"run {run.run_id} reuses another run's tag")
            tags.add(run.tag)

    pairs: dict[str, list[ScheduledRun]] = defaultdict(list)
    for run in runs:
        pairs[run.pair_id].append(run)
    lows: list[int] = []
    for pair_id, members in pairs.items():
        if len({m.key for m in members}) != 1:
            raise ScheduleError(f"pair {pair_id} mixes cells")
        positions: list[int] = []
        for arm in (Arm.CONTROL, Arm.INJECTED):
            attempts = sorted(m.attempt for m in members if m.arm is arm)
            if not attempts:
                raise ScheduleError(f"pair {pair_id} has no {arm.value} run")
            if attempts != list(range(1, len(attempts) + 1)):
                raise ScheduleError(f"pair {pair_id} {arm.value} attempts are not 1..n: {attempts}")
            indexes = {m.schedule_index for m in members if m.arm is arm}
            if len(indexes) != 1:
                raise ScheduleError(f"pair {pair_id} {arm.value} attempts change position")
            positions.append(indexes.pop())
        low, high = sorted(positions)
        if high != low + 1:
            raise ScheduleError(f"pair {pair_id} is not adjacent (positions {low}, {high})")
        lows.append(low)
    if sorted(lows) != list(range(0, 2 * len(lows), 2)):
        raise ScheduleError("pairs are not adjacent: positions are not 0..2*pairs-1 two by two")
