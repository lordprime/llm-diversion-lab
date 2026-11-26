"""The block scheduler: expand an experiment into an ordered list of runs.

For every *cell* ``(target, agent, model, rep)`` the schedule holds one *block* of
three runs, one per arm: control, neutral and instruction (register items T1 and S1).
The three share a ``block_id`` and sit next to each other in the order, so they run
interleaved, from fresh cells, in the same time window (DEVELOPMENT_PLAN 9.4).

Order versus identity
---------------------
Planning the order and assigning identities are separate steps:

* :func:`plan_order` is pure: the order is a deterministic function of the
  experiment's ``seed`` and its cells only. Each block's position is given by
  ``sha256(canonical JSON of [seed, "block", target, agent, model, rep])`` (sorted
  ascending). The arm order inside a block is one of the six permutations of the three
  arms; the blocks are taken six at a time, and each run of six gets every permutation
  exactly once, shuffled by ``sha256([seed, "order", round, permutation])``. So the
  order inside any one block is unpredictable, yet over the schedule each arm holds
  each position equally often (exactly, when the number of blocks is a multiple of
  six). Treating sha256 as a random oracle this is a uniformly random block order, and
  unlike :mod:`random` it can never change across Python versions.
* :func:`build_schedule` takes that order and gives every run a fresh ``run_id``
  (``run_<ULID>``), every block a fresh ``block_id`` and every neutral and instruction
  run a fresh tag. Ids are issued in schedule order from
  :func:`control.core.ids.new_id`, which is monotonic, so sorting runs by ``run_id``
  gives the schedule order. Scheduling the same experiment twice gives the same order
  with new ids and tags: the runs of two schedules are never confused, and a resumed
  queue keeps the runs it already has.

Attempts
--------
An invalid run is re-queued with the identical configuration (DEVELOPMENT_PLAN 5.4).
:func:`retry` gives the next attempt of a run the same block, arm, cell and
``schedule_index``, ``attempt + 1``, a new ``run_id`` and, for a tagged arm, a new
tag, so every attempt's evidence is told apart in leak checks. Every attempt is kept:
a schedule is the list of all of them.

:func:`check_schedule` re-checks a schedule (for example one reloaded from the
database) before it is run or labelled.
"""

from __future__ import annotations

import hashlib
import itertools
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
    "ARM_ORDERS",
    "BLOCK_ARMS",
    "BlockKey",
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


#: The arms of one block, in canonical order.
BLOCK_ARMS: tuple[Arm, ...] = (Arm.CONTROL, Arm.NEUTRAL, Arm.INSTRUCTION)
#: The six orders the arms of a block can run in.
ARM_ORDERS: tuple[tuple[Arm, ...], ...] = tuple(itertools.permutations(BLOCK_ARMS))


class BlockKey(NamedTuple):
    """The cell and repetition one block belongs to."""

    target: str
    agent: str
    model: str
    rep: int


@dataclass(frozen=True, slots=True)
class PlannedRun:
    """One position of the planned order: a block's cell and the arm run there."""

    key: BlockKey
    arm: Arm


class ScheduledRun(BaseModel):
    """One run of a schedule: its identity, arm, cell, position, attempt and tag.

    ``rep`` counts from 0, ``attempt`` from 1. A control run has no tag; a neutral or
    instruction run has one. All attempts of a run share its ``block_id``, arm, cell and
    ``schedule_index`` (see :func:`retry`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Id
    experiment_id: Id
    block_id: Id
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
        if self.arm.tagged and self.tag is None:
            raise ValueError(f"a {self.arm.value} run requires a tag")
        return self

    @property
    def key(self) -> BlockKey:
        return BlockKey(self.target, self.agent, self.model, self.rep)


def _cells(experiment: Experiment) -> Iterator[BlockKey]:
    for target in experiment.targets:
        for agent in experiment.agents:
            for model in experiment.models:
                for rep in range(experiment.repetitions):
                    yield BlockKey(target.name, agent, model, rep)


def _digest(seed: int, purpose: str, *parts: object) -> bytes:
    doc = [seed, purpose, *parts]
    return hashlib.sha256(json.dumps(doc, separators=(",", ":")).encode("utf-8")).digest()


def plan_order(experiment: Experiment) -> list[PlannedRun]:
    """The run order of ``experiment``: three adjacent entries per block, seeded.

    Pure and deterministic: the same seed and cells always give the same order. Every
    six blocks in a row use the six arm orders once each (see the module docstring).
    """
    seed = experiment.seed
    cells = sorted(_cells(experiment), key=lambda k: (_digest(seed, "block", *k), k))
    order: list[PlannedRun] = []
    for index, key in enumerate(cells):
        round_, slot = divmod(index, len(ARM_ORDERS))
        shuffled = sorted(
            ARM_ORDERS,
            key=lambda arms: _digest(seed, "order", round_, [a.value for a in arms]),
        )
        order.extend(PlannedRun(key, arm) for arm in shuffled[slot])
    return order


def build_schedule(experiment: Experiment) -> list[ScheduledRun]:
    """Expand ``experiment`` into its runs, in :func:`plan_order`, with fresh ids and tags."""
    runs: list[ScheduledRun] = []
    block_ids: dict[BlockKey, str] = {}
    tags: set[str] = set()
    for index, planned in enumerate(plan_order(experiment)):
        block_id = block_ids.get(planned.key)
        if block_id is None:
            block_id = block_ids[planned.key] = new_id("block")
        tag: str | None = None
        if planned.arm.tagged:
            tag = new_tag()
            while tag in tags:  # 64 random bits: practically never repeats
                tag = new_tag()
            tags.add(tag)
        runs.append(
            ScheduledRun(
                run_id=new_id("run"),
                experiment_id=experiment.experiment_id,
                block_id=block_id,
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
    """The next attempt of ``run``: same block, arm, cell and position, ``attempt + 1``.

    It gets a new ``run_id`` and, for a neutral or instruction run, a new tag. Add it to
    the schedule beside the earlier attempts; never replace them.
    """
    return run.model_copy(
        update={
            "run_id": new_id("run"),
            "attempt": run.attempt + 1,
            "tag": new_tag() if run.arm.tagged else None,
        }
    )


class ScheduleError(ValueError):
    """A schedule breaks the three-arm block design."""


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
    """Every run belongs to ``experiment`` and each of its cells holds exactly one block."""
    wrong = sorted({r.experiment_id for r in runs} - {experiment.experiment_id})
    if wrong:
        raise ScheduleError(
            f"runs of experiment(s) {', '.join(wrong)}, not {experiment.experiment_id}"
        )
    cells = set(_cells(experiment))
    blocks_per_cell: dict[BlockKey, set[str]] = defaultdict(set)
    for run in runs:
        if run.key not in cells:
            raise ScheduleError(f"run {run.run_id}: cell {tuple(run.key)} is not in the experiment")
        blocks_per_cell[run.key].add(run.block_id)
    for key, block_ids in blocks_per_cell.items():
        if len(block_ids) > 1:
            raise ScheduleError(f"cell {tuple(key)} has more than one block: {sorted(block_ids)}")
    missing = sorted(cells - set(blocks_per_cell))
    if missing:
        shown = ", ".join(str(tuple(k)) for k in missing[:5])
        raise ScheduleError(f"{len(missing)} cell(s) of the experiment are missing: {shown}")


def check_schedule(runs: Sequence[ScheduledRun], *, experiment: Experiment | None = None) -> None:
    """Raise :class:`ScheduleError` unless ``runs`` is a well-formed block schedule.

    With ``experiment``, the schedule must also be *complete* for it: every run belongs
    to it, every run's cell ``(target, agent, model, rep)`` is one of its cells, and
    each cell holds exactly one block (so a truncated schedule, or one with two blocks
    in a cell, is refused). Without it only the structure below is checked.

    Checked over all attempts:

    * ``run_id`` values and tags are unique; a control run has no tag and a neutral or
      instruction run has one; all runs belong to one experiment;
    * ``(schedule_index, attempt)`` and ``(block_id, arm, attempt)`` are unique (the
      database's own uniqueness rules);
    * each block has all three arms and all its runs share one cell; each arm's
      attempts are numbered ``1..n`` and share one ``schedule_index``, so the latest
      attempt of each arm is exactly one run;
    * blocks are contiguous: in ``schedule_index`` order block *k* holds exactly the
      positions ``3k``, ``3k + 1`` and ``3k + 2``, so positions run ``0..3*blocks - 1``
      without gaps.
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
    _unique_by(runs, lambda r: (r.block_id, r.arm.value, r.attempt), "(block_id, arm, attempt)")
    tags: set[str] = set()
    for run in runs:
        if run.arm is Arm.CONTROL and run.tag is not None:
            raise ScheduleError(f"control run {run.run_id} carries a tag")
        if run.arm.tagged and run.tag is None:
            raise ScheduleError(f"{run.arm.value} run {run.run_id} has no tag")
        if run.tag is not None:
            if run.tag in tags:
                raise ScheduleError(f"run {run.run_id} reuses another run's tag")
            tags.add(run.tag)

    blocks: dict[str, list[ScheduledRun]] = defaultdict(list)
    for run in runs:
        blocks[run.block_id].append(run)
    size = len(BLOCK_ARMS)
    lows: list[int] = []
    for block_id, members in blocks.items():
        if len({m.key for m in members}) != 1:
            raise ScheduleError(f"block {block_id} mixes cells")
        positions: list[int] = []
        for arm in BLOCK_ARMS:
            attempts = sorted(m.attempt for m in members if m.arm is arm)
            if not attempts:
                raise ScheduleError(f"block {block_id} has no {arm.value} run")
            if attempts != list(range(1, len(attempts) + 1)):
                raise ScheduleError(
                    f"block {block_id} {arm.value} attempts are not 1..n: {attempts}"
                )
            indexes = {m.schedule_index for m in members if m.arm is arm}
            if len(indexes) != 1:
                raise ScheduleError(f"block {block_id} {arm.value} attempts change position")
            positions.append(indexes.pop())
        low = min(positions)
        if sorted(positions) != list(range(low, low + size)):
            raise ScheduleError(
                f"block {block_id} is not contiguous (positions {sorted(positions)})"
            )
        lows.append(low)
    if sorted(lows) != list(range(0, size * len(lows), size)):
        raise ScheduleError(
            "blocks are not contiguous: positions are not 0..3*blocks-1 three by three"
        )
