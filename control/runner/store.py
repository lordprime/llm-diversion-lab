"""The runner's database side: register an experiment and its schedule, claim runs,
record labels and finish runs.

Registration is idempotent and frozen by hash: an experiment id already registered with
the same ``definition_sha256`` returns the stored schedule (a resumed queue keeps its
runs); the same id with a different hash is refused (:class:`StoreError`), never
overwritten. Registry rows (targets, agents, models) are found or created by their full
configuration, so the same build is one row and a different build a new one.

A stored schedule is turned back into :class:`~control.runner.schedule.ScheduledRun`
objects, whose names are the safe-typed registry names; nothing downstream ever builds
a path or a Compose name from a manifest's ``target``/``agent``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Engine, and_, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from control.core.ids import new_id
from control.core.logging import redact_text
from control.core.models import Arm, EndStatus, FunnelLabel, InvalidReason, RunStatus
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import claim_next_run
from control.runner.experiment import ExperimentFile
from control.runner.schedule import ScheduledRun

__all__ = [
    "AgentRecord",
    "RunCatalog",
    "RunStore",
    "StoreError",
    "TargetRecord",
    "placement_map_sha256",
]


class StoreError(ValueError):
    """The database refuses what the runner asked (hash mismatch, unknown run...)."""


@dataclass(frozen=True, slots=True)
class TargetRecord:
    image_digest: str
    content_pack_sha256: str
    placement_map_sha256: str
    oracle_grader: str


@dataclass(frozen=True, slots=True)
class AgentRecord:
    adapter_version: str
    framework_version: str
    image_digests: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunCatalog:
    """What the registry records about each target and agent build of an experiment."""

    targets: Mapping[str, TargetRecord]
    agents: Mapping[str, AgentRecord]

    @staticmethod
    def provider(model: str) -> str:
        """The provider of a model label (``stub``, or the part before ``/``)."""
        if model == "stub":
            return "stub"
        head, slash, _ = model.partition("/")
        return head if slash else "anthropic"


def placement_map_sha256(placements: Mapping[Any, Any]) -> str:
    doc = {str(getattr(k, "value", k)): v.model_dump() for k, v in placements.items()}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def _get_or_create(session: Session, model: type[Any], key: str, prefix: str, **values: Any) -> str:
    """The id of the row with exactly ``values``, inserted (id ``<prefix>_...``) if absent."""
    found = session.scalar(
        select(getattr(model, key)).where(
            and_(*(getattr(model, k) == v for k, v in values.items()))
        )
    )
    if found is not None:
        return str(found)
    row_id = new_id(prefix)
    session.add(model(**{key: row_id}, **values))
    session.flush()
    return row_id


class RunStore:
    """Registry, queue and outcome writes for the runner (Postgres)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # registration

    def register(
        self, ef: ExperimentFile, schedule: Sequence[ScheduledRun], catalog: RunCatalog
    ) -> list[ScheduledRun]:
        """Store the experiment and ``schedule`` once; return the stored schedule."""
        exp = ef.experiment
        with session_scope(self._engine) as s:
            stored = s.get(t.Experiment, exp.experiment_id)
            if stored is not None:
                if stored.definition_sha256 != ef.definition_sha256:
                    raise StoreError(
                        f"experiment {exp.experiment_id} is registered with another definition "
                        f"(sha256 {stored.definition_sha256}, not {ef.definition_sha256})"
                    )
                self._check_catalog(s, exp.experiment_id, catalog)
            else:
                s.add(
                    t.Experiment(
                        experiment_id=exp.experiment_id,
                        name=exp.name,
                        definition_yaml=ef.definition_yaml,
                        definition_sha256=ef.definition_sha256,
                        schedule_seed=exp.seed,
                        budget_usd=exp.limits.budget_usd,
                    )
                )
                s.flush()
                self._insert_schedule(s, ef, schedule, catalog)
        return self.load_schedule(exp.experiment_id)

    @staticmethod
    def _check_catalog(s: Session, experiment_id: str, catalog: RunCatalog) -> None:
        """Refuse to resume a queue whose runs were registered against other builds."""
        targets = s.execute(
            select(t.Target)
            .join(t.Run, t.Run.target_id == t.Target.target_id)
            .where(t.Run.experiment_id == experiment_id)
            .distinct()
        ).scalars()
        differ: list[str] = []
        for row in targets:
            rec = catalog.targets.get(row.name)
            stored = TargetRecord(
                row.image_digest,
                row.content_pack_sha256,
                row.placement_map_sha256,
                row.oracle_grader,
            )
            if rec != stored:
                differ.append(f"target {row.name}: registered {stored}, now {rec}")
        agents = s.execute(
            select(t.Agent)
            .join(t.Run, t.Run.agent_id == t.Agent.agent_id)
            .where(t.Run.experiment_id == experiment_id)
            .distinct()
        ).scalars()
        for agent in agents:
            arec = catalog.agents.get(agent.adapter)
            stored_agent = AgentRecord(
                agent.adapter_version, agent.framework_version, dict(agent.image_digests)
            )
            if arec is None or (
                arec.adapter_version,
                arec.framework_version,
                dict(arec.image_digests),
            ) != (
                stored_agent.adapter_version,
                stored_agent.framework_version,
                stored_agent.image_digests,
            ):
                differ.append(f"agent {agent.adapter}: registered {stored_agent}, now {arec}")
        if differ:
            raise StoreError(
                f"experiment {experiment_id} was registered with other builds: {'; '.join(differ)}"
            )

    def _insert_schedule(
        self,
        s: Session,
        ef: ExperimentFile,
        schedule: Sequence[ScheduledRun],
        catalog: RunCatalog,
    ) -> None:
        exp = ef.experiment
        payload = exp.arms.injected.payload
        arm_ids = {Arm.CONTROL: new_id("arm"), Arm.INJECTED: new_id("arm")}
        s.add_all(
            [
                t.ExperimentArm(
                    arm_id=arm_ids[Arm.CONTROL],
                    experiment_id=exp.experiment_id,
                    name="control",
                    arm=Arm.CONTROL,
                    surfaces=[],
                ),
                t.ExperimentArm(
                    arm_id=arm_ids[Arm.INJECTED],
                    experiment_id=exp.experiment_id,
                    name="injected",
                    arm=Arm.INJECTED,
                    surfaces=[sf.value for sf in exp.arms.injected.surfaces],
                    payload_family=payload.family.value,
                    payload_style=payload.style.value,
                    payload_version=payload.version,
                ),
            ]
        )
        s.flush()
        targets, agents, models = {}, {}, {}
        for target in exp.targets:
            rec = catalog.targets.get(target.name)
            if rec is None:
                raise StoreError(f"no catalog entry for target {target.name!r}")
            targets[target.name] = _get_or_create(
                s,
                t.Target,
                "target_id",
                "tgt",
                name=target.name,
                image_digest=rec.image_digest,
                content_pack_sha256=rec.content_pack_sha256,
                placement_map_sha256=rec.placement_map_sha256,
                oracle_grader=rec.oracle_grader,
            )
        for agent in exp.agents:
            arec = catalog.agents.get(agent)
            if arec is None:
                raise StoreError(f"no catalog entry for agent {agent!r}")
            agents[agent] = _get_or_create(
                s,
                t.Agent,
                "agent_id",
                "agt",
                adapter=agent,
                adapter_version=arec.adapter_version,
                framework_version=arec.framework_version,
                image_digests=dict(arec.image_digests),
            )
        for model in exp.models:
            existing = s.scalar(
                select(t.LlmModel.model_id).where(
                    t.LlmModel.provider == RunCatalog.provider(model),
                    t.LlmModel.provider_model == model,
                    t.LlmModel.effort.is_(None),
                )
            )
            if existing is None:
                existing = new_id("mdl")
                s.add(
                    t.LlmModel(
                        model_id=existing,
                        provider=RunCatalog.provider(model),
                        provider_model=model,
                        effort=None,
                    )
                )
                s.flush()
            models[model] = existing
        s.add_all(
            [
                t.Run(
                    run_id=r.run_id,
                    experiment_id=r.experiment_id,
                    arm_id=arm_ids[r.arm],
                    arm=r.arm,
                    target_id=targets[r.target],
                    agent_id=agents[r.agent],
                    model_id=models[r.model],
                    pair_id=r.pair_id,
                    schedule_index=r.schedule_index,
                    attempt=r.attempt,
                    tag=r.tag,
                )
                for r in schedule
            ]
        )

    # schedule and queue

    def _select(self) -> Any:
        return (
            select(t.Run, t.Target.name, t.Agent.adapter, t.LlmModel.provider_model)
            .join(t.Target, t.Target.target_id == t.Run.target_id)
            .join(t.Agent, t.Agent.agent_id == t.Run.agent_id)
            .join(t.LlmModel, t.LlmModel.model_id == t.Run.model_id)
        )

    @staticmethod
    def _scheduled(run: t.Run, target: str, agent: str, model: str, rep: int) -> ScheduledRun:
        return ScheduledRun(
            run_id=run.run_id,
            experiment_id=run.experiment_id,
            pair_id=run.pair_id,
            arm=run.arm,
            target=target,
            agent=agent,
            model=model,
            rep=rep,
            schedule_index=run.schedule_index,
            attempt=run.attempt,
            tag=run.tag,
        )

    def load_schedule(self, experiment_id: str) -> list[ScheduledRun]:
        """Every attempt of every run of the experiment, in schedule order.

        ``rep`` is not a column: it is recovered as the pair's rank among the pairs of
        its cell, ordered by schedule position (repetitions are interchangeable).
        """
        with session_scope(self._engine) as s:
            rows = s.execute(
                self._select()
                .where(t.Run.experiment_id == experiment_id)
                .order_by(t.Run.schedule_index, t.Run.attempt)
            ).all()
        reps: dict[tuple[str, str, str], list[str]] = {}
        for run, target, agent, model in rows:
            pairs = reps.setdefault((target, agent, model), [])
            if run.pair_id not in pairs:
                pairs.append(run.pair_id)
        return [
            self._scheduled(
                run, target, agent, model, reps[(target, agent, model)].index(run.pair_id)
            )
            for run, target, agent, model in rows
        ]

    def claim_next(
        self, experiment_id: str, schedule: Sequence[ScheduledRun], *, dev: bool = False
    ) -> ScheduledRun | None:
        """Claim the next queued run of the experiment (it must be in ``schedule``).

        ``dev`` (the host runs development settings) is recorded on the run in the
        claiming transaction, so a run is marked from the moment it starts.
        """
        with session_scope(self._engine) as s:
            row = claim_next_run(s, experiment_id=experiment_id)
            if row is not None and dev:
                s.execute(update(t.Run).where(t.Run.run_id == row.run_id).values(dev=True))
        if row is None:
            return None
        for run in schedule:
            if run.run_id == row.run_id:
                return run
        raise StoreError(f"claimed run {row.run_id} is not in the loaded schedule")

    # outcome

    def finish(
        self,
        run_id: str,
        status: RunStatus,
        *,
        reason: InvalidReason | None = None,
        detail: str | None = None,
        labels: Sequence[FunnelLabel] = (),
        container_ips: Mapping[str, str] | None = None,
        dev: bool = False,
        end_status: EndStatus | None = None,
    ) -> None:
        """Set a running run's final status (``reason`` exactly when invalid).

        ``labels`` are stored in the same transaction, so a run is never valid without
        its labels nor labelled without its status. ``dev`` records that the host ran
        development settings (``LAB_DEV=1``). ``detail`` is redacted
        (:func:`~control.core.logging.redact_text`: it can hold exception text that
        echoes database rows or URLs) and cut to 4,000 characters. ``end_status`` (how
        the agent ended, if it ran) is stored for an invalid run only: a valid run's
        comes with its verdict, the one source of a valid run's end status and Outcome.
        """
        if (status is RunStatus.INVALID) != (reason is not None):
            raise StoreError("an invalid run needs a reason, a valid one none")
        if status not in (RunStatus.VALID, RunStatus.INVALID):
            raise StoreError(f"{status} is not a final status")
        if status is RunStatus.VALID and end_status is not None:
            raise StoreError("a valid run's end status comes with its verdict")
        with session_scope(self._engine) as s:
            rows = [label.model_dump() for label in labels]
            if rows:
                s.execute(pg_insert(t.Label).values(rows).on_conflict_do_nothing())
            done = s.execute(
                update(t.Run)
                .where(t.Run.run_id == run_id, t.Run.status == RunStatus.RUNNING)
                .values(
                    status=status,
                    invalid_reason=reason,
                    invalid_detail=redact_text(detail or "")[:4000] or None,
                    end_status=end_status,
                    container_ips=dict(container_ips) if container_ips else None,
                    finished_at=func.now(),
                    dev=dev,
                )
                .returning(t.Run.run_id)
            ).first()
            if done is None:
                raise StoreError(f"run {run_id} is not running")  # rolls the labels back

    def status(self, run_id: str) -> tuple[RunStatus, InvalidReason | None]:
        with session_scope(self._engine) as s:
            row = s.execute(
                select(t.Run.status, t.Run.invalid_reason).where(t.Run.run_id == run_id)
            ).one_or_none()
        if row is None:
            raise StoreError(f"no run {run_id}")
        return row.status, row.invalid_reason
