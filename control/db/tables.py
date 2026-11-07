"""Postgres schema (SQLAlchemy 2, typed ORM) for the control plane.

Columns mirror the pydantic models in :mod:`control.core.models` and use their field
names verbatim, so ``model.model_dump(exclude={"kind"})`` is a valid row for the
matching table (checked by ``tests/db/test_tables.py``). Migrations under
``control/db/migrations`` are generated from this module; never write ad-hoc DDL.

Event tables
------------
Every evidence-event table (:data:`EVENT_TABLES`) derives from :class:`EventRow` and
carries ``run_id``, ``stream``, ``seq`` and ``ts``. The idempotency key is
:data:`EVENT_KEY` = ``(run_id, stream, seq)``: ``seq`` is numbered per producer stream
*across all kinds*, so ``kind`` is deliberately not part of the key.

Because events of different kinds live in different tables, a per-table unique
constraint alone would let one key be stored twice under two kinds. The key is
therefore claimed first in the ledger table ``event_keys`` (:class:`EventKeyEntry`,
primary key ``(run_id, stream, seq)``, plus the event's ``kind`` and
``content_sha256``); only a newly claimed key is written to its kind table (see
:func:`control.db.repo.insert_events`). The per-table unique constraint on
``(run_id, stream, seq)`` stays as a second line of defence.

Collector tables
----------------
``artifacts`` registers raw artifact files (key ``(run_id, path)``, plus sha256 and
size); ``run_heartbeats`` keeps runner lifecycle heartbeats (key ``(run_id, seq)``);
``rejected_batches`` keeps every request body the Collector API refused, byte for byte,
with the endpoint, the reason and a JSON detail (validation errors or conflicting
keys). Its ``run_id`` is the URL value as received and deliberately not a foreign key,
so a body for an unknown or malformed run is kept too. All three are write-once.

Enums are stored as ``VARCHAR`` with a ``CHECK`` constraint (not native Postgres enum
types), holding the enum *values* (``"queued"``, ``"P1"``...), so adding a value later
is a plain constraint change in a migration.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, Self

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

from control.core import models as m
from control.core.models import (
    STREAM_PATTERN,
    AgentEventType,
    Arm,
    CallbackChannel,
    CollectorEndpoint,
    EndStatus,
    EventKind,
    FunnelStage,
    LlmRole,
    RejectReason,
    RunPhase,
    RunStatus,
    Surface,
)

__all__ = [
    "EVENT_KEY",
    "EVENT_TABLES",
    "Agent",
    "AgentEvent",
    "Artifact",
    "Base",
    "Callback",
    "EventKeyEntry",
    "EventRow",
    "Experiment",
    "ExperimentArm",
    "Label",
    "LlmCall",
    "LlmModel",
    "OraclePoll",
    "Placement",
    "PlacementServe",
    "RejectedBatch",
    "Run",
    "RunHeartbeatRow",
    "Target",
    "TargetAccess",
]

#: Constraint naming convention; keeps Alembic migrations deterministic.
NAMING_CONVENTION: Final = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: Idempotency key of every event table.
EVENT_KEY: Final = ("run_id", "stream", "seq")

# Column types. IDs follow control.core.ids.ID_PATTERN (at most 128 characters).
_ID = String(128)
_SHA256 = String(64)
_TS = DateTime(timezone=True)
_NAME = String(200)
_VERSION = String(64)


def _values(enum_cls: type[StrEnum]) -> list[str]:
    return [member.value for member in enum_cls]


def _enum(enum_cls: type[StrEnum], name: str) -> SAEnum:
    """A VARCHAR + CHECK enum column storing the enum's values."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=_values,
        validate_strings=True,
    )


def _sql_list(values: list[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# --------------------------------------------------------------------------- registry


class Experiment(Base):
    """One registered experiment definition (its YAML, hash and schedule seed)."""

    __tablename__ = "experiments"

    experiment_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    name: Mapped[str] = mapped_column(_NAME)
    definition_yaml: Mapped[str] = mapped_column(Text)
    definition_sha256: Mapped[str] = mapped_column(_SHA256, index=True)
    schedule_seed: Mapped[int] = mapped_column(BigInteger)
    budget_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 4))
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


class ExperimentArm(Base):
    """An arm of an experiment: its condition, surface set and payload."""

    __tablename__ = "arms"
    __table_args__ = (
        UniqueConstraint("experiment_id", "name"),
        # target of the composite FK runs(arm_id, arm): a run's arm matches its arm row
        UniqueConstraint("arm_id", "arm"),
        CheckConstraint(
            f"surfaces <@ ARRAY[{_sql_list(_values(Surface))}]::varchar[]", name="surfaces_known"
        ),
        CheckConstraint(
            "(arm = 'control') = (cardinality(surfaces) = 0)", name="control_has_no_surfaces"
        ),
        CheckConstraint(
            "(arm = 'control') = (payload_family IS NULL)", name="control_has_no_payload"
        ),
    )

    arm_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    experiment_id: Mapped[str] = mapped_column(
        _ID, ForeignKey("experiments.experiment_id"), index=True
    )
    name: Mapped[str] = mapped_column(_NAME)
    arm: Mapped[Arm] = mapped_column(_enum(Arm, "arm"))
    surfaces: Mapped[list[str]] = mapped_column(
        ARRAY(String(8)), default=list, server_default=text("'{}'")
    )
    payload_family: Mapped[str | None] = mapped_column(_NAME)
    payload_style: Mapped[str | None] = mapped_column(_NAME)
    payload_version: Mapped[str | None] = mapped_column(_VERSION)


class Target(Base):
    """A GOAT build: seeded image, content pack, placement map and oracle grader."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint(
            "name",
            "image_digest",
            "content_pack_sha256",
            "placement_map_sha256",
            "oracle_grader",
            name="uq_targets_config",
        ),
    )

    target_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    name: Mapped[str] = mapped_column(_NAME)
    image_digest: Mapped[str] = mapped_column(_NAME)
    content_pack_sha256: Mapped[str] = mapped_column(_SHA256)
    placement_map_sha256: Mapped[str] = mapped_column(_SHA256)
    oracle_grader: Mapped[str] = mapped_column(_NAME)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


class Agent(Base):
    """An agent configuration: adapter, framework version, images, capability sheet."""

    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint(
            "adapter",
            "adapter_version",
            "framework_version",
            "image_digests",
            name="uq_agents_config",
        ),
    )

    agent_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    adapter: Mapped[str] = mapped_column(_NAME)
    adapter_version: Mapped[str] = mapped_column(_VERSION)
    framework_version: Mapped[str] = mapped_column(_VERSION)
    image_digests: Mapped[dict[str, str]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    capability_sheet: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


class LlmModel(Base):
    """A provider model at a given effort setting (table ``models``)."""

    __tablename__ = "models"
    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_model", "effort", postgresql_nulls_not_distinct=True
        ),
    )

    model_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    provider: Mapped[str] = mapped_column(String(64))
    provider_model: Mapped[str] = mapped_column(_NAME)
    effort: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


# --------------------------------------------------------------------------- runs


class Run(Base):
    """One run: a queue entry first (``status='queued'``), then its record."""

    __tablename__ = "runs"
    __table_args__ = (
        ForeignKeyConstraint(["arm_id", "arm"], ["arms.arm_id", "arms.arm"]),
        UniqueConstraint("experiment_id", "schedule_index", "attempt"),
        UniqueConstraint("pair_id", "arm", "attempt"),
        CheckConstraint("schedule_index >= 0", name="schedule_index_nonnegative"),
        CheckConstraint("attempt >= 1", name="attempt_positive"),
        CheckConstraint("(arm = 'control') = (tag IS NULL)", name="control_has_no_tag"),
        # the work queue: claim_next_run scans only queued rows, in this order
        Index(
            "ix_runs_queue",
            "created_at",
            "schedule_index",
            "run_id",
            postgresql_where=text("status = 'queued'"),
        ),
    )

    run_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    experiment_id: Mapped[str] = mapped_column(
        _ID, ForeignKey("experiments.experiment_id"), index=True
    )
    arm_id: Mapped[str] = mapped_column(_ID)
    arm: Mapped[Arm] = mapped_column(_enum(Arm, "arm"))
    target_id: Mapped[str] = mapped_column(_ID, ForeignKey("targets.target_id"))
    agent_id: Mapped[str] = mapped_column(_ID, ForeignKey("agents.agent_id"))
    model_id: Mapped[str] = mapped_column(_ID, ForeignKey("models.model_id"))
    pair_id: Mapped[str] = mapped_column(_ID, index=True)
    schedule_index: Mapped[int] = mapped_column(Integer)
    attempt: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    status: Mapped[RunStatus] = mapped_column(
        _enum(RunStatus, "status"),
        default=RunStatus.QUEUED,
        server_default=RunStatus.QUEUED.value,
    )
    end_status: Mapped[EndStatus | None] = mapped_column(_enum(EndStatus, "end_status"))
    tag: Mapped[str | None] = mapped_column(String(64))
    # oracle verdict (Verdict); outcome is the /done status, the only source of Outcome
    outcome: Mapped[bool | None] = mapped_column(Boolean)
    oracle_message: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(_TS)
    container_ips: Mapped[dict[str, str] | None] = mapped_column(JSONB)
    manifest_sha256: Mapped[str | None] = mapped_column(_SHA256)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(_TS)
    finished_at: Mapped[datetime | None] = mapped_column(_TS)


class Placement(Base):
    """A planned placement (mirrors :class:`control.core.models.Placement`)."""

    __tablename__ = "placements"

    placement_id: Mapped[str] = mapped_column(_ID, primary_key=True)
    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), index=True)
    surface: Mapped[Surface] = mapped_column(_enum(Surface, "surface"))
    url: Mapped[str] = mapped_column(Text)
    locator: Mapped[str] = mapped_column(Text)
    payload_id: Mapped[str] = mapped_column(_NAME)
    payload_version: Mapped[str] = mapped_column(_VERSION)
    tag: Mapped[str] = mapped_column(String(64))
    token: Mapped[str] = mapped_column(String(32), unique=True)
    content_sha256: Mapped[str] = mapped_column(_SHA256)

    @classmethod
    def from_model(cls, placement: m.Placement) -> Self:
        return cls(**placement.model_dump())


# --------------------------------------------------------------------------- events


class EventRow(Base):
    """Columns and idempotency key shared by every evidence-event table."""

    __abstract__ = True

    # sort_order < 0 puts the shared columns first in every event table
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True, sort_order=-5)
    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), sort_order=-4)
    stream: Mapped[str] = mapped_column(String(32), sort_order=-3)
    seq: Mapped[int] = mapped_column(BigInteger, sort_order=-2)
    ts: Mapped[datetime] = mapped_column(_TS, sort_order=-1)
    received_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())

    @declared_attr.directive
    @classmethod
    def __table_args__(cls) -> tuple[Any, ...]:
        return (
            UniqueConstraint(*EVENT_KEY),
            CheckConstraint("seq >= 0", name="seq_nonnegative"),
            CheckConstraint(f"stream ~ '{STREAM_PATTERN}'", name="stream_format"),
        )


class PlacementServe(EventRow):
    """A realised placement (``placement_serve`` events from the injector)."""

    __tablename__ = "placement_serves"

    placement_id: Mapped[str] = mapped_column(
        _ID, ForeignKey("placements.placement_id"), index=True
    )
    surface: Mapped[Surface] = mapped_column(_enum(Surface, "surface"))
    flow_id: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[int] = mapped_column(Integer)
    decoded_sha256: Mapped[str] = mapped_column(_SHA256)
    wire_sha256: Mapped[str] = mapped_column(_SHA256)
    byte_offset: Mapped[int | None] = mapped_column(BigInteger)
    insert_ok: Mapped[bool] = mapped_column(Boolean)
    probe: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class TargetAccess(EventRow):
    """Agent (or probe) requests to the target (``target_access`` events)."""

    __tablename__ = "target_access"

    flow_id: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    probe: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    source_ip: Mapped[str | None] = mapped_column(String(64))


class LlmCall(EventRow):
    """LLM request/response pairs captured by the tap (``llm_call`` events)."""

    __tablename__ = "llm_calls"

    role: Mapped[LlmRole] = mapped_column(
        _enum(LlmRole, "role"), default=LlmRole.MAIN, server_default=LlmRole.MAIN.value
    )
    requested_model: Mapped[str | None] = mapped_column(_NAME)
    returned_model: Mapped[str | None] = mapped_column(_NAME)
    input_tokens: Mapped[int | None] = mapped_column(BigInteger)
    output_tokens: Mapped[int | None] = mapped_column(BigInteger)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(14, 8))
    stop_reason: Mapped[str | None] = mapped_column(String(64))
    refusal: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    refusal_category: Mapped[str | None] = mapped_column(String(64))
    tag_present: Mapped[bool] = mapped_column(Boolean)
    first_tag_seq: Mapped[int | None] = mapped_column(BigInteger)
    request_sha256: Mapped[str] = mapped_column(_SHA256)
    response_sha256: Mapped[str | None] = mapped_column(_SHA256)
    request_artifact: Mapped[str] = mapped_column(Text)
    response_artifact: Mapped[str | None] = mapped_column(Text)


class AgentEvent(EventRow):
    """Normalised agent trajectory steps (``agent_event`` events)."""

    __tablename__ = "agent_events"

    event_type: Mapped[AgentEventType] = mapped_column(_enum(AgentEventType, "event_type"))
    tool_name: Mapped[str | None] = mapped_column(_NAME)
    tool_args: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    text: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    native_ref: Mapped[str | None] = mapped_column(Text)


class Callback(EventRow):
    """HTTP/HTTPS and DNS contacts recorded by the catcher (``callback`` events)."""

    __tablename__ = "callbacks"

    channel: Mapped[CallbackChannel] = mapped_column(_enum(CallbackChannel, "channel"))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    token: Mapped[str | None] = mapped_column(String(32), index=True)
    placement_id: Mapped[str | None] = mapped_column(_ID, ForeignKey("placements.placement_id"))
    method: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    #: ordered raw headers as a JSON list of ``[name, value]`` pairs
    headers: Mapped[list[list[str]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    query: Mapped[str | None] = mapped_column(Text)
    body_b64: Mapped[str | None] = mapped_column(Text)
    #: total bytes received and sha256 of the whole body; ``body_b64`` may hold a prefix
    body_size: Mapped[int | None] = mapped_column(BigInteger)
    body_sha256: Mapped[str | None] = mapped_column(_SHA256)
    body_truncated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    qname: Mapped[str | None] = mapped_column(Text)
    qtype: Mapped[str | None] = mapped_column(String(16))


class OraclePoll(EventRow):
    """Every poll of the oracle's ``GET /done`` (``oracle_poll`` events)."""

    __tablename__ = "oracle_polls"

    status: Mapped[bool] = mapped_column(Boolean)
    message: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    error: Mapped[str | None] = mapped_column(Text)


class EventKeyEntry(Base):
    """Ledger of every stored event key, across all kinds (table ``event_keys``).

    ``content_sha256`` is the hash of the event's canonical JSON
    (:func:`control.db.repo.event_content_sha256`), so a re-shipped key can be told
    apart as an identical duplicate or a conflicting rewrite.
    """

    __tablename__ = "event_keys"
    __table_args__ = (
        CheckConstraint("seq >= 0", name="seq_nonnegative"),
        CheckConstraint(f"stream ~ '{STREAM_PATTERN}'", name="stream_format"),
        CheckConstraint("content_sha256 ~ '^[0-9a-f]{64}$'", name="content_sha256_format"),
    )

    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), primary_key=True)
    stream: Mapped[str] = mapped_column(String(32), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[EventKind] = mapped_column(_enum(EventKind, "kind"))
    content_sha256: Mapped[str] = mapped_column(_SHA256)
    received_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


#: The table that stores each event kind.
EVENT_TABLES: Final[Mapping[EventKind, type[EventRow]]] = {
    EventKind.PLACEMENT_SERVE: PlacementServe,
    EventKind.TARGET_ACCESS: TargetAccess,
    EventKind.LLM_CALL: LlmCall,
    EventKind.AGENT_EVENT: AgentEvent,
    EventKind.CALLBACK: Callback,
    EventKind.ORACLE_POLL: OraclePoll,
}


# --------------------------------------------------------------------------- labels


class Label(Base):
    """One funnel-stage label (mirrors :class:`control.core.models.FunnelLabel`).

    Re-running the same labeller version on a run is idempotent on
    ``(run_id, stage, labeler, labeler_version)``.
    """

    __tablename__ = "labels"
    __table_args__ = (
        UniqueConstraint(
            "run_id", "stage", "labeler", "labeler_version", name="uq_labels_run_stage_labeler"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), index=True)
    stage: Mapped[FunnelStage] = mapped_column(_enum(FunnelStage, "stage"))
    value: Mapped[bool] = mapped_column(Boolean)
    labeler: Mapped[str] = mapped_column(_NAME)
    labeler_version: Mapped[str] = mapped_column(_VERSION)
    evidence_ref: Mapped[list[str]] = mapped_column(
        ARRAY(Text), default=list, server_default=text("'{}'")
    )
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


# --------------------------------------------------------------------------- collector


class Artifact(Base):
    """A registered raw artifact file (mirrors :class:`control.core.models.ArtifactFile`).

    ``path`` is relative to ``runs/<run_id>/``. Write-once: re-registering a path with
    different content is a conflict (see :func:`control.db.repo.register_artifacts`).
    """

    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="size_bytes_nonnegative"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_format"),
    )

    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), primary_key=True)
    path: Mapped[str] = mapped_column(String(512), primary_key=True)
    sha256: Mapped[str] = mapped_column(_SHA256)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str | None] = mapped_column(_NAME)
    received_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


class RunHeartbeatRow(Base):
    """A runner lifecycle heartbeat (mirrors :class:`control.core.models.RunHeartbeat`)."""

    __tablename__ = "run_heartbeats"
    __table_args__ = (CheckConstraint("seq >= 0", name="seq_nonnegative"),)

    run_id: Mapped[str] = mapped_column(_ID, ForeignKey("runs.run_id"), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    phase: Mapped[RunPhase] = mapped_column(_enum(RunPhase, "phase"))
    ts: Mapped[datetime] = mapped_column(_TS)
    message: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    received_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())


class RejectedBatch(Base):
    """A request body the Collector API refused, kept verbatim (never dropped)."""

    __tablename__ = "rejected_batches"
    __table_args__ = (CheckConstraint("body_sha256 ~ '^[0-9a-f]{64}$'", name="body_sha256_format"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    #: the run_id from the request URL, as received (not a foreign key)
    run_id: Mapped[str] = mapped_column(Text, index=True)
    endpoint: Mapped[CollectorEndpoint] = mapped_column(_enum(CollectorEndpoint, "endpoint"))
    reason: Mapped[RejectReason] = mapped_column(_enum(RejectReason, "reason"))
    body: Mapped[bytes] = mapped_column(LargeBinary)
    body_sha256: Mapped[str] = mapped_column(_SHA256)
    #: validation errors, conflicting keys or the database error, as JSON
    detail: Mapped[Any] = mapped_column(JSONB)
    received_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now())
