"""Initial schema: registry, runs queue, placements, evidence events, labels.

Revision ID: 0001
Revises:
Create Date: 2026-11-07 06:59:04.671608+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("adapter", sa.String(length=200), nullable=False),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("framework_version", sa.String(length=64), nullable=False),
        sa.Column(
            "image_digests",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "capability_sheet",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("agent_id", name=op.f("pk_agents")),
        sa.UniqueConstraint(
            "adapter",
            "adapter_version",
            "framework_version",
            "image_digests",
            name="uq_agents_config",
        ),
    )
    op.create_table(
        "experiments",
        sa.Column("experiment_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("definition_yaml", sa.Text(), nullable=False),
        sa.Column("definition_sha256", sa.String(length=64), nullable=False),
        sa.Column("schedule_seed", sa.BigInteger(), nullable=False),
        sa.Column("budget_usd", sa.Numeric(precision=12, scale=4), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("experiment_id", name=op.f("pk_experiments")),
    )
    op.create_index(
        op.f("ix_experiments_definition_sha256"), "experiments", ["definition_sha256"], unique=False
    )
    op.create_table(
        "models",
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_model", sa.String(length=200), nullable=False),
        sa.Column("effort", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("model_id", name=op.f("pk_models")),
        sa.UniqueConstraint(
            "provider",
            "provider_model",
            "effort",
            name=op.f("uq_models_provider_provider_model_effort"),
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.create_table(
        "targets",
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("image_digest", sa.String(length=200), nullable=False),
        sa.Column("content_pack_sha256", sa.String(length=64), nullable=False),
        sa.Column("placement_map_sha256", sa.String(length=64), nullable=False),
        sa.Column("oracle_grader", sa.String(length=200), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("target_id", name=op.f("pk_targets")),
        sa.UniqueConstraint(
            "name",
            "image_digest",
            "content_pack_sha256",
            "placement_map_sha256",
            "oracle_grader",
            name="uq_targets_config",
        ),
    )
    op.create_table(
        "arms",
        sa.Column("arm_id", sa.String(length=128), nullable=False),
        sa.Column("experiment_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column(
            "arm",
            sa.Enum(
                "control",
                "injected",
                name="arm",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "surfaces",
            postgresql.ARRAY(sa.String(length=8)),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("payload_family", sa.String(length=200), nullable=True),
        sa.Column("payload_style", sa.String(length=200), nullable=True),
        sa.Column("payload_version", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(arm = 'control') = (cardinality(surfaces) = 0)",
            name=op.f("ck_arms_control_has_no_surfaces"),
        ),
        sa.CheckConstraint(
            "(arm = 'control') = (payload_family IS NULL)",
            name=op.f("ck_arms_control_has_no_payload"),
        ),
        sa.CheckConstraint(
            "surfaces <@ ARRAY['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7']::varchar[]",
            name=op.f("ck_arms_surfaces_known"),
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name=op.f("fk_arms_experiment_id_experiments"),
        ),
        sa.PrimaryKeyConstraint("arm_id", name=op.f("pk_arms")),
        sa.UniqueConstraint("arm_id", "arm", name=op.f("uq_arms_arm_id_arm")),
        sa.UniqueConstraint("experiment_id", "name", name=op.f("uq_arms_experiment_id_name")),
    )
    op.create_index(op.f("ix_arms_experiment_id"), "arms", ["experiment_id"], unique=False)
    op.create_table(
        "runs",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("experiment_id", sa.String(length=128), nullable=False),
        sa.Column("arm_id", sa.String(length=128), nullable=False),
        sa.Column(
            "arm",
            sa.Enum(
                "control",
                "injected",
                name="arm",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("pair_id", sa.String(length=128), nullable=False),
        sa.Column("schedule_index", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "valid",
                "invalid",
                name="status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            server_default="queued",
            nullable=False,
        ),
        sa.Column(
            "end_status",
            sa.Enum(
                "completed",
                "budget_exhausted",
                "timeout",
                "refused",
                "crashed",
                name="end_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("tag", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.Boolean(), nullable=True),
        sa.Column("oracle_message", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("container_ips", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(arm = 'control') = (tag IS NULL)", name=op.f("ck_runs_control_has_no_tag")
        ),
        sa.CheckConstraint("attempt >= 1", name=op.f("ck_runs_attempt_positive")),
        sa.CheckConstraint("schedule_index >= 0", name=op.f("ck_runs_schedule_index_nonnegative")),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.agent_id"], name=op.f("fk_runs_agent_id_agents")
        ),
        sa.ForeignKeyConstraint(
            ["arm_id", "arm"], ["arms.arm_id", "arms.arm"], name=op.f("fk_runs_arm_id_arms")
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name=op.f("fk_runs_experiment_id_experiments"),
        ),
        sa.ForeignKeyConstraint(
            ["model_id"], ["models.model_id"], name=op.f("fk_runs_model_id_models")
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["targets.target_id"], name=op.f("fk_runs_target_id_targets")
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_runs")),
        sa.UniqueConstraint(
            "experiment_id",
            "schedule_index",
            "attempt",
            name=op.f("uq_runs_experiment_id_schedule_index_attempt"),
        ),
        sa.UniqueConstraint("pair_id", "arm", "attempt", name=op.f("uq_runs_pair_id_arm_attempt")),
    )
    op.create_index(op.f("ix_runs_experiment_id"), "runs", ["experiment_id"], unique=False)
    op.create_index(op.f("ix_runs_pair_id"), "runs", ["pair_id"], unique=False)
    op.create_index(
        "ix_runs_queue",
        "runs",
        ["created_at", "schedule_index", "run_id"],
        unique=False,
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_table(
        "agent_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
                "llm_call",
                "tool_call",
                "http_request",
                "message",
                "final_report",
                name="event_type",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("tool_name", sa.String(length=200), nullable=True),
        sa.Column("tool_args", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("text", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("native_ref", sa.Text(), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_agent_events_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_agent_events_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_agent_events_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_events")),
        sa.UniqueConstraint(
            "run_id", "stream", "seq", name=op.f("uq_agent_events_run_id_stream_seq")
        ),
    )
    op.create_table(
        "event_keys",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "target_access",
                "placement_serve",
                "llm_call",
                "agent_event",
                "callback",
                "oracle_poll",
                name="kind",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_event_keys_content_sha256_format")
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_event_keys_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_event_keys_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_event_keys_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("run_id", "stream", "seq", name=op.f("pk_event_keys")),
    )
    op.create_table(
        "labels",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column(
            "stage",
            sa.Enum(
                "access",
                "visible",
                "uptake",
                "outcome",
                name="stage",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("value", sa.Boolean(), nullable=False),
        sa.Column("labeler", sa.String(length=200), nullable=False),
        sa.Column("labeler_version", sa.String(length=64), nullable=False),
        sa.Column(
            "evidence_ref",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["run_id"], ["runs.run_id"], name=op.f("fk_labels_run_id_runs")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_labels")),
        sa.UniqueConstraint(
            "run_id", "stage", "labeler", "labeler_version", name="uq_labels_run_stage_labeler"
        ),
    )
    op.create_index(op.f("ix_labels_run_id"), "labels", ["run_id"], unique=False)
    op.create_table(
        "llm_calls",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "main",
                "secondary",
                name="role",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            server_default="main",
            nullable=False,
        ),
        sa.Column("requested_model", sa.String(length=200), nullable=True),
        sa.Column("returned_model", sa.String(length=200), nullable=True),
        sa.Column("input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=14, scale=8), nullable=True),
        sa.Column("stop_reason", sa.String(length=64), nullable=True),
        sa.Column("refusal", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("refusal_category", sa.String(length=64), nullable=True),
        sa.Column("tag_present", sa.Boolean(), nullable=False),
        sa.Column("first_tag_seq", sa.BigInteger(), nullable=True),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_sha256", sa.String(length=64), nullable=True),
        sa.Column("request_artifact", sa.Text(), nullable=False),
        sa.Column("response_artifact", sa.Text(), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_llm_calls_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_llm_calls_seq_nonnegative")),
        sa.ForeignKeyConstraint(["run_id"], ["runs.run_id"], name=op.f("fk_llm_calls_run_id_runs")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_calls")),
        sa.UniqueConstraint("run_id", "stream", "seq", name=op.f("uq_llm_calls_run_id_stream_seq")),
    )
    op.create_table(
        "oracle_polls",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.Boolean(), nullable=False),
        sa.Column("message", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_oracle_polls_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_oracle_polls_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_oracle_polls_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oracle_polls")),
        sa.UniqueConstraint(
            "run_id", "stream", "seq", name=op.f("uq_oracle_polls_run_id_stream_seq")
        ),
    )
    op.create_table(
        "placements",
        sa.Column("placement_id", sa.String(length=128), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column(
            "surface",
            sa.Enum(
                "P1",
                "P2",
                "P3",
                "P4",
                "P5",
                "P6",
                "P7",
                name="surface",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("locator", sa.Text(), nullable=False),
        sa.Column("payload_id", sa.String(length=200), nullable=False),
        sa.Column("payload_version", sa.String(length=64), nullable=False),
        sa.Column("tag", sa.String(length=64), nullable=False),
        sa.Column("token", sa.String(length=32), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_placements_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("placement_id", name=op.f("pk_placements")),
        sa.UniqueConstraint("token", name=op.f("uq_placements_token")),
    )
    op.create_index(op.f("ix_placements_run_id"), "placements", ["run_id"], unique=False)
    op.create_table(
        "target_access",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_id", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("probe", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_target_access_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_target_access_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_target_access_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_access")),
        sa.UniqueConstraint(
            "run_id", "stream", "seq", name=op.f("uq_target_access_run_id_stream_seq")
        ),
    )
    op.create_table(
        "callbacks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "channel",
            sa.Enum(
                "http", "dns", name="channel", native_enum=False, create_constraint=True, length=32
            ),
            nullable=False,
        ),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("token", sa.String(length=32), nullable=True),
        sa.Column("placement_id", sa.String(length=128), nullable=True),
        sa.Column("method", sa.String(length=16), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column(
            "headers",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("body_b64", sa.Text(), nullable=True),
        sa.Column("qname", sa.Text(), nullable=True),
        sa.Column("qtype", sa.String(length=16), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_callbacks_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_callbacks_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["placement_id"],
            ["placements.placement_id"],
            name=op.f("fk_callbacks_placement_id_placements"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["runs.run_id"], name=op.f("fk_callbacks_run_id_runs")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_callbacks")),
        sa.UniqueConstraint("run_id", "stream", "seq", name=op.f("uq_callbacks_run_id_stream_seq")),
    )
    op.create_index(op.f("ix_callbacks_token"), "callbacks", ["token"], unique=False)
    op.create_table(
        "placement_serves",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("placement_id", sa.String(length=128), nullable=False),
        sa.Column(
            "surface",
            sa.Enum(
                "P1",
                "P2",
                "P3",
                "P4",
                "P5",
                "P6",
                "P7",
                name="surface",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("flow_id", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("decoded_sha256", sa.String(length=64), nullable=False),
        sa.Column("wire_sha256", sa.String(length=64), nullable=False),
        sa.Column("byte_offset", sa.BigInteger(), nullable=True),
        sa.Column("insert_ok", sa.Boolean(), nullable=False),
        sa.Column("probe", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_placement_serves_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_placement_serves_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["placement_id"],
            ["placements.placement_id"],
            name=op.f("fk_placement_serves_placement_id_placements"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_placement_serves_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_placement_serves")),
        sa.UniqueConstraint(
            "run_id", "stream", "seq", name=op.f("uq_placement_serves_run_id_stream_seq")
        ),
    )
    op.create_index(
        op.f("ix_placement_serves_placement_id"), "placement_serves", ["placement_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_placement_serves_placement_id"), table_name="placement_serves")
    op.drop_table("placement_serves")
    op.drop_index(op.f("ix_callbacks_token"), table_name="callbacks")
    op.drop_table("callbacks")
    op.drop_table("target_access")
    op.drop_index(op.f("ix_placements_run_id"), table_name="placements")
    op.drop_table("placements")
    op.drop_table("oracle_polls")
    op.drop_table("llm_calls")
    op.drop_index(op.f("ix_labels_run_id"), table_name="labels")
    op.drop_table("labels")
    op.drop_table("event_keys")
    op.drop_table("agent_events")
    op.drop_index("ix_runs_queue", table_name="runs", postgresql_where=sa.text("status = 'queued'"))
    op.drop_index(op.f("ix_runs_pair_id"), table_name="runs")
    op.drop_index(op.f("ix_runs_experiment_id"), table_name="runs")
    op.drop_table("runs")
    op.drop_index(op.f("ix_arms_experiment_id"), table_name="arms")
    op.drop_table("arms")
    op.drop_table("targets")
    op.drop_table("models")
    op.drop_index(op.f("ix_experiments_definition_sha256"), table_name="experiments")
    op.drop_table("experiments")
    op.drop_table("agents")
