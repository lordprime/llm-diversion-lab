"""Collector tables: registered artifacts, run heartbeats, rejected request bodies.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-07 07:09:17.780400+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rejected_batches",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column(
            "endpoint",
            sa.Enum(
                "manifest",
                "events",
                "artifacts",
                "verdict",
                "status",
                name="endpoint",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "reason",
            sa.Enum(
                "invalid",
                "run_id_mismatch",
                "unknown_run",
                "unknown_placement",
                "conflict",
                "constraint",
                name="reason",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "body_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_rejected_batches_body_sha256_format")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rejected_batches")),
    )
    op.create_index(
        op.f("ix_rejected_batches_run_id"), "rejected_batches", ["run_id"], unique=False
    )
    op.create_table(
        "artifacts",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(length=200), nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_artifacts_sha256_format")),
        sa.CheckConstraint("size_bytes >= 0", name=op.f("ck_artifacts_size_bytes_nonnegative")),
        sa.ForeignKeyConstraint(["run_id"], ["runs.run_id"], name=op.f("fk_artifacts_run_id_runs")),
        sa.PrimaryKeyConstraint("run_id", "path", name=op.f("pk_artifacts")),
    )
    op.create_table(
        "run_heartbeats",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column(
            "phase",
            sa.Enum(
                "claimed",
                "cell_starting",
                "probing",
                "agent_running",
                "collecting",
                "shipping",
                "teardown",
                "finished",
                name="phase",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("message", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_run_heartbeats_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_run_heartbeats_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("run_id", "seq", name=op.f("pk_run_heartbeats")),
    )


def downgrade() -> None:
    op.drop_table("run_heartbeats")
    op.drop_table("artifacts")
    op.drop_index(op.f("ix_rejected_batches_run_id"), table_name="rejected_batches")
    op.drop_table("rejected_batches")
