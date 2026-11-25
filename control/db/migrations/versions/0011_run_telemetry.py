"""``run_telemetry``: the derived telemetry summary of each run (or why it failed).

Revision ID: 0011
Revises: 0008
Create Date: 2026-11-25 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REQUIRED = (
    "calls",
    "agents",
    "input_tokens",
    "output_tokens",
    "reasoning_chars",
    "calls_with_reasoning",
    "single_call_threads",
    "largest_thread_calls",
    "branch_points",
    "persona_splits",
    "agents_source",
)


def upgrade() -> None:
    op.create_table(
        "run_telemetry",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("telemetry_version", sa.String(length=64), nullable=True),
        sa.Column("calls", sa.BigInteger(), nullable=True),
        sa.Column("agents", sa.BigInteger(), nullable=True),
        sa.Column("agents_source", sa.String(length=16), nullable=True),
        sa.Column("peak_input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("reasoning_chars", sa.BigInteger(), nullable=True),
        sa.Column("calls_with_reasoning", sa.BigInteger(), nullable=True),
        sa.Column("single_call_threads", sa.BigInteger(), nullable=True),
        sa.Column("largest_thread_calls", sa.BigInteger(), nullable=True),
        sa.Column("branch_points", sa.BigInteger(), nullable=True),
        sa.Column("persona_splits", sa.BigInteger(), nullable=True),
        sa.Column("telemetry_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(telemetry_error IS NULL) = (telemetry_version IS NOT NULL)",
            name=op.f("ck_run_telemetry_summary_xor_error"),
        ),
        sa.CheckConstraint(
            "telemetry_error IS NOT NULL OR ("
            + " AND ".join(f"{c} IS NOT NULL" for c in _REQUIRED)
            + ")",
            name=op.f("ck_run_telemetry_summary_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_run_telemetry_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_run_telemetry")),
    )


def downgrade() -> None:
    op.drop_table("run_telemetry")
