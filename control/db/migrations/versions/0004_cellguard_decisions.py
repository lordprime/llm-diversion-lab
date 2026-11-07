"""Cell-guard decisions as an evidence event kind (``cellguard_decision``).

Adds the ``cellguard_decisions`` event table and the new kind to the ``event_keys``
ledger's CHECK constraint.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-07 18:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_KINDS_BEFORE = (
    "target_access",
    "placement_serve",
    "llm_call",
    "agent_event",
    "callback",
    "oracle_poll",
)
_KINDS_AFTER = (*_KINDS_BEFORE, "cellguard_decision")


def _kind_check(kinds: Sequence[str]) -> str:
    return "kind IN (" + ", ".join(f"'{k}'" for k in kinds) + ")"


def upgrade() -> None:
    op.create_table(
        "cellguard_decisions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("stream", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("op", sa.String(length=64), nullable=False),
        sa.Column("rule", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("forwarded_path", sa.Text(), nullable=True),
        sa.Column(
            "forced",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("target_kind", sa.String(length=32), nullable=True),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("target_run", sa.Text(), nullable=True),
        sa.Column("body_bytes", sa.BigInteger(), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "stream ~ '^[a-z][a-z0-9-]{0,31}$'", name=op.f("ck_cellguard_decisions_stream_format")
        ),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_cellguard_decisions_seq_nonnegative")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.run_id"], name=op.f("fk_cellguard_decisions_run_id_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cellguard_decisions")),
        sa.UniqueConstraint(
            "run_id", "stream", "seq", name=op.f("uq_cellguard_decisions_run_id_stream_seq")
        ),
    )
    op.drop_constraint(op.f("ck_event_keys_kind"), "event_keys", type_="check")
    op.create_check_constraint(
        op.f("ck_event_keys_kind"), "event_keys", sa.text(_kind_check(_KINDS_AFTER))
    )


def downgrade() -> None:
    op.execute("DELETE FROM event_keys WHERE kind = 'cellguard_decision'")
    op.drop_constraint(op.f("ck_event_keys_kind"), "event_keys", type_="check")
    op.create_check_constraint(
        op.f("ck_event_keys_kind"), "event_keys", sa.text(_kind_check(_KINDS_BEFORE))
    )
    op.drop_table("cellguard_decisions")
