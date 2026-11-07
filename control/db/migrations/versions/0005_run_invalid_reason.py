"""Runs: why a run is invalid (``invalid_reason``, a bounded set) and free detail.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-07 19:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REASONS = (
    "cell_failed",
    "probe_failed",
    "oracle_unreachable",
    "oracle_unexpected",
    "evidence_incomplete",
    "recording_failed",
    "contaminated",
    "collector_rejected",
    "teardown_failed",
    "internal",
)


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column(
            "invalid_reason",
            sa.Enum(
                *_REASONS,
                name="invalid_reason",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=True,
        ),
    )
    op.add_column("runs", sa.Column("invalid_detail", sa.Text(), nullable=True))
    # rows already invalid (none before the runner existed) get the catch-all reason
    op.execute("UPDATE runs SET invalid_reason = 'internal' WHERE status = 'invalid'")
    op.create_check_constraint(
        op.f("ck_runs_invalid_has_reason"),
        "runs",
        "(status = 'invalid') = (invalid_reason IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_runs_invalid_has_reason"), "runs", type_="check")
    op.drop_column("runs", "invalid_detail")
    op.drop_column("runs", "invalid_reason")
