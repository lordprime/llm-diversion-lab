"""Runs: the oracle's two verdicts, ``effect`` and ``mechanism``, beside ``outcome``.

``outcome`` stays and is the verdict the experiment names as primary. ``effect`` is set
whenever ``outcome`` is (existing rows get ``effect = outcome``); ``mechanism`` stays
NULL when the target cannot decide it, as it does for every existing row.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-24 10:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("effect", sa.Boolean(), nullable=True))
    op.add_column("runs", sa.Column("mechanism", sa.Boolean(), nullable=True))
    op.execute("UPDATE runs SET effect = outcome WHERE outcome IS NOT NULL")
    op.create_check_constraint(
        op.f("ck_runs_outcome_has_effect"), "runs", "(outcome IS NULL) = (effect IS NULL)"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_runs_outcome_has_effect"), "runs", type_="check")
    op.drop_column("runs", "mechanism")
    op.drop_column("runs", "effect")
