"""Event text the agent chooses is unbounded: ``target_access.method``,
``callbacks.method`` and ``callbacks.qtype`` become ``TEXT`` (a 17-character HTTP verb
or DNS type is evidence, never a reason to refuse a batch).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-09 10:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    ("target_access", "method", False),
    ("callbacks", "method", True),
    ("callbacks", "qtype", True),
)


def upgrade() -> None:
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length=16),
            type_=sa.Text(),
            existing_nullable=nullable,
        )


def downgrade() -> None:
    # values longer than the old bound are cut, so the downgrade never fails on data
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.Text(),
            type_=sa.String(length=16),
            existing_nullable=nullable,
            postgresql_using=f"left({column}, 16)",
        )
