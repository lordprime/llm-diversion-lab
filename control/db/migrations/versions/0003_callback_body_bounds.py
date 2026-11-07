"""Callbacks: whole-body size, sha256 and truncation flag (inline body is capped).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-07 10:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("callbacks", sa.Column("body_size", sa.BigInteger(), nullable=True))
    op.add_column("callbacks", sa.Column("body_sha256", sa.String(length=64), nullable=True))
    op.add_column(
        "callbacks",
        sa.Column("body_truncated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("callbacks", "body_truncated")
    op.drop_column("callbacks", "body_sha256")
    op.drop_column("callbacks", "body_size")
