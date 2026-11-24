"""Oracle polls keep the whole done v2 answer: ``objective``, ``mechanism`` and
``latch_events`` (NULL for rows stored before, and for polls that errored).

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-24 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("oracle_polls", sa.Column("objective", sa.Text(), nullable=True))
    op.add_column("oracle_polls", sa.Column("mechanism", sa.Boolean(), nullable=True))
    op.add_column("oracle_polls", sa.Column("latch_events", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("oracle_polls", "latch_events")
    op.drop_column("oracle_polls", "mechanism")
    op.drop_column("oracle_polls", "objective")
