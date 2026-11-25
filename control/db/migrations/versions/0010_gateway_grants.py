"""The model gateway's run grants (``gateway_grants``): run id, key hash, models.

Only the SHA-256 of each run key is stored. The gateway mirrors its in-memory grants
here so that a restart keeps the running runs' grants.

Revision ID: 0010
Revises: 0008
Create Date: 2026-11-25 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "gateway_grants",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("key_sha256", sa.String(length=64), nullable=False),
        sa.Column("models", postgresql.ARRAY(sa.String(length=200)), nullable=False),
        sa.Column("embeddings", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "key_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_gateway_grants_key_sha256_format")
        ),
        sa.CheckConstraint(
            "cardinality(models) >= 1", name=op.f("ck_gateway_grants_models_nonempty")
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_gateway_grants")),
        sa.UniqueConstraint("key_sha256", name=op.f("uq_gateway_grants_key_sha256")),
    )


def downgrade() -> None:
    op.drop_table("gateway_grants")
