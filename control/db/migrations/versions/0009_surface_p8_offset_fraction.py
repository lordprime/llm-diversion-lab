"""Surface P8 (the X-Security-Notice header) and the relative offset of in-page text.

The known-surface CHECKs gain ``P8``; ``placements`` and ``placement_serves`` gain a
nullable ``offset_fraction`` (planned and realised position of the text in the body).

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-24 10:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD = ("P1", "P2", "P3", "P4", "P5", "P6", "P7")
_NEW = (*_OLD, "P8")
_TABLES = ("placements", "placement_serves")


def _in_list(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _set_surfaces(values: Sequence[str]) -> None:
    for table in _TABLES:
        name = op.f(f"ck_{table}_surface")
        op.drop_constraint(name, table, type_="check")
        op.create_check_constraint(name, table, f"surface IN ({_in_list(values)})")
    name = op.f("ck_arms_surfaces_known")
    op.drop_constraint(name, "arms", type_="check")
    op.create_check_constraint(name, "arms", f"surfaces <@ ARRAY[{_in_list(values)}]::varchar[]")


def upgrade() -> None:
    _set_surfaces(_NEW)
    for table in _TABLES:
        op.add_column(table, sa.Column("offset_fraction", sa.Float(), nullable=True))


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "offset_fraction")
    # rows that name P8 would break the old CHECKs, so they go first
    op.execute("DELETE FROM placement_serves WHERE surface = 'P8'")
    op.execute("DELETE FROM placements WHERE surface = 'P8'")
    op.execute("UPDATE arms SET surfaces = array_remove(surfaces, 'P8')")
    _set_surfaces(_OLD)
