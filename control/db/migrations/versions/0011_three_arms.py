"""Three arms per block: ``control``, ``neutral`` and ``instruction`` (register T1, S1).

* The ``arm`` CHECK on ``arms`` and ``runs`` now allows ``control``, ``neutral`` and
  ``instruction``. The two-arm design's treated arm, ``injected``, is the instruction
  arm: every stored ``injected`` row (M0 and M1a self-tests) is rewritten as
  ``instruction``, and an ``arms`` row named ``injected`` is renamed with it. Readers
  still accept ``injected`` for one release (``Arm._missing_``), so manifests and
  evidence written before this migration stay readable.
* ``runs.pair_id`` becomes ``runs.block_id`` (its index and the unique key on
  ``(block_id, arm, attempt)`` follow). An old pair is simply a block with no neutral
  run; no value changes.

The downgrade maps ``instruction`` back to ``injected`` and ``block_id`` back to
``pair_id``. It refuses while any neutral run or arm is stored, naming the experiments
that hold them: the two-arm schema has no place for one, and deleting runs (with their
evidence) is never done silently, so those experiments must be deleted or archived
first.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-26 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("arms", "runs")
_OLD_ARMS = ("control", "injected")
_NEW_ARMS = ("control", "neutral", "instruction")


def _in_list(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _drop_arm_checks() -> None:
    for table in _TABLES:
        op.drop_constraint(op.f(f"ck_{table}_arm"), table, type_="check")


def _create_arm_checks(values: Sequence[str]) -> None:
    for table in _TABLES:
        op.create_check_constraint(op.f(f"ck_{table}_arm"), table, f"arm IN ({_in_list(values)})")


def _rename_arm(old: str, new: str) -> None:
    """Rewrite one arm value everywhere; the composite FK runs -> arms follows on update."""
    # runs(arm_id, arm) references arms(arm_id, arm) with no ON UPDATE, so both sides
    # are rewritten while the FK is dropped
    op.drop_constraint(op.f("fk_runs_arm_id_arms"), "runs", type_="foreignkey")
    op.execute(sa.text("UPDATE arms SET arm = :new WHERE arm = :old").bindparams(old=old, new=new))
    op.execute(
        sa.text("UPDATE arms SET name = :new WHERE name = :old").bindparams(old=old, new=new)
    )
    op.execute(sa.text("UPDATE runs SET arm = :new WHERE arm = :old").bindparams(old=old, new=new))
    op.create_foreign_key(
        op.f("fk_runs_arm_id_arms"), "runs", "arms", ["arm_id", "arm"], ["arm_id", "arm"]
    )


def _rename_block_column(old: str, new: str) -> None:
    op.drop_constraint(op.f(f"uq_runs_{old}_arm_attempt"), "runs", type_="unique")
    op.drop_index(op.f(f"ix_runs_{old}"), table_name="runs")
    op.alter_column("runs", old, new_column_name=new)
    op.create_index(op.f(f"ix_runs_{new}"), "runs", [new], unique=False)
    op.create_unique_constraint(op.f(f"uq_runs_{new}_arm_attempt"), "runs", [new, "arm", "attempt"])


def upgrade() -> None:
    _drop_arm_checks()
    _rename_arm("injected", "instruction")
    _create_arm_checks(_NEW_ARMS)
    _rename_block_column("pair_id", "block_id")


def downgrade() -> None:
    bind = op.get_bind()
    holding = (
        bind.execute(
            sa.text(
                "SELECT DISTINCT experiment_id FROM runs WHERE arm = 'neutral' "
                "UNION SELECT DISTINCT experiment_id FROM arms WHERE arm = 'neutral' "
                "ORDER BY 1"
            )
        )
        .scalars()
        .all()
    )
    if holding:
        raise RuntimeError(
            "cannot downgrade below 0011: experiment(s) "
            f"{', '.join(holding)} hold neutral runs or arms, which the two-arm schema has "
            "no place for; delete or archive those experiments first"
        )
    _rename_block_column("block_id", "pair_id")
    _drop_arm_checks()
    _rename_arm("instruction", "injected")
    _create_arm_checks(_OLD_ARMS)
