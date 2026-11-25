"""``labctl export telemetry``: the raw per-run telemetry table, as CSV or Markdown.

One row per run, in schedule order, so the same database always gives the same bytes.
Rows of different telemetry versions are not comparable (the rules for agents and
tokens change between versions), so mixing them is refused unless asked for.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping, Sequence
from typing import Any, Final

from control.cli.queries import EXPORT_COLUMNS

__all__ = ["FORMATS", "MixedVersionsError", "TelemetryTable"]

FORMATS: Final = ("csv", "md")


class MixedVersionsError(ValueError):
    """The rows come from more than one telemetry version."""


class TelemetryTable:
    """The export rows of one experiment, ready to render."""

    def __init__(self, rows: Sequence[Mapping[str, Any]]) -> None:
        self._rows = rows

    @property
    def versions(self) -> list[str]:
        """The telemetry versions present, sorted (runs without a summary have none)."""
        return sorted({r["telemetry_version"] for r in self._rows if r["telemetry_version"]})

    @property
    def failed(self) -> list[str]:
        """Run ids whose telemetry could not be derived (their metric cells are empty)."""
        return [r["run_id"] for r in self._rows if r["telemetry_error"]]

    def check_versions(self, *, allow_mixed: bool) -> None:
        if len(self.versions) > 1 and not allow_mixed:
            raise MixedVersionsError(
                f"runs have telemetry versions {', '.join(self.versions)}; rerun the old ones "
                "or pass --allow-mixed-versions to export them together"
            )

    def render(self, fmt: str) -> str:
        if fmt == "csv":
            return self._csv()
        if fmt == "md":
            return self._markdown()
        raise ValueError(f"unknown format {fmt!r}")

    def _cells(self, row: Mapping[str, Any], *, empty: str) -> list[str]:
        def cell(name: str) -> str:
            value = row[name]  # a failed derivation stored no summary: its cells are None
            if value is None:
                return empty
            return str(value).lower() if isinstance(value, bool) else str(value)

        return [cell(name) for name in EXPORT_COLUMNS]

    def _csv(self) -> str:
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(EXPORT_COLUMNS)
        writer.writerows(self._cells(row, empty="") for row in self._rows)
        return out.getvalue()

    def _markdown(self) -> str:
        def line(cells: Sequence[str]) -> str:
            return "| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |"

        lines = [line(EXPORT_COLUMNS), line(["---"] * len(EXPORT_COLUMNS))]
        lines += (line(self._cells(row, empty="-")) for row in self._rows)
        return "\n".join(lines) + "\n"
