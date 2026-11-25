"""``labctl export telemetry``: the raw per-run telemetry table, as CSV or Markdown.

One row for every run of the experiment (nothing is filtered out: ``status``,
``invalid_reason`` and ``telemetry_status`` tell the reader what each row is), in
schedule order, so the same database always gives the same bytes.
Rows of different telemetry versions are not comparable (the rules for agents and
tokens change between versions), so mixing them is refused unless asked for.

CSV safety: a spreadsheet runs a text cell that starts with ``=``, ``+``, ``-``, ``@``,
a tab or a carriage return as a formula. Every text cell (ids, names, reasons) that
starts with one of them gets a leading ``'``; numbers and booleans are written as such
and are never touched. Markdown cells have newlines turned into a space and ``|`` and
backticks escaped.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Final

from control.cli.queries import EXPORT_COLUMNS

__all__ = ["FORMATS", "MixedVersionsError", "TelemetryTable"]

FORMATS: Final = ("csv", "md")


#: Cell starts a spreadsheet would read as a formula.
_FORMULA_START: Final = ("=", "+", "-", "@", "\t", "\r")
_LINE_BREAKS: Final = re.compile(r"\r\n|\r|\n")
#: The order ``telemetry_status`` counts are reported in.
_TELEMETRY_STATUSES: Final = ("ok", "error", "missing")


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

    @property
    def telemetry_counts(self) -> dict[str, int]:
        """Rows per ``telemetry_status`` (ok, error, missing; zero included)."""
        counts = Counter(r["telemetry_status"] for r in self._rows)
        return {name: counts.get(name, 0) for name in _TELEMETRY_STATUSES}

    @property
    def not_valid(self) -> int:
        """Rows whose run is not ``valid`` (invalid, queued, still running...)."""
        return sum(1 for r in self._rows if r["status"] != "valid")

    def __len__(self) -> int:
        return len(self._rows)

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

    def _cells(self, row: Mapping[str, Any], *, empty: str, csv_safe: bool) -> list[str]:
        def cell(name: str) -> str:
            value = row[name]  # a run without a summary has None here
            if value is None:
                return empty
            if isinstance(value, bool):
                return str(value).lower()
            text = str(value)
            if csv_safe and isinstance(value, str) and text.startswith(_FORMULA_START):
                return "'" + text
            return text

        return [cell(name) for name in EXPORT_COLUMNS]

    def _csv(self) -> str:
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(EXPORT_COLUMNS)
        writer.writerows(self._cells(row, empty="", csv_safe=True) for row in self._rows)
        return out.getvalue()

    def _markdown(self) -> str:
        def clean(text: str) -> str:
            text = _LINE_BREAKS.sub(" ", text)
            return text.replace("|", "\\|").replace("`", "\\`")

        def line(cells: Sequence[str]) -> str:
            return "| " + " | ".join(clean(c) for c in cells) + " |"

        lines = [line(EXPORT_COLUMNS), line(["---"] * len(EXPORT_COLUMNS))]
        lines += (line(self._cells(row, empty="-", csv_safe=False)) for row in self._rows)
        return "\n".join(lines) + "\n"
