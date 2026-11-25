"""The telemetry export table on its own: hostile cells in CSV, Markdown escaping."""

from __future__ import annotations

import csv
import io
from typing import Any

import pytest

from control.cli.export import TelemetryTable
from control.cli.queries import EXPORT_COLUMNS

STARTS = ["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"]


def _row(**changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = dict.fromkeys(EXPORT_COLUMNS)
    row.update(run_id="run_1", telemetry_error=None, telemetry_status="ok", calls=3)
    row.update(changes)
    return row


def _parsed(table: TelemetryTable) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(table.render("csv"), newline="")))


@pytest.mark.parametrize("start", STARTS)
@pytest.mark.parametrize("column", ["model", "target", "agent", "invalid_reason", "run_id"])
def test_a_text_cell_starting_like_a_formula_is_neutralised(start: str, column: str) -> None:
    (row,) = _parsed(TelemetryTable([_row(**{column: start + "x"})]))
    assert row[column] == "'" + start + "x"


def test_numbers_and_ordinary_text_are_left_alone() -> None:
    (row,) = _parsed(TelemetryTable([_row(model="qwen3:8b", peak_input_tokens=-5, effect=True)]))
    assert (row["model"], row["peak_input_tokens"], row["effect"], row["calls"]) == (
        "qwen3:8b",
        "-5",  # a number, written as one
        "true",
        "3",
    )


def test_quotes_commas_and_newlines_survive_a_csv_round_trip() -> None:
    nasty = '=HYPERLINK("http://x","a,b")\nsecond "line"'
    (row,) = _parsed(TelemetryTable([_row(agent=nasty, model='a,"b"\nc')]))
    assert row["agent"] == "'" + nasty and row["model"] == 'a,"b"\nc'


def test_markdown_cells_have_no_newlines_pipes_or_backticks() -> None:
    out = TelemetryTable([_row(agent="a|b\nc\r\nd `code`")]).render("md")
    lines = out.splitlines()
    assert len(lines) == 3 and all(line.count("|") - line.count("\\|") == 25 for line in lines)
    assert "a\\|b c d \\`code\\`" in lines[2]
