"""Derive one run's telemetry from its collected evidence.

A thin step for the runner: load the tap's calls, summarise them, write the derived
files next to (never inside) the evidence, and describe those files as artifacts so
they ship with the rest. The rules themselves live in :mod:`control.telemetry`.

The derived files go to ``<runs_dir>/<run_id>.derived/telemetry/``, a sibling of the
evidence folder like the verdict file. The output is deterministic, so deriving a run
again writes the same bytes and registers as a duplicate, not a conflict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from control.core.models import ArtifactFile
from control.runner.ship import scan_artifacts
from control.telemetry.extract import load_calls, summarise, write_derived
from control.telemetry.model import RunTelemetry

__all__ = ["DERIVED_SUFFIX", "DerivedTelemetry", "TelemetryDeriver"]

#: Added to the run id to name the derived folder beside the evidence folder.
DERIVED_SUFFIX: Final = ".derived"


@dataclass(frozen=True, slots=True)
class DerivedTelemetry:
    """The summary and the derived files (paths relative to the run's artifact root)."""

    summary: RunTelemetry
    artifacts: tuple[ArtifactFile, ...]


class TelemetryDeriver:
    """Turns a run's tap evidence into a summary and the ``telemetry/*`` files."""

    @staticmethod
    def derived_dir(evidence_dir: Path) -> Path:
        """Where a run's derived files go: beside its evidence folder, never in it."""
        return evidence_dir.with_name(evidence_dir.name + DERIVED_SUFFIX)

    def derive(self, run_id: str, evidence_dir: Path, out_dir: Path) -> DerivedTelemetry:
        """Write the run's telemetry files under ``out_dir``; raises on any failure."""
        calls = load_calls(evidence_dir)
        summary = summarise(run_id, calls)
        write_derived(out_dir, summary, calls)
        return DerivedTelemetry(summary, tuple(scan_artifacts(out_dir)))
