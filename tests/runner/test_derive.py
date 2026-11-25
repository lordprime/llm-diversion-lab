"""Telemetry derivation for one run: the deriver and the store's telemetry rows.

Evidence is written with the real tap recorder, so the files are the ones a cell leaves.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine

from cell.tap.recorder import Recorder, RequestMeta, ResponseMeta, TapConfig
from control.core.ids import new_id
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.derive import DERIVED_SUFFIX, TelemetryDeriver
from control.runner.store import RunStore, StoreError
from control.telemetry.extract import TelemetryError
from control.telemetry.model import TELEMETRY_VERSION, RunTelemetry
from tests.db.test_repo import add_run, seed_experiment
from tests.telemetry.fixtures import ollama_wire as oll

TS = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
ARTIFACTS = {"telemetry/summary.json", "telemetry/calls.jsonl", "telemetry/reasoning.jsonl"}


def record_ollama_calls(evidence: Path, run_id: str, count: int = 1) -> None:
    """``count`` Ollama chat exchanges, written the way the tap writes them."""
    rec = Recorder(TapConfig(run_id=run_id, tags=(), evidence_dir=evidence))
    for _ in range(count):
        rec.record(
            oll.CHAT_REQUEST,
            oll.CHAT_STREAM,
            TS,
            RequestMeta("POST", "/api/chat", "application/json", None, True),
            ResponseMeta(200, "application/x-ndjson", None, True),
        )


@pytest.fixture
def run_id() -> str:
    return new_id("run")


@pytest.fixture
def evidence(tmp_path: Path, run_id: str) -> Path:
    path = tmp_path / "runs" / run_id
    path.mkdir(parents=True)
    return path


def derive(evidence: Path, run_id: str) -> tuple[RunTelemetry, Path]:
    out = TelemetryDeriver.derived_dir(evidence)
    result = TelemetryDeriver().derive(run_id, evidence, out)
    assert {a.path for a in result.artifacts} == ARTIFACTS
    return result.summary, out


# --------------------------------------------------------------------------- the deriver


def test_a_run_with_ollama_calls_gets_its_summary_and_three_files(
    evidence: Path, run_id: str
) -> None:
    record_ollama_calls(evidence, run_id, count=2)
    summary, out = derive(evidence, run_id)
    assert summary.calls == 2 and summary.run_id == run_id
    assert summary.telemetry_version == TELEMETRY_VERSION
    assert summary.peak_input_tokens is not None and summary.reasoning_chars > 0
    assert out == evidence.parent / f"{run_id}{DERIVED_SUFFIX}"
    on_disk = json.loads((out / "telemetry" / "summary.json").read_text())
    assert on_disk["calls"] == 2
    lines = (out / "telemetry" / "calls.jsonl").read_text().splitlines()
    assert len(lines) == 2


def test_the_artifact_hashes_describe_the_files_written(evidence: Path, run_id: str) -> None:
    record_ollama_calls(evidence, run_id)
    out = TelemetryDeriver.derived_dir(evidence)
    result = TelemetryDeriver().derive(run_id, evidence, out)
    for artifact in result.artifacts:
        data = (out / artifact.path).read_bytes()
        assert artifact.sha256 == hashlib.sha256(data).hexdigest()
        assert artifact.size_bytes == len(data)


def test_a_run_without_an_llm_folder_has_an_empty_summary(evidence: Path, run_id: str) -> None:
    summary, out = derive(evidence, run_id)
    assert (summary.calls, summary.agents, summary.peak_input_tokens) == (0, 0, None)
    assert (out / "telemetry" / "calls.jsonl").read_bytes() == b""


def test_corrupt_bodies_become_parse_errors_not_a_failure(evidence: Path, run_id: str) -> None:
    record_ollama_calls(evidence, run_id, count=3)
    llm = evidence / "llm"
    (llm / "0000.req.json").write_bytes(b"\xff\xfe not json {")
    (llm / "0001.resp.body").write_bytes(b'{"half": ')
    (llm / "0002.meta.json").write_bytes(b"[]")
    summary, _ = derive(evidence, run_id)
    assert summary.calls == 3 and summary.parse_errors >= 2


def test_an_llm_folder_that_is_a_symlink_is_refused(
    evidence: Path, run_id: str, tmp_path: Path
) -> None:
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", evidence / "llm")
    with pytest.raises(TelemetryError):
        TelemetryDeriver().derive(run_id, evidence, TelemetryDeriver.derived_dir(evidence))


def test_the_output_folder_is_never_inside_the_evidence(evidence: Path, run_id: str) -> None:
    record_ollama_calls(evidence, run_id)
    with pytest.raises(TelemetryError):
        TelemetryDeriver().derive(run_id, evidence, evidence / "derived")
    assert not (evidence / "derived").exists()


def test_a_huge_run_is_summarised_in_full(evidence: Path, run_id: str) -> None:
    record_ollama_calls(evidence, run_id, count=1500)
    summary, out = derive(evidence, run_id)
    assert summary.calls == 1500
    assert len((out / "telemetry" / "reasoning.jsonl").read_text().splitlines()) == 1500


def test_deriving_again_writes_the_same_bytes(evidence: Path, run_id: str) -> None:
    record_ollama_calls(evidence, run_id, count=2)
    out = TelemetryDeriver.derived_dir(evidence)
    first = TelemetryDeriver().derive(run_id, evidence, out)
    again = TelemetryDeriver().derive(run_id, evidence, out)
    assert first == again
    assert sorted(p.name for p in (out / "telemetry").iterdir()) == sorted(
        n.removeprefix("telemetry/") for n in ARTIFACTS
    )


# --------------------------------------------------------------------------- the store


def _stored_run_summary(engine: Engine, tmp_path: Path, calls: int = 2) -> RunTelemetry:
    """A real summary of ``calls`` Ollama calls, for a run that exists in the database."""
    run_id = add_run(engine, seed_experiment(engine), schedule_index=0)
    evidence = tmp_path / "runs" / run_id
    evidence.mkdir(parents=True)
    record_ollama_calls(evidence, run_id, count=calls)
    return derive(evidence, run_id)[0]


def _row(engine: Engine, run_id: str) -> t.RunTelemetryRow | None:
    with session_scope(engine) as s:
        row = s.get(t.RunTelemetryRow, run_id)
        if row is not None:
            s.expunge(row)
        return row


def test_the_store_keeps_every_summary_field(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    RunStore(engine).record_telemetry(summary)
    row = _row(engine, summary.run_id)
    assert row is not None and row.telemetry_error is None
    for field in (
        "calls", "agents", "agents_source", "peak_input_tokens", "input_tokens",
        "output_tokens", "reasoning_chars", "calls_with_reasoning", "single_call_threads",
        "largest_thread_calls", "branch_points", "persona_splits", "telemetry_version",
    ):  # fmt: skip
        assert getattr(row, field) == getattr(summary, field), field


def test_storing_the_same_summary_again_changes_nothing(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    store = RunStore(engine)
    store.record_telemetry(summary)
    first = _row(engine, summary.run_id)
    store.record_telemetry(summary)
    assert _row(engine, summary.run_id).created_at == first.created_at  # type: ignore[union-attr]


def test_a_stored_summary_is_write_once(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    store = RunStore(engine)
    store.record_telemetry(summary)
    other = summary.model_copy(update={"calls": summary.calls + 1})
    with pytest.raises(StoreError, match="already has different telemetry"):
        store.record_telemetry(other)
    with pytest.raises(StoreError):
        store.record_telemetry_error(summary.run_id, "late failure")
    row = _row(engine, summary.run_id)
    assert row is not None and row.calls == summary.calls and row.telemetry_error is None


def test_an_error_row_is_replaced_by_a_later_summary(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    store = RunStore(engine)
    store.record_telemetry_error(summary.run_id, "first try failed")
    store.record_telemetry_error(summary.run_id, "second try failed")
    row = _row(engine, summary.run_id)
    assert row is not None and row.telemetry_error == "second try failed" and row.calls is None
    store.record_telemetry(summary)
    row = _row(engine, summary.run_id)
    assert row is not None and row.telemetry_error is None and row.calls == summary.calls


def test_the_error_text_is_redacted_and_bounded(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    RunStore(engine).record_telemetry_error(
        summary.run_id, "postgresql://lab:hunter2secret@db/lab refused " + "x" * 9000
    )
    row = _row(engine, summary.run_id)
    assert row is not None and row.telemetry_error is not None
    assert "hunter2secret" not in row.telemetry_error and len(row.telemetry_error) <= 4000


def test_telemetry_for_an_unknown_run_is_refused(engine: Engine, tmp_path: Path) -> None:
    summary = _stored_run_summary(engine, tmp_path)
    store = RunStore(engine)
    with pytest.raises(StoreError, match="no run"):
        store.record_telemetry(summary.model_copy(update={"run_id": "run_nope"}))
    with pytest.raises(StoreError, match="no run"):
        store.record_telemetry_error("run_nope", "boom")
