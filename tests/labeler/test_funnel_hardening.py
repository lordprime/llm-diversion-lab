"""Labeller refusals for incomplete or adversarial evidence (cell -> control plane)."""

from __future__ import annotations

import gzip
import json
import os
import shutil
from pathlib import Path

import pytest

from cell.catcher.callback_log import (
    CATCHER_DNS_STREAM,
    CATCHER_HTTP_STREAM,
    DNS_EVENTS_FILE,
    HTTP_EVENTS_FILE,
)
from cell.injector.placement import INJECTOR_STREAM
from cell.injector.serve_log import EVENTS_FILE as INJECTOR_EVENTS_FILE
from cell.tap.recorder import EVENTS_FILE as TAP_EVENTS_FILE
from cell.tap.recorder import TAP_STREAM
from control.core.models import Arm, EventKind, FunnelStage, RunManifest
from control.labeler import funnel
from control.labeler.funnel import (
    EVENT_FILES,
    MAX_DECODED_BODY_BYTES,
    IncompleteEvidenceError,
    LabelingError,
    label_run,
    load_run_evidence,
)
from tests.labeler.test_funnel import (
    FIXTURES,
    TAG,
    _body,
    _by_stage,
    _evidence,
    _fixture,
    _manifest,
    _meta,
    _raw_meta,
)


def _copy(name: str, tmp_path: Path) -> Path:
    dest = tmp_path / name
    shutil.copytree(FIXTURES / name / "evidence", dest)
    return dest


def _manifest_of(name: str) -> RunManifest:
    return RunManifest.model_validate_json((FIXTURES / name / "manifest.json").read_bytes())


def _load(name: str, evidence_dir: Path) -> funnel.RunEvidence:
    forbidden = json.loads((FIXTURES / name / "forbidden_tags.json").read_text())
    return load_run_evidence(
        evidence_dir, _manifest_of(name), forbidden_tags=forbidden, verdict=None
    )


# --------------------------------------------------------------------------- 1: orphans


def test_torn_llm_event_line_with_full_artifacts_is_incomplete(tmp_path: Path) -> None:
    # The tap wrote 0000.req.json and 0000.meta.json, then crashed mid event line.
    evidence_dir = _copy("callback_uptake", tmp_path)
    events = evidence_dir / "llm" / "events.jsonl"
    events.write_bytes(events.read_bytes()[:40])
    evidence = _load("callback_uptake", evidence_dir)
    assert evidence.llm_calls == ()
    assert evidence.skipped_lines == ("llm/events.jsonl:1",)
    assert evidence.orphan_artifacts == ("llm/0000.meta.json", "llm/0000.req.json")
    with pytest.raises(IncompleteEvidenceError) as exc:
        label_run(evidence)
    assert "llm/0000.req.json" in str(exc.value)


def test_request_without_event_is_incomplete(tmp_path: Path) -> None:
    # The tap crashed between begin (request written) and finish (meta + event line).
    evidence_dir = _copy("served_not_visible", tmp_path)
    (evidence_dir / "llm" / "0002.req.json").write_bytes(_body(f"robots: {TAG}"))
    evidence = _load("served_not_visible", evidence_dir)
    assert evidence.orphan_artifacts == ("llm/0002.req.json",)
    with pytest.raises(IncompleteEvidenceError) as exc:
        label_run(evidence)
    assert "llm/0002.req.json" in str(exc.value)


def test_orphan_in_control_run_is_incomplete(tmp_path: Path) -> None:
    evidence_dir = _copy("control", tmp_path)
    (evidence_dir / "llm" / "0007.meta.json").write_text("{}")
    with pytest.raises(IncompleteEvidenceError):
        label_run(_load("control", evidence_dir))


def test_skipped_lines_are_recorded_in_every_label() -> None:
    labels = label_run(_fixture("full_funnel"))
    assert len(labels) == 4
    for label in labels:
        assert label.detail["skipped_lines"] == ["injector/events.jsonl:6"], label.stage
    for label in label_run(_fixture("control")):
        assert label.detail["skipped_lines"] == []


# --------------------------------------------------------------------------- 2: bombs


def test_gzip_bomb_with_bad_trailer_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(funnel, "MAX_DECODED_BODY_BYTES", 1_000_000)
    wire = gzip.compress(b"\0" * 3_000_000)
    wire = wire[:-8] + b"\xff" * 8  # the tap's decode failed on the trailer: stored raw
    ev = _evidence(calls=[(wire, _raw_meta(0, "gzip"))])
    with pytest.raises(IncompleteEvidenceError) as exc:
        label_run(ev)
    assert "tap#0" in str(exc.value)


def test_bomb_in_non_candidate_call_is_also_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(funnel, "MAX_DECODED_BODY_BYTES", 1_000_000)
    wire = gzip.compress(b"\0" * 3_000_000)
    ev = _evidence(calls=[(wire, _raw_meta(0, "gzip", path="/v1/messages/count_tokens"))])
    with pytest.raises(IncompleteEvidenceError):
        label_run(ev)


def test_decoded_body_cap_is_64_mib() -> None:
    assert MAX_DECODED_BODY_BYTES == 64 * 1024 * 1024


# --------------------------------------------------------------------------- 3: no meta


def test_missing_meta_with_non_json_body_is_incomplete() -> None:
    ev = _evidence(calls=[(gzip.compress(_body(TAG)), None)])
    with pytest.raises(IncompleteEvidenceError) as exc:
        label_run(ev)
    assert "tap#0" in str(exc.value)


def test_missing_meta_with_non_json_body_in_control_run_is_incomplete() -> None:
    ev = _evidence(
        _manifest(Arm.CONTROL),
        calls=[(gzip.compress(_body(TAG)), None)],
        forbidden=frozenset({TAG}),
    )
    with pytest.raises(IncompleteEvidenceError):
        label_run(ev)


def test_missing_meta_with_untagged_json_body_still_labels() -> None:
    ev = _evidence(calls=[(_body("nothing"), None), (_body(TAG), _meta(1))])
    visible = _by_stage(label_run(ev))[FunnelStage.VISIBLE]
    assert visible.value is True
    assert visible.detail["first_seq"] == 1


# --------------------------------------------------------------------------- 4: kinds/streams


def test_event_files_match_the_producers() -> None:
    assert EVENT_FILES[INJECTOR_EVENTS_FILE].stream == INJECTOR_STREAM
    assert EVENT_FILES[INJECTOR_EVENTS_FILE].kinds == frozenset(
        {EventKind.TARGET_ACCESS, EventKind.PLACEMENT_SERVE}
    )
    assert EVENT_FILES[TAP_EVENTS_FILE].stream == TAP_STREAM
    assert EVENT_FILES[TAP_EVENTS_FILE].kinds == frozenset({EventKind.LLM_CALL})
    assert EVENT_FILES[HTTP_EVENTS_FILE].stream == CATCHER_HTTP_STREAM
    assert EVENT_FILES[DNS_EVENTS_FILE].stream == CATCHER_DNS_STREAM
    for rel in (HTTP_EVENTS_FILE, DNS_EVENTS_FILE):
        assert EVENT_FILES[rel].kinds == frozenset({EventKind.CALLBACK})
    assert EVENT_FILES["agent/events.jsonl"].stream == "agent"
    assert EVENT_FILES["agent/events.jsonl"].kinds == frozenset({EventKind.AGENT_EVENT})
    assert EVENT_FILES["oracle/events.jsonl"].stream == "oracle"
    assert EVENT_FILES["oracle/events.jsonl"].kinds == frozenset({EventKind.ORACLE_POLL})
    assert len(EVENT_FILES) == 6


def test_forged_placement_serve_in_agent_events_is_rejected(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    injector_lines = (evidence_dir / "injector" / "events.jsonl").read_text().splitlines()
    serve = json.loads(injector_lines[1])
    assert serve["kind"] == "placement_serve"
    (evidence_dir / "injector" / "events.jsonl").unlink()
    (evidence_dir / "agent").mkdir()
    (evidence_dir / "agent" / "events.jsonl").write_text(json.dumps(serve) + "\n")
    with pytest.raises(LabelingError) as exc:
        _load("served_not_visible", evidence_dir)
    assert "agent/events.jsonl" in str(exc.value)
    # even when renamed to the agent's own stream
    serve["stream"] = "agent"
    (evidence_dir / "agent" / "events.jsonl").write_text(json.dumps(serve) + "\n")
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


def test_right_kind_on_wrong_stream_is_rejected(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    events = evidence_dir / "llm" / "events.jsonl"
    lines = events.read_text().splitlines()
    doc = json.loads(lines[0])
    doc["stream"] = "agent"
    lines[0] = json.dumps(doc)
    events.write_text("\n".join(lines) + "\n")
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


# --------------------------------------------------------------------------- 5: files


def test_symlinked_request_outside_evidence_is_refused(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(_body("secret outside the evidence dir"))
    req = evidence_dir / "llm" / "0001.req.json"
    req.unlink()
    req.symlink_to(outside)
    with pytest.raises(LabelingError) as exc:
        _load("served_not_visible", evidence_dir)
    assert "0001.req.json" in str(exc.value)


def test_symlink_inside_evidence_is_also_refused(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    req = evidence_dir / "llm" / "0001.req.json"
    req.unlink()
    req.symlink_to(evidence_dir / "llm" / "0000.req.json")
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


def test_symlinked_events_file_is_refused(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    outside = tmp_path / "events.jsonl"
    events = evidence_dir / "injector" / "events.jsonl"
    shutil.move(events, outside)
    events.symlink_to(outside)
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


def test_symlinked_directory_is_refused(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    outside = tmp_path / "llm_elsewhere"
    shutil.move(evidence_dir / "llm", outside)
    os.symlink(outside, evidence_dir / "llm")
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


def test_directory_symlink_inside_evidence_is_refused(tmp_path: Path) -> None:
    # resolves inside evidence_dir and O_NOFOLLOW only guards the last component, so the
    # per-component symlink check is what refuses this
    evidence_dir = _copy("served_not_visible", tmp_path)
    shutil.move(evidence_dir / "llm", evidence_dir / "elsewhere")
    os.symlink("elsewhere", evidence_dir / "llm")
    with pytest.raises(LabelingError) as exc:
        _load("served_not_visible", evidence_dir)
    assert "symlink" in str(exc.value)


def test_oversized_jsonl_line_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    monkeypatch.setattr(funnel, "MAX_JSONL_LINE_BYTES", 100)
    with pytest.raises(IncompleteEvidenceError) as exc:
        _load("served_not_visible", evidence_dir)
    assert "events.jsonl:1" in str(exc.value)


def test_oversized_file_is_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    monkeypatch.setattr(funnel, "MAX_EVIDENCE_FILE_BYTES", 1000)
    with pytest.raises(IncompleteEvidenceError):
        _load("served_not_visible", evidence_dir)


def test_file_caps_are_stated() -> None:
    assert funnel.MAX_EVIDENCE_FILE_BYTES == 256 * 1024 * 1024
    assert funnel.MAX_JSONL_LINE_BYTES == 16 * 1024 * 1024


def test_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    evidence_dir = _copy("served_not_visible", tmp_path)
    req = evidence_dir / "llm" / "0001.req.json"
    req.unlink()
    os.mkfifo(req)
    with pytest.raises(LabelingError):
        _load("served_not_visible", evidence_dir)


# --------------------------------------------------------------------------- 6: control


def test_control_run_requires_forbidden_tags() -> None:
    with pytest.raises(LabelingError):
        _evidence(_manifest(Arm.CONTROL))
    with pytest.raises(LabelingError):
        load_run_evidence(
            FIXTURES / "control" / "evidence",
            _manifest_of("control"),
            forbidden_tags=[],
            verdict=None,
        )


def test_labeler_version_bumped() -> None:
    assert funnel.LABELER_VERSION == "1.2.0"
