"""Shipping evidence: verbatim event lines, artifacts, and terminal Collector answers."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from control.core.ids import new_id
from control.core.models import ArtifactFile, OraclePoll, TargetAccessEvent
from control.runner import ship
from control.runner.ship import (
    SHIP_FILES,
    CollectorClient,
    CollectorError,
    EvidenceError,
    read_event_lines,
    scan_artifacts,
)

RUN = new_id("run")
TS = datetime(2026, 11, 7, tzinfo=UTC)


def _poll(seq: int, run: str = RUN) -> bytes:
    return (
        OraclePoll(run_id=run, stream="oracle", seq=seq, ts=TS, status=False)
        .model_dump_json()
        .encode()
    )


def test_lines_are_shipped_verbatim_and_torn_lines_skipped(tmp_path: Path) -> None:
    (tmp_path / "oracle").mkdir()
    (tmp_path / "oracle" / "events.jsonl").write_bytes(_poll(0) + b"\n" + _poll(1) + b'\n{"torn')
    skipped: list[str] = []
    lines = read_event_lines(tmp_path, RUN, skipped)
    assert lines == [_poll(0), _poll(1)]
    assert skipped == ["oracle/events.jsonl:3"]


@pytest.mark.parametrize(
    "line",
    [
        _poll(0, new_id("run")),  # another run's event
        TargetAccessEvent(
            run_id=RUN, stream="oracle", seq=5, ts=TS, flow_id="f", method="GET", url="/"
        )
        .model_dump_json()
        .encode(),  # a kind this producer never writes
        b'{"kind": "oracle_poll"}',  # JSON, not an event
    ],
)
def test_a_line_that_does_not_belong_makes_the_evidence_unusable(
    tmp_path: Path, line: bytes
) -> None:
    (tmp_path / "oracle").mkdir()
    (tmp_path / "oracle" / "events.jsonl").write_bytes(line + b"\n")
    with pytest.raises(EvidenceError):
        read_event_lines(tmp_path, RUN, [])


def test_cell_guard_decisions_are_shipped() -> None:
    assert SHIP_FILES["cellguard/decisions.jsonl"].stream == "cellguard"


def test_artifacts_are_hashed_and_links_refused(tmp_path: Path) -> None:
    (tmp_path / "llm").mkdir()
    (tmp_path / "llm" / "0000.req.json").write_bytes(b"{}")
    (files,) = [scan_artifacts(tmp_path)]
    assert files == [
        ArtifactFile(
            path="llm/0000.req.json",
            sha256="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            size_bytes=2,
        )
    ]
    os.symlink("/etc/passwd", tmp_path / "llm" / "x")
    with pytest.raises(EvidenceError, match="not a regular file"):
        scan_artifacts(tmp_path)


def test_hidden_artifact_names_are_refused(tmp_path: Path) -> None:
    (tmp_path / ".hidden").write_bytes(b"x")
    with pytest.raises(EvidenceError, match="artifact path"):
        scan_artifacts(tmp_path)


def test_events_go_in_bounded_batches_and_non_200_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200 if len(bodies) < 3 else 409, json={"reason": "conflict"})

    monkeypatch.setattr(ship, "MAX_EVENTS_PER_BATCH", 2)
    client = CollectorClient(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://c")
    )
    lines = [_poll(i) for i in range(4)]
    assert client.post_events(RUN, lines) == 4
    assert [len(b["events"]) for b in bodies] == [2, 2]  # type: ignore[arg-type]
    assert bodies[0]["run_id"] == RUN
    with pytest.raises(CollectorError) as err:
        client.post_events(RUN, lines[:1])
    assert err.value.status == 409
    assert err.value.reason == "conflict"


def test_a_collector_that_cannot_be_reached_is_a_collector_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = CollectorClient(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://c")
    )
    with pytest.raises(CollectorError) as err:
        client.post_events(RUN, [_poll(0)])
    assert (err.value.status, err.value.reason) == (0, None)
    assert "ConnectError" in str(err.value)


def test_a_rejection_reason_is_read_from_the_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"reason": "unknown_placement", "rejected_id": 1})

    client = CollectorClient(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://c")
    )
    with pytest.raises(CollectorError) as err:
        client.post_events(RUN, [_poll(0)])
    assert (err.value.status, err.value.reason) == (422, "unknown_placement")
    for body in ("not json", "[]", '{"reason": 3}'):
        assert CollectorError("events", 500, body).reason is None
