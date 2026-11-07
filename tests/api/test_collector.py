"""Collector API: idempotent, validated, write-once evidence intake.

Every test runs against a fresh Postgres database migrated to ``head`` (the shared
``engine`` fixture in ``tests/conftest.py``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import OperationalError

from control.api.app import create_app
from control.core import models as m
from control.core.ids import new_id
from control.core.models import Arm, EndStatus, Event
from control.db import repo
from control.db import tables as t
from control.db.engine import create_db_engine, session_scope
from tests.db.test_repo import SHA, TAG, TOKEN, TS, _events, add_run, seed_experiment

OTHER_SHA = "b" * 64
OTHER_TOKEN = "zzzzzzzz2345"  # noqa: S105 -- fixture callback token, not a secret


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as c:
        yield c


# --------------------------------------------------------------------- helpers


def _placement(
    run_id: str, *, token: str = TOKEN, url: str = "http://target/robots.txt"
) -> m.Placement:
    return m.Placement(
        placement_id=new_id("pl"),
        run_id=run_id,
        surface="P1",
        url=url,
        locator="robots.txt:append",
        payload_id="derail-override",
        payload_version="1",
        tag=TAG,
        token=token,
        content_sha256=SHA,
    )


def _injected_run(engine: Engine) -> tuple[str, dict[str, str]]:
    ids = seed_experiment(engine)
    return add_run(engine, ids, schedule_index=0, arm=Arm.INJECTED), ids


def _manifest(engine: Engine, run_id: str) -> m.RunManifest:
    with session_scope(engine) as s:
        run = s.get(t.Run, run_id)
        assert run is not None
        return m.RunManifest(
            run_id=run.run_id,
            experiment_id=run.experiment_id,
            pair_id=run.pair_id,
            arm=run.arm,
            target="dvga",
            agent="scripted",
            model="stub-1",
            schedule_index=run.schedule_index,
            attempt=run.attempt,
            tag=run.tag,
            placements=[_placement(run_id)] if run.arm is Arm.INJECTED else [],
            created_at=TS,
        )


def _run_with_manifest(client: TestClient, engine: Engine) -> tuple[str, str]:
    """An injected run whose manifest (one placement) was posted; (run_id, placement_id)."""
    run_id, _ = _injected_run(engine)
    manifest = _manifest(engine, run_id)
    r = client.post(f"/v1/runs/{run_id}/manifest", content=manifest.model_dump_json())
    assert r.status_code == 200, r.text
    return run_id, manifest.placements[0].placement_id


def _batch_json(run_id: str, events: list[Event]) -> str:
    return m.EventBatch(run_id=run_id, events=events).model_dump_json()


def _count(engine: Engine, table: type[Any]) -> int:
    with session_scope(engine) as s:
        return s.scalar(select(func.count()).select_from(table)) or 0


def _event_rows(engine: Engine) -> int:
    return sum(_count(engine, table) for table in t.EVENT_TABLES.values())


def _rejected(engine: Engine) -> list[t.RejectedBatch]:
    with session_scope(engine) as s:
        return list(s.scalars(select(t.RejectedBatch).order_by(t.RejectedBatch.id)))


def _run(engine: Engine, run_id: str) -> t.Run:
    with session_scope(engine) as s:
        run = s.get(t.Run, run_id)
        assert run is not None
        return run


def _verdict(run_id: str, **overrides: Any) -> m.Verdict:
    fields: dict[str, Any] = {
        "run_id": run_id,
        "end_status": EndStatus.COMPLETED,
        "outcome": True,
        "oracle_message": "ssrf reached the canary",
        "decided_at": TS,
    } | overrides
    return m.Verdict(**fields)


# --------------------------------------------------------------------- health


def test_healthz_is_live_without_a_database() -> None:
    with TestClient(create_app(create_db_engine("postgresql://x:y@127.0.0.1:1/none"))) as c:
        r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_ok_when_database_reachable(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready"}


def test_readyz_503_when_database_unreachable() -> None:
    engine = create_db_engine(
        "postgresql://x:y@127.0.0.1:1/none", connect_args={"connect_timeout": 2}
    )
    with TestClient(create_app(engine)) as c:
        r = c.get("/readyz")
    assert r.status_code == 503
    assert r.json()["status"] == "unavailable"


# --------------------------------------------------------------------- events


def test_same_batch_twice_stores_events_once(client: TestClient, engine: Engine) -> None:
    run_id, placement_id = _run_with_manifest(client, engine)
    body = _batch_json(run_id, _events(run_id, placement_id))
    url = f"/v1/runs/{run_id}/events:batch"

    first = client.post(url, content=body)
    assert first.status_code == 200, first.text
    assert first.json() == {"run_id": run_id, "inserted": 7, "duplicates": 0, "conflicts": []}
    assert _event_rows(engine) == 7

    second = client.post(url, content=body)
    assert second.status_code == 200, second.text
    assert second.json() == {"run_id": run_id, "inserted": 0, "duplicates": 7, "conflicts": []}
    assert _event_rows(engine) == 7
    assert _count(engine, t.EventKeyEntry) == 7
    assert _rejected(engine) == []


def test_schema_invalid_batch_is_422_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    good = json.loads(
        _batch_json(
            run_id,
            [m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)],
        )
    )
    good["events"][0]["seq"] = -1  # violates NonNegativeInt
    body = json.dumps(good).encode()

    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)

    assert r.status_code == 422, r.text
    payload = r.json()
    assert payload["reason"] == "invalid"
    assert any("seq" in [str(p) for p in err["loc"]] for err in payload["errors"])
    assert _event_rows(engine) == 0
    [rejected] = _rejected(engine)
    assert rejected.id == payload["rejected_id"]
    assert rejected.run_id == run_id
    assert rejected.endpoint is m.CollectorEndpoint.EVENTS
    assert rejected.reason is m.RejectReason.INVALID
    assert rejected.body == body  # the exact bytes, kept for later inspection
    assert rejected.detail


def test_unparseable_body_is_422_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    body = b'{"run_id": "\xff not json'
    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)
    assert r.status_code == 422
    [rejected] = _rejected(engine)
    assert rejected.body == body
    assert rejected.reason is m.RejectReason.INVALID


def test_url_and_payload_run_id_must_match(client: TestClient, engine: Engine) -> None:
    run_id, ids = _injected_run(engine)
    other = add_run(engine, ids, schedule_index=1)
    body = _batch_json(
        other, [m.OraclePoll(run_id=other, stream="oracle", seq=0, ts=TS, status=True)]
    )

    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)

    assert r.status_code == 422
    assert r.json()["reason"] == "run_id_mismatch"
    assert _event_rows(engine) == 0
    [rejected] = _rejected(engine)
    assert rejected.reason is m.RejectReason.RUN_ID_MISMATCH
    assert rejected.run_id == run_id


def test_unknown_run_is_404_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id = new_id("run")
    body = _batch_json(
        run_id, [m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=True)]
    )

    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)

    assert r.status_code == 404
    assert r.json()["reason"] == "unknown_run"
    [rejected] = _rejected(engine)
    assert rejected.reason is m.RejectReason.UNKNOWN_RUN
    assert rejected.body == body.encode()


def test_conflict_stores_the_rest_and_answers_409(client: TestClient, engine: Engine) -> None:
    run_id, placement_id = _run_with_manifest(client, engine)
    url = f"/v1/runs/{run_id}/events:batch"
    events = _events(run_id, placement_id)
    assert client.post(url, content=_batch_json(run_id, events)).status_code == 200

    altered = events[-1].model_copy(update={"status": True})  # oracle#0, different content
    fresh = m.OraclePoll(run_id=run_id, stream="oracle", seq=1, ts=TS, status=True)
    body = _batch_json(run_id, [events[0], altered, fresh])

    r = client.post(url, content=body)

    assert r.status_code == 409, r.text
    payload = r.json()
    assert payload["reason"] == "conflict"
    assert payload["inserted"] == 1
    assert payload["duplicates"] == 1
    assert payload["conflicts"] == [{"stream": "oracle", "seq": 0, "kind": "oracle_poll"}]
    # the honest new event is kept, the conflicting one is not written over the original
    assert _count(engine, t.OraclePoll) == 2
    with session_scope(engine) as s:
        stored = s.scalars(select(t.OraclePoll).where(t.OraclePoll.seq == 0)).one()
        assert stored.status is False
    [rejected] = _rejected(engine)
    assert rejected.id == payload["rejected_id"]
    assert rejected.reason is m.RejectReason.CONFLICT
    assert rejected.body == body.encode()
    assert rejected.detail == [{"stream": "oracle", "seq": 0, "kind": "oracle_poll"}]


def test_event_for_a_placement_of_no_such_run_is_422(client: TestClient, engine: Engine) -> None:
    run_id, _ = _run_with_manifest(client, engine)
    serve = _events(run_id, new_id("pl"))[1]  # placement_serve for an unknown placement
    r = client.post(f"/v1/runs/{run_id}/events:batch", content=_batch_json(run_id, [serve]))
    assert r.status_code == 422
    assert r.json()["reason"] == "unknown_placement"
    assert _event_rows(engine) == 0
    assert [x.reason for x in _rejected(engine)] == [m.RejectReason.UNKNOWN_PLACEMENT]


def test_batch_the_database_refuses_is_422_and_persisted(
    client: TestClient, engine: Engine
) -> None:
    """Schema-valid but unstorable (method longer than its column): nothing half-written."""
    run_id, _ = _injected_run(engine)
    ok = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)
    bad = m.TargetAccessEvent(
        run_id=run_id, stream="injector", seq=0, ts=TS, flow_id="f", method="X" * 40, url="/"
    )
    r = client.post(f"/v1/runs/{run_id}/events:batch", content=_batch_json(run_id, [ok, bad]))
    assert r.status_code == 422, r.text
    assert r.json()["reason"] == "constraint"
    assert _event_rows(engine) == 0
    assert _count(engine, t.EventKeyEntry) == 0
    assert [x.reason for x in _rejected(engine)] == [m.RejectReason.CONSTRAINT]


def test_nul_in_text_is_422_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    ev = m.AgentEvent(
        run_id=run_id, stream="agent", seq=0, ts=TS, event_type="message", text="a\x00b"
    )
    body = _batch_json(run_id, [ev])
    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)
    assert r.status_code == 422, r.text
    assert _event_rows(engine) == 0
    [rejected] = _rejected(engine)
    assert rejected.body == body.encode()


# --------------------------------------------------------------------- verdict


def test_verdict_sets_end_status_and_outcome(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    r = client.post(f"/v1/runs/{run_id}/verdict", content=_verdict(run_id).model_dump_json())
    assert r.status_code == 200, r.text
    assert r.json() == {"run_id": run_id, "result": "stored"}
    run = _run(engine, run_id)
    assert run.end_status is EndStatus.COMPLETED
    assert run.outcome is True
    assert run.oracle_message == "ssrf reached the canary"
    assert run.decided_at == TS


def test_verdict_is_write_once(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    url = f"/v1/runs/{run_id}/verdict"
    assert client.post(url, content=_verdict(run_id).model_dump_json()).status_code == 200

    again = client.post(url, content=_verdict(run_id).model_dump_json())
    assert again.status_code == 200
    assert again.json() == {"run_id": run_id, "result": "duplicate"}

    other = _verdict(run_id, outcome=False, end_status=EndStatus.TIMEOUT)
    r = client.post(url, content=other.model_dump_json())
    assert r.status_code == 409
    assert r.json()["reason"] == "conflict"
    run = _run(engine, run_id)
    assert run.outcome is True
    assert run.end_status is EndStatus.COMPLETED
    assert [x.endpoint for x in _rejected(engine)] == [m.CollectorEndpoint.VERDICT]


def test_verdict_same_instant_other_timezone_is_a_duplicate(
    client: TestClient, engine: Engine
) -> None:
    run_id, _ = _injected_run(engine)
    url = f"/v1/runs/{run_id}/verdict"
    assert client.post(url, content=_verdict(run_id).model_dump_json()).status_code == 200
    shifted = TS.astimezone(timezone(timedelta(hours=2)))
    r = client.post(url, content=_verdict(run_id, decided_at=shifted).model_dump_json())
    assert r.status_code == 200
    assert r.json()["result"] == "duplicate"


def test_verdict_run_id_mismatch_is_422(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    r = client.post(f"/v1/runs/{run_id}/verdict", content=_verdict(new_id("run")).model_dump_json())
    assert r.status_code == 422
    assert _run(engine, run_id).outcome is None


def test_verdict_for_unknown_run_is_404(client: TestClient, engine: Engine) -> None:
    run_id = new_id("run")
    r = client.post(f"/v1/runs/{run_id}/verdict", content=_verdict(run_id).model_dump_json())
    assert r.status_code == 404


# --------------------------------------------------------------------- manifest


def test_manifest_stores_placements_and_hash_once(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    manifest = _manifest(engine, run_id)
    url = f"/v1/runs/{run_id}/manifest"

    r = client.post(url, content=manifest.model_dump_json())
    assert r.status_code == 200, r.text
    assert r.json() == {"run_id": run_id, "result": "stored"}
    assert _count(engine, t.Placement) == 1
    stored_hash = _run(engine, run_id).manifest_sha256
    assert stored_hash is not None
    assert len(stored_hash) == 64

    again = client.post(url, content=manifest.model_dump_json())
    assert again.status_code == 200
    assert again.json()["result"] == "duplicate"
    assert _count(engine, t.Placement) == 1

    changed = manifest.model_copy(update={"placements": [_placement(run_id, token=OTHER_TOKEN)]})
    r = client.post(url, content=changed.model_dump_json())
    assert r.status_code == 409
    assert _count(engine, t.Placement) == 1
    assert _run(engine, run_id).manifest_sha256 == stored_hash
    assert [x.endpoint for x in _rejected(engine)] == [m.CollectorEndpoint.MANIFEST]


def test_manifest_must_agree_with_the_queued_run(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    manifest = _manifest(engine, run_id).model_copy(update={"pair_id": new_id("pair")})
    r = client.post(f"/v1/runs/{run_id}/manifest", content=manifest.model_dump_json())
    assert r.status_code == 409
    assert "pair_id" in r.json()["fields"]
    assert _count(engine, t.Placement) == 0
    assert _run(engine, run_id).manifest_sha256 is None


def test_manifest_schema_invalid_is_422_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    bad = json.loads(_manifest(engine, run_id).model_dump_json())
    bad["placements"] = []  # injected run without placements
    r = client.post(f"/v1/runs/{run_id}/manifest", content=json.dumps(bad))
    assert r.status_code == 422
    assert [x.endpoint for x in _rejected(engine)] == [m.CollectorEndpoint.MANIFEST]


# --------------------------------------------------------------------- artifacts


def _artifacts(run_id: str, *files: tuple[str, str, int]) -> str:
    return m.ArtifactBatch(
        run_id=run_id,
        artifacts=[m.ArtifactFile(path=p, sha256=h, size_bytes=n) for p, h, n in files],
    ).model_dump_json()


def test_artifacts_registered_idempotently(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    url = f"/v1/runs/{run_id}/artifacts"
    body = _artifacts(run_id, ("manifest.json", SHA, 10), ("llm/0000.req.json", SHA, 99))

    r = client.post(url, content=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"run_id": run_id, "inserted": 2, "duplicates": 0, "conflicts": []}
    r = client.post(url, content=body)
    assert r.json() == {"run_id": run_id, "inserted": 0, "duplicates": 2, "conflicts": []}
    assert _count(engine, t.Artifact) == 2


def test_artifact_rehash_is_a_conflict(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    url = f"/v1/runs/{run_id}/artifacts"
    assert client.post(url, content=_artifacts(run_id, ("net.pcap", SHA, 5))).status_code == 200

    body = _artifacts(run_id, ("net.pcap", OTHER_SHA, 5), ("oracle.json", SHA, 2))
    r = client.post(url, content=body)

    assert r.status_code == 409
    assert r.json()["conflicts"] == ["net.pcap"]
    assert r.json()["inserted"] == 1
    with session_scope(engine) as s:
        pcap = s.get(t.Artifact, (run_id, "net.pcap"))
        assert pcap is not None
        assert pcap.sha256 == SHA
    assert [x.reason for x in _rejected(engine)] == [m.RejectReason.CONFLICT]


@pytest.mark.parametrize(
    "path", ["../etc/passwd", "/abs/path", "a//b", "a/../b", ".hidden", "a\\b", ""]
)
def test_artifact_path_must_be_a_safe_relative_key(
    client: TestClient, engine: Engine, path: str
) -> None:
    run_id, _ = _injected_run(engine)
    body = json.dumps(
        {"run_id": run_id, "artifacts": [{"path": path, "sha256": SHA, "size_bytes": 1}]}
    )
    r = client.post(f"/v1/runs/{run_id}/artifacts", content=body)
    assert r.status_code == 422
    assert _count(engine, t.Artifact) == 0
    assert [x.reason for x in _rejected(engine)] == [m.RejectReason.INVALID]


# --------------------------------------------------------------------- status


def _heartbeat(run_id: str, seq: int, phase: m.RunPhase, **kw: Any) -> str:
    return m.RunHeartbeat(
        run_id=run_id, seq=seq, phase=phase, ts=datetime.now(UTC), **kw
    ).model_dump_json()


def test_status_heartbeats_are_stored_idempotently(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    url = f"/v1/runs/{run_id}/status"
    hb = _heartbeat(run_id, 0, m.RunPhase.AGENT_RUNNING)

    r = client.post(url, content=hb)
    assert r.status_code == 200, r.text
    assert r.json() == {"run_id": run_id, "result": "stored"}
    assert client.post(url, content=hb).json()["result"] == "duplicate"
    assert _count(engine, t.RunHeartbeatRow) == 1

    clash = client.post(url, content=_heartbeat(run_id, 0, m.RunPhase.TEARDOWN))
    assert clash.status_code == 409
    assert _count(engine, t.RunHeartbeatRow) == 1


# --------------------------------------------------------------------- surface


def test_api_exposes_no_way_to_update_or_delete_evidence() -> None:
    app = create_app(create_db_engine("postgresql://x:y@127.0.0.1:1/none"))
    paths = app.openapi()["paths"]
    assert {path: set(ops) for path, ops in paths.items()} == {
        "/v1/runs/{run_id}/manifest": {"post"},
        "/v1/runs/{run_id}/events:batch": {"post"},
        "/v1/runs/{run_id}/artifacts": {"post"},
        "/v1/runs/{run_id}/verdict": {"post"},
        "/v1/runs/{run_id}/status": {"post"},
        "/healthz": {"get"},
        "/readyz": {"get"},
    }
    # and nothing hidden from the schema answers a mutating method either
    run_id = new_id("run")
    with TestClient(app) as c:
        for path in paths:
            url = path.replace("{run_id}", run_id)
            for method in ("PUT", "PATCH", "DELETE"):
                assert c.request(method, url).status_code == 405, (method, url)


# --------------------------------------------------------------------- limits and failures


def test_oversized_batch_is_422_and_persisted(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    n = m.MAX_EVENTS_PER_BATCH + 1
    events = [
        m.OraclePoll(run_id=run_id, stream="oracle", seq=i, ts=TS, status=False).model_dump(
            mode="json"
        )
        for i in range(n)
    ]
    body = json.dumps({"schema_version": 1, "run_id": run_id, "events": events}).encode()

    r = client.post(f"/v1/runs/{run_id}/events:batch", content=body)

    assert r.status_code == 422, r.text
    assert r.json()["reason"] == "invalid"
    assert _event_rows(engine) == 0
    [rejected] = _rejected(engine)
    assert rejected.reason is m.RejectReason.INVALID
    assert rejected.body == body


def test_oversized_artifact_batch_is_422(client: TestClient, engine: Engine) -> None:
    run_id, _ = _injected_run(engine)
    files = [
        {"path": f"f/{i}", "sha256": SHA, "size_bytes": 1}
        for i in range(m.MAX_ARTIFACTS_PER_BATCH + 1)
    ]
    body = json.dumps({"run_id": run_id, "artifacts": files})
    r = client.post(f"/v1/runs/{run_id}/artifacts", content=body)
    assert r.status_code == 422
    assert [x.reason for x in _rejected(engine)] == [m.RejectReason.INVALID]


def test_unexpected_db_error_is_500_and_body_kept(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any, **__: Any) -> Any:
        raise OperationalError("INSERT ...", {}, Exception("server closed the connection"))

    monkeypatch.setattr(repo, "insert_events", broken)
    run_id, _ = _injected_run(engine)
    body = _batch_json(
        run_id, [m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=True)]
    )

    with TestClient(create_app(engine), raise_server_exceptions=False) as c:
        r = c.post(f"/v1/runs/{run_id}/events:batch", content=body)

    assert r.status_code == 500
    assert r.json()["reason"] == "db_error"
    assert _event_rows(engine) == 0
    [rejected] = _rejected(engine)
    assert rejected.id == r.json()["rejected_id"]
    assert rejected.reason is m.RejectReason.DB_ERROR
    assert rejected.endpoint is m.CollectorEndpoint.EVENTS
    assert rejected.body == body.encode()
