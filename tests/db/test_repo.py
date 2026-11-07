import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError

from control.core import models as m
from control.core.ids import new_id
from control.core.models import Arm, Event, RunStatus
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import EventKey, InsertResult, claim_next_run, insert_events

TS = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
SHA = "a" * 64
TAG = "0123456789abcdef"
TOKEN = "abcdefgh2345"  # noqa: S105 -- fixture callback token, not a secret


def seed_experiment(engine: Engine) -> dict[str, str]:
    """Insert one experiment with a control and an injected arm, plus registry rows."""
    ids = {
        "experiment_id": new_id("exp"),
        "control_arm_id": new_id("arm"),
        "injected_arm_id": new_id("arm"),
        "target_id": new_id("tgt"),
        "agent_id": new_id("agt"),
        "model_id": new_id("mdl"),
    }
    with session_scope(engine) as s:
        s.add(
            t.Experiment(
                experiment_id=ids["experiment_id"],
                name="m0-selftest",
                definition_yaml="name: m0-selftest\n",
                definition_sha256=SHA,
                schedule_seed=7,
                budget_usd=None,
            )
        )
        s.add_all(
            [
                t.ExperimentArm(
                    arm_id=ids["control_arm_id"],
                    experiment_id=ids["experiment_id"],
                    name="control",
                    arm=Arm.CONTROL,
                    surfaces=[],
                ),
                t.ExperimentArm(
                    arm_id=ids["injected_arm_id"],
                    experiment_id=ids["experiment_id"],
                    name="p1-p7-derail",
                    arm=Arm.INJECTED,
                    surfaces=["P1", "P7"],
                    payload_family="derail",
                    payload_style="override",
                    payload_version="1",
                ),
                t.Target(
                    target_id=ids["target_id"],
                    name="dvga",
                    image_digest="sha256:" + SHA,
                    content_pack_sha256=SHA,
                    placement_map_sha256=SHA,
                    oracle_grader="dvga_ssrf",
                ),
                t.Agent(
                    agent_id=ids["agent_id"],
                    adapter="scripted",
                    adapter_version="0.1.0",
                    framework_version="0.1.0",
                    image_digests={"agent": "sha256:" + SHA},
                    capability_sheet={"tools": ["http"]},
                ),
                t.LlmModel(
                    model_id=ids["model_id"],
                    provider="stub",
                    provider_model="stub-1",
                    effort=None,
                ),
            ]
        )
    return ids


def run_row(
    ids: dict[str, str],
    *,
    schedule_index: int,
    arm: Arm = Arm.CONTROL,
    status: RunStatus = RunStatus.QUEUED,
    pair_id: str | None = None,
) -> t.Run:
    return t.Run(
        run_id=new_id("run"),
        experiment_id=ids["experiment_id"],
        arm_id=ids["control_arm_id" if arm is Arm.CONTROL else "injected_arm_id"],
        arm=arm,
        target_id=ids["target_id"],
        agent_id=ids["agent_id"],
        model_id=ids["model_id"],
        pair_id=pair_id or new_id("pair"),
        schedule_index=schedule_index,
        status=status,
        tag=None if arm is Arm.CONTROL else TAG,
    )


def add_run(engine: Engine, ids: dict[str, str], **kwargs: Any) -> str:
    """Insert one run in its own transaction and return its id."""
    row = run_row(ids, **kwargs)
    with session_scope(engine) as s:
        s.add(row)
    return row.run_id


# --------------------------------------------------------------------- claim_next_run


def test_claim_next_run_skips_locked(engine: Engine) -> None:
    """Two queued runs, two claims -> each returned exactly once; a third gets None.

    The first claim's transaction is still open (its row lock held) when the second
    claim runs, so the second must skip the locked row rather than wait or repeat it.
    """
    ids = seed_experiment(engine)
    queued = {add_run(engine, ids, schedule_index=i) for i in range(2)}

    with session_scope(engine) as first:
        a = claim_next_run(first)
        assert a is not None
        with session_scope(engine) as second:
            b = claim_next_run(second)
            assert b is not None
    assert {a.run_id, b.run_id} == queued

    with session_scope(engine) as third:
        assert claim_next_run(third) is None

    with session_scope(engine) as s:
        rows = s.scalars(select(t.Run)).all()
        assert {r.status for r in rows} == {RunStatus.RUNNING}
        assert all(r.started_at is not None for r in rows)


def test_claim_next_run_none_when_queue_empty(engine: Engine) -> None:
    with session_scope(engine) as s:
        assert claim_next_run(s) is None


def test_claim_next_run_follows_schedule_order_and_skips_non_queued(engine: Engine) -> None:
    """Oldest first (created_at), then by schedule_index; valid/invalid runs are left."""
    ids = seed_experiment(engine)
    # one transaction, so every row has the same created_at (now()); schedule_index
    # then decides the order, not insertion order
    rows = [
        run_row(ids, schedule_index=0, status=RunStatus.VALID),
        run_row(ids, schedule_index=2),
        run_row(ids, schedule_index=1),
        run_row(ids, schedule_index=3, status=RunStatus.INVALID),
    ]
    with session_scope(engine) as s:
        s.add_all(rows)
    first, second = rows[2].run_id, rows[1].run_id

    order = []
    while True:
        with session_scope(engine) as s:
            run = claim_next_run(s)
        if run is None:
            break
        order.append(run.run_id)
    assert order == [first, second]


def test_claim_rolled_back_returns_run_to_queue(engine: Engine) -> None:
    ids = seed_experiment(engine)
    run_id = add_run(engine, ids, schedule_index=0)

    with pytest.raises(RuntimeError), session_scope(engine) as s:
        claimed = claim_next_run(s)
        assert claimed is not None
        raise RuntimeError("worker crashed before commit")

    with session_scope(engine) as s:
        again = claim_next_run(s)
    assert again is not None
    assert again.run_id == run_id


def test_concurrent_workers_never_claim_the_same_run(engine: Engine) -> None:
    ids = seed_experiment(engine)
    queued = {add_run(engine, ids, schedule_index=i) for i in range(24)}
    workers = 8
    start = threading.Barrier(workers)

    def worker() -> list[str]:
        start.wait()
        got: list[str] = []
        while True:
            with session_scope(engine) as s:
                run = claim_next_run(s)
            if run is None:
                return got
            got.append(run.run_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = [f.result() for f in [pool.submit(worker) for _ in range(workers)]]

    claimed = [r for rs in results for r in rs]
    assert len(claimed) == len(set(claimed)) == len(queued)
    assert set(claimed) == queued


# --------------------------------------------------------------------- constraints


def test_control_run_cannot_carry_a_tag(engine: Engine) -> None:
    ids = seed_experiment(engine)
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(
            t.Run(
                run_id=new_id("run"),
                experiment_id=ids["experiment_id"],
                arm_id=ids["control_arm_id"],
                arm=Arm.CONTROL,
                target_id=ids["target_id"],
                agent_id=ids["agent_id"],
                model_id=ids["model_id"],
                pair_id=new_id("pair"),
                schedule_index=0,
                tag=TAG,
            )
        )


def test_run_arm_must_match_its_arm_row(engine: Engine) -> None:
    ids = seed_experiment(engine)
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(
            t.Run(
                run_id=new_id("run"),
                experiment_id=ids["experiment_id"],
                arm_id=ids["control_arm_id"],
                arm=Arm.INJECTED,
                target_id=ids["target_id"],
                agent_id=ids["agent_id"],
                model_id=ids["model_id"],
                pair_id=new_id("pair"),
                schedule_index=0,
                tag=TAG,
            )
        )


# --------------------------------------------------------------------- idempotent events


def _events(run_id: str, placement_id: str) -> list[Event]:
    return [
        m.TargetAccessEvent(
            run_id=run_id, stream="injector", seq=0, ts=TS, flow_id="f1", method="GET", url="/"
        ),
        m.PlacementServe(
            run_id=run_id,
            stream="injector",
            seq=1,
            ts=TS,
            placement_id=placement_id,
            surface="P1",
            flow_id="f2",
            url="/robots.txt",
            status=200,
            decoded_sha256=SHA,
            wire_sha256=SHA,
            byte_offset=12,
            insert_ok=True,
        ),
        m.LlmCall(
            run_id=run_id,
            stream="tap",
            seq=0,
            ts=TS,
            returned_model="stub-1",
            input_tokens=10,
            output_tokens=5,
            cost_usd=0.0125,
            tag_present=True,
            first_tag_seq=0,
            request_sha256=SHA,
            request_artifact="llm/0000.req.json",
        ),
        m.AgentEvent(
            run_id=run_id,
            stream="agent",
            seq=0,
            ts=TS,
            event_type="tool_call",
            tool_name="http",
            tool_args={"url": "http://target/", "n": [1, 2]},
        ),
        # same kind, same seq, different producer streams: both must be kept
        m.Callback(
            run_id=run_id,
            stream="catcher-http",
            seq=0,
            ts=TS,
            channel="http",
            token=TOKEN,
            placement_id=placement_id,
            method="GET",
            url=f"http://cb.lab.test/r/{TOKEN}",
            headers=[("Host", "cb.lab.test"), ("X-A", "1")],
        ),
        m.Callback(
            run_id=run_id,
            stream="catcher-dns",
            seq=0,
            ts=TS,
            channel="dns",
            token=TOKEN,
            qname=f"{TOKEN}.cb.lab.test",
            qtype="A",
        ),
        m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False),
    ]


def _count(engine: Engine, model: type[Any]) -> int:
    with session_scope(engine) as s:
        return s.scalar(select(func.count()).select_from(model)) or 0


def _seed_injected_run(engine: Engine) -> tuple[str, str]:
    """An injected run with one planted placement; returns (run_id, placement_id)."""
    ids = seed_experiment(engine)
    run_id = add_run(engine, ids, schedule_index=0, arm=Arm.INJECTED)
    placement_id = new_id("pl")
    with session_scope(engine) as s:
        s.add(
            t.Placement.from_model(
                m.Placement(
                    placement_id=placement_id,
                    run_id=run_id,
                    surface="P1",
                    url="http://target/robots.txt",
                    locator="robots.txt:append",
                    payload_id="derail-override",
                    payload_version="1",
                    tag=TAG,
                    token=TOKEN,
                    content_sha256=SHA,
                )
            )
        )
    return run_id, placement_id


def _ledger(engine: Engine) -> dict[tuple[str, str, int], m.EventKind]:
    with session_scope(engine) as s:
        return {(e.run_id, e.stream, e.seq): e.kind for e in s.scalars(select(t.EventKeyEntry))}


def _kind_table_counts(engine: Engine) -> dict[str, int]:
    return {table.__tablename__: _count(engine, table) for table in t.EVENT_TABLES.values()}


def test_normal_batch_inserts_all_rows_and_records_every_key(engine: Engine) -> None:
    """(d) a fresh batch: every event stored, every key in event_keys with its kind."""
    run_id, placement_id = _seed_injected_run(engine)
    events = _events(run_id, placement_id)

    with session_scope(engine) as s:
        assert insert_events(s, events) == InsertResult(inserted=len(events))

    assert _ledger(engine) == {(e.run_id, e.stream, e.seq): e.kind for e in events}
    assert _kind_table_counts(engine) == {
        "placement_serves": 1,
        "target_access": 1,
        "llm_calls": 1,
        "agent_events": 1,
        "callbacks": 2,  # catcher-http#0 and catcher-dns#0: same kind+seq, two streams
        "oracle_polls": 1,
    }
    with session_scope(engine) as s:
        http = s.scalars(select(t.Callback).where(t.Callback.stream == "catcher-http")).one()
        assert http.headers == [["Host", "cb.lab.test"], ["X-A", "1"]]
        call = s.scalars(select(t.LlmCall)).one()
        assert float(call.cost_usd or 0) == pytest.approx(0.0125)
        agent = s.scalars(select(t.AgentEvent)).one()
        assert agent.tool_args == {"url": "http://target/", "n": [1, 2]}
        hashes = s.scalars(select(t.EventKeyEntry.content_sha256)).all()
        assert all(len(h) == 64 for h in hashes)
        assert len(set(hashes)) == len(events)


def test_reshipping_identical_events_counts_duplicates(engine: Engine) -> None:
    """(b) an identical re-ship: all duplicates, nothing inserted, no conflict."""
    run_id, placement_id = _seed_injected_run(engine)
    events = _events(run_id, placement_id)
    with session_scope(engine) as s:
        insert_events(s, events)
    before = _kind_table_counts(engine)

    with session_scope(engine) as s:
        result = insert_events(s, events)
    assert result == InsertResult(inserted=0, duplicates=len(events), conflicts=[])
    assert _kind_table_counts(engine) == before
    assert len(_ledger(engine)) == len(events)


def test_same_key_under_another_kind_is_a_conflict(engine: Engine) -> None:
    """(a) injector#0 stored as target_access, re-shipped as placement_serve: rejected."""
    run_id, placement_id = _seed_injected_run(engine)
    access = m.TargetAccessEvent(
        run_id=run_id, stream="injector", seq=0, ts=TS, flow_id="f1", method="GET", url="/"
    )
    with session_scope(engine) as s:
        assert insert_events(s, [access]).inserted == 1

    serve = m.PlacementServe(
        run_id=run_id,
        stream="injector",
        seq=0,
        ts=TS,
        placement_id=placement_id,
        surface="P1",
        flow_id="f1",
        url="/robots.txt",
        status=200,
        decoded_sha256=SHA,
        wire_sha256=SHA,
        insert_ok=True,
    )
    with session_scope(engine) as s:
        result = insert_events(s, [serve])
    assert result == InsertResult(
        inserted=0,
        duplicates=0,
        conflicts=[EventKey(run_id, "injector", 0, m.EventKind.PLACEMENT_SERVE)],
    )
    assert _count(engine, t.PlacementServe) == 0
    assert _count(engine, t.TargetAccess) == 1
    assert _ledger(engine) == {(run_id, "injector", 0): m.EventKind.TARGET_ACCESS}


def test_same_key_and_kind_with_altered_content_is_a_conflict(engine: Engine) -> None:
    """(c) write-once evidence: a changed event under a stored key is rejected."""
    run_id, _ = _seed_injected_run(engine)
    original = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)
    altered = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=True)
    with session_scope(engine) as s:
        insert_events(s, [original])

    with session_scope(engine) as s:
        result = insert_events(s, [altered])
    assert result == InsertResult(
        conflicts=[EventKey(run_id, "oracle", 0, m.EventKind.ORACLE_POLL)]
    )
    with session_scope(engine) as s:
        assert s.scalars(select(t.OraclePoll.status)).all() == [False]


def test_mixed_batch_reports_each_outcome(engine: Engine) -> None:
    """New, duplicate and conflicting events in one batch are each handled correctly."""
    run_id, _ = _seed_injected_run(engine)
    first = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)
    with session_scope(engine) as s:
        insert_events(s, [first])

    later = m.OraclePoll(run_id=run_id, stream="oracle", seq=1, ts=TS, status=True)
    clash = m.TargetAccessEvent(
        run_id=run_id, stream="oracle", seq=0, ts=TS, flow_id="f", method="GET", url="/"
    )
    with session_scope(engine) as s:
        result = insert_events(s, [first, later, clash])
    assert result == InsertResult(
        inserted=1,
        duplicates=1,
        conflicts=[EventKey(run_id, "oracle", 0, m.EventKind.TARGET_ACCESS)],
    )
    assert _count(engine, t.OraclePoll) == 2
    assert _count(engine, t.TargetAccess) == 0


def test_conflict_within_one_call_first_event_wins(engine: Engine) -> None:
    run_id, _ = _seed_injected_run(engine)
    a = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)
    b = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=True)
    with session_scope(engine) as s:
        result = insert_events(s, [a, a, b])
    assert result == InsertResult(
        inserted=1,
        duplicates=1,
        conflicts=[EventKey(run_id, "oracle", 0, m.EventKind.ORACLE_POLL)],
    )
    with session_scope(engine) as s:
        assert s.scalars(select(t.OraclePoll.status)).all() == [False]


def test_per_table_unique_key_is_a_second_line_of_defence(engine: Engine) -> None:
    """A kind-table row written around the ledger makes insert_events fail loudly."""
    run_id, _ = _seed_injected_run(engine)
    poll = m.OraclePoll(run_id=run_id, stream="oracle", seq=0, ts=TS, status=False)
    with session_scope(engine) as s:
        s.add(t.OraclePoll(**poll.model_dump(exclude={"kind"})))  # bypasses event_keys

    with pytest.raises(IntegrityError), session_scope(engine) as s:
        insert_events(s, [poll])
    assert _ledger(engine) == {}  # the failed transaction left no ledger entry


def test_insert_events_empty_input(engine: Engine) -> None:
    with session_scope(engine) as s:
        assert insert_events(s, []) == InsertResult()


def test_claim_next_run_is_fifo_across_transactions(engine: Engine) -> None:
    """A run queued earlier is claimed first even if its schedule_index is larger."""
    ids = seed_experiment(engine)
    earlier = add_run(engine, ids, schedule_index=5)
    later = add_run(engine, ids, schedule_index=0)
    claimed = []
    for _ in range(2):
        with session_scope(engine) as s:
            run = claim_next_run(s)
        assert run is not None
        claimed.append(run.run_id)
    assert claimed == [earlier, later]
