import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from control.core import models as m
from control.core.ids import new_id
from control.core.models import (
    ALL_MODELS,
    AgentEvent,
    Arm,
    Callback,
    EndStatus,
    EventBatch,
    FunnelLabel,
    FunnelStage,
    LlmCall,
    OraclePoll,
    Placement,
    PlacementServe,
    RunManifest,
    RunStatus,
    Surface,
    TargetAccessEvent,
    Verdict,
)
from control.core.tokens import derive_token, new_tag

TS = "2026-11-07T12:00:00Z"
RUN = "run_01JC0000000000000000000000"
EXP = "exp_01JC0000000000000000000000"
PAIR = "pair_01JC000000000000000000000"
SHA = "a" * 64
TAG = "0123456789abcdef"
TOKEN = "abcdefgh2345"  # noqa: S105 -- fixture callback token, not a secret


def placement_dict(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "placement_id": "pl_1",
        "run_id": RUN,
        "surface": "P1",
        "url": "http://target/robots.txt",
        "locator": "robots.txt:append",
        "payload_id": "derail-override",
        "payload_version": "1",
        "tag": TAG,
        "token": TOKEN,
        "content_sha256": SHA,
    }
    d.update(over)
    return d


def manifest_dict(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "run_id": RUN,
        "experiment_id": EXP,
        "pair_id": PAIR,
        "arm": "injected",
        "target": "dvga",
        "agent": "scripted",
        "model": "stub",
        "schedule_index": 0,
        "attempt": 1,
        "tag": TAG,
        "placements": [placement_dict()],
        "created_at": TS,
    }
    d.update(over)
    return d


EVENT_FIXTURES: dict[type[BaseModel], dict[str, Any]] = {
    PlacementServe: {
        "kind": "placement_serve",
        "run_id": RUN,
        "stream": "injector",
        "seq": 0,
        "ts": TS,
        "placement_id": "pl_1",
        "surface": "P7",
        "flow_id": "f-1",
        "url": "http://target/admin",
        "status": 404,
        "decoded_sha256": SHA,
        "wire_sha256": SHA,
        "byte_offset": 120,
        "insert_ok": True,
        "probe": False,
    },
    TargetAccessEvent: {
        "kind": "target_access",
        "run_id": RUN,
        "stream": "injector",
        "seq": 1,
        "ts": TS,
        "flow_id": "f-1",
        "method": "GET",
        "url": "http://target/robots.txt",
        "status": 200,
        "probe": False,
        "source_ip": "10.0.0.5",
    },
    LlmCall: {
        "kind": "llm_call",
        "run_id": RUN,
        "stream": "tap",
        "seq": 0,
        "ts": TS,
        "role": "main",
        "returned_model": "stub-1",
        "input_tokens": 10,
        "output_tokens": 5,
        "cost_usd": 0.0,
        "stop_reason": "end_turn",
        "tag_present": True,
        "first_tag_seq": 0,
        "request_sha256": SHA,
        "response_sha256": SHA,
        "request_artifact": "llm/0000.req.json",
        "response_artifact": "llm/0000.resp.sse",
    },
    AgentEvent: {
        "kind": "agent_event",
        "run_id": RUN,
        "stream": "agent",
        "seq": 0,
        "ts": TS,
        "event_type": "tool_call",
        "tool_name": "http_get",
        "tool_args": {"url": "http://target/robots.txt", "n": 1, "nested": {"a": [1, None]}},
    },
    Callback: {
        "kind": "callback",
        "run_id": RUN,
        "stream": "catcher-http",
        "seq": 0,
        "ts": TS,
        "channel": "http",
        "source_ip": "10.0.0.5",
        "token": TOKEN,
        "placement_id": "pl_1",
        "method": "GET",
        "url": f"http://cb.lab.test/r/{TOKEN}",
        "host": "cb.lab.test",
        "headers": [["Host", "cb.lab.test"], ["X-A", "1"], ["X-A", "2"]],
        "body_b64": "",
    },
    OraclePoll: {
        "kind": "oracle_poll",
        "run_id": RUN,
        "stream": "oracle",
        "seq": 0,
        "ts": TS,
        "status": True,
        "message": "objective met",
    },
}


@pytest.mark.parametrize("model", list(EVENT_FIXTURES), ids=lambda c: c.__name__)
def test_event_models_construct_from_dict(model: type[BaseModel]) -> None:
    obj = model.model_validate(EVENT_FIXTURES[model])
    assert obj.model_dump(mode="json")["run_id"] == RUN


def test_placement_constructs() -> None:
    p = Placement.model_validate(placement_dict())
    assert p.surface is Surface.P1


@pytest.mark.parametrize("surface", ["P1", "P7"])
def test_placement_surface_accepts_p1_p7(surface: str) -> None:
    assert Placement.model_validate(placement_dict(surface=surface)).surface == surface


@pytest.mark.parametrize("surface", ["P9", "P0", "p1", ""])
def test_placement_surface_rejects_unknown(surface: str) -> None:
    with pytest.raises(ValidationError):
        Placement.model_validate(placement_dict(surface=surface))


def test_surface_enum_is_p1_to_p7() -> None:
    assert [s.value for s in Surface] == [f"P{i}" for i in range(1, 8)]


def test_enum_values() -> None:
    assert {a.value for a in Arm} == {"control", "injected"}
    assert [s.value for s in FunnelStage] == ["access", "visible", "uptake", "outcome"]
    assert {e.value for e in EndStatus} == {
        "completed",
        "budget_exhausted",
        "timeout",
        "refused",
        "crashed",
    }
    assert {s.value for s in RunStatus} == {"queued", "running", "valid", "invalid"}


def test_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Placement.model_validate(placement_dict(surfcae="P1"))


def test_models_are_frozen() -> None:
    p = Placement.model_validate(placement_dict())
    with pytest.raises(ValidationError):
        p.surface = Surface.P2  # type: ignore[misc]


def test_naive_timestamp_rejected() -> None:
    d = dict(EVENT_FIXTURES[OraclePoll], ts="2026-11-07T12:00:00")
    with pytest.raises(ValidationError):
        OraclePoll.model_validate(d)


def test_run_id_rejects_path_traversal() -> None:
    with pytest.raises(ValidationError):
        Placement.model_validate(placement_dict(run_id="../etc"))


def test_bad_sha256_rejected() -> None:
    with pytest.raises(ValidationError):
        Placement.model_validate(placement_dict(content_sha256="xyz"))


def test_real_tag_and_token_validate() -> None:
    tag = new_tag()
    token = derive_token(b"k", RUN, "pl_1")
    p = Placement.model_validate(placement_dict(tag=tag, token=token))
    assert (p.tag, p.token) == (tag, token)


def test_manifest_injected_constructs() -> None:
    mf = RunManifest.model_validate(manifest_dict())
    assert mf.arm is Arm.INJECTED
    assert mf.placements[0].surface is Surface.P1


def test_manifest_control_must_be_tag_free() -> None:
    ok = RunManifest.model_validate(manifest_dict(arm="control", tag=None, placements=[]))
    assert ok.tag is None
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(arm="control", tag=None))
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(arm="control", tag=TAG, placements=[]))


def test_manifest_injected_requires_tag_and_placements() -> None:
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(tag=None))
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(placements=[]))


def test_manifest_placements_must_match_run_and_tag() -> None:
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(placements=[placement_dict(run_id="run_other")]))
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(placements=[placement_dict(tag="f" * 16)]))


def test_manifest_placement_ids_unique() -> None:
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest_dict(placements=[placement_dict(), placement_dict()]))


def test_callback_http_requires_method_and_url() -> None:
    d = dict(EVENT_FIXTURES[Callback])
    del d["method"]
    with pytest.raises(ValidationError):
        Callback.model_validate(d)


def test_callback_dns_requires_qname() -> None:
    base = {
        "kind": "callback",
        "run_id": RUN,
        "stream": "catcher-dns",
        "seq": 1,
        "ts": TS,
        "channel": "dns",
    }
    ok = Callback.model_validate({**base, "qname": f"{TOKEN}.cb.lab.test", "qtype": "A"})
    assert ok.qname == f"{TOKEN}.cb.lab.test"
    with pytest.raises(ValidationError):
        Callback.model_validate(base)


def test_callback_body_bounds_consistent() -> None:
    full = b"0123456789"
    sha = hashlib.sha256(full).hexdigest()
    base = dict(EVENT_FIXTURES[Callback])
    whole = {**base, "body_b64": base64.b64encode(full).decode(), "body_size": 10}
    truncated = {**base, "body_b64": base64.b64encode(full[:4]).decode(), "body_size": 10}
    ok = Callback.model_validate({**whole, "body_sha256": sha})
    assert (ok.body_size, ok.body_truncated) == (10, False)
    cut = Callback.model_validate({**truncated, "body_sha256": sha, "body_truncated": True})
    assert cut.body_truncated
    assert Callback.model_validate(base).body_size is None  # older/DNS-style: unset
    bad = [
        {**truncated, "body_sha256": sha},  # prefix but not marked truncated
        {**whole, "body_sha256": sha, "body_truncated": True},  # marked but whole
        {**truncated, "body_truncated": True},  # truncated without sha256
        {**base, "body_b64": None, "body_size": 10, "body_sha256": sha, "body_truncated": True},
        {**whole, "body_sha256": "nothex"},
        {**whole, "body_size": -1},
        {**whole, "body_b64": "!!notbase64!!"},
    ]
    for doc in bad:
        with pytest.raises(ValidationError):
            Callback.model_validate(doc)


def test_funnel_label_constructs() -> None:
    lbl = FunnelLabel.model_validate(
        {
            "run_id": RUN,
            "stage": "visible",
            "value": True,
            "labeler": "deterministic",
            "labeler_version": "0.1.0",
            "evidence_ref": ["llm/0000.req.json"],
        }
    )
    assert lbl.stage is FunnelStage.VISIBLE


def test_verdict_constructs() -> None:
    v = Verdict.model_validate(
        {"run_id": RUN, "end_status": "completed", "outcome": True, "decided_at": TS}
    )
    assert v.end_status is EndStatus.COMPLETED


def batch_dict(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"run_id": RUN, "events": list(EVENT_FIXTURES.values())}
    d.update(over)
    return d


def test_event_batch_round_trips_json() -> None:
    batch = EventBatch.model_validate(batch_dict())
    assert [type(e) for e in batch.events] == list(EVENT_FIXTURES)
    again = EventBatch.model_validate_json(batch.model_dump_json())
    assert again == batch
    assert again.model_dump_json() == batch.model_dump_json()


def test_event_batch_rejects_foreign_run_id() -> None:
    ev = dict(EVENT_FIXTURES[OraclePoll], run_id="run_other")
    with pytest.raises(ValidationError):
        EventBatch.model_validate(batch_dict(events=[ev]))


def test_event_batch_rejects_duplicate_stream_seq() -> None:
    ev = EVENT_FIXTURES[OraclePoll]
    with pytest.raises(ValidationError):
        EventBatch.model_validate(batch_dict(events=[ev, ev]))


def test_event_batch_rejects_same_stream_seq_across_kinds() -> None:
    # Key is (stream, seq), not (kind, seq): one stream numbers all its events.
    serve = EVENT_FIXTURES[PlacementServe]
    access = dict(EVENT_FIXTURES[TargetAccessEvent], seq=serve["seq"])
    assert serve["stream"] == access["stream"]
    with pytest.raises(ValidationError):
        EventBatch.model_validate(batch_dict(events=[serve, access]))


def test_event_batch_accepts_same_seq_on_different_streams() -> None:
    # HTTP and DNS catchers both emit kind="callback" and each numbers from 0.
    http_cb = dict(EVENT_FIXTURES[Callback], stream="catcher-http", seq=0)
    dns_cb = {
        "kind": "callback",
        "run_id": RUN,
        "stream": "catcher-dns",
        "seq": 0,
        "ts": TS,
        "channel": "dns",
        "qname": f"{TOKEN}.cb.lab.test",
        "qtype": "A",
    }
    batch = EventBatch.model_validate(batch_dict(events=[http_cb, dns_cb]))
    assert [(e.stream, e.seq) for e in batch.events] == [("catcher-http", 0), ("catcher-dns", 0)]


@pytest.mark.parametrize("model", list(EVENT_FIXTURES), ids=lambda c: c.__name__)
def test_event_requires_stream(model: type[BaseModel]) -> None:
    d = dict(EVENT_FIXTURES[model])
    del d["stream"]
    with pytest.raises(ValidationError):
        model.model_validate(d)


@pytest.mark.parametrize("stream", ["", "Tap", "1tap", "tap_1", "tap.x", "a" * 33])
def test_event_rejects_bad_stream(stream: str) -> None:
    with pytest.raises(ValidationError):
        OraclePoll.model_validate(dict(EVENT_FIXTURES[OraclePoll], stream=stream))


def test_event_batch_rejects_unknown_kind() -> None:
    ev = dict(EVENT_FIXTURES[OraclePoll], kind="nope")
    with pytest.raises(ValidationError):
        EventBatch.model_validate(batch_dict(events=[ev]))


def test_all_models_lists_every_model() -> None:
    defined = {
        obj
        for obj in vars(m).values()
        if isinstance(obj, type)
        and issubclass(obj, BaseModel)
        and obj.__module__ == m.__name__
        and not obj.__name__.startswith("_")
    }
    assert set(ALL_MODELS) == defined


def test_new_id_prefix() -> None:
    rid = new_id("run")
    assert rid.startswith("run_")
    assert len(rid) == len("run_") + 26


def test_new_id_unique_and_time_sorted() -> None:
    ids = [new_id("run") for _ in range(2000)]
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids)


def test_new_id_embeds_creation_time() -> None:
    from ulid import ULID

    before = datetime.now(UTC)
    rid = new_id("exp")
    ts = ULID.from_str(rid.removeprefix("exp_")).datetime
    assert abs((ts - before).total_seconds()) < 5


@pytest.mark.parametrize("prefix", ["", "Run", "run_", "r-1", "../x"])
def test_new_id_rejects_bad_prefix(prefix: str) -> None:
    with pytest.raises(ValueError):
        new_id(prefix)
