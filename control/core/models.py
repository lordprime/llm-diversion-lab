"""Domain vocabulary: enums, evidence events, manifests and Collector API envelopes.

These pydantic v2 models are the single source of truth for every event, manifest
and API payload. JSON Schemas under ``schemas/`` are generated from them by
``python -m tools.gen_schemas`` and must never be edited by hand.

Field names use the study's domain words verbatim: ``surface``, ``placement``,
``arm``, ``pair_id``, ``access``, ``visible``, ``uptake``, ``outcome``, ``run_id``,
``experiment_id``.

Event sequencing and idempotency contract
-----------------------------------------
Every evidence event carries ``run_id``, ``stream`` and ``seq``.

* ``stream`` names the *producer* of the event (``STREAM_PATTERN``:
  ``^[a-z][a-z0-9-]{0,31}$``). Conventional names: ``injector``, ``tap``,
  ``catcher-http``, ``catcher-dns``, ``agent``, ``oracle``, ``cellguard``. Two components that
  emit the same ``kind`` (e.g. the HTTP and DNS catchers both emit ``callback``)
  MUST use different streams.
* ``seq`` is numbered per ``(run_id, stream)``: each producer counts its own events
  from 0, monotonically, across all kinds it emits.
* The idempotency key for storing an event is ``(run_id, stream, seq)``. Re-shipping
  an event with the same key is a no-op; ``kind`` is NOT part of the key.
* An :class:`EventBatch` rejects a duplicate ``(stream, seq)`` within one batch.
"""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    NonNegativeFloat,
    NonNegativeInt,
    PositiveInt,
    StringConstraints,
    model_validator,
)

from control.core.ids import ID_PATTERN
from control.core.tokens import TAG_PATTERN, TOKEN_PATTERN

__all__ = [
    "ALL_MODELS",
    "ARTIFACT_PATH_PATTERN",
    "MAX_ARTIFACTS_PER_BATCH",
    "MAX_EVENTS_PER_BATCH",
    "SCHEMA_VERSION",
    "STREAM_PATTERN",
    "AgentEvent",
    "AgentEventType",
    "Arm",
    "ArtifactBatch",
    "ArtifactFile",
    "Callback",
    "CallbackChannel",
    "CellGuardDecision",
    "CollectorEndpoint",
    "EndStatus",
    "Event",
    "EventBatch",
    "EventKind",
    "FunnelLabel",
    "FunnelStage",
    "InvalidReason",
    "LeakFlag",
    "LlmCall",
    "LlmRole",
    "OraclePoll",
    "Placement",
    "PlacementServe",
    "RejectReason",
    "RunHeartbeat",
    "RunManifest",
    "RunPhase",
    "RunStatus",
    "Surface",
    "TargetAccessEvent",
    "Verdict",
]

#: Version of the Collector API envelope format; bump on any breaking model change.
SCHEMA_VERSION: Final = 1

#: Most events one :class:`EventBatch` may carry; ship more as several batches.
MAX_EVENTS_PER_BATCH: Final = 5_000
#: Most files one :class:`ArtifactBatch` may register; ship more as several batches.
MAX_ARTIFACTS_PER_BATCH: Final = 10_000

# --------------------------------------------------------------------------- types

Id = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Tag = Annotated[str, StringConstraints(pattern=TAG_PATTERN)]
Token = Annotated[str, StringConstraints(pattern=TOKEN_PATTERN)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
HttpStatus = Annotated[int, Field(ge=100, le=599)]

#: Accepted shape of an event producer stream name.
STREAM_PATTERN = r"^[a-z][a-z0-9-]{0,31}$"
Stream = Annotated[str, StringConstraints(pattern=STREAM_PATTERN)]

# --------------------------------------------------------------------------- enums


class Surface(StrEnum):
    """Where a placement lives on the target (DEVELOPMENT_PLAN section 4.4)."""

    P1 = "P1"  # comment / extra line in /robots.txt
    P2 = "P2"  # page at a robots.txt-disallowed path
    P3 = "P3"  # HTML comment on a page the task requires
    P4 = "P4"  # off-screen positioned text
    P5 = "P5"  # aria-hidden element
    P6 = "P6"  # JSON-LD descriptive field
    P7 = "P7"  # 403/404 error body on a commonly probed path


class Arm(StrEnum):
    CONTROL = "control"
    INJECTED = "injected"


class FunnelStage(StrEnum):
    """The four funnel stages, in order."""

    ACCESS = "access"
    VISIBLE = "visible"
    UPTAKE = "uptake"
    OUTCOME = "outcome"


class EndStatus(StrEnum):
    """Uniform agent end state, mapped by each adapter's ``wait()``."""

    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    CRASHED = "crashed"


class RunStatus(StrEnum):
    """Run lifecycle status (``runs.status``)."""

    QUEUED = "queued"
    RUNNING = "running"
    VALID = "valid"
    INVALID = "invalid"


class InvalidReason(StrEnum):
    """Why the runner marked a run invalid (``runs.invalid_reason``; a bounded set).

    Set in exactly one place, the runner's error classification. A run that ends
    normally (the agent finished, crashed or timed out, the oracle answered and the
    evidence is complete and clean) is valid, whatever its labels.
    """

    #: the cell could not be rendered or started (config, images, subnets, engine)
    CELL_FAILED = "cell_failed"
    #: the pre-flight probe failed (target unhealthy, placement map wrong, the oracle
    #: not answering "not yet" before the agent)
    PROBE_FAILED = "probe_failed"
    #: no oracle poll succeeded, so there is no verdict
    ORACLE_UNREACHABLE = "oracle_unreachable"
    #: the oracle reported a success it should never report for this target
    ORACLE_UNEXPECTED = "oracle_unexpected"
    #: evidence missing, refused at collection, or not labellable
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    #: a cell component could not record evidence (injector/tap/catcher/cell-guard), a
    #: recorder died or did not stop cleanly, or an event line was torn
    RECORDING_FAILED = "recording_failed"
    #: the injector died, or its evidence lacks the pre-flight probe (DEVELOPMENT_PLAN 5.4)
    INJECTOR_FAILED = "injector_failed"
    #: the agent made no LLM call at all (DEVELOPMENT_PLAN 5.4)
    NO_LLM_CALLS = "no_llm_calls"
    #: a forbidden tag or an unplanned placement serve in the run's evidence (the
    #: labeller's check, or the Collector's ``unknown_placement``)
    CONTAMINATED = "contaminated"
    #: the Collector refused part of the run's evidence (409/422/500) or could not be
    #: reached
    COLLECTOR_REJECTED = "collector_rejected"
    #: the cell could not be fully removed
    TEARDOWN_FAILED = "teardown_failed"
    #: anything else (a runner bug): never silently valid
    INTERNAL = "internal"


class RunPhase(StrEnum):
    """Runner lifecycle phase reported by ``POST /v1/runs/{run_id}/status`` heartbeats.

    Informational only (live dashboard); it never changes ``runs.status``.
    """

    CLAIMED = "claimed"
    CELL_STARTING = "cell_starting"
    PROBING = "probing"
    AGENT_RUNNING = "agent_running"
    COLLECTING = "collecting"
    SHIPPING = "shipping"
    TEARDOWN = "teardown"
    FINISHED = "finished"


class EventKind(StrEnum):
    """Discriminator of evidence events in an :class:`EventBatch`."""

    TARGET_ACCESS = "target_access"
    PLACEMENT_SERVE = "placement_serve"
    LLM_CALL = "llm_call"
    AGENT_EVENT = "agent_event"
    CALLBACK = "callback"
    ORACLE_POLL = "oracle_poll"
    CELLGUARD_DECISION = "cellguard_decision"


class LlmRole(StrEnum):
    """Whether an LLM call was the agent's main call or a secondary (summariser) call."""

    MAIN = "main"
    SECONDARY = "secondary"


class AgentEventType(StrEnum):
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    HTTP_REQUEST = "http_request"
    MESSAGE = "message"
    FINAL_REPORT = "final_report"


class CallbackChannel(StrEnum):
    HTTP = "http"
    DNS = "dns"


class LeakFlag(StrEnum):
    """Leak categories the labeller sets on a callback (DEVELOPMENT_PLAN section 3.4)."""

    LEAK_MODEL = "leak_model"
    LEAK_SYSPROMPT = "leak_sysprompt"
    LEAK_TASK = "leak_task"
    LEAK_OPERATOR = "leak_operator"
    LEAK_TAG = "leak_tag"


# --------------------------------------------------------------------------- bases


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Event(_Model):
    run_id: Id
    stream: Stream
    seq: NonNegativeInt
    ts: AwareDatetime


# --------------------------------------------------------------------------- planned


class Placement(_Model):
    """A planned placement: where a prevention prompt *should* be served in a run."""

    placement_id: Id
    run_id: Id
    surface: Surface
    url: NonEmptyStr
    locator: NonEmptyStr
    payload_id: NonEmptyStr
    payload_version: NonEmptyStr
    tag: Tag
    token: Token
    content_sha256: Sha256


# --------------------------------------------------------------------------- events


class PlacementServe(_Event):
    """A realised placement: one delivery of planted bytes by the surface injector."""

    kind: Literal[EventKind.PLACEMENT_SERVE] = EventKind.PLACEMENT_SERVE
    placement_id: Id
    surface: Surface
    flow_id: NonEmptyStr
    url: NonEmptyStr
    status: HttpStatus
    decoded_sha256: Sha256
    wire_sha256: Sha256
    byte_offset: NonNegativeInt | None = None
    insert_ok: bool
    probe: bool = False


class TargetAccessEvent(_Event):
    """One agent (or pre-flight probe) request to the target, seen by the injector."""

    kind: Literal[EventKind.TARGET_ACCESS] = EventKind.TARGET_ACCESS
    flow_id: NonEmptyStr
    method: NonEmptyStr
    url: NonEmptyStr
    status: HttpStatus | None = None
    probe: bool = False
    source_ip: str | None = None


class LlmCall(_Event):
    """One LLM request/response pair captured by the tap; the basis of *visible*.

    ``first_tag_seq`` is the ``seq`` of the first call in the run whose request body
    contained the run's tag (after JSON-unescaping), or ``None`` if none has yet.
    """

    kind: Literal[EventKind.LLM_CALL] = EventKind.LLM_CALL
    role: LlmRole = LlmRole.MAIN
    requested_model: str | None = None
    returned_model: str | None = None
    input_tokens: NonNegativeInt | None = None
    output_tokens: NonNegativeInt | None = None
    cost_usd: NonNegativeFloat | None = None
    stop_reason: str | None = None
    refusal: bool = False
    refusal_category: str | None = None
    tag_present: bool
    first_tag_seq: NonNegativeInt | None = None
    request_sha256: Sha256
    response_sha256: Sha256 | None = None
    request_artifact: NonEmptyStr
    response_artifact: str | None = None

    @model_validator(mode="after")
    def _first_tag_seq_consistent(self) -> Self:
        if self.tag_present and self.first_tag_seq is None:
            raise ValueError("tag_present requires first_tag_seq")
        if self.first_tag_seq is not None and self.first_tag_seq > self.seq:
            raise ValueError("first_tag_seq cannot be later than seq")
        return self


class AgentEvent(_Event):
    """One normalised step of the agent trajectory (adapter ``collect()``)."""

    kind: Literal[EventKind.AGENT_EVENT] = EventKind.AGENT_EVENT
    event_type: AgentEventType
    tool_name: str | None = None
    tool_args: dict[str, JsonValue] | None = None
    text: str | None = None
    url: str | None = None
    native_ref: str | None = None


class Callback(_Event):
    """One HTTP/HTTPS or DNS contact recorded by the callback catcher.

    ``token`` is set only when a well-formed token was extracted; the raw request is
    always kept in ``url``/``headers``/``body_b64`` or ``qname``.

    An HTTP body is kept inline (``body_b64``) only up to the catcher's cap; the rest
    is read and discarded. ``body_size`` and ``body_sha256`` always describe the
    *whole* body as received, and ``body_truncated`` says whether ``body_b64`` holds
    only its first bytes. DNS callbacks leave all body fields unset.
    """

    kind: Literal[EventKind.CALLBACK] = EventKind.CALLBACK
    channel: CallbackChannel
    source_ip: str | None = None
    token: Token | None = None
    placement_id: Id | None = None
    # HTTP
    method: str | None = None
    url: str | None = None
    host: str | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    query: str | None = None
    body_b64: str | None = None
    body_size: NonNegativeInt | None = None
    body_sha256: Sha256 | None = None
    body_truncated: bool = False
    # DNS
    qname: str | None = None
    qtype: str | None = None

    @model_validator(mode="after")
    def _channel_fields(self) -> Self:
        if self.channel is CallbackChannel.HTTP and not (self.method and self.url):
            raise ValueError("http callback requires method and url")
        if self.channel is CallbackChannel.DNS and not (self.qname and self.qtype):
            raise ValueError("dns callback requires qname and qtype")
        if self.body_truncated and (
            self.body_b64 is None or self.body_size is None or self.body_sha256 is None
        ):
            raise ValueError("body_truncated requires body_b64, body_size and body_sha256")
        if self.body_b64 is not None and self.body_size is not None:
            try:
                inline = len(base64.b64decode(self.body_b64, validate=True))
            except (binascii.Error, ValueError) as exc:
                raise ValueError("body_b64 is not valid base64") from exc
            if self.body_truncated and inline >= self.body_size:
                raise ValueError("a truncated body must keep fewer bytes than body_size")
            if not self.body_truncated and inline != self.body_size:
                raise ValueError("an untruncated body must keep exactly body_size bytes")
        return self


class OraclePoll(_Event):
    """One poll of the oracle's ``GET /done`` (``{"status": bool, "message": str}``)."""

    kind: Literal[EventKind.ORACLE_POLL] = EventKind.ORACLE_POLL
    status: bool
    message: str = ""
    error: str | None = None


class CellGuardDecision(_Event):
    """One request an agent sent to its cell-guard Docker socket, and the decision.

    Written by cell-guard (stream ``cellguard``) before anything is forwarded, allowed
    or denied. A denial is a containment signal. The request body is never stored, only
    its size and sha256 (it may carry the agent's environment). ``forwarded_path`` is
    what was forwarded to the daemon, set exactly when the request was allowed.
    ``target*`` describe the object the request named, as the daemon reported it.
    """

    kind: Literal[EventKind.CELLGUARD_DECISION] = EventKind.CELLGUARD_DECISION
    allowed: bool
    #: Empty ``method``/``op`` only for a request too malformed to parse.
    op: Annotated[str, StringConstraints(max_length=64)]
    rule: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    reason: str
    method: Annotated[str, StringConstraints(max_length=16)]
    path: str
    forwarded_path: str | None = None
    forced: list[str] = Field(default_factory=list)
    target_kind: Annotated[str, StringConstraints(max_length=32)] | None = None
    target: str | None = None
    target_run: str | None = None
    body_bytes: NonNegativeInt
    body_sha256: Sha256

    @model_validator(mode="after")
    def _forwarded_iff_allowed(self) -> Self:
        if self.allowed != (self.forwarded_path is not None):
            raise ValueError("forwarded_path is set exactly when the request was allowed")
        return self


Event = Annotated[
    TargetAccessEvent
    | PlacementServe
    | LlmCall
    | AgentEvent
    | Callback
    | OraclePoll
    | CellGuardDecision,
    Field(discriminator="kind"),
]

# --------------------------------------------------------------------------- labels


class FunnelLabel(_Model):
    """One funnel-stage label for a run, stamped with the labeller that produced it."""

    run_id: Id
    stage: FunnelStage
    value: bool
    labeler: NonEmptyStr
    labeler_version: NonEmptyStr
    evidence_ref: list[str] = Field(default_factory=list)
    detail: dict[str, JsonValue] = Field(default_factory=dict)


# --------------------------------------------------------------------------- manifest


class RunManifest(_Model):
    """Everything planned for one run, written before the agent starts.

    A control run is tag-free: no ``tag`` and no placements. An injected run has a
    tag and at least one placement, each belonging to this run and carrying its tag.
    """

    run_id: Id
    experiment_id: Id
    pair_id: Id
    arm: Arm
    target: NonEmptyStr
    agent: NonEmptyStr
    model: NonEmptyStr
    schedule_index: NonNegativeInt
    attempt: PositiveInt = 1
    tag: Tag | None
    placements: list[Placement]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _arm_invariants(self) -> Self:
        if self.arm is Arm.CONTROL:
            if self.tag is not None or self.placements:
                raise ValueError("control run must have no tag and no placements")
            return self
        if self.tag is None or not self.placements:
            raise ValueError("injected run requires a tag and at least one placement")
        ids = [p.placement_id for p in self.placements]
        if len(set(ids)) != len(ids):
            raise ValueError("placement_id values must be unique")
        for p in self.placements:
            if p.run_id != self.run_id:
                raise ValueError(f"placement {p.placement_id} belongs to another run")
            if p.tag != self.tag:
                raise ValueError(f"placement {p.placement_id} carries a different tag")
        return self


# --------------------------------------------------------------------------- Collector API


class EventBatch(_Model):
    """``POST /v1/runs/{run_id}/events:batch`` body."""

    schema_version: Literal[1] = SCHEMA_VERSION
    run_id: Id
    events: Annotated[list[Event], Field(max_length=MAX_EVENTS_PER_BATCH)]

    @model_validator(mode="after")
    def _events_consistent(self) -> Self:
        seen: set[tuple[str, int]] = set()
        for ev in self.events:
            if ev.run_id != self.run_id:
                raise ValueError(f"event {ev.stream}#{ev.seq} has run_id {ev.run_id}")
            key = (ev.stream, ev.seq)
            if key in seen:
                raise ValueError(f"duplicate event {ev.stream}#{ev.seq} in batch")
            seen.add(key)
        return self


class Verdict(_Model):
    """``POST /v1/runs/{run_id}/verdict`` body: oracle outcome plus end status.

    Write-once per run: the first verdict stored wins; re-posting the same verdict is a
    no-op and a different one is rejected.
    """

    run_id: Id
    end_status: EndStatus
    outcome: bool
    oracle_message: str = ""
    decided_at: AwareDatetime


#: A path segment of an artifact key: no empty, ``.`` or ``..`` segments, no hidden
#: files, no backslashes. Keys are relative to ``runs/<run_id>/``.
_ARTIFACT_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9._+=@,-]*"
ARTIFACT_PATH_PATTERN: Final = rf"^{_ARTIFACT_SEGMENT}(/{_ARTIFACT_SEGMENT})*$"
ArtifactPath = Annotated[str, StringConstraints(pattern=ARTIFACT_PATH_PATTERN, max_length=512)]


class ArtifactFile(_Model):
    """One raw artifact file of a run, identified by its key and content hash.

    ``path`` is relative to the run's artifact directory ``runs/<run_id>/`` (e.g.
    ``llm/0000.req.json``, ``net.pcap``); ``sha256`` and ``size_bytes`` describe the
    exact bytes stored there.
    """

    path: ArtifactPath
    sha256: Sha256
    size_bytes: NonNegativeInt
    media_type: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None


class ArtifactBatch(_Model):
    """``POST /v1/runs/{run_id}/artifacts`` body: register artifact files with sha256.

    Idempotent on ``(run_id, path)``: re-registering a path with the same hash, size and
    media type is a no-op; any difference is a conflict. Paths are unique per batch.
    """

    schema_version: Literal[1] = SCHEMA_VERSION
    run_id: Id
    artifacts: Annotated[list[ArtifactFile], Field(max_length=MAX_ARTIFACTS_PER_BATCH)]

    @model_validator(mode="after")
    def _paths_unique(self) -> Self:
        paths = [a.path for a in self.artifacts]
        if len(set(paths)) != len(paths):
            raise ValueError("artifact paths must be unique within a batch")
        return self


class RunHeartbeat(_Model):
    """``POST /v1/runs/{run_id}/status`` body: one runner lifecycle heartbeat.

    ``seq`` is numbered per run by the runner from 0; the idempotency key is
    ``(run_id, seq)``.
    """

    schema_version: Literal[1] = SCHEMA_VERSION
    run_id: Id
    seq: NonNegativeInt
    phase: RunPhase
    ts: AwareDatetime
    message: str = ""


class CollectorEndpoint(StrEnum):
    """Collector API write endpoint, as recorded on a rejected request."""

    MANIFEST = "manifest"
    EVENTS = "events"
    ARTIFACTS = "artifacts"
    VERDICT = "verdict"
    STATUS = "status"


class RejectReason(StrEnum):
    """Why the Collector API rejected (and kept) a request body."""

    #: not valid JSON, or fails the envelope's schema
    INVALID = "invalid"
    #: ``run_id`` in the URL differs from the one in the payload
    RUN_ID_MISMATCH = "run_id_mismatch"
    #: no such run
    UNKNOWN_RUN = "unknown_run"
    #: an event references a placement that is not planned for this run
    UNKNOWN_PLACEMENT = "unknown_placement"
    #: contradicts evidence already stored (write-once)
    CONFLICT = "conflict"
    #: schema-valid but refused by a database constraint (length, NUL byte, uniqueness)
    CONSTRAINT = "constraint"
    #: any other database failure while storing (answered 500; the body is still kept)
    DB_ERROR = "db_error"


#: Every model with a generated JSON Schema in ``schemas/``.
ALL_MODELS: tuple[type[BaseModel], ...] = (
    Placement,
    PlacementServe,
    TargetAccessEvent,
    LlmCall,
    AgentEvent,
    Callback,
    OraclePoll,
    CellGuardDecision,
    FunnelLabel,
    RunManifest,
    EventBatch,
    Verdict,
    ArtifactFile,
    ArtifactBatch,
    RunHeartbeat,
)
