"""The run plan the RedAmon adapter hands to its in-cell driver, and how a session ends.

RedAmon is not one program but a five-service stack (postgres, neo4j, the Kali tool
sandbox, the LangGraph agent and the Next.js webapp), driven over REST and the agent's
``/ws/agent`` WebSocket (AUTOMATION_FEASIBILITY §2.1). The cell's ``agent`` service
runs our driver (:mod:`agents.redamon.driver`), which starts the five services as
siblings through cell-guard, seeds the webapp and drives one chat session.

This module is shared by both sides and imports nothing from the harness, so the
driver image stays small:

* :class:`RunPlan`: everything the adapter decides for a run (the services and their
  switches, the model endpoint, the project body, the limits). Secrets and container
  names are not in it: the driver makes those at run time, and the plan is stored
  with the run as evidence.
* :class:`SessionEnding`: how one session ended, read from the agent's last frame. The
  driver uses it for its exit code and the adapter for the end state's extra flags,
  so both sides read RedAmon's own exit signals the same way.

Every citation is to RedAmon at commit 73ca9d3.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Annotated, Any, Final, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

__all__ = [
    "AGENT_TAG_PATTERN",
    "DRIVER_LOG_FILE",
    "GIB",
    "KALI_STANDIN_MARK",
    "NATIVE_LOG_DIR",
    "OUTCOME_FILE",
    "PLAN_FILE",
    "WS_LOG_FILE",
    "EndingKind",
    "LlmEndpoint",
    "RunPlan",
    "ServiceRole",
    "ServiceSpec",
    "SessionEnding",
]

GIB: Final = 1 << 30
#: The plan's file name in the agent's config volume (``/etc/lab/agent``).
PLAN_FILE: Final = "redamon-plan.json"
#: The driver's evidence, relative to the run's evidence dir (as the scripted agent's
#: ``agent/events.jsonl``): every WebSocket frame, the session's ending, the driver's
#: own steps, and RedAmon's per-session logs copied out of the agent container.
WS_LOG_FILE: Final = "agent/redamon/ws.jsonl"
OUTCOME_FILE: Final = "agent/redamon/outcome.json"
DRIVER_LOG_FILE: Final = "agent/redamon/driver.jsonl"
NATIVE_LOG_DIR: Final = "agent/redamon/native"
#: Every Kali stand-in image carries this in its name, so it can never pass for the
#: real sandbox (the stand-in has the MCP servers but none of the tools).
KALI_STANDIN_MARK: Final = "kali-standin-smoke-only"
#: The ``user`` field patch 0002 writes into every model request: purpose and agent.
AGENT_TAG_PATTERN: Final = re.compile(
    r"^redamon:(?P<purpose>[a-z_]{1,32}):(?P<agent>root|member-\d{1,3}-[0-9a-f]{8})$"
)

_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"
_IMAGE = r"^[a-z0-9][a-z0-9._/:@-]{0,254}$"
_URL = r"^https?://[^\s/]+(/\S*)?$"
_NO_NUL = r"^[^\x00]*$"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServiceRole(StrEnum):
    """The five RedAmon services, in the order the driver starts them."""

    POSTGRES = "postgres"
    NEO4J = "neo4j"
    KALI = "kali"
    AGENT = "agent"
    WEBAPP = "webapp"

    @property
    def container_name(self) -> str:
        """The name the driver asks cell-guard for (cell-guard adds the cell prefix)."""
        return f"redamon-{self.value}"


class ServiceSpec(_Frozen):
    """One sibling container: its image and the settings that do not depend on the run's
    secrets or container names (the driver adds those)."""

    role: ServiceRole
    #: a logical image name from images.lock (or, in the smoke, a local build)
    image: Annotated[str, StringConstraints(pattern=_IMAGE)]
    env: dict[Annotated[str, StringConstraints(pattern=_ENV_NAME)], str] = Field(
        default_factory=dict
    )
    #: cell-guard's ceiling is 2 GiB; a lower request would be kept, so ask for it all
    mem_bytes: Annotated[StrictInt, Field(gt=0, le=2 * GIB)] = 2 * GIB
    #: cell-guard allows NET_RAW and nothing else
    cap_add: tuple[Annotated[str, StringConstraints(pattern=r"^NET_RAW$")], ...] = ()
    #: mounts the cell's scratch volume at /workspace (the agent and Kali share it)
    workspace: StrictBool = False
    #: the port the driver waits on before starting the next service
    port: Annotated[StrictInt, Field(gt=0, lt=65536)]
    #: an HTTP path that must answer 2xx, or None for a plain TCP connect
    health_path: Annotated[str, StringConstraints(pattern=r"^/\S*$")] | None = None


class LlmEndpoint(_Frozen):
    """The one OpenAI-compatible provider row: the tap, and the model behind it."""

    base_url: Annotated[str, StringConstraints(pattern=_URL)]
    model: Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=_NO_NUL)]
    max_tokens: Annotated[StrictInt, Field(gt=0, le=1 << 20)]
    timeout_s: Annotated[StrictInt, Field(gt=0, le=24 * 3600)]


class RunPlan(_Frozen):
    """Everything the driver needs for one run, rendered by the adapter."""

    run_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,127}$")]
    #: the chat session id (the WebSocket ticket's ``sid``)
    session_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,127}$")]
    objective: Annotated[str, StringConstraints(min_length=1, max_length=8192, pattern=_NO_NUL)]
    target_url: Annotated[str, StringConstraints(pattern=_URL)]
    llm: LlmEndpoint
    #: the body of ``POST /api/projects``; the driver adds ``agentOpenaiModel``
    #: (``custom/<provider id>``) once the provider row exists
    project: dict[str, JsonValue]
    services: tuple[ServiceSpec, ...]
    #: the one reply to any question the agent asks (identical in every arm)
    canned_answer: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    #: the run's turn cap, the project's agentMaxIterations
    max_iterations: Annotated[StrictInt, Field(gt=0, le=10_000)]
    #: true only for the CI smoke; the only plan that may use the Kali stand-in
    smoke: StrictBool = False

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        roles = [s.role for s in self.services]
        if roles != list(ServiceRole):
            raise ValueError(
                f"services: one per role in start order {[r.value for r in ServiceRole]}, "
                f"not {[r.value for r in roles]}"
            )
        if "agentOpenaiModel" in self.project:
            raise ValueError("project: agentOpenaiModel is set by the driver, never the plan")
        if self.project.get("agentMaxIterations") != self.max_iterations:
            raise ValueError("project: agentMaxIterations must be the plan's max_iterations")
        kali = self.service(ServiceRole.KALI)
        if KALI_STANDIN_MARK in kali.image and not self.smoke:
            raise ValueError(f"services: the Kali stand-in {kali.image!r} is for the smoke only")
        return self

    def service(self, role: ServiceRole) -> ServiceSpec:
        return next(s for s in self.services if s.role is role)

    @classmethod
    def from_json(cls, text: str) -> RunPlan:
        return cls.model_validate_json(text)


# --------------------------------------------------------------------------- endings


class EndingKind(StrEnum):
    """How a RedAmon session ended, from the agent's own frames."""

    #: task_complete after the model chose to finish
    COMPLETED = "completed"
    #: task_complete because the run reached MAX_ITERATIONS (orchestrator.py:741-743
    #: routes to the final report before it looks at the model's decision)
    TURN_CAP = "turn_cap"
    #: task_complete with think_node's parse fallback (think_node.py:1128-1137)
    TOOL_FORMAT_FAILURE = "tool_format_failure"
    #: task_complete with an ``llm_error:`` reason: a model call failed after retries
    #: (think_node.py:1084-1093, llm_retry.py:237-246)
    LLM_ERROR = "llm_error"
    #: a non-recoverable error frame (websocket_api.py:1619-1630)
    RUN_ERROR = "run_error"
    #: the agent confirmed a stop (only the driver sends one, on SIGTERM)
    STOPPED = "stopped"
    #: the driver never got the session started (stack, seeding or socket)
    SETUP_FAILED = "setup_failed"
    #: the socket closed before any end frame
    CONNECTION_LOST = "connection_lost"

    @property
    def exit_code(self) -> int:
        """The driver's exit code: 0 only when the agent ran to an end of its own."""
        return _EXIT_CODES[self]


_EXIT_CODES: Final = {
    EndingKind.COMPLETED: 0,
    EndingKind.TURN_CAP: 0,
    EndingKind.TOOL_FORMAT_FAILURE: 0,
    EndingKind.LLM_ERROR: 5,
    EndingKind.RUN_ERROR: 3,
    EndingKind.STOPPED: 143,
    EndingKind.SETUP_FAILED: 2,
    EndingKind.CONNECTION_LOST: 4,
}

#: think_node.py:1135: the completion reason of the parse fallback.
_PARSE_FAILURE = re.compile(r"^Unable to continue: JSON parsing failed after \d+ attempts$")
#: llm_retry.py:246: the completion reason of a failed model call.
_LLM_ERROR = "llm_error:"


class SessionEnding(_Frozen):
    """The end of one session, as the driver writes it to :data:`OUTCOME_FILE`."""

    kind: EndingKind
    #: the frame's own text: task_complete's message, an error's message, or the
    #: driver's reason when the agent never said anything
    message: Annotated[str, StringConstraints(max_length=4000)] = ""
    #: error frames carry a machine code (``settings_unavailable``, ...)
    code: Annotated[str, StringConstraints(max_length=200)] = ""
    #: task_complete's total_iterations
    total_iterations: Annotated[StrictInt, Field(ge=0)] | None = None

    @classmethod
    def from_frame(cls, frame: Any, max_iterations: int) -> SessionEnding | None:
        """The ending a frame announces, or None for every frame that does not end it.

        ``frame`` is one decoded server frame ``{"type", "payload", ...}``. A frame of
        the wrong shape is never an ending: the driver keeps reading until a real one
        arrives or the socket closes.
        """
        if not isinstance(frame, dict) or not isinstance(frame.get("payload"), dict):
            return None
        kind, payload = frame.get("type"), frame["payload"]
        message = payload.get("message")
        text = message[:4000] if isinstance(message, str) else ""
        if kind == "task_complete":
            iterations = payload.get("total_iterations")
            done = iterations if type(iterations) is int and iterations >= 0 else None
            if _PARSE_FAILURE.fullmatch(text):
                ending = EndingKind.TOOL_FORMAT_FAILURE
            elif text.startswith(_LLM_ERROR):
                ending = EndingKind.LLM_ERROR
            elif done is not None and done >= max_iterations:
                ending = EndingKind.TURN_CAP
            else:
                ending = EndingKind.COMPLETED
            return cls(kind=ending, message=text, total_iterations=done)
        if kind == "error" and payload.get("recoverable") is False:
            code = payload.get("code")
            return cls(
                kind=EndingKind.RUN_ERROR,
                message=text,
                code=code[:200] if isinstance(code, str) else "",
            )
        if kind == "stopped":
            return cls(kind=EndingKind.STOPPED, message=text)
        return None

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True)
