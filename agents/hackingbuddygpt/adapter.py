"""The hackingBuddyGPT adapter (DEVELOPMENT_PLAN §2.3).

One run is one container running the lab's use case (``lab_hbg``, baked into the image;
see its docs) with every setting on the command line, the objective in a file, and the
LiteLLM switches in the environment. Every model call goes to the cell's tap:
``--llm.api_base`` (honoured by the image's patch) and ``OLLAMA_API_BASE`` (LiteLLM's own
fallback for the Ollama route) both name it. Command-line settings are used for
everything because hackingBuddyGPT lets environment variables and ``.env`` files set any
option, and only the command line overrides both.

The framework's own record of the run is its log: one JSONL file of OpenTelemetry-style
spans (``utils/log_storage.py`` and ``utils/logging.py`` at the pinned commit), written to
``<evidence>/agent/hbg/``. :class:`RunLog` reads it for the end state and the trajectory.
The run is a single agent, so :meth:`Adapter.agent_ids` stays ``None``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, JsonValue, StrictStr, ValidationError

from agents.base import Adapter, AdapterRun, AgentHost, AgentLaunch, ExitSignals
from agents.hackingbuddygpt.lab_hbg.contract import (
    OFFERED_TOOLS,
    USE_CASE_NAME,
    ObjectiveFile,
    RunExit,
    ToolOutputCap,
)
from agents.scripted.agent import AGENT_STREAM
from control.core.models import AgentEvent, AgentEventType

__all__ = ["HackingBuddyGPTAdapter", "LogSpan", "RunLog"]

# span attribute keys, from utils/log_storage.py at the pinned commit
_OPERATION: Final = "gen_ai.operation.name"
_OUTPUT_MESSAGES: Final = "gen_ai.output.messages"
_FINISH_REASONS: Final = "gen_ai.response.finish_reasons"
_TOOL_NAME: Final = "gen_ai.tool.name"
_TOOL_ARGUMENTS: Final = "gen_ai.tool.call.arguments"
_TOOL_RESULT: Final = "hackingbuddygpt.tool.result"
_MESSAGE_ROLE: Final = "hackingbuddygpt.message.role"
_RUN_STATE: Final = "hackingbuddygpt.run.state"
#: what upstream's run_capability_json returns when a tool call's arguments do not parse
#: or the tool raises (capability.py at the pinned commit)
_TOOL_EXCEPTION: Final = "EXCEPTION: "
#: the status message upstream logs for a tool call it cannot even look up (agents.py)
_TOOL_CALL_ERROR: Final = "Error during tool call "
#: the run state upstream records for a completed run (utils/logging.py run_was_success)
_SUCCESS_STATE: Final = "got root"
#: finish reasons that mean the model refused
_REFUSAL_REASONS: Final = frozenset({"refusal", "content_filter"})


class LogSpan(BaseModel):
    """One line of hackingBuddyGPT's run log (``Span`` in ``utils/log_storage.py``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: StrictStr
    span_id: StrictStr
    parent_span_id: StrictStr | None
    name: StrictStr
    kind: StrictStr
    start_time: StrictStr
    end_time: StrictStr | None
    attributes: dict[str, JsonValue]
    status: dict[str, StrictStr]

    @property
    def operation(self) -> str | None:
        value = self.attributes.get(_OPERATION)
        return value if isinstance(value, str) else None

    def text(self, key: str) -> str:
        """A string attribute, or "" when it is missing or not a string."""
        value = self.attributes.get(key)
        return value if isinstance(value, str) else ""

    @property
    def output_text(self) -> str:
        """The text parts of the span's output messages, joined."""
        texts: list[str] = []
        messages = self.attributes.get(_OUTPUT_MESSAGES)
        for message in messages if isinstance(messages, list) else []:
            parts = message.get("parts") if isinstance(message, dict) else None
            for part in parts if isinstance(parts, list) else []:
                content = part.get("content") if isinstance(part, dict) else None
                if isinstance(content, str):
                    texts.append(content)
        return "\n".join(texts)

    @property
    def finish_reasons(self) -> tuple[str, ...]:
        value = self.attributes.get(_FINISH_REASONS)
        return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()

    @property
    def timestamp(self) -> datetime:
        """When the span ended (or started, if it never ended), as an aware time.

        Upstream writes ``datetime.now().isoformat()``: local time without a zone. The
        agent container runs with no ``TZ``, so that is UTC.
        """
        raw = self.end_time or self.start_time
        try:
            moment = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"span {self.span_id}: bad timestamp {raw!r}") from exc
        return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


class RunLog:
    """hackingBuddyGPT's log of one run, read defensively.

    The log is evidence the agent's container wrote, so it is read with limits: a size
    cap, one JSON object per line, every line a :class:`LogSpan`. Only the last line may
    be cut off (the runner killed the agent while it was writing); any other bad line
    makes the log unreadable rather than half-read.
    """

    #: Where the agent writes its log, relative to the evidence dir (``--log.log_dir``).
    DIR: ClassVar[PurePosixPath] = PurePosixPath("agent/hbg")
    #: Upstream names the file after the run's start (``SpanWriter.open``).
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"log-\d{8}-\d{6}(-\d+)?\.jsonl")
    MAX_BYTES: ClassVar[int] = 1024**3
    MAX_LINE_BYTES: ClassVar[int] = 64 * 1024**2

    def __init__(self, path: Path, spans: tuple[LogSpan, ...]) -> None:
        self.path = path
        self.spans = spans

    @classmethod
    def find(cls, evidence: Path) -> RunLog | None:
        """The run's log, or ``None`` if the agent never started one.

        A cell's evidence volume is fresh, so it holds at most one run's log; two logs,
        or anything else in the log directory that looks like one, is refused.
        """
        directory = evidence / cls.DIR
        if not directory.is_dir():
            return None
        found = sorted(p for p in directory.iterdir() if p.name.endswith(".jsonl"))
        odd = [p.name for p in found if not cls.PATTERN.fullmatch(p.name) or p.is_symlink()]
        if odd:
            raise ValueError(f"{directory}: unexpected files {odd}")
        if len(found) > 1:
            raise ValueError(f"{directory}: {len(found)} run logs, a run writes one")
        return cls.read(found[0]) if found else None

    @classmethod
    def read(cls, path: Path) -> RunLog:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{path}: not a regular file")
        size = path.stat().st_size
        if size > cls.MAX_BYTES:
            raise ValueError(f"{path}: {size} bytes, more than {cls.MAX_BYTES}")
        return cls(path, tuple(cls._spans(path)))

    @classmethod
    def _spans(cls, path: Path) -> Iterator[LogSpan]:
        with path.open("rb") as fh:
            number = 0
            while line := fh.readline(cls.MAX_LINE_BYTES + 1):
                number += 1
                complete = line.endswith(b"\n")
                if not complete and len(line) > cls.MAX_LINE_BYTES:
                    raise ValueError(f"{path}:{number}: a line over {cls.MAX_LINE_BYTES} bytes")
                try:
                    yield LogSpan.model_validate_json(line)
                except ValidationError as exc:
                    if complete:
                        raise ValueError(f"{path}:{number}: not a log span: {exc}") from None
                    # the last line, cut off mid-write: the run was killed

    # what the log says about the run

    def _with(self, operation: str) -> tuple[LogSpan, ...]:
        return tuple(s for s in self.spans if s.operation == operation)

    @property
    def chats(self) -> tuple[LogSpan, ...]:
        """One span per model call, in the order the calls returned."""
        return self._with("chat")

    @property
    def tool_calls(self) -> tuple[LogSpan, ...]:
        return self._with("execute_tool")

    @property
    def final_state(self) -> str | None:
        """The run's end state as upstream records it, or ``None`` if it never ended.

        Upstream writes the run span twice: at the start without an end time, and at the
        end with the state (``"got root"``, a limit's reason, ``"exception occurred"``).
        """
        ended = [s for s in self.spans if s.parent_span_id is None and s.end_time is not None]
        if not ended:
            return None
        return ended[-1].text(_RUN_STATE) or None

    @property
    def hit_a_limit(self) -> bool:
        """Whether one of upstream's own limits (the turn cap above all) ended the run."""
        state = self.final_state
        return state is not None and state.startswith("Reached maximum ")

    @property
    def ended_on_refusal(self) -> bool:
        """Whether the run's last model call was refused (a refusal finish reason)."""
        chats = self.chats
        return bool(chats) and bool(_REFUSAL_REASONS & set(chats[-1].finish_reasons))

    #: Assistant text that is a tool call written out instead of made: a JSON object
    #: naming one of the offered tools, or a ``<tool_call>`` tag (Hermes/Qwen style).
    TEXT_TOOL_CALL: ClassVar[re.Pattern[str]] = re.compile(
        r"<tool_call>|\"name\"\s*:\s*\"(?:"
        + "|".join(sorted(re.escape(t) for t in OFFERED_TOOLS))
        + r")\""
    )

    @property
    def tool_format_failure(self) -> bool:
        """Whether the model's tool calls never worked because of their format.

        hackingBuddyGPT never gives up on broken tool calls: it logs the error and asks
        again until a limit stops it. So this is a property of the whole run: the model
        was asked at least once, no tool call ever ran, and the log shows it trying (a
        tool call whose arguments did not parse, a call to a tool that does not exist,
        or a tool call written out as text).
        """
        if not self.chats:
            return False
        results = [s.text(_TOOL_RESULT) for s in self.tool_calls]
        if any(not r.startswith(_TOOL_EXCEPTION) for r in results):
            return False
        unknown_tool = any(
            s.name == "message"
            and s.text(_MESSAGE_ROLE) == "status"
            and s.output_text.startswith(_TOOL_CALL_ERROR)
            for s in self.spans
        )
        as_text = any(self.TEXT_TOOL_CALL.search(s.output_text) for s in self.chats)
        return bool(results) or unknown_tool or as_text

    # the trajectory

    def events(self, run: AdapterRun) -> list[AgentEvent]:
        """The log as AgentEvents, in the order upstream wrote the spans.

        Model calls, tool calls (an ``HTTPRequest`` also gets the URL it asked for) and
        upstream's own messages (system prompt, limits, status); the run's end becomes the
        final report, with ``complete``'s summary when the model gave one. Sections are
        structure, not steps, and are left out; the log itself stays as it is.
        """
        events: list[AgentEvent] = []
        summary: str | None = None

        def add(kind: AgentEventType, span: LogSpan, **fields: object) -> None:
            events.append(
                AgentEvent.model_validate(
                    {
                        "run_id": run.run_id,
                        "stream": AGENT_STREAM,
                        "seq": len(events),
                        "ts": span.timestamp,
                        "event_type": kind,
                        "native_ref": f"{self.DIR / self.path.name}#{span.span_id}",
                        **fields,
                    }
                )
            )

        final: LogSpan | None = None
        for span in self.spans:
            if span.operation == "chat":
                add(AgentEventType.LLM_CALL, span, text=span.output_text)
            elif span.operation == "execute_tool":
                tool = span.text(_TOOL_NAME)
                args = self._arguments(span.text(_TOOL_ARGUMENTS))
                if tool == "complete" and isinstance(args.get("summary"), str):
                    summary = str(args["summary"])
                add(
                    AgentEventType.TOOL_CALL,
                    span,
                    tool_name=tool,
                    tool_args=args,
                    text=span.text(_TOOL_RESULT),
                    url=self._request_url(run, tool, args),
                )
            elif span.name == "message" and span.text(_MESSAGE_ROLE) in {
                "system",
                "status",
                "limit",
            }:
                add(AgentEventType.MESSAGE, span, text=span.output_text)
            elif span.parent_span_id is None and span.end_time is not None:
                final = span
        if final is not None:
            text = summary if summary is not None else final.text(_RUN_STATE)
            add(AgentEventType.FINAL_REPORT, final, text=text)
        return events

    @staticmethod
    def _arguments(raw: str) -> dict[str, JsonValue]:
        """A tool call's arguments as JSON, or the raw text when they are not an object."""
        try:
            value = json.loads(raw)
        except ValueError:
            return {"raw": raw}
        return value if isinstance(value, dict) else {"raw": raw}

    @staticmethod
    def _request_url(run: AdapterRun, tool: str, args: dict[str, JsonValue]) -> str | None:
        """The URL an ``HTTPRequest`` call asked for, built the way upstream builds it."""
        path, query = args.get("path"), args.get("query")
        if tool != "HTTPRequest" or not isinstance(path, str):
            return None
        host = run.target_url
        if not host.endswith("/") and not path.startswith("/"):
            path = "/" + path
        return host + path + (f"?{query}" if isinstance(query, str) and query else "")


class HackingBuddyGPTAdapter(Adapter):
    """hackingBuddyGPT's lab web use case on the cell's Ollama route."""

    framework = "hackingbuddygpt"

    #: the agent image's logical name (``ghcr.io/lordprime/agent-hackingbuddygpt`` in CI)
    IMAGE: ClassVar[str] = "agent-hackingbuddygpt"
    #: where the cell mounts the agent's evidence and config volumes
    EVIDENCE_ROOT: ClassVar[PurePosixPath] = PurePosixPath("/evidence")
    CONFIG_DIR: ClassVar[PurePosixPath] = PurePosixPath("/etc/lab/agent")
    #: LiteLLM sends it to the tap as a bearer token; Ollama ignores it, and it is no secret
    API_KEY: ClassVar[str] = "ollama"
    #: upstream's defaults, set explicitly so the environment cannot change them
    API_TIMEOUT_S: ClassVar[int] = 300
    API_RETRIES: ClassVar[int] = 3
    #: most characters of one tool result the model sees (the plugin's ToolOutputCap)
    TOOL_OUTPUT_CAP_CHARS: ClassVar[int] = 32_000
    #: LiteLLM's switches: no remote cost map, no remote Anthropic beta-header list, and
    #: no ``.env`` loading (LiteLLM's DEV mode reads one at import)
    LITELLM_ENV: ClassVar[dict[str, str]] = {
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS": "True",
        "LITELLM_MODE": "PRODUCTION",
    }
    #: an Ollama model name (``qwen3:32b``, ``hf.co/org/model:Q4_K_M``)
    MODEL_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")

    # rendering

    def settings(self, run: AdapterRun) -> dict[str, str]:
        """Every option the run sets, as ``--<name>=<value>`` on the command line.

        Upstream's limits other than the turn cap are switched off (0): the gateway
        enforces the token budget and the runner the wall-clock limit, the same way for
        every framework.
        """
        if not self.MODEL_NAME.fullmatch(run.model.name):
            raise ValueError(f"{run.model.name!r} is not an Ollama model name")
        num_ctx = run.model.num_ctx
        if num_ctx is None:  # prepare() refuses such a run before rendering
            raise ValueError(f"{run.model.name}: num_ctx is not pinned")
        return {
            "llm.model": f"ollama_chat/{run.model.name}",
            "llm.api_base": run.llm_base_url,
            "llm.api_key": self.API_KEY,
            "llm.context_size": str(num_ctx),
            "llm.api_timeout": str(self.API_TIMEOUT_S),
            "llm.api_retries": str(self.API_RETRIES),
            "llm.provider": "",
            "llm.proxy": "",
            "host": run.target_url,
            "hints": "",
            "objective_file": str(self.CONFIG_DIR / ObjectiveFile.NAME),
            "max_tool_output_chars": str(ToolOutputCap(self.TOOL_OUTPUT_CAP_CHARS).limit),
            self._sheet.max_turns_knob: str(run.limits.max_turns),
            "limits.max_tokens": "0",
            "limits.max_cost": "0",
            "limits.max_duration": "0",
            "log.log_dir": str(self.EVIDENCE_ROOT / RunLog.DIR),
            "log.tag": run.run_id,
        }

    def render(self, run: AdapterRun) -> AgentLaunch:
        settings = self.settings(run)
        return AgentLaunch(
            image=self.IMAGE,
            command=(
                "python",
                "-m",
                "lab_hbg",
                USE_CASE_NAME,
                *(f"--{name}={value}" for name, value in settings.items()),
            ),
            env={"OLLAMA_API_BASE": run.llm_base_url, **self.LITELLM_ENV},
            files={ObjectiveFile.NAME: ObjectiveFile.encode(run.objective)},
            # the key is no setting the results depend on; an empty value means "off"
            recorded_settings={
                name: value for name, value in settings.items() if name != "llm.api_key" and value
            },
        )

    # the run

    def start(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: the container's command is the whole run."""

    def exit_signals(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> ExitSignals:
        """``observed`` plus the plugin's exit code and what the run log shows.

        * the turn cap (or another upstream limit) ended the run: exit code ``TURN_CAP`` or
          ``OTHER_LIMIT``, or the log's end state says so -> ``budget_exhausted``;
        * the last model call was refused -> ``refused``;
        * no tool call ever ran because of its format -> ``tool_format_failure``.
        """
        log = RunLog.find(evidence)
        limit_exit = observed.exit_code in {RunExit.TURN_CAP, RunExit.OTHER_LIMIT}
        return observed.model_copy(
            update={
                "budget_exhausted": observed.budget_exhausted
                or limit_exit
                or (log is not None and log.hit_a_limit),
                "refused": observed.refused or (log is not None and log.ended_on_refusal),
                "tool_format_failure": observed.tool_format_failure
                or (log is not None and log.tool_format_failure),
            }
        )

    def collect(self, run: AdapterRun, evidence: Path) -> list[AgentEvent]:
        log = RunLog.find(evidence)
        return [] if log is None else log.events(run)

    def teardown(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: the agent starts no containers and writes only to its volumes."""
