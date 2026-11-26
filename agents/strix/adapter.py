"""Strix behind the adapter contract (DEVELOPMENT_PLAN §2.3).

Strix (usestrix/strix, pinned in ``agents/strix/source.yaml``) runs headless in the
cell's ``agent`` container: ``strix -n -t <target> --instruction-file ... --max-turns N``.
Every value the run depends on comes from ``agents/sheets/strix.yaml`` and is cited
there against the pinned source. In short:

* **Model.** ``STRIX_LLM=ollama/<model>`` routes through LiteLLM's ``ollama_chat``
  provider, and ``LLM_API_BASE`` (the tap) becomes LiteLLM's global ``api_base``, which
  wins over any per-call base. So the main agent, the history compaction, the dedupe
  judge and the start-up preflight all reach the tap. The model's ``num_ctx`` goes into
  every request's ``options`` (lab patch 0001, ``LAB_OLLAMA_NUM_CTX``) and into Strix's
  own context budget (``STRIX_CONTEXT_FALLBACK_TOKENS``), so compaction fires in time.
* **Side channels.** Each one in the sheet is switched off by the environment rendered
  here (:attr:`StrixAdapter.SIDE_CHANNEL_ENV`) or by a patch, and the environment never
  carries a key that would switch one back on (:attr:`StrixAdapter.FORBIDDEN_ENV`).
* **Sandbox.** Strix starts a Kali sandbox for its tools through the Docker SDK. The
  launch asks for cell-guard (``needs_docker``), so ``DOCKER_HOST`` is cell-guard's
  socket and never the real one. The sandbox joins the cell's agent network and is
  never pulled (it must be on the host and in ``images.lock`` with role ``agent``).
* **Turn cap.** ``--max-turns`` is Strix's own limit, per agent and per run cycle; the
  gateway's token budget bounds the whole run.

What the adapter reads back, all from the run's own files under
``<evidence>/agent/strix/strix_runs/<run>/`` (see :class:`StrixRun`):

* end-state signals from ``strix.log`` and ``state/agents.json``;
* sub-agent ids from ``run.json``'s ``llm_requests`` (``STRIX_RUN_RECORD_TIMINGS=true``),
  matched to the tap's calls by start order and token counts;
* the trajectory (model calls, tool calls, the final report) for :meth:`collect`.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Final, NamedTuple

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
)

from agents.base import (
    Adapter,
    AdapterRun,
    AgentHost,
    AgentLaunch,
    ExitSignals,
)
from control.core.models import AgentEvent, AgentEventType
from control.core.yaml_loader import UniqueKeyLoader
from control.telemetry.extract import load_calls
from control.telemetry.model import CallTelemetry
from control.telemetry.wire import parse_call

__all__ = [
    "SOURCE_FILE",
    "StrixAdapter",
    "StrixLlmAttempt",
    "StrixRun",
    "StrixSource",
    "StrixToolCall",
]

#: The pins of the Strix image (repository, commit, base images, sandbox image).
SOURCE_FILE: Final = Path(__file__).resolve().parent / "source.yaml"
_MAX_SOURCE_BYTES: Final = 16 * 1024
_SHA40 = r"^[0-9a-f]{40}$"
_DIGEST_REF = r"^[^@\s]+@sha256:[0-9a-f]{64}$"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StrixSource(_Frozen):
    """``agents/strix/source.yaml``: what the image is built from."""

    name: StrictStr
    repo: Annotated[str, StringConstraints(pattern=r"^https://github\.com/[\w.-]+/[\w.-]+$")]
    commit: Annotated[str, StringConstraints(pattern=_SHA40)]
    version: StrictStr
    license: StrictStr
    image_base: Annotated[str, StringConstraints(pattern=_DIGEST_REF)]
    uv_image: Annotated[str, StringConstraints(pattern=_DIGEST_REF)]
    #: the Kali sandbox, by digest: Strix's ``STRIX_IMAGE``
    sandbox_image: Annotated[str, StringConstraints(pattern=_DIGEST_REF)]
    sandbox_tag: StrictStr

    @classmethod
    def load(cls, path: Path = SOURCE_FILE) -> StrixSource:
        """Read and validate the pins; ``ValueError`` when they cannot be trusted."""
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"{path}: cannot read the Strix source pins: {exc}") from exc
        if len(data) > _MAX_SOURCE_BYTES:
            raise ValueError(f"{path}: {len(data)} bytes, more than {_MAX_SOURCE_BYTES}")
        try:
            doc = yaml.load(data.decode("utf-8"), Loader=UniqueKeyLoader)  # noqa: S506 - SafeLoader
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"{path}: not UTF-8 YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError(f"{path}: the source pins are a mapping")
        source = cls.model_validate(doc)
        if source.name != "strix":
            raise ValueError(f"{path}: pins {source.name!r}, not strix")
        return source


# --------------------------------------------------------------------------- run files


class _RecordEntry(BaseModel):
    """One timed entry of ``run.json`` (``STRIX_RUN_RECORD_TIMINGS=true``).

    Other fields Strix adds are ignored; the ones read here must be well-formed, or the
    whole list reads as unreadable.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    started_at: datetime
    agent_id: StrictStr | None = None

    @field_validator("started_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        # Strix stamps these in UTC; a naive time is read as UTC too.
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class StrixLlmAttempt(_RecordEntry):
    """One provider attempt in ``run.json``'s ``llm_requests``.

    Written by Strix's own request log sink (``record_llm_request``,
    strix/report/state.py 1024-1045) once the attempt settles, retries included.
    """

    input_tokens: StrictInt | None = None
    output_tokens: StrictInt | None = None
    outcome: StrictStr | None = None


class StrixToolCall(_RecordEntry):
    """One tool call in ``run.json``'s ``tool_calls`` (strix/core/hooks.py 380-394)."""

    tool: StrictStr


class _RootAgent(NamedTuple):
    agent_id: str
    status: str | None
    error: str | None


class _LogRecord(NamedTuple):
    scan: str
    logger: str
    message: str
    #: the lines after the first (a traceback, for ``logger.exception``)
    detail: str


class StrixRun:
    """One Strix run's own files in the collected evidence. Read-only and bounded.

    A run folder is ``<evidence>/agent/strix/strix_runs/<run name>/`` holding
    ``run.json``, ``strix.log`` and ``state/agents.json`` (lab patch 0004 drops the dot
    from ``.state``). Anything missing, oversized, a symlink or unparsable reads as
    absent: the adapter then adds no signal and claims no agent ids, it never guesses.
    """

    #: Where the entrypoint puts Strix's working directory, relative to the evidence.
    RUNS_DIR: ClassVar[PurePosixPath] = PurePosixPath("agent/strix/strix_runs")
    #: The executive report finish_scan writes (strix/report/writer.py 139-145).
    FINAL_REPORT: ClassVar[str] = "penetration_test_report.md"
    #: Largest native file read.
    MAX_FILE_BYTES: ClassVar[int] = 128 * 1024 * 1024

    #: One log record's first line (strix/telemetry/logging.py 46-47):
    #: ``<date> <time>.<ms> <LEVEL> <scan id> <agent id> <logger>: <message>``.
    LOG_RECORD: ClassVar[re.Pattern[str]] = re.compile(
        r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} (?P<level>[A-Z]+) +(?P<scan>\S+) "
        r"(?P<agent>\S+) (?P<logger>[\w.]+): (?P<message>.*)$",
        re.MULTILINE,
    )
    #: The SDK's turn-cap error (agents/run.py 1109 at v0.19.0).
    TURN_CAP: ClassVar[re.Pattern[str]] = re.compile(r"^Max turns \(\d+\) exceeded")
    #: An agent that kept answering in text instead of calling a tool until its recovery
    #: budget ran out (strix/core/execution.py 675-677).
    RECOVERY_EXHAUSTED: ClassVar[str] = (
        "Agent exhausted recovery attempts without calling finish_scan or agent_finish."
    )

    def __init__(self, folder: Path) -> None:
        self.folder = folder

    @classmethod
    def find(cls, evidence: Path) -> StrixRun | None:
        """The run folder under ``evidence``, if there is exactly one."""
        base = evidence / cls.RUNS_DIR
        if not cls._real_dir(base):
            return None
        try:
            found = [d for d in base.iterdir() if cls._real_dir(d) and (d / "run.json").is_file()]
        except OSError:
            return None
        return cls(found[0]) if len(found) == 1 else None

    @staticmethod
    def _real_dir(path: Path) -> bool:
        try:
            return stat.S_ISDIR(os.lstat(path).st_mode)
        except OSError:
            return False

    def _read(self, relative: str) -> bytes | None:
        """A regular file's bytes, or ``None`` (absent, a link, unreadable, too big)."""
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.folder / relative, flags)
        except OSError:
            return None
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            data = fh.read(self.MAX_FILE_BYTES + 1)
        return None if len(data) > self.MAX_FILE_BYTES else data

    def _json_object(self, relative: str) -> dict[str, object]:
        data = self._read(relative)
        if data is None:
            return {}
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {}
        return doc if isinstance(doc, dict) else {}

    def record(self) -> dict[str, object]:
        """``run.json``, or ``{}``."""
        return self._json_object("run.json")

    def log(self) -> str:
        """``strix.log``, or ``""``."""
        data = self._read("strix.log")
        return "" if data is None else data.decode("utf-8", errors="replace")

    def root_agent(self) -> _RootAgent | None:
        """The root agent as ``state/agents.json`` records it (strix/core/agents.py 637-660).

        The root is the one agent without a parent; with none or several there is no
        root to speak of.
        """
        graph = self._json_object("state/agents.json")
        parents = graph.get("parent_of")
        if not isinstance(parents, dict):
            return None
        roots = [aid for aid, parent in parents.items() if parent is None and aid]
        if len(roots) != 1:
            return None
        statuses, errors = graph.get("statuses"), graph.get("errors")
        status = statuses.get(roots[0]) if isinstance(statuses, dict) else None
        error = errors.get(roots[0]) if isinstance(errors, dict) else None
        return _RootAgent(
            roots[0],
            status if isinstance(status, str) else None,
            error if isinstance(error, str) else None,
        )

    def log_records(self) -> list[_LogRecord]:
        """``strix.log`` split into records: logger, message, and the lines after it."""
        log = self.log()
        found = list(self.LOG_RECORD.finditer(log))
        ends = [m.start() for m in found[1:]] + [len(log)] if found else []
        return [
            _LogRecord(m["scan"], m["logger"], m["message"], log[m.end() : end].strip("\n"))
            for m, end in zip(found, ends, strict=True)
        ]

    def end_flags(self) -> dict[str, bool]:
        """What the run's own files say about how the root agent stopped.

        * ``budget_exhausted``: the root hit Strix's turn cap (``--max-turns``): its error
          in agents.json is the SDK's turn-cap error;
        * ``tool_format_failure``: the root kept answering without a tool call until its
          recovery budget ran out (the runner's failure record ends in that error), or
          the scan ended on a text-only turn;
        * ``refused``: the provider's structured refusal stopped the root.

        A sub-agent that stops this way does not end the run, so only the root counts.
        The log holds model text, which can contain line breaks, so a log record counts
        only when ``agents.json`` (structured, written by Strix alone) agrees: the
        record names this run, and the root's recorded status fits.
        """
        root = self.root_agent()
        if root is None:
            return {"budget_exhausted": False, "tool_format_failure": False, "refused": False}
        run_name = self.folder.name
        last_error = ""
        text_only_end = refused = False
        for record in self.log_records():
            if record.scan != run_name:
                continue
            if record.logger == "strix.core.runner":
                if record.message == f"Strix scan {run_name} failed":
                    lines = record.detail.splitlines()
                    last_error = lines[-1] if lines else ""
                text_only_end |= record.message.startswith(
                    f"Scan {run_name} ended without calling finish_scan."
                )
            elif record.logger == "strix.core.execution":
                refused |= record.message.startswith(
                    f"agent {root.agent_id} refused by the model provider:"
                )
        failed = root.status in {"failed", "crashed"}
        turn_cap = bool(root.error and self.TURN_CAP.match(root.error))
        recovery = failed and last_error.endswith(f"MaxTurnsExceeded: {self.RECOVERY_EXHAUSTED}")
        return {
            "budget_exhausted": turn_cap,
            "tool_format_failure": recovery or (text_only_end and root.status != "completed"),
            "refused": refused and root.status == "failed",
        }

    def _entries[T: _RecordEntry](self, key: str, model: type[T]) -> list[T] | None:
        raw = self.record().get(key, [])
        if not isinstance(raw, list):
            return None
        try:
            return [model.model_validate(item) for item in raw]
        except ValidationError:
            return None

    def llm_attempts(self) -> list[StrixLlmAttempt] | None:
        """Every recorded provider attempt, by start time; ``None`` if unreadable."""
        attempts = self._entries("llm_requests", StrixLlmAttempt)
        return None if attempts is None else sorted(attempts, key=lambda a: a.started_at)

    def tool_calls(self) -> list[StrixToolCall] | None:
        calls = self._entries("tool_calls", StrixToolCall)
        return None if calls is None else sorted(calls, key=lambda c: c.started_at)

    def final_report_time(self) -> datetime | None:
        """When the executive report was written (the run's end), if there is one."""
        report = self.folder / self.FINAL_REPORT
        if report.is_symlink() or not report.is_file():
            return None
        end_time = self.record().get("end_time")
        if not isinstance(end_time, str):
            return None
        try:
            ended = datetime.fromisoformat(end_time)
        except ValueError:
            return None
        return ended if ended.tzinfo is not None else ended.replace(tzinfo=UTC)


class _Step(NamedTuple):
    """One trajectory step before it becomes an :class:`AgentEvent`."""

    ts: datetime
    kind: AgentEventType
    native_ref: str
    tool_name: str | None = None
    text: str | None = None


# --------------------------------------------------------------------------- adapter


class StrixAdapter(Adapter):
    """Strix in a cell: headless, one run per container, sandbox through cell-guard."""

    framework = "strix"

    #: The agent image's logical name in ``images.lock`` (built by CI from this folder).
    IMAGE: ClassVar[str] = "agent-strix"
    #: The image's launcher (agents/strix/strix-entrypoint.sh).
    ENTRYPOINT: ClassVar[str] = "/opt/lab/strix-entrypoint"
    #: Where the runner mounts the agent's config files (read-only).
    CONFIG_DIR: ClassVar[PurePosixPath] = PurePosixPath("/etc/lab/agent")
    OBJECTIVE_FILE: ClassVar[str] = "objective.txt"
    #: A tmpfs path: the root file system is read-only and ~/.strix must start empty.
    HOME: ClassVar[str] = "/tmp/strix-home"  # noqa: S108 - the container's own tmpfs
    #: Strix's scan mode, the same for every run (AUTOMATION_FEASIBILITY §2.2).
    SCAN_MODE: ClassVar[str] = "standard"
    #: The cell's agent network: control/runner/cell_spec.py names it
    #: ``<project_name(run)>_agent`` with project_name ``c-<run id lowercased>``.
    NETWORK_FORMAT: ClassVar[str] = "c-{run_id}_agent"
    #: An Ollama model name (``qwen3:32b``, ``hf.co/org/model:q4``).
    MODEL_NAME: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}$")

    #: The switch of every side channel the sheet lists as disabled by a setting.
    SIDE_CHANNEL_ENV: ClassVar[Mapping[str, str]] = {
        "STRIX_TELEMETRY": "false",
        "STRIX_MAX_CONTEXT_IMAGES": "0",
        "STRIX_NO_UPDATE_CHECK": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS": "True",
        "OPENAI_AGENTS_DISABLE_TRACING": "1",
    }
    #: Keys that would switch a side channel back on or move a model call off the tap.
    #: None of them is ever rendered.
    FORBIDDEN_ENV: ClassVar[frozenset[str]] = frozenset(
        {
            "PERPLEXITY_API_KEY",
            "EXA_API_KEY",
            "POSTMAN_API_KEY",
            "STRIX_DEDUPE_MODEL",
            "DEDUPE_LLM_API_BASE",
            "DEDUPE_LLM_API_KEY",
            "OLLAMA_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "LITELLM_MODEL_COST_MAP_URL",
            "STRIX_MCP_CONFIG",
            "STRIX_API_TYPE",
            "STRIX_FORCE_API",
        }
    )

    #: The fixed prompt of the CLI's warm-up call (strix/interface/scan_setup.py 152-157).
    PREFLIGHT_SYSTEM: ClassVar[str] = "You are a helpful assistant."
    PREFLIGHT_INPUT: ClassVar[str] = "Reply with just 'OK'."

    def __init__(self, source: StrixSource | None = None) -> None:
        super().__init__()
        self._source = source if source is not None else StrixSource.load()
        if not self._source.commit.startswith(self.describe().commit):
            raise ValueError(
                f"strix: source.yaml pins {self._source.commit}, the sheet {self.describe().commit}"
            )

    @property
    def source(self) -> StrixSource:
        return self._source

    # rendering

    def render(self, run: AdapterRun) -> AgentLaunch:
        num_ctx = run.model.num_ctx
        if num_ctx is None:  # prepare() refuses this first; render alone must not guess
            raise ValueError(f"strix: {run.model.name}: num_ctx is not pinned")
        if not self.MODEL_NAME.fullmatch(run.model.name):
            raise ValueError(f"strix: {run.model.name!r} is not an Ollama model name")
        if not run.objective.strip():
            raise ValueError("strix: the objective is blank (Strix refuses an empty instruction)")
        model = f"ollama/{run.model.name}"
        turns = str(run.limits.max_turns)
        env = {
            "STRIX_LLM": model,
            "LLM_API_BASE": run.llm_base_url,
            "LAB_OLLAMA_NUM_CTX": str(num_ctx),
            "STRIX_CONTEXT_FALLBACK_TOKENS": str(num_ctx),
            **self.SIDE_CHANNEL_ENV,
            "STRIX_RUN_RECORD_TIMINGS": "true",
            "STRIX_IMAGE": self._source.sandbox_image,
            "STRIX_DOCKER_SANDBOX_NETWORK": self.NETWORK_FORMAT.format(run_id=run.run_id.lower()),
            "STRIX_RUN_ID": run.run_id,
            # cell-guard refuses any LogConfig; "0" keeps the daemon's log driver
            "STRIX_SANDBOX_LOG_MAX_SIZE": "0",
            "HOME": self.HOME,
        }
        command = (
            self.ENTRYPOINT,
            "--non-interactive",
            "--target",
            run.target_url,
            "--instruction-file",
            str(self.CONFIG_DIR / self.OBJECTIVE_FILE),
            "--scan-mode",
            self.SCAN_MODE,
            "--max-turns",
            turns,
        )
        return AgentLaunch(
            image=self.IMAGE,
            command=command,
            env=env,
            files={self.OBJECTIVE_FILE: run.objective.encode("utf-8")},
            needs_docker=True,
            recorded_settings={
                self.describe().max_turns_knob: turns,
                "--scan-mode": self.SCAN_MODE,
                "STRIX_LLM": model,
                "num_ctx": str(num_ctx),
                "STRIX_IMAGE": self._source.sandbox_image,
                "strix_commit": self._source.commit,
            },
        )

    def start(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: the container's command is the headless scan itself."""

    def teardown(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: Strix creates containers and volumes only through cell-guard,
        which labels each with the run, and the cell's teardown removes everything so
        labelled (control/runner/compose_backend.py, ``teardown``). HOME is the agent
        container's tmpfs and goes with it."""

    # reading the run back

    def exit_signals(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> ExitSignals:
        strix_run = StrixRun.find(evidence)
        if strix_run is None:
            return observed
        flags = strix_run.end_flags()
        return observed.model_copy(
            update={name: getattr(observed, name) or value for name, value in flags.items()}
        )

    def collect(self, run: AdapterRun, evidence: Path) -> list[AgentEvent]:
        """Model calls, tool calls and the final report, in time order.

        The native files stay where they are; each event's ``native_ref`` points into
        them. A run without its files (Strix never started) has no events.
        """
        strix_run = StrixRun.find(evidence)
        if strix_run is None:
            return []
        steps = [
            _Step(
                a.started_at,
                AgentEventType.LLM_CALL,
                f"run.json#llm_requests/{i}",
                text=f"agent {a.agent_id or '-'}: {a.outcome or '-'}",
            )
            for i, a in enumerate(strix_run.llm_attempts() or [])
        ]
        steps += [
            _Step(
                c.started_at,
                AgentEventType.TOOL_CALL,
                f"run.json#tool_calls/{i}",
                tool_name=c.tool,
                text=f"agent {c.agent_id or '-'}",
            )
            for i, c in enumerate(strix_run.tool_calls() or [])
        ]
        report_time = strix_run.final_report_time()
        if report_time is not None:
            steps.append(_Step(report_time, AgentEventType.FINAL_REPORT, StrixRun.FINAL_REPORT))
        steps.sort(key=lambda step: step.ts)
        return [
            AgentEvent(
                run_id=run.run_id,
                stream="agent",
                seq=seq,
                ts=step.ts,
                event_type=step.kind,
                tool_name=step.tool_name,
                text=step.text,
                native_ref=step.native_ref,
            )
            for seq, step in enumerate(steps)
        ]

    def agent_ids(self, run: AdapterRun, collected: Path) -> dict[int, str] | None:
        """Tap call ``seq`` -> the Strix agent that made it, or ``None``.

        Strix records every provider attempt with its agent in ``run.json`` (lab setting
        ``STRIX_RUN_RECORD_TIMINGS=true``); the CLI's warm-up call runs before the run
        record exists and is told apart by its fixed prompt. It is counted for the
        root agent, whose model it checks. The tap's calls, warm-up aside, are paired
        with the recorded attempts in start order, and every pair must agree on the
        token counts both sides know. Any doubt (a count that differs, an attempt
        without an agent, a missing root) gives ``None``, never a guess.
        """
        strix_run = StrixRun.find(collected)
        if strix_run is None:
            return None
        root = strix_run.root_agent()
        attempts = strix_run.llm_attempts()
        calls = load_calls(collected)
        if root is None or attempts is None or not calls:
            return None
        preflight = self._preflight_thread_key()
        warmups = [c for c in calls if self._is_preflight(c, preflight)]
        others = [c for c in calls if not self._is_preflight(c, preflight)]
        if len(others) != len(attempts):
            return None
        ids = {c.seq: root.agent_id for c in warmups}
        for call, attempt in zip(others, attempts, strict=True):
            if not attempt.agent_id or not self._same_tokens(call, attempt):
                return None
            ids[call.seq] = attempt.agent_id
        return ids

    def _preflight_thread_key(self) -> str:
        # The tap's parser gives the warm-up conversation the same key as the real call.
        body = {
            "model": "preflight",
            "messages": [
                {"role": "system", "content": self.PREFLIGHT_SYSTEM},
                {"role": "user", "content": self.PREFLIGHT_INPUT},
            ],
        }
        return parse_call("/api/chat", json.dumps(body).encode(), None, None).thread_key

    @staticmethod
    def _is_preflight(call: CallTelemetry, thread_key: str) -> bool:
        return call.thread_key == thread_key and len(call.history_hashes) == 1

    @staticmethod
    def _same_tokens(call: CallTelemetry, attempt: StrixLlmAttempt) -> bool:
        pairs: Sequence[tuple[int | None, int | None]] = (
            (call.input_tokens, attempt.input_tokens),
            (call.output_tokens, attempt.output_tokens),
        )
        return all(a is None or b is None or a == b for a, b in pairs)
