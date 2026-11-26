"""The base every pentest-framework adapter builds on.

An adapter hides one framework (Strix, PentAGI, RedAmon, hackingBuddyGPT, PentestGPT)
behind the contract in DEVELOPMENT_PLAN §2.3: describe, prepare, start, wait, collect
and teardown. This module holds the parts every adapter shares:

* :class:`CapabilitySheet`: what we know about a framework, read from
  ``agents/sheets/<framework>.yaml``. Each value comes from
  ``docs/OLLAMA_SUPPORT_AUDIT.md`` (``audit_refs`` says which section), and
  ``"unknown"`` marks what the audit could not verify.
* :meth:`CapabilitySheet.check_context`: a run whose model context (``num_ctx``) is not
  pinned, or is smaller than the framework needs, is ``unsupported``. We never run it
  with a smaller context than the framework asks for.
* :class:`AgentEndState` and :class:`EndStateMapper`: one end state per run, decided
  the same way for every framework.
* :class:`Adapter`: the abstract class each framework fills in.

How the end states map onto the runner's :class:`~control.core.models.EndStatus`
(applied when the runner is wired to adapters):

* ``completed`` -> ``EndStatus.COMPLETED``: exited 0 with no other signal;
* ``budget_exhausted`` -> ``EndStatus.BUDGET_EXHAUSTED``: the token budget ran out;
* ``timeout`` -> ``EndStatus.TIMEOUT``: the runner killed it at the wall-clock limit;
* ``refused`` -> ``EndStatus.REFUSED``: the model refused and the run ended;
* ``crashed`` -> ``EndStatus.CRASHED``: any other non-zero exit;
* ``tool_format_failure`` -> a new ``EndStatus.TOOL_FORMAT_FAILURE`` (same value): the
  framework gave up because the model's tool calls did not parse;
* ``unsupported`` -> a new ``EndStatus.UNSUPPORTED`` (same value): never started, see
  :meth:`CapabilitySheet.check_context`.

Each value is the same string on both sides, so the mapping is ``EndStatus(state.value)``
(:meth:`EndStateMapper.end_status`).

``tool_format_failure`` is a valid outcome, not an infrastructure failure, and it
never counts as a completion. ``unsupported`` means the cell was never run.

The ``agent_ids`` contract (what :meth:`Adapter.agent_ids` returns, and what
:func:`control.telemetry.extract.summarise` accepts):

* ``None`` when the framework's own logs cannot tell its sub-agents apart. Telemetry
  then infers agents from the traffic (``agents_source="inferred"``).
* Otherwise a map from **every** tap call ``seq`` of the run to a non-empty agent id,
  and nothing else: no missing call, no seq the tap never recorded. Telemetry refuses
  anything less (``agents_source="adapter"``). An empty map is not "no ids": with any
  calls recorded it is refused, so return ``None`` instead. The seqs to cover are the
  ones :func:`control.telemetry.extract.load_calls` reads from the same evidence.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, ClassVar, Final, Literal, Protocol, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

from control.core.models import AgentEvent, EndStatus, Id
from control.runner.experiment import RunLimits, _UniqueKeyLoader
from control.telemetry.model import WireFormat

__all__ = [
    "MAX_NUM_CTX",
    "MAX_SHEET_BYTES",
    "SHEETS_DIR",
    "UNKNOWN",
    "Adapter",
    "AdapterRun",
    "AgentEndState",
    "AgentHost",
    "AgentLaunch",
    "CapabilitySheet",
    "CommandOutcome",
    "EndStateMapper",
    "ExitSignals",
    "ModelConfig",
    "Patch",
    "SupportLevel",
    "UnsupportedRun",
]

#: Where the shipped capability sheets live, one ``<framework>.yaml`` each.
SHEETS_DIR: Final = Path(__file__).resolve().parent / "sheets"
#: What a sheet says when the audit could not verify a value.
UNKNOWN: Final = "unknown"
#: The largest context we accept anywhere (16M tokens); anything bigger is a typo.
MAX_NUM_CTX: Final = 1 << 24
#: A sheet is a short hand-written file; anything bigger is not one.
MAX_SHEET_BYTES: Final = 64 * 1024

# A single line of printable text with at least one visible character.
_LINE = r"^[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f][^\x00-\x1f\x7f]*$"
Text = Annotated[str, StringConstraints(pattern=_LINE, max_length=1000)]
_SLUG = r"^[a-z][a-z0-9_-]{0,63}$"
_COMMIT = r"^[0-9a-f]{7,40}$"
_DIGEST = r"^(sha256:[0-9a-f]{64}|unknown)$"
# "§2.2" or "§2.2, §3": the audit sections a value comes from.
_AUDIT_REF = r"^§\d+(\.\d+)*(, §\d+(\.\d+)*)*$"
_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"
# a flat file name that is not made of dots alone (so never "." or "..")
_FILE_NAME = r"^[A-Za-z0-9._-]*[A-Za-z0-9_-][A-Za-z0-9._-]*$"
_HTTP_URL = r"^https?://[^\s/]+(/\S*)?$"

NumCtx = Annotated[StrictInt, Field(gt=0, le=MAX_NUM_CTX)]
EnvName = Annotated[str, StringConstraints(pattern=_ENV_NAME)]
FileName = Annotated[str, StringConstraints(pattern=_FILE_NAME, max_length=128)]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- the sheet


class SupportLevel(StrEnum):
    """How a framework reaches Ollama (audit §1 summary table)."""

    #: the framework documents Ollama as a provider
    NATIVE = "native"
    #: reached through the framework's generic OpenAI-compatible provider
    OPENAI_COMPATIBLE = "openai_compatible"
    #: works, but through a route the project does not support (reported separately)
    UNOFFICIAL = "unofficial"
    #: cannot be pointed at Ollama at all
    NONE = "none"


class Patch(_Frozen):
    """A small change applied to the framework's source when its image is built."""

    #: the upstream file the patch touches, relative to the framework's repository
    upstream_file: Text
    #: what the patch changes
    change: Text
    #: why it is needed
    reason: Text


class ModelConfig(_Frozen):
    """The model a run uses, as the experiment pins it."""

    name: Text
    #: Ollama's context window for this model; ``None`` when the experiment left it
    #: unpinned (such a run is unsupported, see :meth:`CapabilitySheet.check_context`).
    num_ctx: NumCtx | None = None


class AgentEndState(StrEnum):
    """How a run's agent ended, as the adapter sees it (mapping in the module docs)."""

    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    CRASHED = "crashed"
    #: the framework gave up because the model's tool calls did not parse
    TOOL_FORMAT_FAILURE = "tool_format_failure"
    #: the run was never started: the framework cannot run this model as configured
    UNSUPPORTED = "unsupported"


class UnsupportedRun(_Frozen):
    """Why a run cannot be started. Its end state is always ``unsupported``."""

    reason: Text

    @property
    def end_state(self) -> AgentEndState:
        return AgentEndState.UNSUPPORTED


class CapabilitySheet(_Frozen):
    """What we know about one framework, with the audit section behind each value."""

    #: Fields whose value must cite an audit section in ``audit_refs``.
    AUDITED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "version",
            "support_level",
            "wire_formats",
            "model_call_paths",
            "side_channels_disabled",
            "min_num_ctx",
            "sub_agents",
            "agent_id_source",
            "patches",
            "max_turns_knob",
        }
    )

    framework: Annotated[str, StringConstraints(pattern=_SLUG)]
    #: the release the audit read, or "unknown" when the commit has no release
    version: Text
    #: the commit the audit read
    commit: Annotated[str, StringConstraints(pattern=_COMMIT)]
    #: the agent image's digest, or "unknown" until the adapter's image is built
    image_digest: Annotated[str, StringConstraints(pattern=_DIGEST)]
    support_level: SupportLevel
    #: the model APIs the framework speaks to Ollama
    wire_formats: tuple[WireFormat, ...]
    #: every code path that calls a model; each must be shown to reach the tap
    model_call_paths: tuple[Text, ...]
    #: side channel -> the setting (or action) that turns it off
    side_channels_disabled: dict[Text, Text]
    #: the smallest context the framework documents, or "unknown" if it gives none
    min_num_ctx: NumCtx | Literal["unknown"]
    #: whether it runs one agent, a fixed set, or spawns agents as it goes
    sub_agents: Literal["none", "fixed", "dynamic"]
    #: where the adapter reads which sub-agent made each call, or None
    agent_id_source: Text | None = None
    #: why agent ids are not available, when the framework has sub-agents but no source
    agent_id_gap: Text | None = None
    patches: tuple[Patch, ...] = ()
    #: the framework's own setting for the maximum number of turns, or "unknown"
    max_turns_knob: Text
    #: field -> the audit section(s) its value comes from, e.g. "§2.2, §3"
    audit_refs: dict[str, Annotated[str, StringConstraints(pattern=_AUDIT_REF)]]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        self._check_runnable_lists()
        self._check_side_channels()
        self._check_agent_ids()
        self._check_unique()
        self._check_audit_refs()
        return self

    def _check_runnable_lists(self) -> None:
        # A framework we run must tell us how it reaches the model, or we cannot prove
        # that every call goes through the tap.
        if self.support_level is SupportLevel.NONE:
            return
        if not self.model_call_paths:
            raise ValueError(
                f"model_call_paths: a {self.support_level.value} framework must list its "
                "model call paths"
            )
        if not self.wire_formats:
            raise ValueError(
                f"wire_formats: a {self.support_level.value} framework must name its wire format"
            )

    def _check_side_channels(self) -> None:
        for channel, setting in self.side_channels_disabled.items():
            if setting.strip().casefold() == UNKNOWN:
                raise ValueError(
                    f"side_channels_disabled: {channel!r} has no disabling setting; a side "
                    "channel we cannot turn off is a blocker, not a sheet entry"
                )

    def _check_agent_ids(self) -> None:
        if self.agent_id_source is not None and self.agent_id_gap is not None:
            raise ValueError("agent_id_source and agent_id_gap: give one or the other")
        if self.sub_agents == "none":
            if self.agent_id_source is not None:
                raise ValueError("agent_id_source: a single-agent framework has no sub-agent ids")
        elif self.agent_id_source is None and self.agent_id_gap is None:
            raise ValueError(
                "agent_id_source: a framework with sub-agents names where their ids come "
                "from, or says why they cannot be read (agent_id_gap)"
            )

    def _check_unique(self) -> None:
        for what, values in (
            ("wire_formats", self.wire_formats),
            ("model_call_paths", self.model_call_paths),
            ("patches", tuple(p.upstream_file for p in self.patches)),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"{what}: duplicate entries")

    def _check_audit_refs(self) -> None:
        missing = sorted(self.AUDITED_FIELDS - set(self.audit_refs))
        extra = sorted(set(self.audit_refs) - self.AUDITED_FIELDS)
        if missing or extra:
            raise ValueError(
                f"audit_refs: every audited field cites the audit; missing {missing}, "
                f"not audited fields {extra}"
            )

    # loading

    @classmethod
    def load(cls, path: Path) -> CapabilitySheet:
        """Read and validate a sheet; its file must be named after its framework.

        Raises ``ValueError`` (a :class:`pydantic.ValidationError` for a bad value) when
        the file cannot be read, is too big, is not UTF-8 YAML, has a duplicate key, is
        not a mapping, or does not validate.
        """
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"{path}: cannot read the capability sheet: {exc}") from exc
        if len(data) > MAX_SHEET_BYTES:
            raise ValueError(f"{path}: {len(data)} bytes, more than {MAX_SHEET_BYTES}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{path}: not UTF-8: {exc}") from exc
        try:
            doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: YAML does not parse: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError(f"{path}: a capability sheet is a mapping")
        sheet = cls.model_validate(doc)
        if sheet.framework != path.stem:
            raise ValueError(f"{path}: the sheet describes {sheet.framework!r}, not {path.stem!r}")
        return sheet

    @classmethod
    def for_framework(cls, framework: str, *, sheets_dir: Path = SHEETS_DIR) -> CapabilitySheet:
        """The sheet ``<sheets_dir>/<framework>.yaml``."""
        if not re.fullmatch(_SLUG, framework):
            raise ValueError(f"framework {framework!r} is not a sheet name")
        return cls.load(sheets_dir / f"{framework}.yaml")

    # the checks a run must pass before it starts

    def check_context(self, model: ModelConfig) -> UnsupportedRun | None:
        """``None`` if ``model``'s context is enough for this framework, else why not.

        The model is never changed: a context that is too small makes the run
        unsupported, it is never shrunk or raised behind the experiment's back. An
        unpinned ``num_ctx`` is unsupported too, because Ollama's default is far below
        what any of these frameworks needs. Without a documented minimum ("unknown") any
        pinned context passes.
        """
        if model.num_ctx is None:
            return UnsupportedRun(
                reason=f"{model.name}: num_ctx is not pinned in the experiment; {self.framework} "
                "would run on Ollama's default context"
            )
        if self.min_num_ctx == UNKNOWN or model.num_ctx >= self.min_num_ctx:
            return None
        return UnsupportedRun(
            reason=f"{model.name}: num_ctx {model.num_ctx} is below {self.framework}'s "
            f"documented minimum of {self.min_num_ctx}"
        )

    def check_runnable(self, model: ModelConfig) -> UnsupportedRun | None:
        """:meth:`check_context`, after refusing a framework that cannot reach Ollama."""
        if self.support_level is SupportLevel.NONE:
            return UnsupportedRun(reason=f"{self.framework} has no Ollama support")
        return self.check_context(model)


# --------------------------------------------------------------------------- end states


class ExitSignals(_Frozen):
    """What is known about how the agent stopped.

    The runner fills in ``exit_code`` and ``timed_out``; the adapter adds what only the
    framework's own logs show (``budget_exhausted``, ``refused``,
    ``tool_format_failure``) and must not change the runner's part.
    """

    #: the agent container's exit code; ``None`` when it never exited by itself
    exit_code: StrictInt | None
    #: the runner hit the wall-clock limit and killed the agent
    timed_out: StrictBool = False
    #: the gateway's token budget (or the framework's own turn cap) ended the run
    budget_exhausted: StrictBool = False
    #: the model refused and the framework stopped because of it
    refused: StrictBool = False
    #: the framework gave up because the model's tool calls did not parse
    tool_format_failure: StrictBool = False

    @model_validator(mode="after")
    def _exited_or_killed(self) -> Self:
        if self.exit_code is None and not self.timed_out:
            raise ValueError("timed_out: an agent that never exited must have been killed")
        return self


class EndStateMapper:
    """Turns :class:`ExitSignals` into one end state, the same way for every framework.

    Precedence, first match wins: the harness's limits (budget, then timeout) are hard
    facts and come first; then what the model did (refused, then tool calls that did
    not parse); then the exit code. So a framework that gives up on broken tool calls
    and exits 0 is a ``tool_format_failure``, never a completion.
    """

    _PRECEDENCE: ClassVar[tuple[tuple[str, AgentEndState], ...]] = (
        ("budget_exhausted", AgentEndState.BUDGET_EXHAUSTED),
        ("timed_out", AgentEndState.TIMEOUT),
        ("refused", AgentEndState.REFUSED),
        ("tool_format_failure", AgentEndState.TOOL_FORMAT_FAILURE),
    )

    #: Each end state's :class:`EndStatus` value (the table in the module docs).
    END_STATUS_VALUES: ClassVar[Mapping[AgentEndState, str]] = {s: s.value for s in AgentEndState}
    #: End states :class:`EndStatus` does not have yet; the wiring adds them.
    PENDING_IN_END_STATUS: ClassVar[frozenset[AgentEndState]] = frozenset(
        {AgentEndState.TOOL_FORMAT_FAILURE, AgentEndState.UNSUPPORTED}
    )

    @classmethod
    def classify(cls, signals: ExitSignals) -> AgentEndState:
        for flag, state in cls._PRECEDENCE:
            if getattr(signals, flag):
                return state
        return AgentEndState.COMPLETED if signals.exit_code == 0 else AgentEndState.CRASHED

    @classmethod
    def end_status(cls, state: AgentEndState) -> EndStatus:
        """The runner's :class:`EndStatus` for ``state``.

        Raises ``LookupError`` for the end states :class:`EndStatus` lacks until the
        runner is wired to adapters.
        """
        value = cls.END_STATUS_VALUES[state]
        try:
            return EndStatus(value)
        except ValueError:
            raise LookupError(
                f"EndStatus has no {value!r} yet; add it when the runner is wired to adapters"
            ) from None


# --------------------------------------------------------------------------- the adapter


class AdapterRun(_Frozen):
    """What an adapter needs to render one run."""

    run_id: Id
    model: ModelConfig
    #: the GOAT target's URL inside the cell
    target_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    #: the task given to the agent
    objective: Annotated[str, StringConstraints(min_length=1, max_length=8192)]
    #: the cell's LLM tap; every model call must go here
    llm_base_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    #: the experiment's limits, identical in every arm
    limits: RunLimits


class AgentLaunch(_Frozen):
    """How to run the framework in the cell's ``agent`` service.

    The runner turns it into an ``AgentSpec`` and writes ``files`` into the agent's
    config volume before the cell starts.
    """

    image: Text
    command: Annotated[tuple[Text, ...], Field(min_length=1)]
    env: dict[EnvName, str] = Field(default_factory=dict)
    #: config file name -> its bytes (flat names: no directories)
    files: dict[FileName, bytes] = Field(default_factory=dict)
    #: the framework starts containers, so the cell gets a cell-guard (§2.4)
    needs_docker: StrictBool = False
    cap_add: tuple[Text, ...] = ()


class CommandOutcome(Protocol):
    """The result of a command run in a cell service."""

    @property
    def returncode(self) -> int: ...
    @property
    def stdout(self) -> bytes: ...


class AgentHost(Protocol):
    """What an adapter may do in a running cell: run a command in one of its services."""

    def exec(self, service: str, argv: Sequence[str], *, timeout_s: float) -> CommandOutcome: ...


class Adapter(ABC):
    """One framework behind the adapter contract (DEVELOPMENT_PLAN §2.3).

    A subclass sets :attr:`framework` and fills in the framework-specific steps. The
    shared steps are fixed here: :meth:`prepare` refuses a run the sheet cannot support
    before anything is rendered, and :meth:`wait` classifies every run the same way.

    The runner drives the lifecycle: ``prepare`` -> (cell up) -> ``start`` -> (the
    runner polls the agent until it exits or times out, then collects the evidence) ->
    ``wait`` -> ``collect`` and ``agent_ids`` -> ``teardown``.
    """

    #: the sheet's name, ``agents/sheets/<framework>.yaml``
    framework: ClassVar[str]
    sheets_dir: ClassVar[Path] = SHEETS_DIR

    def __init__(self) -> None:
        # Read the sheet up front, so an adapter with a bad sheet is never built.
        self._sheet = CapabilitySheet.for_framework(
            type(self).framework, sheets_dir=type(self).sheets_dir
        )

    def describe(self) -> CapabilitySheet:
        """The capability sheet, stored with every run."""
        return self._sheet

    def prepare(self, run: AdapterRun) -> AgentLaunch | UnsupportedRun:
        """The run's launch, or why it cannot be started (nothing is rendered then)."""
        refusal = self._sheet.check_runnable(run.model)
        if refusal is not None:
            return refusal
        return self.render(run)

    def wait(self, observed: ExitSignals, evidence: Path) -> AgentEndState:
        """The run's end state, from what the runner saw and the framework's own logs.

        The runner does the waiting (it polls the agent container until it exits or
        the timeout kills it). ``observed`` is what it saw, ``evidence`` the run's
        collected evidence.
        """
        signals = self.exit_signals(observed, evidence)
        if (signals.exit_code, signals.timed_out) != (observed.exit_code, observed.timed_out):
            raise ValueError(
                f"{self.framework}: the adapter changed what the runner saw "
                f"(exit {observed.exit_code}, timed out {observed.timed_out})"
            )
        return EndStateMapper.classify(signals)

    def agent_ids(self, collected: Path) -> dict[int, str] | None:
        """Tap call ``seq`` -> sub-agent id, or ``None`` (contract in the module docs).

        The default is ``None``, allowed only when the sheet names no
        ``agent_id_source``. An adapter whose sheet names one must override this.
        """
        if self._sheet.agent_id_source is not None:
            raise NotImplementedError(
                f"{self.framework}: the sheet's agent_id_source is "
                f"{self._sheet.agent_id_source!r}, but agent_ids() is not implemented"
            )
        return None

    @abstractmethod
    def render(self, run: AdapterRun) -> AgentLaunch:
        """The container command, env and config files for a run the sheet supports.

        Every model call must go to ``run.llm_base_url`` with ``run.model``'s exact
        ``num_ctx``, and every side channel in the sheet must be switched off.
        """

    @abstractmethod
    def start(self, host: AgentHost) -> None:
        """Kick the framework off once its container runs (no human input, ever)."""

    @abstractmethod
    def exit_signals(self, observed: ExitSignals, evidence: Path) -> ExitSignals:
        """``observed`` plus what the framework's logs say about how it stopped."""

    @abstractmethod
    def collect(self, evidence: Path) -> list[AgentEvent]:
        """The framework's native trajectory as AgentEvents; native files stay as they are."""

    @abstractmethod
    def teardown(self, host: AgentHost) -> None:
        """Remove anything the framework created that the cell's teardown would miss."""
