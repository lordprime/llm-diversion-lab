"""The base every pentest-framework adapter builds on.

An adapter hides one framework (Strix, PentAGI, RedAmon, hackingBuddyGPT, PentestGPT)
behind the contract in DEVELOPMENT_PLAN §2.3: describe, prepare, start, wait, collect
and teardown. This module holds the parts every adapter shares:

* :class:`CapabilitySheet`: what we know about a framework, read from
  ``agents/sheets/<framework>.yaml``. Each value comes from
  ``docs/OLLAMA_SUPPORT_AUDIT.md`` (``audit_refs`` and each side channel's
  ``audit_ref`` say which section), and ``"unknown"`` marks what the audit could not
  verify.
* :meth:`CapabilitySheet.check_runnable`: a run is ``unsupported`` (never started) when
  the framework cannot reach Ollama, when a side channel is still unresolved, when the
  framework's turn cap is unknown, or when the model's context (``num_ctx``) is not
  pinned or is smaller than the framework needs. We never run a framework with a
  smaller context than it asks for, and never with a side channel we cannot turn off.
* :class:`AgentEndState`, :class:`EndStateMapper` and :class:`AdapterOutcome`: one end
  state per run, decided the same way for every framework, kept together with every
  signal behind it so that nothing (a refusal, say) disappears in the collapse.
* :class:`Adapter`: the abstract class each framework fills in.

How the end states map onto the runner's :class:`~control.core.models.EndStatus`
(applied when the runner is wired to adapters):

* ``completed`` -> ``EndStatus.COMPLETED``: exited 0 with no other signal;
* ``budget_exhausted`` -> ``EndStatus.BUDGET_EXHAUSTED``: the gateway's token budget ran
  out, or the framework stopped at its own turn cap (the sheet's ``max_turns_knob``);
* ``timeout`` -> ``EndStatus.TIMEOUT``: the runner killed it at the wall-clock limit;
* ``refused`` -> ``EndStatus.REFUSED``: the model refused and the run ended;
* ``crashed`` -> ``EndStatus.CRASHED``: any other non-zero exit;
* ``tool_format_failure`` -> a new ``EndStatus.TOOL_FORMAT_FAILURE`` (same value): the
  framework gave up because the model's tool calls did not parse;
* ``unsupported`` -> a new ``EndStatus.UNSUPPORTED`` (same value): never started, see
  :meth:`CapabilitySheet.check_runnable`.

Each value is the same string on both sides, so the mapping is ``EndStatus(state.value)``
(:meth:`EndStateMapper.end_status`). ``tool_format_failure`` is a valid outcome, not an
infrastructure failure, and it never counts as a completion.

The ``agent_ids`` contract (what :meth:`Adapter.agent_ids` returns, and what
:func:`control.telemetry.extract.summarise` accepts):

* ``None`` when the framework's own logs cannot tell its sub-agents apart. Telemetry
  then infers agents from the traffic (``agents_source="inferred"``).
* Otherwise a map from **every** tap call ``seq`` of the run to a non-empty agent id,
  and nothing else: no missing call, no seq the tap never recorded. Telemetry refuses
  anything less (``agents_source="adapter"``). An empty map is not "no ids": with any
  calls recorded it is refused, so return ``None`` instead. The seqs to cover are the
  ones :func:`control.telemetry.extract.load_calls` reads from the same evidence.

This module must not import ``control.runner``: the runner imports the adapters.
"""

from __future__ import annotations

import re
import unicodedata
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
from control.core.yaml_loader import UniqueKeyLoader
from control.telemetry.model import WireFormat

__all__ = [
    "MAX_NUM_CTX",
    "MAX_SHEET_BYTES",
    "SHEETS_DIR",
    "UNKNOWN",
    "Adapter",
    "AdapterLimits",
    "AdapterOutcome",
    "AdapterRun",
    "AgentEndState",
    "AgentHost",
    "AgentLaunch",
    "CapabilitySheet",
    "ChannelStatus",
    "CommandOutcome",
    "EndStateMapper",
    "ExitSignals",
    "ModelConfig",
    "Patch",
    "SideChannel",
    "SubAgentCap",
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
#: Words that stand in for a setting without being one (compared case-insensitively).
PLACEHOLDERS: Final = frozenset(
    {"", UNKNOWN, "tbd", "todo", "?", "??", "off", "none", "null", "n/a", "na", "-", "..."}
)

# A single line of printable text with at least one character that is neither
# whitespace nor an invisible format character (Cf: zero-width space, BOM, ...).
_LINE = r"^[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f\p{Cf}][^\x00-\x1f\x7f]*$"
Text = Annotated[str, StringConstraints(pattern=_LINE, max_length=1000)]
_SLUG = r"^[a-z][a-z0-9_-]{0,63}$"
_COMMIT = r"^[0-9a-f]{7,40}$"
_DIGEST = r"^(sha256:[0-9a-f]{64}|unknown)$"
# "§2.2" or "§2.2, §3": the audit sections a value comes from.
AuditRef = Annotated[str, StringConstraints(pattern=r"^§\d+(\.\d+)*(, §\d+(\.\d+)*)*$")]
_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"
# a flat file name that is not made of dots alone (so never "." or "..")
_FILE_NAME = r"^[A-Za-z0-9._-]*[A-Za-z0-9_-][A-Za-z0-9._-]*$"
_HTTP_URL = r"^https?://[^\s/]+(/\S*)?$"
_NO_NUL = r"^[^\x00]*$"

NumCtx = Annotated[StrictInt, Field(gt=0, le=MAX_NUM_CTX)]
EnvName = Annotated[str, StringConstraints(pattern=_ENV_NAME)]
EnvValue = Annotated[str, StringConstraints(pattern=_NO_NUL)]
FileName = Annotated[str, StringConstraints(pattern=_FILE_NAME, max_length=128)]
PositiveCount = Annotated[StrictInt, Field(gt=0, le=10_000)]


def _is_placeholder(value: str) -> bool:
    """Whether ``value`` stands in for a setting without being one.

    Settings are env and flag names, so the check sees through disguises: compatibility
    forms (full-width letters) are folded with NFKC, invisible format characters are
    dropped, and punctuation and whitespace are stripped from both ends. The value is a
    placeholder when it has no letter or digit, has a letter outside ASCII (a Cyrillic
    or accented look-alike), or is a placeholder word or starts with one followed by
    something that is not part of a word ("unknown: ...", "none found", "TBD - ...").
    """
    text = "".join(
        c for c in unicodedata.normalize("NFKC", value) if unicodedata.category(c) != "Cf"
    )
    start, end = 0, len(text)
    while start < end and (text[start].isspace() or unicodedata.category(text[start])[0] == "P"):
        start += 1
    while end > start and (
        text[end - 1].isspace() or unicodedata.category(text[end - 1])[0] == "P"
    ):
        end -= 1
    text = text[start:end].casefold()
    if not any(c.isalnum() for c in text):
        return True
    if any(c.isalpha() and not c.isascii() for c in text):
        return True
    for word in PLACEHOLDERS:
        if any(c.isalnum() for c in word) and text.startswith(word):
            rest = text[len(word) :]
            if not rest or not (rest[0].isalnum() or rest[0] == "_"):
                return True
    return False


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- the sheet


class SupportLevel(StrEnum):
    """How a framework reaches Ollama, as the audit labels it (§1 summary table)."""

    #: the project documents Ollama as a provider option, either as its own provider
    #: or as a preset of its OpenAI-compatible provider (RedAmon's case)
    NATIVE = "native"
    #: the project documents no Ollama route, but its generic OpenAI-compatible
    #: provider can be pointed at Ollama's ``/v1`` API
    OPENAI_COMPATIBLE = "openai_compatible"
    #: works, but through a route the project does not support (reported separately)
    UNOFFICIAL = "unofficial"
    #: cannot be pointed at Ollama at all
    NONE = "none"


class ChannelStatus(StrEnum):
    """Whether a side channel is known to be off."""

    #: turned off by the channel's ``setting``
    DISABLED = "disabled"
    #: found (by the audit or AUTOMATION_FEASIBILITY) but no switch is verified yet:
    #: the framework cannot run
    UNRESOLVED = "unresolved"


class SideChannel(_Frozen):
    """A way the framework could talk to something other than the tap, and its switch."""

    status: ChannelStatus
    #: the setting (or action) that turns it off; required when disabled, absent when
    #: unresolved
    setting: Text | None = None
    #: the audit section(s) the channel comes from
    audit_ref: AuditRef | None = None
    #: the docs/AUTOMATION_FEASIBILITY.md section(s), for a channel the audit missed or
    #: a candidate switch it names (unverified until the adapter task checks the source)
    feasibility_ref: AuditRef | None = None
    #: what the channel is, where it was found, and any candidate switch
    note: Text | None = None

    @model_validator(mode="after")
    def _setting_matches_status(self) -> Self:
        if self.audit_ref is None and self.feasibility_ref is None:
            raise ValueError("audit_ref: a side channel cites where it was found")
        if self.status is ChannelStatus.DISABLED:
            if self.setting is None or _is_placeholder(self.setting):
                raise ValueError(
                    f"setting: a disabled side channel names the setting that turns it off, "
                    f"not {self.setting!r}"
                )
        elif self.setting is not None:
            raise ValueError("setting: an unresolved side channel has no known setting yet")
        return self


class SubAgentCap(_Frozen):
    """A framework's own limit on its sub-agents. The adapter sets it and records it."""

    max_agents: PositiveCount
    max_concurrent: PositiveCount
    #: the framework's settings for the two limits
    max_agents_setting: Text
    max_concurrent_setting: Text
    audit_ref: AuditRef

    @model_validator(mode="after")
    def _sane(self) -> Self:
        if self.max_concurrent > self.max_agents:
            raise ValueError("max_concurrent: more concurrent sub-agents than sub-agents")
        settings = (self.max_agents_setting, self.max_concurrent_setting)
        if any(_is_placeholder(s) for s in settings):
            raise ValueError(f"sub_agent_cap: placeholder settings {settings!r}")
        if self.max_agents_setting == self.max_concurrent_setting:
            raise ValueError("sub_agent_cap: the two limits need two different settings")
        return self

    @property
    def settings(self) -> dict[str, int]:
        """Each setting with the cap the audit found for it."""
        return {
            self.max_agents_setting: self.max_agents,
            self.max_concurrent_setting: self.max_concurrent,
        }


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
    #: the token budget ran out, or the framework stopped at its own turn cap
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

    reason: Annotated[str, StringConstraints(pattern=_LINE, max_length=4000)]

    @property
    def end_state(self) -> AgentEndState:
        return AgentEndState.UNSUPPORTED


class CapabilitySheet(_Frozen):
    """What we know about one framework, with the audit section behind each value."""

    #: Fields whose value must cite an audit section in ``audit_refs`` (side channels
    #: and the sub-agent cap cite their own, entry by entry).
    AUDITED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "version",
            "support_level",
            "wire_formats",
            "model_call_paths",
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
    #: the mode or use case the adapter runs when the framework has several; call
    #: paths and sub-agents below describe that one only
    use_case: Text | None = None
    support_level: SupportLevel
    #: the model APIs the framework speaks to Ollama
    wire_formats: tuple[WireFormat, ...]
    #: every code path that calls a model; each must be shown to reach the tap
    model_call_paths: tuple[Text, ...]
    #: side channel name -> its status and switch; an unresolved one blocks every run
    side_channels: dict[Annotated[str, StringConstraints(pattern=_SLUG)], SideChannel]
    #: the smallest context the framework documents, or "unknown" if it gives none
    min_num_ctx: NumCtx | Literal["unknown"]
    #: whether it runs one agent, a fixed set, or spawns agents as it goes
    sub_agents: Literal["none", "fixed", "dynamic"]
    #: the framework's own cap on its sub-agents, if it has one
    sub_agent_cap: SubAgentCap | None = None
    #: where the adapter reads which sub-agent made each call, or None
    agent_id_source: Text | None = None
    #: why agent ids are not available, when the framework has sub-agents but no source
    agent_id_gap: Text | None = None
    patches: tuple[Patch, ...] = ()
    #: the framework's own setting for the maximum number of turns, or "unknown"
    #: (an unknown turn cap blocks every run: limits must be identical across arms)
    max_turns_knob: Text
    #: field -> the audit section(s) its value comes from, e.g. "§2.2, §3"
    audit_refs: dict[str, AuditRef]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        self._check_runnable_lists()
        self._check_max_turns_knob()
        self._check_sub_agents()
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

    def _check_max_turns_knob(self) -> None:
        if self.max_turns_knob != UNKNOWN and _is_placeholder(self.max_turns_knob):
            raise ValueError(
                f"max_turns_knob: name the setting or say 'unknown', not {self.max_turns_knob!r}"
            )

    def _check_sub_agents(self) -> None:
        if self.agent_id_source is not None and self.agent_id_gap is not None:
            raise ValueError("agent_id_source and agent_id_gap: give one or the other")
        if self.sub_agents == "none":
            if self.agent_id_source is not None or self.agent_id_gap is not None:
                raise ValueError(
                    "agent_id_source and agent_id_gap: a single-agent framework has no "
                    "sub-agent ids to find"
                )
            if self.sub_agent_cap is not None:
                raise ValueError("sub_agent_cap: a single-agent framework has no sub-agents")
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
            doc = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
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

    @property
    def unresolved_side_channels(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                name
                for name, channel in self.side_channels.items()
                if channel.status is ChannelStatus.UNRESOLVED
            )
        )

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
        """``None`` if a run may start, else every reason it may not, in one place.

        A run is unsupported when the framework cannot reach Ollama, when any side
        channel is unresolved, when its turn cap is unknown (the run's turn limit could
        not be applied), or when :meth:`check_context` refuses the model.
        """
        reasons: list[str] = []
        if self.support_level is SupportLevel.NONE:
            reasons.append(f"{self.framework} has no Ollama support")
        reasons += [f"unresolved side channel {name}" for name in self.unresolved_side_channels]
        if _is_placeholder(self.max_turns_knob):
            reasons.append(f"{self.framework}'s turn cap setting is unknown")
        context = self.check_context(model)
        if context is not None:
            reasons.append(context.reason)
        return UnsupportedRun(reason="; ".join(reasons)) if reasons else None


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
    #: the gateway's token budget, or the framework's own turn cap, ended the run
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
    and exits 0 is a ``tool_format_failure``, never a completion. The collapsed state
    loses the other signals, so :class:`AdapterOutcome` keeps them all beside it.
    """

    PRECEDENCE: ClassVar[tuple[tuple[str, AgentEndState], ...]] = (
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
    def signalled(cls, signals: ExitSignals) -> tuple[AgentEndState, ...]:
        """Every end state the signals point to, in precedence order (never empty)."""
        states = [state for flag, state in cls.PRECEDENCE if getattr(signals, flag)]
        if signals.exit_code is not None and signals.exit_code != 0:
            states.append(AgentEndState.CRASHED)
        return tuple(states) or (AgentEndState.COMPLETED,)

    @classmethod
    def classify(cls, signals: ExitSignals) -> AgentEndState:
        """The one end state of the run: the first of :meth:`signalled`."""
        return cls.signalled(signals)[0]

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


class AdapterOutcome(_Frozen):
    """A run's end state together with every signal behind it.

    ``end_state`` is the collapsed state the run is filed under; ``signals`` keeps the
    rest, so a refusal followed by a timeout or a budget stop is still visible. The
    runner stores both.
    """

    end_state: AgentEndState
    signals: ExitSignals

    @classmethod
    def of(cls, signals: ExitSignals) -> AdapterOutcome:
        return cls(end_state=EndStateMapper.classify(signals), signals=signals)

    @model_validator(mode="after")
    def _collapsed_from_signals(self) -> Self:
        expected = EndStateMapper.classify(self.signals)
        if self.end_state is not expected:
            raise ValueError(f"end_state: the signals give {expected.value}, not {self.end_state}")
        return self

    @property
    def signalled(self) -> tuple[AgentEndState, ...]:
        """Every end state the signals point to, the filed one first."""
        return EndStateMapper.signalled(self.signals)


# --------------------------------------------------------------------------- the adapter


class AdapterLimits(_Frozen):
    """The run's limits an adapter maps onto the framework's own settings.

    Identical in every arm. The token budget is enforced by the gateway, not here.
    """

    max_turns: PositiveCount
    timeout_s: Annotated[StrictInt, Field(gt=0, le=7 * 24 * 3600)]


class AdapterRun(_Frozen):
    """One run as an adapter sees it, passed to every step of the lifecycle.

    It is plain, serialisable data: after a runner restart a fresh adapter given the
    same ``AdapterRun`` can still collect and tear down, so an adapter keeps no
    per-run state of its own.
    """

    run_id: Id
    model: ModelConfig
    #: the GOAT target's URL inside the cell
    target_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    #: the task given to the agent
    objective: Annotated[str, StringConstraints(min_length=1, max_length=8192, pattern=_NO_NUL)]
    #: the cell's LLM tap; every model call must go here
    llm_base_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    limits: AdapterLimits


class AgentLaunch(_Frozen):
    """How to run the framework in the cell's ``agent`` service.

    The runner turns it into an ``AgentSpec``, writes ``files`` into the agent's config
    volume before the cell starts, and stores ``recorded_settings`` with the run.
    """

    image: Text
    command: Annotated[tuple[Text, ...], Field(min_length=1)]
    env: dict[EnvName, EnvValue] = Field(default_factory=dict)
    #: config file name -> its bytes (flat names: no directories)
    files: dict[FileName, bytes] = Field(default_factory=dict)
    #: the framework starts containers, so the cell gets a cell-guard (§2.4)
    needs_docker: StrictBool = False
    cap_add: tuple[Text, ...] = ()
    #: settings the run's results depend on, stored with the run (e.g. the sub-agent cap)
    recorded_settings: dict[Text, Text] = Field(default_factory=dict)


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
    ``wait`` -> ``collect`` and ``agent_ids`` -> ``teardown``. Every step gets the
    run's :class:`AdapterRun`, and an adapter keeps no state between steps.
    """

    #: the sheet's name, ``agents/sheets/<framework>.yaml``
    framework: ClassVar[str]
    sheets_dir: ClassVar[Path] = SHEETS_DIR

    def __init__(self) -> None:
        # Read the sheet up front, so an adapter with a bad sheet is never built.
        self._sheet = CapabilitySheet.for_framework(
            type(self).framework, sheets_dir=type(self).sheets_dir
        )
        if self._sheet.agent_id_source is not None and type(self).agent_ids is Adapter.agent_ids:
            raise TypeError(
                f"{self.framework}: the sheet reads agent ids from "
                f"{self._sheet.agent_id_source!r}, but the adapter does not override agent_ids()"
            )

    def describe(self) -> CapabilitySheet:
        """The capability sheet, stored with every run."""
        return self._sheet

    def prepare(self, run: AdapterRun) -> AgentLaunch | UnsupportedRun:
        """The run's launch, or why it cannot be started (nothing is rendered then)."""
        refusal = self._sheet.check_runnable(run.model)
        if refusal is not None:
            return refusal
        launch = self.render(run)
        self._check_recorded_settings(run, launch)
        return launch

    def _check_recorded_settings(self, run: AdapterRun, launch: AgentLaunch) -> None:
        # The turn cap and any sub-agent cap are part of the agent configuration: the
        # adapter sets them explicitly and records them with the run. The turn cap is
        # exactly the run's limit; a sub-agent cap stays within the framework's own.
        turns = run.limits.max_turns
        wanted = {self._sheet.max_turns_knob: (turns, turns)}
        cap = self._sheet.sub_agent_cap
        if cap is not None:
            wanted |= {setting: (1, limit) for setting, limit in cap.settings.items()}
        for setting, (low, high) in wanted.items():
            value = launch.recorded_settings.get(setting)
            # Only the plain ASCII form counts ("50", never "050", other digit scripts or
            # "³"), so the recorded text is exactly what every run with this limit records.
            if value not in {str(n) for n in range(low, high + 1)}:
                wanted_text = str(low) if low == high else f"a number from {low} to {high}"
                raise ValueError(
                    f"{self.framework}: the launch must record {setting} as {wanted_text}, "
                    f"not {value!r}"
                )

    def wait(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> AdapterOutcome:
        """The run's outcome, from what the runner saw and the framework's own logs.

        The runner does the waiting (it polls the agent container until it exits or
        the timeout kills it). ``observed`` is what it saw, ``evidence`` the run's
        collected evidence.
        """
        signals = self.exit_signals(run, observed, evidence)
        if (signals.exit_code, signals.timed_out) != (observed.exit_code, observed.timed_out):
            raise ValueError(
                f"{self.framework}: the adapter changed what the runner saw "
                f"(exit {observed.exit_code}, timed out {observed.timed_out})"
            )
        # The adapter may only add what the framework's logs show; it never takes a
        # signal back (a refusal stays a refusal).
        cleared = sorted(
            name for name, value in observed if value is True and not getattr(signals, name)
        )
        if cleared:
            raise ValueError(f"{self.framework}: the adapter cleared observed signals {cleared}")
        return AdapterOutcome.of(signals)

    def agent_ids(self, run: AdapterRun, collected: Path) -> dict[int, str] | None:
        """Tap call ``seq`` -> sub-agent id, or ``None`` (contract in the module docs).

        ``collected`` is the run's collected evidence. The default is ``None``. An
        adapter whose sheet names an ``agent_id_source`` must override this, or it cannot
        be built.
        """
        return None

    @abstractmethod
    def render(self, run: AdapterRun) -> AgentLaunch:
        """The container command, env and config files for a run the sheet supports.

        Every model call must go to ``run.llm_base_url`` with ``run.model``'s exact
        ``num_ctx``, and every side channel in the sheet must be switched off.
        """

    @abstractmethod
    def start(self, run: AdapterRun, host: AgentHost) -> None:
        """Kick the framework off once its container runs (no human input, ever)."""

    @abstractmethod
    def exit_signals(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> ExitSignals:
        """``observed`` plus what the framework's logs say about how it stopped."""

    @abstractmethod
    def collect(self, run: AdapterRun, evidence: Path) -> list[AgentEvent]:
        """The framework's native trajectory as AgentEvents; native files stay as they are."""

    @abstractmethod
    def teardown(self, run: AdapterRun, host: AgentHost) -> None:
        """Remove anything the framework created that the cell's teardown would miss.

        It must work from ``run`` alone, with a fresh adapter, after a runner restart.
        """
