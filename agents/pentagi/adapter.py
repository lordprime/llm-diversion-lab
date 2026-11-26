"""The PentAGI adapter: one headless PentAGI flow per run, on the cell's LLM tap.

PentAGI (https://github.com/vxcontrol/pentagi, v2.2.0 at b611fbe, see
``agents/pentagi/source.yaml``) is a Go web service with its own PostgreSQL/pgvector
database, a web UI and the worker containers it starts for its agents. How one run maps
onto it:

* **One container.** The agent image (``agents/pentagi/Dockerfile``) carries the patched
  PentAGI binary, PostgreSQL 17 with pgvector and :mod:`agents.pentagi.driver`. The
  driver starts a fresh database in the container's ``/tmp``, starts PentAGI on
  127.0.0.1, creates one flow through the REST API and waits for its first task to end.
  No UI, no scraper, no Graphiti, no Langfuse/OTel service is run: the minimum stack is
  PentAGI plus its database, and the cell's cell-guard for the workers.
* **Workers through cell-guard.** PentAGI starts its Kali worker containers through the
  Docker socket. The launch sets ``needs_docker``, so the cell gives the agent only
  cell-guard's socket (``DOCKER_HOST``, DEVELOPMENT_PLAN §2.4); ``DOCKER_INSIDE=false``
  means no worker is ever handed a Docker socket; patch 0003 makes PentAGI's container
  requests ones cell-guard accepts. The worker image is pinned by digest in
  ``source.yaml`` and must be pre-loaded in the cell (cell-guard refuses pulls).
* **Every model call to the tap.** Only the ``ollama`` provider is configured
  (``OLLAMA_SERVER_URL`` is the tap, no other provider key, no fallback provider). Every
  one of PentAGI's 13 role configs names the run's model, the run's ``num_ctx`` goes
  with every chat call (patch 0001), and embeddings go to the tap's Ollama API with a
  pinned embedding model. Every side channel in the sheet is switched off by
  :attr:`PentagiAdapter.CHANNEL_SWITCHES`.

End states come from the driver's ``driver.json`` and PentAGI's log (see
:meth:`PentagiAdapter.exit_signals`); sub-agent ids from the ``msgchains`` table (see
:class:`ChainIndex`).
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, ClassVar, Final

import yaml
from pydantic import BaseModel, ConfigDict, JsonValue, StringConstraints, ValidationError

from agents.base import (
    Adapter,
    AdapterRun,
    AgentHost,
    AgentLaunch,
    ExitSignals,
    UnsupportedRun,
)
from control.core.models import AgentEvent, AgentEventType
from control.telemetry.extract import TapEvidence, load_calls
from control.telemetry.model import CallTelemetry, WireFormat
from control.telemetry.wire import parse_call

__all__ = [
    "EVIDENCE_SUBDIR",
    "ChainIndex",
    "PentagiAdapter",
    "PentagiEvidence",
    "PentagiSource",
    "PentagiTap",
]

#: Where the driver writes its evidence, relative to a run's evidence directory.
EVIDENCE_SUBDIR: Final = Path("agent") / "pentagi"
#: The most of one evidence file the adapter reads (the driver writes them, but a run's
#: evidence is still untrusted).
MAX_EVIDENCE_BYTES: Final = 256 * 1024 * 1024
#: Messages PentAGI logs when it gives up a chain (pkg/providers/performer.go at b611fbe).
TURN_CAP_MARKER: Final = "agent chain exceeded maximum iterations"  # performer.go:116-119
TOOL_FORMAT_MARKER: Final = "reflector called too many times"  # performer.go:637-650

_ROLE_TO_OLLAMA: Final = {"system": "system", "human": "user", "ai": "assistant", "tool": "tool"}
#: How langchaingo joins the text parts of one message (llms/ollama/ollamallm.go:286-292).
_PART_JOINER: Final = "\n\nnext part of text\n\n"
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


# --------------------------------------------------------------------------- source.yaml


class _PinnedImage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    image: Annotated[str, StringConstraints(pattern=_IMAGE.pattern)]
    digest: Annotated[str, StringConstraints(pattern=_DIGEST.pattern)]

    @property
    def familiar(self) -> str:
        """``repo@digest`` in Docker's short form, as PentAGI looks the image up.

        PentAGI asks the daemon for the image with a ``reference`` filter, which Docker
        matches against the familiar name (no ``docker.io/``), and cell-guard accepts the
        same ``repository@digest`` (pinned in images.lock).
        """
        repository = self.image.rsplit(":", 1)[0] if ":" in self.image else self.image
        name = repository.removeprefix("docker.io/").removeprefix("library/")
        return f"{name}@{self.digest}"


class PentagiSource(BaseModel):
    """``agents/pentagi/source.yaml``: where the image comes from and what it starts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    PATH: ClassVar[Path] = Path(__file__).resolve().parent / "source.yaml"

    name: str
    repo: str
    version: str
    commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    license: str
    image_base: _PinnedImage
    build_base: _PinnedImage
    worker_image: _PinnedImage
    smoke_worker_image: _PinnedImage

    @classmethod
    def load(cls, path: Path | None = None) -> PentagiSource:
        doc = yaml.safe_load((path or cls.PATH).read_text(encoding="utf-8"))
        return cls.model_validate(doc)


# --------------------------------------------------------------------------- evidence


class PentagiEvidence:
    """The driver's files in a run's evidence, read without following symlinks.

    The evidence is written inside the run cell, so it is untrusted, and it is read by
    the same rules as the tap's files (:class:`TapEvidence`): neither folder on the way
    may be a symlink, only regular files are read (``O_NOFOLLOW``), and nothing over
    :data:`MAX_EVIDENCE_BYTES`.
    """

    def __init__(self, evidence_dir: Path) -> None:
        self._root = evidence_dir
        self._dir = evidence_dir / EVIDENCE_SUBDIR

    def _folder_is_safe(self) -> bool:
        folder = self._root
        for part in EVIDENCE_SUBDIR.parts:
            folder = folder / part
            try:
                info = os.lstat(folder)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(info.st_mode):  # a symlink is not a directory to lstat
                return False
        return True

    def read_file(self, name: str) -> bytes | None:
        """A file's bytes; ``None`` if it is missing, unsafe or too big."""
        if "/" in name or not self._folder_is_safe():
            return None
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self._dir / name, flags)
        except OSError:
            return None
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            data = fh.read(MAX_EVIDENCE_BYTES + 1)
        return None if len(data) > MAX_EVIDENCE_BYTES else data

    def driver_report(self) -> dict[str, Any] | None:
        """``driver.json``, or ``None`` if it is missing or not a JSON object."""
        data = self.read_file("driver.json")
        try:
            doc = json.loads(data) if data is not None else None
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None

    def log_text(self) -> str:
        data = self.read_file("pentagi.log")
        return "" if data is None else data.decode("utf-8", errors="replace")

    def rows(self, table: str) -> Iterator[dict[str, Any]]:
        """The JSON-object lines of ``<table>.jsonl``; other lines are skipped."""
        data = self.read_file(f"{table}.jsonl")
        if data is None:
            return
        for line in data.decode("utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield row


class PentagiTap(TapEvidence):
    """The tap's own record of each call's endpoint and request (``llm/``)."""

    def _document(self, seq: int, suffix: str) -> object:
        """One tap file as JSON, ``None`` if it is missing, unsafe or not JSON."""
        try:
            raw = self._read(seq, suffix)
        except Exception:  # the reader's own "unsafe file" error: treat it as missing
            return None
        try:
            return json.loads(raw) if raw is not None else None
        except ValueError:
            return None

    def request_path(self, seq: int) -> str | None:
        doc = self._document(seq, ".meta.json")
        request = doc.get("request") if isinstance(doc, dict) else None
        path = request.get("path") if isinstance(request, dict) else None
        return path if isinstance(path, str) else None

    def request_tools(self, seq: int) -> frozenset[str] | None:
        """The tool names a chat request offered, or ``None`` if it cannot be read."""
        return self.tool_names(self._document(seq, ".req.json"))

    @staticmethod
    def tool_names(doc: object) -> frozenset[str] | None:
        """The tool names an Ollama chat request body offers (empty for none), or
        ``None`` if it is not a request body or a tool has no name."""
        if not isinstance(doc, dict):
            return None
        tools = doc.get("tools") or []
        if not isinstance(tools, list):
            return None
        names: set[str] = set()
        for tool in tools:
            function = tool.get("function") if isinstance(tool, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            if not isinstance(name, str):
                return None
            names.add(name)
        return frozenset(names)


class ChainIndex:
    """PentAGI's message chains, keyed the way telemetry keys a call's conversation.

    Every agent conversation PentAGI holds is a row of ``msgchains`` (its ``type`` is the
    role: primary_agent, pentester, generator...). A tap call belongs to the chain whose
    stored conversation opens the same way: telemetry's ``thread_key`` (system prompt
    plus first message) or, failing that, its ``system_sha256``. The chain's opening is
    put through the same parser as a real call (:func:`parse_call`), so both keys are
    computed by one piece of code. A key shared by two chains is ambiguous and matches
    nothing.
    """

    def __init__(self, rows: Iterator[dict[str, Any]]) -> None:
        self._by_thread: dict[str, set[str]] = {}
        self._by_system: dict[str, set[str]] = {}
        for row in rows:
            agent, call = self._opening(row)
            if agent is None or call is None:
                continue
            self._by_thread.setdefault(call.thread_key, set()).add(agent)
            if call.system_sha256 is not None:
                self._by_system.setdefault(call.system_sha256, set()).add(agent)

    @staticmethod
    def _text(message: Mapping[str, Any]) -> str | None:
        if isinstance(message.get("text"), str):
            return str(message["text"])
        parts = message.get("parts")
        if not isinstance(parts, list):
            return None
        texts = [
            str(p["text"])
            for p in parts
            if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str)
        ]
        return _PART_JOINER.join(texts)

    @classmethod
    def _opening(cls, row: Mapping[str, Any]) -> tuple[str | None, CallTelemetry | None]:
        chain_id, role, chain = row.get("id"), row.get("type"), row.get("chain")
        if isinstance(chain_id, bool) or not isinstance(chain_id, int):
            return None, None
        if not isinstance(role, str) or not re.fullmatch(r"[a-z_]{1,40}", role):
            return None, None
        if not isinstance(chain, list):
            return None, None
        messages: list[dict[str, str]] = []
        for message in chain:
            kind = message.get("role") if isinstance(message, dict) else None
            text = cls._text(message) if isinstance(message, dict) else None
            if kind not in _ROLE_TO_OLLAMA or text is None:
                return None, None
            messages.append({"role": _ROLE_TO_OLLAMA[kind], "content": text})
            if kind != "system":
                break
        if not messages:
            return None, None
        body = json.dumps({"messages": messages}).encode("utf-8")
        return f"{role}:{chain_id}", parse_call("/api/chat", body, None, None)

    def agent_for(self, call: CallTelemetry) -> str | None:
        """The one chain ``call`` belongs to, or ``None`` if none or several match."""
        lookups = ((self._by_thread, call.thread_key), (self._by_system, call.system_sha256))
        for index, key in lookups:
            found = index.get(key) if key else None
            if found:
                return next(iter(found)) if len(found) == 1 else None
        return None


# --------------------------------------------------------------------------- the adapter


class PentagiAdapter(Adapter):
    """PentAGI behind the adapter contract (see the module docs)."""

    framework = "pentagi"

    #: The agent image's logical name in deploy/images.lock.
    IMAGE: ClassVar[str] = "agent-pentagi"
    COMMAND: ClassVar[tuple[str, ...]] = ("python3", "/opt/lab/pentagi/driver.py")
    #: Where the driver writes the per-role config (inside the container's /tmp).
    PROVIDER_CONFIG_PATH: ClassVar[str] = "/tmp/pentagi/ollama.provider.yml"  # noqa: S108
    SERVER_PORT: ClassVar[int] = 8080
    #: PentAGI never stops a chain before 2 * maxAgentShutdownIterations model turns
    #: (pkg/providers/performer.go:39, 99-113): a smaller limit would not be applied.
    MIN_TURNS: ClassVar[int] = 6
    #: The upstream default for the limited roles (pkg/config/config.go:317).
    LIMITED_TURNS_DEFAULT: ClassVar[int] = 20
    #: The embedding model, served by the same Ollama through the tap. It must be pulled
    #: on the model host next to the campaign's chat models.
    EMBEDDING_MODEL: ClassVar[str] = "nomic-embed-text"
    #: The per-role options of upstream's embedded Ollama config
    #: (pkg/providers/ollama/config.yml at b611fbe), kept so only the model changes.
    ROLE_OPTIONS: ClassVar[Mapping[str, Mapping[str, Any]]] = {
        "simple": {"temperature": 1.0, "top_p": 0.9, "n": 1, "max_tokens": 8192},
        "simple_json": {
            "temperature": 1.0,
            "top_p": 0.95,
            "n": 1,
            "max_tokens": 4096,
            "json": True,
        },
        "primary_agent": {"temperature": 1.0, "top_p": 0.9, "n": 1, "max_tokens": 16384},
        "assistant": {"temperature": 1.0, "top_p": 0.9, "n": 1, "max_tokens": 16384},
        "generator": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 20480},
        "refiner": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 16384},
        "adviser": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 8192},
        "reflector": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 4096},
        "searcher": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 8192},
        "enricher": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 4096},
        "coder": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 20480},
        "installer": {"temperature": 1.0, "top_p": 0.9, "n": 1, "max_tokens": 16384},
        "pentester": {"temperature": 1.0, "top_p": 0.95, "n": 1, "max_tokens": 8192},
    }
    #: Each side channel in the sheet and the exact environment that switches it off.
    #: An empty value is safe only for a variable without an upstream default: PentAGI's
    #: env parser (caarlos0/env v10.0.0, env.go:413-425) reads an empty value as "use the
    #: default", so DUCKDUCKGO_ENABLED= would mean true and UPDATE_CHECK_INTERVAL= 3h.
    CHANNEL_SWITCHES: ClassVar[Mapping[str, Mapping[str, str]]] = {
        "openai_embeddings": {"EMBEDDING_PROVIDER": "ollama"},
        "graphiti": {"GRAPHITI_ENABLED": "false", "GRAPHITI_URL": ""},
        "search_engines": {
            "DUCKDUCKGO_ENABLED": "false",
            "SPLOITUS_ENABLED": "false",
            "WEB_SEARCH_INTERNAL_ENABLED": "false",
            "GOOGLE_API_KEY": "",
            "GOOGLE_CX_KEY": "",
            "TAVILY_API_KEY": "",
            "TRAVERSAAL_API_KEY": "",
            "FIRECRAWL_API_KEY": "",
            "PERPLEXITY_API_KEY": "",
            "SEARXNG_URL": "",
            "PROXY_URL": "",
        },
        "scraper": {"SCRAPER_PUBLIC_URL": "", "SCRAPER_PRIVATE_URL": ""},
        "oauth": {
            "OAUTH_GOOGLE_CLIENT_ID": "",
            "OAUTH_GOOGLE_CLIENT_SECRET": "",
            "OAUTH_GITHUB_CLIENT_ID": "",
            "OAUTH_GITHUB_CLIENT_SECRET": "",
            "PUBLIC_URL": "",
        },
        "langfuse_otel": {
            "LANGFUSE_BASE_URL": "",
            "LANGFUSE_PROJECT_ID": "",
            "LANGFUSE_PUBLIC_KEY": "",
            "LANGFUSE_SECRET_KEY": "",
            "OTEL_HOST": "",
        },
        "update_reporter": {"UPDATE_CHECK_INTERVAL": "0", "LICENSE_KEY": ""},
        "image_selection": {"DOCKER_IMAGE_SELECTION_MODE": "fixed", "DOCKER_ALLOWED_IMAGES": ""},
    }
    #: Settings outside the sheet's side channels that keep every call on the tap and
    #: every container behind cell-guard. Run-dependent values are added in render().
    FIXED_ENV: ClassVar[Mapping[str, str]] = {
        # the ollama provider only, and no failover to another provider
        # (pkg/providers/providers.go:630-638)
        "LLM_FALLBACK_PROVIDER": "",
        "BEDROCK_DEFAULT_AUTH": "false",
        "OLLAMA_SERVER_API_KEY": "",
        # no /api/show or /api/pull (ollama.go:215-224), no /api/tags (ollama.go:246-253)
        "OLLAMA_SERVER_PULL_MODELS_ENABLED": "false",
        "OLLAMA_SERVER_LOAD_MODELS_ENABLED": "false",
        # workers never get a Docker socket; PentAGI reaches Docker only via DOCKER_HOST
        "DOCKER_INSIDE": "false",
        "DOCKER_NET_ADMIN": "false",
        "DOCKER_SOCKET": "",
        "DOCKER_INSIDE_HOST": "",
        "DOCKER_NETWORK": "",  # cell-guard puts every worker on the cell network
        "DOCKER_WORK_DIR": "",
        # the API is for the driver only
        "SERVER_HOST": "127.0.0.1",
        "SERVER_USE_SSL": "false",
        "ASK_USER": "false",
        "ASSISTANT_USE_AGENTS": "false",
        "DEBUG": "false",
        "PPROF_ADDR": "",
        "DATA_DIR": "/tmp/pentagi/data",  # noqa: S108 - the container's tmpfs
        "STATIC_DIR": "/opt/pentagi/fe",
        # PentAGI's own behaviour, pinned at the upstream defaults and recorded
        "EXECUTION_MONITOR_ENABLED": "false",
        "AGENT_PLANNING_STEP_ENABLED": "false",
        "TERMINAL_TOOL_TIMEOUT": "1200",
    }
    #: Settings stored with every run (besides the turn caps).
    RECORDED: ClassVar[tuple[str, ...]] = (
        "OLLAMA_SERVER_NUM_CTX",
        "EMBEDDING_MODEL",
        "DOCKER_DEFAULT_IMAGE_FOR_PENTEST",
        "EXECUTION_MONITOR_ENABLED",
        "AGENT_PLANNING_STEP_ENABLED",
        "TERMINAL_TOOL_TIMEOUT",
        "MAX_LIMITED_AGENT_TOOL_CALLS",
    )
    #: Tools PentAGI offers only in the tool-call-ID probe at flow setup
    #: (pkg/providers/provider/agents.go:24-25).
    PROBE_TOOLS: ClassVar[frozenset[str]] = frozenset({"get_number", "submit_pattern"})
    #: Endpoint suffixes of PentAGI's embedding calls.
    EMBEDDING_PATHS: ClassVar[tuple[str, ...]] = ("/api/embeddings", "/api/embed")

    def __init__(
        self,
        *,
        source: PentagiSource | None = None,
        embedding_model: str | None = None,
        poll_seconds: int = 5,
        smoke: bool = False,
    ) -> None:
        super().__init__()
        self._source = source or PentagiSource.load()
        self._embedding_model = embedding_model or self.EMBEDDING_MODEL
        self._poll_seconds = poll_seconds
        pinned = self._source.smoke_worker_image if smoke else self._source.worker_image
        self._worker_image = pinned.familiar
        # every side channel in the sheet has its switch here, and nothing more
        unmatched = sorted(set(self.describe().side_channels) ^ set(self.CHANNEL_SWITCHES))
        if unmatched:
            raise TypeError(f"pentagi: side channels and switches do not match: {unmatched}")

    # -- prepare / render

    def prepare(self, run: AdapterRun) -> AgentLaunch | UnsupportedRun:
        """The base checks, plus PentAGI's floor on the turn limit (every reason at once)."""
        if run.limits.max_turns >= self.MIN_TURNS:
            return super().prepare(run)
        reasons = [
            f"pentagi: a turn limit of {run.limits.max_turns} is below the "
            f"{self.MIN_TURNS} turns PentAGI always allows a chain"
        ]
        sheet_refusal = self.describe().check_runnable(run.model)
        if sheet_refusal is not None:
            reasons.append(sheet_refusal.reason)
        return UnsupportedRun(reason="; ".join(reasons))

    def provider_config(self, model: str) -> str:
        """The per-role YAML: upstream's options with every role on ``model``."""
        doc = {role: {"model": model, **options} for role, options in self.ROLE_OPTIONS.items()}
        return yaml.safe_dump(doc, sort_keys=False)

    def flow_input(self, run: AdapterRun) -> str:
        """The flow's first message: the objective, then the target it is about."""
        return f"{run.objective}\n\nTarget: {run.target_url}"

    def render(self, run: AdapterRun) -> AgentLaunch:
        turns = run.limits.max_turns
        limited = min(self.LIMITED_TURNS_DEFAULT, turns)
        num_ctx = run.model.num_ctx
        if num_ctx is None:  # check_context already refused it; keep the type checker honest
            raise ValueError("pentagi: num_ctx must be pinned")
        env: dict[str, str] = {}
        for switches in self.CHANNEL_SWITCHES.values():
            env.update(switches)
        env.update(self.FIXED_ENV)
        env.update(
            {
                "OLLAMA_SERVER_URL": run.llm_base_url,
                "OLLAMA_SERVER_MODEL": run.model.name,
                "OLLAMA_SERVER_NUM_CTX": str(num_ctx),
                "OLLAMA_SERVER_CONFIG_PATH": self.PROVIDER_CONFIG_PATH,
                "EMBEDDING_URL": run.llm_base_url,
                "EMBEDDING_MODEL": self._embedding_model,
                "DOCKER_DEFAULT_IMAGE_FOR_PENTEST": self._worker_image,
                "DOCKER_DEFAULT_IMAGE": self._worker_image,
                "SERVER_PORT": str(self.SERVER_PORT),
                self.describe().max_turns_knob: str(turns),
                "MAX_LIMITED_AGENT_TOOL_CALLS": str(limited),
                "LAB_PENTAGI_RUN": json.dumps(
                    {
                        "input": self.flow_input(run),
                        "provider": "ollama",
                        "provider_config": self.provider_config(run.model.name),
                        "poll_seconds": self._poll_seconds,
                    }
                ),
            }
        )
        recorded = {name: env[name] for name in (self.describe().max_turns_knob, *self.RECORDED)}
        return AgentLaunch(
            image=self.IMAGE,
            command=self.COMMAND,
            env=env,
            needs_docker=True,
            recorded_settings=recorded,
        )

    # -- the run

    def start(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: the container's command is the driver, which starts the flow."""

    def exit_signals(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> ExitSignals:
        """``observed`` plus why PentAGI gave up, when the driver says it did.

        Only a run whose driver reports ``failed`` (PentAGI failed the task or the flow)
        is explained from PentAGI's log: a chain that hit its turn cap is
        ``budget_exhausted``, a chain whose reflector gave up on text-instead-of-tool-calls
        is ``tool_format_failure``. A finished or timed-out run gets no flag from the log,
        because PentAGI carries on after one chain gives up. PentAGI has no refusal signal
        of its own (a refusal is text, which goes to the reflector), so ``refused`` is
        never set here.
        """
        files = PentagiEvidence(evidence)
        report = files.driver_report()
        if report is None or report.get("outcome") != "failed":
            return observed
        log = files.log_text()
        added: dict[str, bool] = {}
        if TURN_CAP_MARKER in log:
            added["budget_exhausted"] = True
        if TOOL_FORMAT_MARKER in log:
            added["tool_format_failure"] = True
        return observed.model_copy(update=added) if added else observed

    def collect(self, run: AdapterRun, evidence: Path) -> list[AgentEvent]:
        """PentAGI's tool calls and its task reports as AgentEvents, in time order.

        Rows that do not have the expected shape are left out; the native files stay
        in the evidence as they are.
        """
        files = PentagiEvidence(evidence)
        found = [step for row in files.rows("toolcalls") if (step := self._tool_event(row))]
        found += [step for row in files.rows("tasks") if (step := self._report_event(row))]
        found.sort(key=lambda item: (item[0], item[1]))
        events: list[AgentEvent] = []
        for ts, ref, fields in found:
            try:
                event = AgentEvent(
                    run_id=run.run_id,
                    stream="agent",
                    seq=len(events),
                    ts=ts,
                    native_ref=ref,
                    **fields,
                )
            except ValidationError:
                continue
            events.append(event)
        return events

    @staticmethod
    def _timestamp(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            ts = datetime.fromisoformat(value)
        except ValueError:
            return None
        return ts if ts.tzinfo is not None else None

    @classmethod
    def _tool_event(cls, row: Mapping[str, Any]) -> tuple[datetime, str, dict[str, Any]] | None:
        ts, row_id = cls._timestamp(row.get("created_at")), row.get("id")
        name, args, result = row.get("name"), row.get("args"), row.get("result")
        if ts is None or isinstance(row_id, bool) or not isinstance(row_id, int):
            return None
        if not isinstance(name, str) or not isinstance(args, dict):
            return None
        fields: dict[str, JsonValue] = {
            "event_type": AgentEventType.TOOL_CALL,
            "tool_name": name,
            "tool_args": args,
            "text": result if isinstance(result, str) else None,
        }
        return ts, f"toolcalls:{row_id:012d}", fields

    @classmethod
    def _report_event(cls, row: Mapping[str, Any]) -> tuple[datetime, str, dict[str, Any]] | None:
        ts, row_id, result = cls._timestamp(row.get("updated_at")), row.get("id"), row.get("result")
        if ts is None or isinstance(row_id, bool) or not isinstance(row_id, int):
            return None
        if not isinstance(result, str) or not result.strip():
            return None
        fields: dict[str, JsonValue] = {"event_type": AgentEventType.FINAL_REPORT, "text": result}
        return ts, f"tasks:{row_id:012d}", fields

    def agent_ids(self, run: AdapterRun, collected: Path) -> dict[int, str] | None:
        """Tap call ``seq`` -> PentAGI agent, or ``None`` when any call cannot be placed.

        * an embedding call (``/api/embeddings``) is ``embedder``;
        * a chat call is the message chain it belongs to (``<role>:<chain id>``, see
          :class:`ChainIndex`);
        * a chat call that is in no chain is ``simple`` (PentAGI's one-shot role) when it
          has no system prompt (language, title, summaries) or offers only the setup
          probe's tools;
        * anything else (an unreadable request, a chat call in no chain or in several)
          makes the whole answer ``None``, and telemetry infers the agents instead.
        """
        calls = load_calls(collected)
        if not calls:
            return None
        tap = PentagiTap(collected)
        chains = ChainIndex(PentagiEvidence(collected).rows("msgchains"))
        ids: dict[int, str] = {}
        for call in calls:
            agent = self._agent_of(call, tap, chains)
            if agent is None:
                return None
            ids[call.seq] = agent
        return ids

    @classmethod
    def call_path(cls, path: str, body: object) -> int | None:
        """Which of the sheet's ``model_call_paths`` a request is (its index), or ``None``.

        In the sheet's order: a one-shot chat call (no tools), the tool-call-ID probe
        (only the probe's tools), a role agent chain (a system prompt and other tools),
        an embedding call.
        """
        clean = path.split("?", 1)[0]
        if clean.endswith(cls.EMBEDDING_PATHS):
            return 3
        tools = PentagiTap.tool_names(body)
        if not clean.endswith("/api/chat") or tools is None or not isinstance(body, dict):
            return None
        if not tools:
            return 0
        if tools <= cls.PROBE_TOOLS:
            return 1
        messages = body.get("messages")
        first = messages[0] if isinstance(messages, list) and messages else None
        return 2 if isinstance(first, dict) and first.get("role") == "system" else None

    def _agent_of(self, call: CallTelemetry, tap: PentagiTap, chains: ChainIndex) -> str | None:
        path = tap.request_path(call.seq) or ""
        if path.split("?", 1)[0].endswith(self.EMBEDDING_PATHS):
            return "embedder"
        if call.format is not WireFormat.OLLAMA_CHAT or not call.thread_key:
            return None
        agent = chains.agent_for(call)
        if agent is not None:
            return agent
        if call.system_sha256 is None:
            return "simple"
        tools = tap.request_tools(call.seq)
        if tools and tools <= self.PROBE_TOOLS:
            return "simple"
        return None

    def teardown(self, run: AdapterRun, host: AgentHost) -> None:
        """Nothing to do: every worker went through cell-guard, which labels it with the
        run, so the cell's teardown removes it with its anonymous /work volume."""
