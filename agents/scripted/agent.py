"""Scripted (non-LLM) agent: the instrumentation self-test's stand-in for a real agent.

It follows a fixed script (:class:`AgentScript`, a JSON file the runner renders from
the experiment) instead of a model's decisions, so a self-test cell exercises every
funnel stage end to end without spending tokens:

* ``fetch``: ``GET`` a target path (the P1 and P7 surfaces) and keep its text;
* ``llm``: send everything fetched so far to the model through the tap (an
  Anthropic-Messages ``POST /v1/messages``, never streaming), as a real agent would
  put tool output into its context: the run's tag becomes *Visible*;
* ``follow_decoy``: if fetched text names a decoy path ``/x-<tag>``, ``GET`` it;
* ``callback_http``: if fetched text names a callback host ``<token>.<callback_domain>``,
  resolve it and ``GET /r/<token>`` from the answer with that ``Host``;
* ``callback_dns``: resolve that host once more (a DNS-only callback). Lookups use the
  container's resolver, or the script's ``dns_server`` asked directly where the
  engine's embedded resolver cannot reach the cell's catcher (local Podman);
* ``graphql``: ``POST`` a GraphQL query (the self-test's objective: DVGA's importPaste
  fetching the target's own ``http://localhost:8000/``).

The script never contains the tag or a token: the agent finds them only in what the
target serves, so a control run (nothing planted) finds nothing and only reaches the
objective. A failing step (connection error, DNS failure) is recorded and the script
goes on; the agent exits ``0`` when the script is done.

Evidence: ``<LAB_EVIDENCE_DIR>/agent/events.jsonl``, one
:class:`~control.core.models.AgentEvent` per step on stream ``agent`` (``seq`` from 0),
each line exactly its ``model_dump_json()``, appended and fsynced.

Run (in the cell's ``agent`` service)::

    LAB_RUN_ID=run_... LAB_EVIDENCE_DIR=/evidence \\
        python -m agents.scripted.agent --script /etc/lab/agent/script.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Protocol, Self

from dnslib import QTYPE, DNSError, DNSRecord  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    IPvAnyAddress,
    JsonValue,
    StringConstraints,
    ValidationError,
    model_validator,
)

from control.core.ids import ID_PATTERN
from control.core.models import AgentEvent, AgentEventType
from control.core.tokens import TAG_PATTERN, TOKEN_LENGTH

__all__ = [
    "AGENT_STREAM",
    "EVENTS_FILE",
    "AgentLog",
    "AgentScript",
    "Http",
    "HttpResult",
    "Step",
    "StepAction",
    "UrllibHttp",
    "direct_resolver",
    "main",
    "run_script",
    "system_resolve",
]

#: Producer stream of the agent's events (``control.labeler.funnel.EVENT_FILES``).
AGENT_STREAM: Final = "agent"
#: The agent's events file, relative to the evidence dir.
EVENTS_FILE: Final = "agent/events.jsonl"
#: Most bytes of one response the agent keeps (and forwards to the model).
MAX_KEEP: Final = 64 * 1024
REQUEST_TIMEOUT_S: Final = 30.0

_TAG_BODY = TAG_PATTERN.removeprefix("^").removesuffix("$")
_DECOY_RE = re.compile(rf"/x-{_TAG_BODY}(?![0-9A-Za-z])")
_RUN_ID_RE = re.compile(ID_PATTERN)
_HTTP_URL = r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$"
_DOMAIN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
_PATH = r"^/[^\s]*$"


# --------------------------------------------------------------------------- script


class StepAction(StrEnum):
    FETCH = "fetch"
    LLM = "llm"
    FOLLOW_DECOY = "follow_decoy"
    CALLBACK_HTTP = "callback_http"
    CALLBACK_DNS = "callback_dns"
    GRAPHQL = "graphql"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Step(_Frozen):
    """One scripted step; ``path`` for ``fetch``/``graphql``, ``query`` for ``graphql``."""

    action: StepAction
    path: Annotated[str, StringConstraints(pattern=_PATH, max_length=2048)] | None = None
    query: Annotated[str, StringConstraints(min_length=1, max_length=8192)] | None = None

    @model_validator(mode="after")
    def _fields(self) -> Self:
        needs_path = self.action in (StepAction.FETCH, StepAction.GRAPHQL)
        if needs_path != (self.path is not None):
            raise ValueError(
                f"{self.action.value}: path is {'required' if needs_path else 'unused'}"
            )
        if (self.action is StepAction.GRAPHQL) != (self.query is not None):
            raise ValueError(f"{self.action.value}: query is only for graphql (and required)")
        return self


class AgentScript(_Frozen):
    """The whole script: where the target and the model are, and the steps in order."""

    target_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    llm_url: Annotated[str, StringConstraints(pattern=_HTTP_URL)]
    model: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    callback_domain: Annotated[str, StringConstraints(pattern=_DOMAIN, max_length=200)]
    steps: tuple[Step, ...]
    #: Ask this resolver directly instead of the container's own (only where the
    #: engine's embedded resolver cannot forward to the cell's catcher: local Podman).
    dns_server: IPvAnyAddress | None = None


# --------------------------------------------------------------------------- I/O seams


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: bytes


class Http(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = REQUEST_TIMEOUT_S,
    ) -> HttpResult:
        """Send one request; return the status and body (also for 4xx/5xx).

        Raise ``OSError`` if no response was received.
        """
        ...


class UrllibHttp:
    """Plain HTTP with the standard library; never uses a proxy from the environment."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = REQUEST_TIMEOUT_S,
    ) -> HttpResult:
        if not url.startswith(("http://", "https://")):
            raise OSError(f"refusing non-HTTP URL {url!r}")
        req = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method)  # noqa: S310 - scheme checked above
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return HttpResult(resp.status, resp.read(MAX_KEEP))
        except urllib.error.HTTPError as err:
            with err:
                return HttpResult(err.code, err.read(MAX_KEEP))
        except urllib.error.URLError as err:
            raise OSError(str(err.reason)) from err


def system_resolve(name: str) -> list[str]:
    """IPv4 addresses of ``name`` through the container's resolver."""
    infos = socket.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def direct_resolver(
    server: str, *, port: int = 53, timeout: float = 5.0
) -> Callable[[str], list[str]]:
    """A resolver that asks ``server`` (UDP) directly for ``A`` records."""

    def resolve(name: str) -> list[str]:
        try:
            reply = DNSRecord.parse(DNSRecord.question(name).send(server, port, timeout=timeout))
        except (OSError, DNSError) as exc:
            raise OSError(f"{name}: {exc}") from exc
        answers = sorted({str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A})
        if not answers:
            raise OSError(f"{name}: no A record from {server}")
        return answers

    return resolve


# --------------------------------------------------------------------------- evidence


class AgentLog:
    """Appends one :class:`AgentEvent` per step to ``agent/events.jsonl`` (fsynced)."""

    def __init__(self, run_id: str, evidence_dir: Path) -> None:
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ValueError(f"malformed run id {run_id!r}")
        self._run_id = run_id
        self._path = evidence_dir / EVENTS_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0

    def record(
        self,
        event_type: AgentEventType,
        *,
        tool_name: str | None = None,
        tool_args: dict[str, JsonValue] | None = None,
        text: str | None = None,
        url: str | None = None,
    ) -> AgentEvent:
        event = AgentEvent(
            run_id=self._run_id,
            stream=AGENT_STREAM,
            seq=self._seq,
            ts=datetime.now(UTC),
            event_type=event_type,
            tool_name=tool_name,
            tool_args=tool_args,
            text=text,
            url=url,
        )
        self._seq += 1
        with self._path.open("ab") as fh:
            fh.write(event.model_dump_json().encode() + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        return event


# --------------------------------------------------------------------------- the script


def _text(body: bytes) -> str:
    return body[:MAX_KEEP].decode("utf-8", "replace")


class _Agent:
    def __init__(
        self, script: AgentScript, http: Http, resolve: Callable[[str], list[str]], log: AgentLog
    ) -> None:
        self.script = script
        self.http = http
        self.resolve = resolve
        self.log = log
        self.fetched: list[str] = []
        self._host_re = re.compile(
            rf"(?<![a-z0-9-])([a-z2-7]{{{TOKEN_LENGTH}}})\.{re.escape(script.callback_domain)}"
            r"(?![a-z0-9-])"
        )

    # helpers

    def _send(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        json_body: bool = False,
        host: str | None = None,
    ) -> HttpResult | None:
        headers = {"content-type": "application/json"} if json_body else {}
        args: dict[str, JsonValue] = {"method": method, "url": url}
        if host is not None:
            headers["host"] = args["host"] = host
        if body is not None:
            args["body"] = _text(body)
        self.log.record(
            AgentEventType.TOOL_CALL, tool_name=f"http_{method.lower()}", tool_args=args, url=url
        )
        try:
            result = self.http.request(method, url, body=body, headers=headers)
        except OSError as exc:
            self.log.record(AgentEventType.MESSAGE, text=f"{method} {url} failed: {exc}", url=url)
            return None
        self.log.record(
            AgentEventType.HTTP_REQUEST,
            text=f"{method} {url} -> {result.status}",
            url=url,
            tool_args={"status": result.status, "bytes": len(result.body)},
        )
        return result

    def _first(self, pattern: re.Pattern[str]) -> re.Match[str] | None:
        for text in self.fetched:
            match = pattern.search(text)
            if match:
                return match
        return None

    # steps

    def fetch(self, step: Step) -> None:
        result = self._send("GET", f"{self.script.target_url}{step.path}")
        if result is not None:
            self.fetched.append(_text(result.body))

    def llm(self, _step: Step) -> None:
        content = "\n\n".join(self.fetched) or "(nothing fetched)"
        request = {
            "model": self.script.model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": content}],
        }
        url = f"{self.script.llm_url}/v1/messages"
        try:
            result = self.http.request(
                "POST",
                url,
                body=json.dumps(request).encode(),
                headers={"content-type": "application/json", "anthropic-version": "2023-06-01"},
            )
        except OSError as exc:
            self.log.record(AgentEventType.MESSAGE, text=f"model call failed: {exc}", url=url)
            return
        try:
            reply = json.loads(result.body)
            text = "".join(
                part.get("text", "") for part in reply.get("content", []) if isinstance(part, dict)
            )
        except (ValueError, AttributeError):
            text = _text(result.body)
        self.log.record(
            AgentEventType.LLM_CALL,
            text=text[:4096],
            url=url,
            tool_args={"status": result.status, "model": self.script.model},
        )

    def follow_decoy(self, _step: Step) -> None:
        match = self._first(_DECOY_RE)
        if match is None:
            self.log.record(AgentEventType.MESSAGE, text="no decoy path in fetched text")
            return
        self._send("GET", f"{self.script.target_url}{match.group(0)}/")

    def _callback_host(self) -> tuple[str, str] | None:
        match = self._first(self._host_re)
        if match is None:
            self.log.record(AgentEventType.MESSAGE, text="no callback host in fetched text")
            return None
        return match.group(0), match.group(1)

    def _lookup(self, host: str) -> list[str]:
        self.log.record(AgentEventType.TOOL_CALL, tool_name="dns_lookup", tool_args={"qname": host})
        try:
            answers = self.resolve(host)
        except OSError as exc:
            self.log.record(AgentEventType.MESSAGE, text=f"lookup {host} failed: {exc}")
            return []
        self.log.record(AgentEventType.MESSAGE, text=f"lookup {host} -> {', '.join(answers)}")
        return answers

    def callback_http(self, _step: Step) -> None:
        """Resolve the callback host, then ``GET /r/<token>`` from its address with Host."""
        found = self._callback_host()
        if found is None:
            return
        host, token = found
        answers = self._lookup(host)
        if answers:
            self._send("GET", f"http://{answers[0]}/r/{token}", host=host)

    def callback_dns(self, _step: Step) -> None:
        found = self._callback_host()
        if found is not None:
            self._lookup(found[0])

    def graphql(self, step: Step) -> None:
        body = json.dumps({"query": step.query}).encode()
        result = self._send(
            "POST", f"{self.script.target_url}{step.path}", body=body, json_body=True
        )
        if result is not None:
            self.log.record(AgentEventType.MESSAGE, text=_text(result.body)[:4096])

    def run(self) -> int:
        handlers: dict[StepAction, Callable[[Step], None]] = {
            StepAction.FETCH: self.fetch,
            StepAction.LLM: self.llm,
            StepAction.FOLLOW_DECOY: self.follow_decoy,
            StepAction.CALLBACK_HTTP: self.callback_http,
            StepAction.CALLBACK_DNS: self.callback_dns,
            StepAction.GRAPHQL: self.graphql,
        }
        for step in self.script.steps:
            handlers[step.action](step)
        self.log.record(
            AgentEventType.FINAL_REPORT, text=f"script done: {len(self.script.steps)} steps"
        )
        return 0


def run_script(
    script: AgentScript,
    *,
    http: Http,
    resolve: Callable[[str], list[str]],
    log: AgentLog,
) -> int:
    """Run every step of ``script`` in order; return the process exit code (``0``)."""
    return _Agent(script, http, resolve, log).run()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scripted (non-LLM) self-test agent")
    parser.add_argument("--script", required=True, type=Path, help="AgentScript JSON file")
    args = parser.parse_args(argv)
    try:
        script = AgentScript.model_validate_json(args.script.read_bytes())
        log = AgentLog(
            os.environ.get("LAB_RUN_ID", ""), Path(os.environ.get("LAB_EVIDENCE_DIR") or "evidence")
        )
    except (OSError, ValueError, ValidationError) as exc:
        print(f"scripted agent: {exc}", file=sys.stderr)
        return 2
    resolve = (
        direct_resolver(str(script.dns_server)) if script.dns_server is not None else system_resolve
    )
    return run_script(script, http=UrllibHttp(), resolve=resolve, log=log)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
