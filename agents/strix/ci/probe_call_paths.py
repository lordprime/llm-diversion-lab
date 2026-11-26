# mypy: ignore-errors
# (it imports the Agents SDK's `agents`, which the lab's own `agents` package shadows here)
"""CI smoke probe: send one request down each Strix model-call path, through Strix's code.

Runs inside the Strix agent image (``python -I -c "$(cat probe_call_paths.py)"``) with the
environment the adapter renders, under agents/ci/smoke.sh, where the only reachable
host is the recording stub model behind the tap. It is never run on a workstation.

A full headless scan cannot run there: Strix starts its Kali sandbox before the first
agent turn, and the smoke cell has no Docker. So each path of the sheet's
``model_call_paths`` is driven by the same Strix functions a scan uses, after the same
``configure_sdk_model_defaults`` that points LiteLLM at the tap:

* the start-up preflight: ``preflight_model_connection`` (scan_setup.py 103-122);
* the main agent: the Agents SDK ``Runner`` with ``StrixProvider``, the provider every
  scan agent's ``RunConfig`` uses (strix/core/runner.py 433-436);
* the history compaction: ``compaction._summarize`` (compaction.py 302-326);
* the dedupe judge: ``dedupe.check_duplicate`` with one earlier report (dedupe.py 347-436).

Each request carries a marker that agents/strix/ci/check.sh looks for in the tap's
record. The probe fails loudly if a path raises; check_duplicate swallows its own
errors, so its request is proven by the record alone.
"""

import asyncio

from strix.config import load_settings
from strix.config.models import StrixProvider, configure_sdk_model_defaults
from strix.interface.scan_setup import preflight_model_connection
from strix.llm.compaction import _summarize
from strix.report.dedupe import check_duplicate

from agents import Agent, RunConfig, Runner

MAIN_MARKER = "lab smoke: main agent"
COMPACTION_MARKER = "lab smoke: compaction"


def _report(report_id: str, endpoint: str) -> dict[str, object]:
    return {
        "id": report_id,
        "title": f"lab smoke: reflected XSS at {endpoint}",
        "description": "lab smoke: dedupe judge",
        "severity": "medium",
        "endpoint": endpoint,
        "method": "GET",
    }


async def main() -> None:
    settings = load_settings()
    model = settings.llm.model or ""
    await preflight_model_connection(model, settings=settings)
    configure_sdk_model_defaults(settings)
    await Runner.run(
        Agent(name="root", instructions=MAIN_MARKER),
        f"{MAIN_MARKER} task",
        run_config=RunConfig(model=model, model_provider=StrixProvider(), tracing_disabled=True),
        max_turns=1,
    )
    if await _summarize(model, COMPACTION_MARKER, 64) is None:
        raise SystemExit("compaction summary call failed")
    await check_duplicate(_report("vuln-b", "/search"), [_report("vuln-a", "/login")])


asyncio.run(main())
