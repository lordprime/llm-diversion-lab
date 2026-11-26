"""The RedAmon CI smoke's plan: the adapter's own plan, on the CI-built images.

``agents/redamon/ci/check.sh`` runs the driver image under ``agents/ci/smoke.sh
--docker``. The plan is the one :class:`~agents.redamon.adapter.RedAmonPlanner`
renders for a real run, with three differences, all visible in the plan itself:

* the services use the images this CI job built (and postgres by digest);
* Kali is the stand-in (the same MCP servers, none of the tools), which only a plan
  marked ``smoke`` accepts;
* the model endpoint is the smoke's stub model at ``http://tap:8000/v1``.

It writes an env file for ``smoke.sh --env-file``::

    python -m agents.redamon.smoke --images <file> --out <env file>

where ``<file>`` maps each service role to its image, one ``role=image`` per line.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path

from agents.base import AdapterLimits, AdapterRun, ModelConfig
from agents.redamon.adapter import RedAmonPlanner
from agents.redamon.plan import KALI_STANDIN_MARK, RunPlan, ServiceRole

__all__ = ["SmokePlan", "main"]


class SmokePlan:
    """Builds the smoke's plan and its env file."""

    RUN = AdapterRun(
        run_id="run_redamon_smoke",
        model=ModelConfig(name="stub-model", num_ctx=65536),
        target_url="http://target.lab.test/",
        objective="Find out what web server runs on the target and report it.",
        llm_base_url="http://tap:8000/v1",
        limits=AdapterLimits(max_turns=8, timeout_s=2400),
    )

    def __init__(self, planner: RedAmonPlanner | None = None):
        self._planner = planner or RedAmonPlanner()

    @staticmethod
    def read_images(text: str) -> dict[ServiceRole, str]:
        """``role=image`` lines; every role exactly once, nothing else."""
        images: dict[ServiceRole, str] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            role, sep, image = line.partition("=")
            if not sep or not image.strip():
                raise ValueError(f"not a role=image line: {line!r}")
            key = ServiceRole(role.strip())
            if key in images:
                raise ValueError(f"{key.value} is given twice")
            images[key] = image.strip()
        missing = sorted(r.value for r in ServiceRole if r not in images)
        if missing:
            raise ValueError(f"no image for {missing}")
        return images

    def plan(self, images: Mapping[ServiceRole, str]) -> RunPlan:
        if KALI_STANDIN_MARK not in images[ServiceRole.KALI]:
            raise ValueError("the smoke runs the Kali stand-in, never the real image")
        real = self._planner.plan(self.RUN)
        services = tuple(s.model_copy(update={"image": images[s.role]}) for s in real.services)
        # validated again, so the stand-in passes only because smoke is set
        return RunPlan.model_validate(
            {**real.model_dump(), "services": [s.model_dump() for s in services], "smoke": True}
        )

    def env_file(self, images: Mapping[ServiceRole, str]) -> str:
        return (
            f"LAB_REDAMON_PLAN={self.plan(images).model_dump_json()}\n"
            "LAB_EVIDENCE_DIR=/tmp/evidence\n"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the RedAmon smoke's env file.")
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    smoke = SmokePlan()
    images = smoke.read_images(args.images.read_text(encoding="utf-8"))
    args.out.write_text(smoke.env_file(images), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
