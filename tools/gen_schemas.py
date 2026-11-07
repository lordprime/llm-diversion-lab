"""Generate JSON Schema files for every domain model into ``schemas/<Model>.json``.

The pydantic models in ``control.core.models`` are the source of truth; the files in
``schemas/`` are derived and must never be edited by hand.

Usage (from the repository root)::

    uv run python -m tools.gen_schemas          # (re)write schemas/
    uv run python -m tools.gen_schemas --check  # exit 1 if schemas/ is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from control.core.models import ALL_MODELS

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


def render_schemas() -> dict[str, str]:
    """Return ``{"<Model>.json": <schema text>}`` for every model, deterministically."""
    return {
        f"{model.__name__}.json": json.dumps(model.model_json_schema(), indent=2, sort_keys=True)
        + "\n"
        for model in ALL_MODELS
    }


def _stale(rendered: dict[str, str], schema_dir: Path) -> list[str]:
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in schema_dir.glob("*.json")}
    names = sorted(set(rendered) | set(on_disk))
    return [name for name in names if rendered.get(name) != on_disk.get(name)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="fail if schemas/ is out of date")
    args = parser.parse_args(argv)

    rendered = render_schemas()
    if args.check:
        stale = _stale(rendered, SCHEMA_DIR)
        if stale:
            print("stale schemas (run `python -m tools.gen_schemas`):", *stale, file=sys.stderr)
            return 1
        print(f"{len(rendered)} schemas up to date")
        return 0

    SCHEMA_DIR.mkdir(exist_ok=True)
    for old in SCHEMA_DIR.glob("*.json"):
        if old.name not in rendered:
            old.unlink()
    for name, text in rendered.items():
        (SCHEMA_DIR / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(rendered)} schemas to {SCHEMA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
