from pathlib import Path

from control.core.models import ALL_MODELS
from tools.gen_schemas import SCHEMA_DIR, render_schemas


def test_one_schema_per_model() -> None:
    assert set(render_schemas()) == {f"{model.__name__}.json" for model in ALL_MODELS}


def test_committed_schemas_match_models() -> None:
    """Regenerating schemas/ must produce no diff (run `python -m tools.gen_schemas`)."""
    rendered = render_schemas()
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in Path(SCHEMA_DIR).glob("*.json")}
    assert on_disk == rendered
