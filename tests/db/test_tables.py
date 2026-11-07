"""Tables mirror the pydantic models (no database needed)."""

import pytest
from pydantic import BaseModel

from control.core import models as m
from control.db import tables as t

MIRRORS: list[tuple[type[BaseModel], type[t.Base]]] = [
    (m.Placement, t.Placement),
    (m.PlacementServe, t.PlacementServe),
    (m.TargetAccessEvent, t.TargetAccess),
    (m.LlmCall, t.LlmCall),
    (m.AgentEvent, t.AgentEvent),
    (m.Callback, t.Callback),
    (m.OraclePoll, t.OraclePoll),
    (m.FunnelLabel, t.Label),
    (m.ArtifactFile, t.Artifact),
]


@pytest.mark.parametrize(("model", "table"), MIRRORS, ids=lambda x: x.__name__)
def test_every_model_field_has_a_column(model: type[BaseModel], table: type[t.Base]) -> None:
    fields = set(model.model_fields) - {"kind"}
    columns = set(table.__table__.columns.keys())
    assert fields <= columns, sorted(fields - columns)


def test_event_tables_cover_every_event_kind() -> None:
    assert set(t.EVENT_TABLES) == set(m.EventKind)


@pytest.mark.parametrize("kind", list(m.EventKind))
def test_event_tables_keyed_by_run_stream_seq(kind: m.EventKind) -> None:
    table = t.EVENT_TABLES[kind].__table__
    keys = {
        tuple(c.name for c in con.columns)
        for con in table.constraints
        if con.__class__.__name__ == "UniqueConstraint"
    }
    assert ("run_id", "stream", "seq") in keys


def test_run_columns_cover_manifest_scalars() -> None:
    # target/agent/model are names in the manifest and foreign keys (``*_id``) on runs
    manifest = set(m.RunManifest.model_fields) - {"placements", "target", "agent", "model"}
    columns = set(t.Run.__table__.columns.keys())
    assert manifest <= columns, sorted(manifest - columns)
