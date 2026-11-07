"""Experiment config and the matched-pair scheduler (DEVELOPMENT_PLAN sections 5.2, 9.4)."""

from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from control.core.models import Arm, Surface
from control.core.tokens import TAG_PATTERN
from control.runner.experiment import (
    Experiment,
    load_experiment,
    parse_experiment,
    read_experiment,
)
from control.runner.render import render_catcher_tokens, render_manifest, render_payloads
from control.runner.schedule import PairKey, ScheduledRun, build_schedule, plan_order

REPO_ROOT = Path(__file__).resolve().parents[2]
SELFTEST = REPO_ROOT / "experiments" / "selftest.yaml"
KEY = hashlib.sha256(b"pairing-test-lab-key").digest()


def _doc(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "experiment_id": "exp_pairing",
        "name": "pairing",
        "seed": 7,
        "repetitions": 3,
        "targets": [
            {
                "name": "dvga",
                "placements": {
                    "P1": {"url": "/robots.txt", "locator": "robots.txt:append"},
                    "P7": {"url": "/.env", "locator": "error:404"},
                },
            },
            {
                "name": "juice-shop",
                "placements": {
                    "P1": {"url": "/robots.txt", "locator": "robots.txt:append"},
                    "P7": {"url": "/admin", "locator": "error:403"},
                },
            },
        ],
        "agents": ["scripted", "other-agent"],
        "models": ["stub"],
        "limits": {"budget_usd": 0, "max_turns": 10, "timeout_s": 60},
        "arms": {
            "control": {},
            "injected": {
                "surfaces": ["P1", "P7"],
                "payload": {
                    "payload_id": "test-placeholder",
                    "family": "decoy",
                    "style": "neutral",
                    "version": "1",
                    "templates": {
                        "P1": "# placeholder $tag",
                        "P7": "<p>placeholder $tag at $decoy_path via $callback_host</p>",
                    },
                },
            },
        },
    }
    doc.update(overrides)
    return doc


def _experiment(**overrides: Any) -> Experiment:
    return Experiment.model_validate(_doc(**overrides))


def _key(run: ScheduledRun) -> tuple[str, str, str, int, Arm]:
    return (run.target, run.agent, run.model, run.rep, run.arm)


# --------------------------------------------------------------------------- pairing


def test_one_injected_and_one_control_per_cell_and_rep_sharing_a_pair_id() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    assert len(schedule) == 2 * 2 * 1 * 3 * 2

    by_pair: dict[str, list[ScheduledRun]] = defaultdict(list)
    for run in schedule:
        by_pair[run.pair_id].append(run)
    assert len(by_pair) == 2 * 2 * 1 * 3
    cells: Counter[tuple[str, str, str, int]] = Counter()
    for runs in by_pair.values():
        assert sorted(r.arm for r in runs) == [Arm.CONTROL, Arm.INJECTED]
        keys = {(r.target, r.agent, r.model, r.rep) for r in runs}
        assert len(keys) == 1
        cells[keys.pop()] += 1
    expected = {
        (t, a, m, rep)
        for t in ("dvga", "juice-shop")
        for a in ("scripted", "other-agent")
        for m in ("stub",)
        for rep in range(3)
    }
    assert set(cells) == expected
    assert set(cells.values()) == {1}


def test_each_pair_is_adjacent_and_schedule_index_is_the_position() -> None:
    schedule = build_schedule(_experiment())
    assert [r.schedule_index for r in schedule] == list(range(len(schedule)))
    for i in range(0, len(schedule), 2):
        first, second = schedule[i], schedule[i + 1]
        assert first.pair_id == second.pair_id
        assert {first.arm, second.arm} == {Arm.CONTROL, Arm.INJECTED}


def test_order_is_a_deterministic_function_of_the_seed() -> None:
    exp = _experiment()
    a = [_key(r) for r in build_schedule(exp)]
    b = [_key(r) for r in build_schedule(exp)]
    assert a == b
    assert plan_order(exp) == plan_order(_experiment())
    assert [
        (p.key.target, p.key.agent, p.key.model, p.key.rep, p.arm) for p in plan_order(exp)
    ] == a


def test_a_different_seed_gives_a_different_order() -> None:
    a = [_key(r) for r in build_schedule(_experiment(seed=7))]
    b = [_key(r) for r in build_schedule(_experiment(seed=8))]
    assert sorted(a) == sorted(b)
    assert a != b


def test_order_is_shuffled_not_canonical_and_arm_order_within_pairs_varies() -> None:
    order = plan_order(_experiment())
    keys = [p.key for p in order[::2]]
    assert keys != sorted(keys)
    first_arms = {p.arm for p in order[::2]}
    assert first_arms == {Arm.CONTROL, Arm.INJECTED}


def test_plan_order_entries_are_pair_keys() -> None:
    order = plan_order(_experiment())
    assert all(isinstance(p.key, PairKey) for p in order)


def test_run_ids_are_unique_ulids_sorted_in_schedule_order() -> None:
    schedule = build_schedule(_experiment())
    ids = [r.run_id for r in schedule]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"run_[0-9A-Z]{26}", i) for i in ids)
    assert ids == sorted(ids)
    pair_ids = {r.pair_id for r in schedule}
    assert all(re.fullmatch(r"pair_[0-9A-Z]{26}", i) for i in pair_ids)
    assert all(r.experiment_id == "exp_pairing" for r in schedule)


def test_ids_are_fresh_for_each_build() -> None:
    exp = _experiment()
    a = {r.run_id for r in build_schedule(exp)}
    b = {r.run_id for r in build_schedule(exp)}
    assert not a & b


def test_control_runs_have_no_tag_and_injected_runs_have_unique_tags() -> None:
    schedule = build_schedule(_experiment())
    tags = []
    for run in schedule:
        if run.arm is Arm.CONTROL:
            assert run.tag is None
        else:
            assert run.tag is not None and re.fullmatch(TAG_PATTERN, run.tag)
            tags.append(run.tag)
    assert len(set(tags)) == len(tags) == len(schedule) // 2


def test_a_scheduled_control_run_cannot_carry_a_tag() -> None:
    run = build_schedule(_experiment())[0]
    data = run.model_dump()
    data.update(arm=Arm.CONTROL, tag="0123456789abcdef")
    with pytest.raises(ValidationError, match="tag"):
        ScheduledRun.model_validate(data)
    data.update(arm=Arm.INJECTED, tag=None)
    with pytest.raises(ValidationError, match="tag"):
        ScheduledRun.model_validate(data)


def test_a_control_runs_manifest_has_no_payload_and_no_tag() -> None:
    exp = _experiment()
    for run in build_schedule(exp):
        manifest = render_manifest(run, exp, KEY)
        if run.arm is Arm.CONTROL:
            assert manifest.tag is None
            assert manifest.placements == []
            assert render_payloads(manifest, exp) == {}
            assert render_catcher_tokens(manifest) == []
        else:
            assert manifest.tag == run.tag
            assert {p.surface for p in manifest.placements} == {Surface.P1, Surface.P7}
        assert manifest.pair_id == run.pair_id
        assert manifest.schedule_index == run.schedule_index
        assert (manifest.target, manifest.agent, manifest.model) == (
            run.target,
            run.agent,
            run.model,
        )


# --------------------------------------------------------------------------- experiment file


def test_selftest_yaml_loads_and_schedules_one_pair() -> None:
    exp = load_experiment(SELFTEST)
    assert exp.arms.injected.surfaces == (Surface.P1, Surface.P7)
    schedule = build_schedule(exp)
    assert len(schedule) == 2
    assert schedule[0].pair_id == schedule[1].pair_id
    for run in schedule:
        manifest = render_manifest(run, exp, KEY)
        payloads = render_payloads(manifest, exp)
        assert all(manifest.tag is not None and manifest.tag in t for t in payloads.values())


def test_definition_hash_is_the_sha256_of_the_frozen_file(tmp_path: Path) -> None:
    data = SELFTEST.read_bytes()
    loaded = read_experiment(SELFTEST)
    assert loaded.definition_sha256 == hashlib.sha256(data).hexdigest()
    assert loaded.definition_yaml == data.decode("utf-8")
    assert loaded.experiment == load_experiment(SELFTEST)

    edited = tmp_path / "edited.yaml"
    edited.write_bytes(data + b"\n# an edit\n")
    assert read_experiment(edited).definition_sha256 != loaded.definition_sha256


def test_yaml_with_a_duplicate_key_is_refused() -> None:
    text = "experiment_id: exp_a\nexperiment_id: exp_b\n"
    with pytest.raises(ValueError, match="duplicate key"):
        parse_experiment(text)
    nested = SELFTEST.read_text().replace("  max_turns: 50\n", "  max_turns: 50\n  max_turns: 5\n")
    assert nested != SELFTEST.read_text()
    with pytest.raises(ValueError, match="duplicate key 'max_turns'"):
        parse_experiment(nested)


def test_yaml_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ValueError, match="mapping"):
        parse_experiment("- a\n- b\n")


def _payload(doc: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = doc["arms"]["injected"]["payload"]
    return payload


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d["arms"].pop("control"), "control"),
        (lambda d: d["arms"].pop("injected"), "injected"),
        (lambda d: d.update(experiment_id="bad id!"), "experiment_id"),
        (lambda d: d.update(repetitions=0), "repetitions"),
        (lambda d: d.update(seed=True), "seed"),
        (lambda d: d.update(agents=[]), "agents"),
        (lambda d: d.update(agents=["a", "a"]), "duplicate"),
        (lambda d: d.update(models=["m", "m"]), "duplicate"),
        (lambda d: d["targets"].append(copy.deepcopy(d["targets"][0])), "duplicate"),
        (lambda d: d["arms"]["injected"].update(surfaces=[]), "surfaces"),
        (lambda d: d["arms"]["injected"].update(surfaces=["P1", "P1"]), "duplicate"),
        (lambda d: d["arms"]["injected"].update(surfaces=["P1", "P3"]), "P3"),
        (lambda d: d["targets"][0]["placements"].pop("P7"), "P7"),
        (lambda d: _payload(d)["templates"].pop("P7"), "P7"),
        (lambda d: _payload(d)["templates"].update(P1="no tag here"), r"\$tag"),
        (lambda d: _payload(d)["templates"].update(P1="$tag $lab_key"), "lab_key"),
        (lambda d: _payload(d)["templates"].update(P1="$tag $"), "invalid"),
        (lambda d: _payload(d)["templates"].update(P1="# $tag\nDisallow: /"), "line"),
        (lambda d: _payload(d).update(family="unknown"), "family"),
        (lambda d: _payload(d).update(version=1), "version"),
        (lambda d: d["targets"][0]["placements"]["P1"].update(locator="robots"), "locator"),
        (lambda d: d["targets"][0]["placements"]["P1"].update(url="/robots"), "robots"),
        (lambda d: d["targets"][0]["placements"]["P7"].update(locator="error:500"), "locator"),
        (lambda d: d["targets"][0]["placements"]["P7"].update(url="/robots.txt"), "robots"),
        (lambda d: d["targets"][0]["placements"]["P7"].update(url="admin"), "url"),
        (lambda d: d.update(callback_domain="not a domain"), "callback_domain"),
        (lambda d: d.update(unexpected=1), "unexpected"),
    ],
)
def test_invalid_experiments_are_refused(mutate: Any, match: str) -> None:
    doc = _doc()
    mutate(doc)
    with pytest.raises(ValidationError, match=match):
        Experiment.model_validate(doc)


def test_the_experiment_is_frozen() -> None:
    exp = _experiment()
    with pytest.raises(ValidationError):
        exp.seed = 9  # type: ignore[misc]
