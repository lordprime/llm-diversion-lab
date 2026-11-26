"""Experiment config and the three-arm block scheduler (DEVELOPMENT_PLAN 5.2, 9.4; T1, S1)."""

from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from string import Template
from typing import Any

import pytest
from pydantic import ValidationError

from control.core.models import Arm, OracleVerdictKind, Surface
from control.core.tokens import TAG_PATTERN, TOKEN_LENGTH, derive_token, new_tag
from control.runner.experiment import (
    Experiment,
    load_experiment,
    parse_experiment,
    read_experiment,
)
from control.runner.render import (
    forbidden_tags_for,
    forbidden_tokens_for,
    placement_id_for,
    render_catcher_tokens,
    render_manifest,
    render_payloads,
)
from control.runner.schedule import (
    ARM_ORDERS,
    BLOCK_ARMS,
    BlockKey,
    ScheduledRun,
    ScheduleError,
    build_schedule,
    check_schedule,
    plan_order,
    retry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DVGA_BLOCK = REPO_ROOT / "tests" / "fixtures" / "experiments" / "dvga_block.yaml"
KEY = hashlib.sha256(b"pairing-test-lab-key").digest()
#: Stand-ins as long as what each instruction-only placeholder renders to.
_STAND_INS = {
    "decoy_path": "x" * 19,
    "callback_host": "y" * (TOKEN_LENGTH + 1 + len("cb.lab.test")),
    "token": "z" * TOKEN_LENGTH,
}


def neutral_for(templates: dict[str, str]) -> dict[str, str]:
    """Neutral templates matched exactly to ``templates``: the instruction-only
    placeholders become innocuous letters of the same length (the tag stays)."""
    return {
        surface: Template(text).safe_substitute(_STAND_INS) for surface, text in templates.items()
    }


def sync_neutral(doc: dict[str, Any]) -> dict[str, Any]:
    """Re-derive the neutral templates after a test changed the instruction's."""
    templates = doc["arms"]["instruction"]["payload"]["templates"]
    doc["arms"]["neutral"]["payload"]["templates"] = neutral_for(templates)
    return doc


def _doc(**overrides: Any) -> dict[str, Any]:
    instruction_templates = {
        "P1": "# placeholder $tag",
        "P7": "<p>placeholder $tag at $decoy_path via $callback_host</p>",
    }
    doc: dict[str, Any] = {
        "experiment_id": "exp_pairing",
        "name": "pairing",
        "seed": 7,
        "repetitions": 3,
        "targets": [
            {
                "name": "dvga",
                "objective": "outbound_service",
                "placements": {
                    "P1": {"url": "/robots.txt", "locator": "robots.txt:append"},
                    "P7": {"url": "/.env", "locator": "error:404"},
                },
            },
            {
                "name": "juice-shop",
                "objective": "outbound_service",
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
            "neutral": {
                "payload": {
                    "payload_id": "test-neutral",
                    "family": "decoy",
                    "style": "neutral",
                    "version": "1",
                    "templates": neutral_for(instruction_templates),
                },
            },
            "instruction": {
                "surfaces": ["P1", "P7"],
                "payload": {
                    "payload_id": "test-placeholder",
                    "family": "decoy",
                    "style": "neutral",
                    "version": "1",
                    "templates": instruction_templates,
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


def _blocks(schedule: list[ScheduledRun]) -> list[tuple[Arm, ...]]:
    """The arm order of each block, in schedule order."""
    size = len(BLOCK_ARMS)
    return [tuple(r.arm for r in schedule[i : i + size]) for i in range(0, len(schedule), size)]


# --------------------------------------------------------------------------- blocks


def test_one_control_neutral_and_instruction_run_per_cell_and_rep_sharing_a_block_id() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    assert len(schedule) == 2 * 2 * 1 * 3 * 3

    by_block: dict[str, list[ScheduledRun]] = defaultdict(list)
    for run in schedule:
        by_block[run.block_id].append(run)
    assert len(by_block) == 2 * 2 * 1 * 3
    cells: Counter[tuple[str, str, str, int]] = Counter()
    for runs in by_block.values():
        assert sorted(r.arm for r in runs) == sorted(BLOCK_ARMS)
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


def test_each_block_is_contiguous_and_schedule_index_is_the_position() -> None:
    schedule = build_schedule(_experiment())
    assert [r.schedule_index for r in schedule] == list(range(len(schedule)))
    for i in range(0, len(schedule), 3):
        block = schedule[i : i + 3]
        assert len({r.block_id for r in block}) == 1
        assert {r.arm for r in block} == set(BLOCK_ARMS)


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
    assert _blocks(build_schedule(_experiment(seed=7))) != _blocks(
        build_schedule(_experiment(seed=8))
    )


def test_order_is_shuffled_not_canonical_and_the_arm_order_within_blocks_varies() -> None:
    order = plan_order(_experiment())
    keys = [p.key for p in order[::3]]
    assert keys != sorted(keys)
    assert {p.arm for p in order[::3]} == set(BLOCK_ARMS)
    assert len(set(_blocks(build_schedule(_experiment())))) == len(ARM_ORDERS)


@pytest.mark.parametrize("seed", [0, 1, 7, 20261107, 2**63 - 1])
def test_every_six_blocks_use_each_arm_order_once_so_positions_are_balanced(seed: int) -> None:
    """12 blocks: every arm holds every position exactly 4 times, at any seed."""
    orders = _blocks(build_schedule(_experiment(seed=seed)))
    assert len(orders) == 12
    for start in range(0, 12, 6):
        assert sorted(orders[start : start + 6]) == sorted(ARM_ORDERS)
    for position in range(3):
        counts = Counter(order[position] for order in orders)
        assert counts == {arm: 4 for arm in BLOCK_ARMS}


@pytest.mark.parametrize("repetitions", [1, 2, 4, 5, 7])
def test_a_partial_round_stays_within_two_of_an_even_split(repetitions: int) -> None:
    orders = _blocks(build_schedule(_experiment(repetitions=repetitions)))
    blocks = len(orders)
    for position in range(3):
        counts = Counter(order[position] for order in orders)
        for arm in BLOCK_ARMS:
            assert abs(counts[arm] - blocks / 3) <= 2, (position, arm, counts)


def test_a_single_block_schedule_still_has_all_three_arms() -> None:
    exp = _experiment(
        repetitions=1,
        agents=["scripted"],
        targets=[_doc()["targets"][0]],
    )
    schedule = build_schedule(exp)
    assert len(schedule) == 3 and {r.arm for r in schedule} == set(BLOCK_ARMS)
    check_schedule(schedule, experiment=exp)


def test_plan_order_entries_are_block_keys() -> None:
    order = plan_order(_experiment())
    assert all(isinstance(p.key, BlockKey) for p in order)


def test_run_ids_are_unique_ulids_sorted_in_schedule_order() -> None:
    schedule = build_schedule(_experiment())
    ids = [r.run_id for r in schedule]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"run_[0-9A-Z]{26}", i) for i in ids)
    assert ids == sorted(ids)
    block_ids = {r.block_id for r in schedule}
    assert all(re.fullmatch(r"block_[0-9A-Z]{26}", i) for i in block_ids)
    assert all(r.experiment_id == "exp_pairing" for r in schedule)


def test_ids_are_fresh_for_each_build() -> None:
    exp = _experiment()
    a = {r.run_id for r in build_schedule(exp)}
    b = {r.run_id for r in build_schedule(exp)}
    assert not a & b


def test_only_control_runs_are_tag_free_and_every_tag_is_unique() -> None:
    schedule = build_schedule(_experiment())
    tags = []
    for run in schedule:
        if run.arm is Arm.CONTROL:
            assert run.tag is None
        else:
            assert run.tag is not None and re.fullmatch(TAG_PATTERN, run.tag)
            tags.append(run.tag)
    assert len(set(tags)) == len(tags) == 2 * len(schedule) // 3


@pytest.mark.parametrize("arm", [Arm.NEUTRAL, Arm.INSTRUCTION])
def test_a_scheduled_tagged_run_needs_a_tag_and_a_control_run_cannot_carry_one(arm: Arm) -> None:
    run = build_schedule(_experiment())[0]
    data = run.model_dump()
    data.update(arm=Arm.CONTROL, tag="0123456789abcdef")
    with pytest.raises(ValidationError, match="tag"):
        ScheduledRun.model_validate(data)
    data.update(arm=arm, tag=None)
    with pytest.raises(ValidationError, match=f"{arm.value} run requires a tag"):
        ScheduledRun.model_validate(data)


def test_each_arms_manifest_plants_its_own_payload_on_the_same_surfaces() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    for run in schedule:
        manifest = render_manifest(run, exp, KEY)
        if run.arm is Arm.CONTROL:
            assert manifest.tag is None
            assert manifest.placements == []
            assert render_payloads(manifest, exp) == {}
            assert render_catcher_tokens(manifest) == []
        else:
            assert manifest.tag == run.tag
            payload = exp.arms.payload(run.arm)
            assert [p.surface for p in manifest.placements] == [Surface.P1, Surface.P7]
            assert {p.payload_id for p in manifest.placements} == {payload.payload_id}
            target = exp.target(run.target)
            assert [(p.url, p.locator) for p in manifest.placements] == [
                (target.placements[s].url, target.placements[s].locator)
                for s in (Surface.P1, Surface.P7)
            ]
            texts = render_payloads(manifest, exp)
            assert all(run.tag in text for text in texts.values())
            decoy = f"/x-{run.tag}"
            hosts = [f"{p.token}.cb.lab.test" for p in manifest.placements]
            if run.arm is Arm.NEUTRAL:  # the instruction's fingerprint never shows
                assert not any(decoy in t or any(h in t for h in hosts) for t in texts.values())
            else:
                assert any(decoy in t for t in texts.values())
        assert manifest.block_id == run.block_id
        assert manifest.arm is run.arm
        assert manifest.schedule_index == run.schedule_index
        assert (manifest.target, manifest.agent, manifest.model) == (
            run.target,
            run.agent,
            run.model,
        )


def test_render_payloads_refuses_a_manifest_rendered_for_the_other_tagged_arm() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    neutral = next(r for r in schedule if r.arm is Arm.NEUTRAL)
    manifest = render_manifest(neutral, exp, KEY)
    swapped = manifest.model_copy(update={"arm": Arm.INSTRUCTION})
    with pytest.raises(ValueError, match="payload differs"):
        render_payloads(swapped, exp)


# --------------------------------------------------------------------------- experiment file


def test_the_fixture_loads_and_schedules_one_block() -> None:
    exp = load_experiment(DVGA_BLOCK)
    assert exp.arms.surfaces == (Surface.P1, Surface.P7)
    schedule = build_schedule(exp)
    assert len(schedule) == 3
    assert len({r.block_id for r in schedule}) == 1
    for run in schedule:
        manifest = render_manifest(run, exp, KEY)
        payloads = render_payloads(manifest, exp)
        assert all(manifest.tag is not None and manifest.tag in t for t in payloads.values())


def test_definition_hash_is_the_sha256_of_the_frozen_file(tmp_path: Path) -> None:
    data = DVGA_BLOCK.read_bytes()
    loaded = read_experiment(DVGA_BLOCK)
    assert loaded.definition_sha256 == hashlib.sha256(data).hexdigest()
    assert loaded.definition_yaml == data.decode("utf-8")
    assert loaded.experiment == load_experiment(DVGA_BLOCK)

    edited = tmp_path / "edited.yaml"
    edited.write_bytes(data + b"\n# an edit\n")
    assert read_experiment(edited).definition_sha256 != loaded.definition_sha256


def test_yaml_with_a_duplicate_key_is_refused() -> None:
    text = "experiment_id: exp_a\nexperiment_id: exp_b\n"
    with pytest.raises(ValueError, match="duplicate key"):
        parse_experiment(text)
    nested = DVGA_BLOCK.read_text().replace(
        "  max_turns: 50\n", "  max_turns: 50\n  max_turns: 5\n"
    )
    assert nested != DVGA_BLOCK.read_text()
    with pytest.raises(ValueError, match="duplicate key 'max_turns'"):
        parse_experiment(nested)


def test_yaml_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ValueError, match="mapping"):
        parse_experiment("- a\n- b\n")


@pytest.mark.parametrize("experiment_id", ["exp_selftest_x", "exp_selftest_01JABCDEF"])
def test_the_self_test_prefix_is_reserved(tmp_path: Path, experiment_id: str) -> None:
    """Study metrics and the self-test's sweep treat exp_selftest_* as self-tests, so a
    study experiment may never take such an id (only derive_experiment does)."""
    text = DVGA_BLOCK.read_text().replace(
        "experiment_id: exp_selftest\n", f"experiment_id: {experiment_id}\n"
    )
    with pytest.raises(ValueError, match="reserved"):
        parse_experiment(text)
    path = tmp_path / "study.yaml"
    path.write_text(text)
    with pytest.raises(ValueError, match="reserved"):
        read_experiment(path)
    assert parse_experiment(text, selftest=True).experiment_id == experiment_id
    assert parse_experiment(DVGA_BLOCK.read_text()).experiment_id == "exp_selftest"  # no prefix


def test_run_tags_are_lowercase_hex() -> None:
    """Tags are drawn from [0-9a-f]; the pattern accepts nothing else (the labeller's
    Visible check is case-sensitive, its contamination scan case-insensitive)."""
    assert re.fullmatch(TAG_PATTERN, new_tag())
    assert re.fullmatch(TAG_PATTERN, "0123456789abcdef")
    for bad in ("0123456789ABCDEF", "0123456789abcdeg", "0123456789abcde", "z" * 16):
        assert not re.fullmatch(TAG_PATTERN, bad), bad


def _payload(doc: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = doc["arms"]["instruction"]["payload"]
    return payload


def _neutral(doc: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = doc["arms"]["neutral"]["payload"]
    return payload


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d["arms"].pop("control"), "control"),
        (lambda d: d["arms"].pop("instruction"), "instruction"),
        (lambda d: d["arms"].pop("neutral"), "neutral"),
        # the two-arm experiment shape is gone: no "injected" arm any more
        (lambda d: d["arms"].update(injected=d["arms"].pop("instruction")), "injected"),
        (lambda d: _neutral(d)["templates"].pop("P7"), "neutral payload must have one template"),
        (lambda d: _neutral(d)["templates"].update(P2="x $tag"), "not planted: P2"),
        (lambda d: _neutral(d).update(payload_id="test-placeholder"), "share the payload_id"),
        (lambda d: _neutral(d).update(style="override"), "style must be neutral"),
        (lambda d: _neutral(d).update(family="beacon"), "family must be the instruction's"),
        (lambda d: _neutral(d)["templates"].update(P1="# no tag at all"), r"\$tag"),
        (lambda d: _neutral(d).update(match_tolerance=0.06), "match_tolerance"),
        (lambda d: _neutral(d).update(match_tolerance=-0.01), "match_tolerance"),
        (lambda d: _neutral(d).update(match_tolerance=True), "match_tolerance"),
        (lambda d: _neutral(d).update(match_tolerance="0.05"), "match_tolerance"),
        (lambda d: d.update(experiment_id="bad id!"), "experiment_id"),
        (lambda d: d.update(repetitions=0), "repetitions"),
        (lambda d: d.update(seed=True), "seed"),
        (lambda d: d.update(agents=[]), "agents"),
        (lambda d: d.update(agents=["a", "a"]), "duplicate"),
        (lambda d: d.update(models=["m", "m"]), "duplicate"),
        (lambda d: d["targets"].append(copy.deepcopy(d["targets"][0])), "duplicate"),
        (lambda d: d["arms"]["instruction"].update(surfaces=[]), "surfaces"),
        (lambda d: d["arms"]["instruction"].update(surfaces=["P1", "P1"]), "duplicate"),
        (lambda d: d["arms"]["instruction"].update(surfaces=["P1", "P3"]), "P3"),
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
        (lambda d: d["targets"][0].pop("objective"), "objective"),
        (lambda d: d["targets"][0].update(objective=""), "objective"),
        (lambda d: d["targets"][0].update(objective=None), "objective"),
        (lambda d: d["targets"][0].update(objective="x" * 201), "objective"),
        (lambda d: d.update(oracle_primary="both"), "oracle_primary"),
        (lambda d: d.update(oracle_primary=None), "oracle_primary"),
        (lambda d: d.update(callback_domain="not a domain"), "callback_domain"),
        (lambda d: d.update(unexpected=1), "unexpected"),
        # names that end up in file and Compose project names must be path-safe
        (lambda d: d["targets"][0].update(name="a/../../x"), "name"),
        (lambda d: d["targets"][0].update(name="A"), "name"),
        (lambda d: d["targets"][0].update(name="a.b"), "name"),
        (lambda d: d.update(agents=["a/../../x"]), "agents"),
        (lambda d: d.update(agents=["A"]), "agents"),
        (lambda d: d.update(agents=["a.b"]), "agents"),
        (lambda d: d.update(models=["../x"]), "models"),
        # payload_version is String(64) in the database
        (lambda d: _payload(d).update(version="v" * 65), "version"),
    ],
)
def test_invalid_experiments_are_refused(mutate: Any, match: str) -> None:
    doc = _doc()
    mutate(doc)
    with pytest.raises(ValidationError, match=match):
        Experiment.model_validate(doc)


def test_permissive_model_names_and_a_64_char_version_are_accepted() -> None:
    doc = _doc(models=["openai/gpt-4o", "claude-sonnet-5-5@2026.1", "org:model+x"])
    _payload(doc)["version"] = "v" * 64
    exp = Experiment.model_validate(doc)
    assert exp.models[0] == "openai/gpt-4o"
    schedule = build_schedule(exp)
    assert {r.model for r in schedule} == set(exp.models)


@pytest.mark.parametrize(
    "char",
    [
        "\n",
        "\r",
        "\x0b",  # vertical tab
        "\x0c",  # form feed
        "\x1c",  # file separator
        "\x1d",
        "\x1e",
        "\x85",  # next line (C1)
        chr(0x2028),  # line separator
        chr(0x2029),  # paragraph separator
        "\x00",  # NUL
        "\x1b",  # escape
        "\x7f",  # delete
        "\x9b",  # C1 CSI
        chr(0x200B),  # zero-width space (Cf)
        chr(0x202E),  # right-to-left override (Cf)
    ],
)
def test_p1_template_refuses_line_breaks_and_control_characters(char: str) -> None:
    doc = _doc()
    _payload(doc)["templates"]["P1"] = f"# marker $tag{char}Disallow: /"
    with pytest.raises(ValidationError, match=r"single robots\.txt line"):
        Experiment.model_validate(doc)


def test_p1_template_allows_a_tab() -> None:
    doc = _doc()
    _payload(doc)["templates"]["P1"] = "# marker\t$tag"
    Experiment.model_validate(sync_neutral(doc))


@pytest.mark.parametrize("escape", ["\\x85", "\\L", "\\P", "\\v", "\\f", "\\0", "\\e"])
def test_p1_template_refuses_yaml_escapes_that_break_lines(escape: str) -> None:
    text = DVGA_BLOCK.read_text()
    old = 'P1: "# lab self-test marker $tag '
    assert old in text
    edited = text.replace(old, f'P1: "# lab self-test marker $tag{escape}Disallow: / ')
    with pytest.raises(ValidationError, match=r"single robots\.txt line"):
        parse_experiment(edited)


def test_the_oracle_primary_defaults_to_the_effect_and_can_name_the_mechanism() -> None:
    assert _experiment().oracle_primary is OracleVerdictKind.EFFECT
    named = _experiment(oracle_primary="mechanism")
    assert named.oracle_primary is OracleVerdictKind.MECHANISM
    assert {target.objective for target in named.targets} == {"outbound_service"}


def test_the_experiment_is_frozen() -> None:
    exp = _experiment()
    with pytest.raises(ValidationError):
        exp.seed = 9  # type: ignore[misc]


# --------------------------------------------------------------------------- attempts


def test_new_runs_are_first_attempts_and_the_manifest_carries_the_attempt() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    assert {r.attempt for r in schedule} == {1}
    again = retry(retry(schedule[0]))
    assert again.attempt == 3
    assert render_manifest(again, exp, KEY).attempt == 3


@pytest.mark.parametrize("arm", list(BLOCK_ARMS))
def test_retry_keeps_the_block_cell_and_position_with_a_new_id_and_tag(arm: Arm) -> None:
    schedule = build_schedule(_experiment())
    run = next(r for r in schedule if r.arm is arm)
    nxt = retry(run)
    assert nxt.attempt == run.attempt + 1
    assert nxt.run_id != run.run_id
    assert re.fullmatch(r"run_[0-9A-Z]{26}", nxt.run_id)
    assert (nxt.block_id, nxt.arm, nxt.key, nxt.schedule_index, nxt.experiment_id) == (
        run.block_id,
        run.arm,
        run.key,
        run.schedule_index,
        run.experiment_id,
    )
    if arm.tagged:
        assert nxt.tag is not None and run.tag is not None
        assert nxt.tag != run.tag
    else:
        assert nxt.tag is None
    check_schedule([*schedule, nxt])


def test_forbidden_tags_cover_every_other_attempt() -> None:
    schedule = build_schedule(_experiment())
    first = next(r for r in schedule if r.arm is Arm.INSTRUCTION)
    second = retry(first)
    ctrl = next(r for r in schedule if r.arm is Arm.CONTROL and r.block_id == first.block_id)
    full = [*schedule, second]
    assert {first.tag, second.tag} <= forbidden_tags_for(ctrl, full)
    assert first.tag in forbidden_tags_for(second, full)
    assert second.tag not in forbidden_tags_for(second, full)
    assert second.tag in forbidden_tags_for(first, full)


def _block_of(schedule: list[ScheduledRun], arm: Arm) -> dict[Arm, ScheduledRun]:
    """The runs of the block holding the first run of ``arm``, by arm."""
    anchor = next(r for r in schedule if r.arm is arm)
    return {r.arm: r for r in schedule if r.block_id == anchor.block_id}


def test_a_control_run_forbids_both_tags_of_its_block_and_every_other_tag() -> None:
    schedule = build_schedule(_experiment())
    block = _block_of(schedule, Arm.CONTROL)
    forbidden = forbidden_tags_for(block[Arm.CONTROL], schedule)
    assert {block[Arm.NEUTRAL].tag, block[Arm.INSTRUCTION].tag} <= forbidden
    assert forbidden == {r.tag for r in schedule if r.tag is not None}


def test_a_neutral_run_forbids_its_blocks_instruction_tag_but_never_its_own() -> None:
    schedule = build_schedule(_experiment())
    block = _block_of(schedule, Arm.NEUTRAL)
    forbidden = forbidden_tags_for(block[Arm.NEUTRAL], schedule)
    assert block[Arm.INSTRUCTION].tag in forbidden
    assert block[Arm.NEUTRAL].tag not in forbidden
    # an instruction run forbids its neutral's tag too: cross-run leaks either way
    assert block[Arm.NEUTRAL].tag in forbidden_tags_for(block[Arm.INSTRUCTION], schedule)


@pytest.mark.parametrize(
    ("arm", "missing"),
    [
        (Arm.CONTROL, Arm.NEUTRAL),
        (Arm.CONTROL, Arm.INSTRUCTION),
        (Arm.NEUTRAL, Arm.INSTRUCTION),
    ],
)
def test_forbidden_marks_refuse_a_schedule_missing_a_guarded_partner(
    arm: Arm, missing: Arm
) -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    block = _block_of(schedule, arm)
    partial = [r for r in schedule if r.run_id != block[missing].run_id]
    with pytest.raises(ValueError, match=f"no {missing.value} run of its block"):
        forbidden_tags_for(block[arm], partial)
    with pytest.raises(ValueError, match=f"no {missing.value} run of its block"):
        forbidden_tokens_for(block[arm], partial, exp, KEY)


def test_an_instruction_run_needs_no_partner_and_a_run_outside_the_schedule_is_refused() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    block = _block_of(schedule, Arm.INSTRUCTION)
    alone = [block[Arm.INSTRUCTION]]
    assert forbidden_tags_for(block[Arm.INSTRUCTION], alone) == frozenset()
    assert forbidden_tokens_for(block[Arm.INSTRUCTION], alone, exp, KEY) == frozenset()
    with pytest.raises(ValueError, match="not in the schedule"):
        forbidden_tags_for(block[Arm.CONTROL], alone)


def _tokens(run: ScheduledRun, exp: Experiment) -> set[str]:
    return {
        derive_token(KEY, run.run_id, placement_id_for(run.run_id, s)) for s in exp.arms.surfaces
    }


@pytest.mark.parametrize("arm", [Arm.CONTROL, Arm.NEUTRAL])
def test_control_and_neutral_forbid_every_attempt_of_their_instructions_tokens(arm: Arm) -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    block = _block_of(schedule, arm)
    again = retry(block[Arm.INSTRUCTION])
    full = [*schedule, again]
    tokens = forbidden_tokens_for(block[arm], full, exp, KEY)
    assert tokens == _tokens(block[Arm.INSTRUCTION], exp) | _tokens(again, exp)
    # the manifest's own tokens are exactly those the lab key derives
    manifest = render_manifest(block[Arm.INSTRUCTION], exp, KEY)
    assert {p.token for p in manifest.placements} == _tokens(block[Arm.INSTRUCTION], exp)
    # never another block's tokens, nor the run's own
    assert not tokens & _tokens(block[arm], exp)
    other = next(r for r in schedule if r.arm is Arm.INSTRUCTION and r.block_id != again.block_id)
    assert not tokens & _tokens(other, exp)


def test_forbidden_tokens_need_a_lab_key() -> None:
    exp = _experiment()
    schedule = build_schedule(exp)
    with pytest.raises(ValueError, match="lab_key"):
        forbidden_tokens_for(schedule[0], schedule, exp, b"")


def test_check_schedule_accepts_a_built_schedule_and_its_retries() -> None:
    schedule = build_schedule(_experiment())
    check_schedule(schedule)
    check_schedule(list(reversed(schedule)))
    once = retry(schedule[0])
    check_schedule([*schedule, once, retry(once)])
    check_schedule([])


def _replace(schedule: list[ScheduledRun], index: int, **update: Any) -> list[ScheduledRun]:
    out = list(schedule)
    out[index] = out[index].model_copy(update=update)
    return out


def _drop_one_arm(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return s[1:]


def _duplicate_latest(s: list[ScheduledRun]) -> list[ScheduledRun]:
    nxt = retry(s[0])
    return [*s, nxt, nxt.model_copy(update={"run_id": "run_duplicate"})]


def _attempt_gap(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return [*s, retry(s[0]).model_copy(update={"attempt": 3})]


def _swap_positions(s: list[ScheduledRun]) -> list[ScheduledRun]:
    # block 0's last run takes position 3 and block 1's first run takes position 2
    return _replace(_replace(s, 2, schedule_index=3), 3, schedule_index=2)


def _drop_neutral(s: list[ScheduledRun]) -> list[ScheduledRun]:
    i = next(i for i, r in enumerate(s) if r.arm is Arm.NEUTRAL)
    return s[:i] + s[i + 1 :]


def _neutral_without_tag(s: list[ScheduledRun]) -> list[ScheduledRun]:
    i = next(i for i, r in enumerate(s) if r.arm is Arm.NEUTRAL)
    out = list(s)
    # model_construct skips the model's own check, as a raw database row could
    out[i] = ScheduledRun.model_construct(**{**s[i].model_dump(), "tag": None})
    return out


def _interleave_blocks(s: list[ScheduledRun]) -> list[ScheduledRun]:
    # two blocks woven together: positions 0, 2, 4 and 1, 3, 5
    return [
        r.model_copy(update={"schedule_index": [0, 2, 4, 1, 3, 5][r.schedule_index]})
        if r.schedule_index < 6
        else r
        for r in s
    ]


def _mixed_cells(s: list[ScheduledRun]) -> list[ScheduledRun]:
    other = next(t for t in ("dvga", "juice-shop") if t != s[1].target)
    return _replace(s, 1, target=other)


def _control_with_tag(s: list[ScheduledRun]) -> list[ScheduledRun]:
    i = next(i for i, r in enumerate(s) if r.arm is Arm.CONTROL)
    out = list(s)
    # model_construct skips the model's own check, as a raw database row could
    out[i] = ScheduledRun.model_construct(**{**s[i].model_dump(), "tag": "0123456789abcdef"})
    return out


def _shared_tag(s: list[ScheduledRun]) -> list[ScheduledRun]:
    inj = [i for i, r in enumerate(s) if r.arm is Arm.INSTRUCTION]
    return _replace(s, inj[1], tag=s[inj[0]].tag)


def _gap_in_positions(s: list[ScheduledRun]) -> list[ScheduledRun]:
    # the last block moves one position up, leaving a hole before it
    return [
        r.model_copy(update={"schedule_index": r.schedule_index + 1})
        if r.schedule_index >= len(s) - 3
        else r
        for r in s
    ]


def _spread_block(s: list[ScheduledRun]) -> list[ScheduledRun]:
    # the last block keeps its first position but its last run moves two further on, so
    # every block still starts at a multiple of three
    last = max(r.schedule_index for r in s)
    return [
        r.model_copy(update={"schedule_index": last + 2}) if r.schedule_index == last else r
        for r in s
    ]


def _retry_moves(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return [*s, retry(s[0]).model_copy(update={"schedule_index": len(s)})]


def _two_experiments(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return _replace(s, 0, experiment_id="exp_other")


def _duplicate_run_id(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return _replace(s, 1, run_id=s[0].run_id)


@pytest.mark.parametrize(
    ("match", "corrupt"),
    [
        ("no (control|neutral|instruction) run", _drop_one_arm),
        ("has no neutral run", _drop_neutral),
        ("neutral run .* has no tag", _neutral_without_tag),
        ("not contiguous", _interleave_blocks),
        ("is not contiguous", _spread_block),
        ("duplicate", _duplicate_latest),
        ("not 1..n", _attempt_gap),
        ("not contiguous", _swap_positions),
        ("mixes cells", _mixed_cells),
        ("carries a tag", _control_with_tag),
        ("reuses another run's tag", _shared_tag),
        ("not contiguous", _gap_in_positions),
        ("change position", _retry_moves),
        ("several experiments", _two_experiments),
        ("duplicate run_id", _duplicate_run_id),
    ],
)
def test_check_schedule_refuses_a_broken_schedule(match: str, corrupt: Any) -> None:
    schedule = build_schedule(_experiment())
    with pytest.raises(ScheduleError, match=match):
        check_schedule(corrupt(schedule))


# --------------------------------------------------------------------------- 14b carry-ins


def _move_block(s: list[ScheduledRun], block_id: str, **update: Any) -> list[ScheduledRun]:
    return [r.model_copy(update=update) if r.block_id == block_id else r for r in s]


def test_check_schedule_with_the_experiment_accepts_a_built_schedule_and_retries() -> None:
    experiment = _experiment()
    schedule = build_schedule(experiment)
    check_schedule(schedule, experiment=experiment)
    check_schedule([*schedule, retry(schedule[0])], experiment=experiment)


def test_check_schedule_with_the_experiment_refuses_a_truncated_schedule() -> None:
    small = _experiment(repetitions=1)
    full = _experiment(repetitions=3)
    schedule = build_schedule(small)
    check_schedule(schedule)  # well-formed on its own
    with pytest.raises(ScheduleError, match="missing"):
        check_schedule(schedule, experiment=full)
    with pytest.raises(ScheduleError, match="missing"):
        check_schedule([], experiment=full)


def test_check_schedule_with_the_experiment_refuses_two_blocks_in_one_cell() -> None:
    experiment = _experiment()
    schedule = build_schedule(experiment)
    first = schedule[0]
    second = next(r for r in schedule if r.key != first.key)
    doubled = _move_block(
        schedule,
        second.block_id,
        target=first.target,
        agent=first.agent,
        model=first.model,
        rep=first.rep,
    )
    check_schedule(doubled)  # each block is still well-formed
    with pytest.raises(ScheduleError, match="more than one block"):
        check_schedule(doubled, experiment=experiment)


@pytest.mark.parametrize(
    ("field", "value"),
    [("target", "juice-shop-2"), ("agent", "other"), ("model", "other-model"), ("rep", 3)],
)
def test_check_schedule_with_the_experiment_refuses_a_block_outside_its_cells(
    field: str, value: Any
) -> None:
    experiment = _experiment()
    schedule = build_schedule(experiment)
    moved = _move_block(schedule, schedule[0].block_id, **{field: value})
    with pytest.raises(ScheduleError, match="not in the experiment"):
        check_schedule(moved, experiment=experiment)


def test_check_schedule_with_the_experiment_refuses_another_experiments_runs() -> None:
    experiment = _experiment()
    other = _experiment(experiment_id="exp_other")
    with pytest.raises(ScheduleError, match="exp_other"):
        check_schedule(build_schedule(other), experiment=experiment)


@pytest.mark.parametrize(
    "line",
    [
        "Disallow: /x-$tag",
        "disallow:/x $tag",
        "  Allow: /$tag",
        "User-agent: $tag",
        "USER-AGENT : x $tag",
        "Sitemap: http://$callback_host/$tag",
        "Crawl-delay: 1 # $tag",
        "Host: $callback_host $tag",
        "\tDisallow: $decoy_path $tag",
    ],
)
def test_p1_template_refuses_a_robots_directive(line: str) -> None:
    doc = _doc()
    _payload(doc)["templates"]["P1"] = line
    with pytest.raises(ValidationError, match=r"robots\.txt directive"):
        Experiment.model_validate(doc)


@pytest.mark.parametrize(
    "line",
    [
        "# Disallow: /x $tag",
        "# lab marker $tag",
        "X-Lab-Note: $tag",
        "$tag Disallow: x",
        "Disallowed $tag",
    ],
)
def test_p1_template_accepts_a_comment_or_a_non_standard_line(line: str) -> None:
    doc = _doc()
    _payload(doc)["templates"]["P1"] = line
    Experiment.model_validate(sync_neutral(doc))
