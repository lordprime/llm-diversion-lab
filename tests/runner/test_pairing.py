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
from control.runner.render import (
    forbidden_tags_for,
    render_catcher_tokens,
    render_manifest,
    render_payloads,
)
from control.runner.schedule import (
    PairKey,
    ScheduledRun,
    ScheduleError,
    build_schedule,
    check_schedule,
    plan_order,
    retry,
)

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
    Experiment.model_validate(doc)


@pytest.mark.parametrize("escape", ["\\x85", "\\L", "\\P", "\\v", "\\f", "\\0", "\\e"])
def test_p1_template_refuses_yaml_escapes_that_break_lines(escape: str) -> None:
    text = SELFTEST.read_text()
    old = 'P1: "# lab self-test marker $tag '
    assert old in text
    edited = text.replace(old, f'P1: "# lab self-test marker $tag{escape}Disallow: / ')
    with pytest.raises(ValidationError, match=r"single robots\.txt line"):
        parse_experiment(edited)


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


@pytest.mark.parametrize("arm", [Arm.INJECTED, Arm.CONTROL])
def test_retry_keeps_the_pair_cell_and_position_with_a_new_id_and_tag(arm: Arm) -> None:
    schedule = build_schedule(_experiment())
    run = next(r for r in schedule if r.arm is arm)
    nxt = retry(run)
    assert nxt.attempt == run.attempt + 1
    assert nxt.run_id != run.run_id
    assert re.fullmatch(r"run_[0-9A-Z]{26}", nxt.run_id)
    assert (nxt.pair_id, nxt.arm, nxt.key, nxt.schedule_index, nxt.experiment_id) == (
        run.pair_id,
        run.arm,
        run.key,
        run.schedule_index,
        run.experiment_id,
    )
    if arm is Arm.INJECTED:
        assert nxt.tag is not None and run.tag is not None
        assert nxt.tag != run.tag
    else:
        assert nxt.tag is None
    check_schedule([*schedule, nxt])


def test_forbidden_tags_cover_every_other_attempt() -> None:
    schedule = build_schedule(_experiment())
    first = next(r for r in schedule if r.arm is Arm.INJECTED)
    second = retry(first)
    ctrl = next(r for r in schedule if r.arm is Arm.CONTROL and r.pair_id == first.pair_id)
    full = [*schedule, second]
    assert {first.tag, second.tag} <= forbidden_tags_for(ctrl, full)
    assert first.tag in forbidden_tags_for(second, full)
    assert second.tag not in forbidden_tags_for(second, full)
    assert second.tag in forbidden_tags_for(first, full)


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
    # pair 0's second run takes position 2 and pair 1's first run takes position 1
    return _replace(_replace(s, 1, schedule_index=2), 2, schedule_index=1)


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
    inj = [i for i, r in enumerate(s) if r.arm is Arm.INJECTED]
    return _replace(s, inj[1], tag=s[inj[0]].tag)


def _gap_in_positions(s: list[ScheduledRun]) -> list[ScheduledRun]:
    last = len(s) - 1
    return _replace(_replace(s, last, schedule_index=last + 2), last - 1, schedule_index=last + 1)


def _retry_moves(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return [*s, retry(s[0]).model_copy(update={"schedule_index": len(s)})]


def _two_experiments(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return _replace(s, 0, experiment_id="exp_other")


def _duplicate_run_id(s: list[ScheduledRun]) -> list[ScheduledRun]:
    return _replace(s, 1, run_id=s[0].run_id)


@pytest.mark.parametrize(
    ("match", "corrupt"),
    [
        ("no control run|no injected run", _drop_one_arm),
        ("duplicate", _duplicate_latest),
        ("not 1..n", _attempt_gap),
        ("not adjacent", _swap_positions),
        ("mixes cells", _mixed_cells),
        ("carries a tag", _control_with_tag),
        ("reuses another run's tag", _shared_tag),
        ("not adjacent", _gap_in_positions),
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


def _move_pair(s: list[ScheduledRun], pair_id: str, **update: Any) -> list[ScheduledRun]:
    return [r.model_copy(update=update) if r.pair_id == pair_id else r for r in s]


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


def test_check_schedule_with_the_experiment_refuses_two_pairs_in_one_cell() -> None:
    experiment = _experiment()
    schedule = build_schedule(experiment)
    first = schedule[0]
    second = next(r for r in schedule if r.key != first.key)
    doubled = _move_pair(
        schedule,
        second.pair_id,
        target=first.target,
        agent=first.agent,
        model=first.model,
        rep=first.rep,
    )
    check_schedule(doubled)  # each pair is still well-formed
    with pytest.raises(ScheduleError, match="more than one pair"):
        check_schedule(doubled, experiment=experiment)


@pytest.mark.parametrize(
    ("field", "value"),
    [("target", "juice-shop-2"), ("agent", "other"), ("model", "other-model"), ("rep", 3)],
)
def test_check_schedule_with_the_experiment_refuses_a_pair_outside_its_cells(
    field: str, value: Any
) -> None:
    experiment = _experiment()
    schedule = build_schedule(experiment)
    moved = _move_pair(schedule, schedule[0].pair_id, **{field: value})
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
    Experiment.model_validate(doc)
