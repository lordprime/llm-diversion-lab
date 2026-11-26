"""Rendering a run's manifest and its per-component cell inputs (control plane only)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cell.catcher.callback_log import CatcherConfig
from cell.catcher.classify import TokenIndex
from cell.injector.placement import build_plan
from control.core.models import Arm, RunManifest, Surface
from control.core.tokens import derive_token
from control.labeler.funnel import RunEvidence
from control.runner.experiment import Experiment, load_experiment
from control.runner.render import (
    TokenMismatchError,
    forbidden_tags_for,
    forbidden_tokens_for,
    placement_id_for,
    render_catcher_file,
    render_catcher_tokens,
    render_manifest,
    render_payloads,
    verify_manifest_tokens,
)
from control.runner.schedule import ScheduledRun, build_schedule
from tests.runner.test_blocks import _experiment

REPO_ROOT = Path(__file__).resolve().parents[2]
DVGA_BLOCK = REPO_ROOT / "tests" / "fixtures" / "experiments" / "dvga_block.yaml"
# Derived at runtime so no key-like literal sits in the repository.
KEY = hashlib.sha256(b"render-test-lab-key").digest()
OTHER_KEY = hashlib.sha256(b"render-test-other-key").digest()
WHEN = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def experiment() -> Experiment:
    return load_experiment(DVGA_BLOCK)


@pytest.fixture(scope="module")
def schedule(experiment: Experiment) -> list[ScheduledRun]:
    return build_schedule(experiment)


def _run(schedule: list[ScheduledRun], arm: Arm) -> ScheduledRun:
    return next(r for r in schedule if r.arm is arm)


@pytest.fixture(scope="module")
def injected(experiment: Experiment, schedule: list[ScheduledRun]) -> RunManifest:
    """The instruction run's manifest (the fixture keeps its short historical name)."""
    return render_manifest(_run(schedule, Arm.INSTRUCTION), experiment, KEY, created_at=WHEN)


@pytest.fixture(scope="module")
def neutral(experiment: Experiment, schedule: list[ScheduledRun]) -> RunManifest:
    return render_manifest(_run(schedule, Arm.NEUTRAL), experiment, KEY, created_at=WHEN)


@pytest.fixture(scope="module")
def control(experiment: Experiment, schedule: list[ScheduledRun]) -> RunManifest:
    return render_manifest(_run(schedule, Arm.CONTROL), experiment, KEY, created_at=WHEN)


# --------------------------------------------------------------------------- manifest


def test_injected_manifest_plans_p1_and_p7_with_derived_tokens(injected: RunManifest) -> None:
    assert injected.arm is Arm.INSTRUCTION
    assert injected.tag is not None
    assert [p.surface for p in injected.placements] == [Surface.P1, Surface.P7]
    for p in injected.placements:
        assert p.run_id == injected.run_id
        assert p.tag == injected.tag
        assert p.token == derive_token(KEY, injected.run_id, p.placement_id)
        assert p.payload_id == "selftest-placeholder"
        assert p.payload_version == "1"
    p1, p7 = injected.placements
    assert (p1.url, p1.locator) == ("/robots.txt", "robots.txt:append")
    assert p7.locator in {"error:403", "error:404"}
    assert injected.created_at == WHEN


def test_rendering_is_deterministic_for_a_run(
    experiment: Experiment, schedule: list[ScheduledRun], injected: RunManifest
) -> None:
    again = render_manifest(_run(schedule, Arm.INSTRUCTION), experiment, KEY, created_at=WHEN)
    assert again == injected
    assert injected.placements[0].placement_id == placement_id_for(injected.run_id, Surface.P1)


def test_placement_ids_are_distinct_across_runs(
    experiment: Experiment, injected: RunManifest
) -> None:
    other_run = _run(build_schedule(experiment), Arm.INSTRUCTION)
    other = render_manifest(other_run, experiment, KEY)
    assert {p.placement_id for p in other.placements}.isdisjoint(
        p.placement_id for p in injected.placements
    )
    assert {p.token for p in other.placements}.isdisjoint(p.token for p in injected.placements)


def test_default_created_at_is_now_and_aware(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    before = datetime.now(UTC)
    manifest = render_manifest(_run(schedule, Arm.CONTROL), experiment, KEY)
    assert before <= manifest.created_at <= datetime.now(UTC)


def test_render_refuses_a_run_of_another_experiment(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    run = _run(schedule, Arm.INSTRUCTION).model_copy(update={"experiment_id": "exp_other"})
    with pytest.raises(ValueError, match="experiment"):
        render_manifest(run, experiment, KEY)


def test_render_refuses_a_run_whose_target_is_not_in_the_experiment(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    run = _run(schedule, Arm.INSTRUCTION).model_copy(update={"target": "juice-shop"})
    with pytest.raises(ValueError, match="target"):
        render_manifest(run, experiment, KEY)


def test_render_refuses_an_empty_key(experiment: Experiment, schedule: list[ScheduledRun]) -> None:
    with pytest.raises(ValueError, match="lab_key"):
        render_manifest(_run(schedule, Arm.CONTROL), experiment, b"")


# --------------------------------------------------------------------------- tokens


def test_tokens_verify(injected: RunManifest, control: RunManifest) -> None:
    verify_manifest_tokens(injected, KEY)
    verify_manifest_tokens(control, KEY)


def test_a_tampered_token_is_rejected(injected: RunManifest) -> None:
    p1, p7 = injected.placements
    forged = derive_token(KEY, injected.run_id, "pl_somethingelse")
    tampered = injected.model_copy(
        update={"placements": [p1.model_copy(update={"token": forged}), p7]}
    )
    with pytest.raises(TokenMismatchError, match=p1.placement_id):
        verify_manifest_tokens(tampered, KEY)


def test_a_swapped_token_is_rejected(injected: RunManifest) -> None:
    p1, p7 = injected.placements
    swapped = injected.model_copy(
        update={
            "placements": [
                p1.model_copy(update={"token": p7.token}),
                p7.model_copy(update={"token": p1.token}),
            ]
        }
    )
    with pytest.raises(TokenMismatchError):
        verify_manifest_tokens(swapped, KEY)


def test_tokens_from_another_key_are_rejected(injected: RunManifest) -> None:
    with pytest.raises(TokenMismatchError):
        verify_manifest_tokens(injected, OTHER_KEY)


def test_token_mismatch_is_a_value_error() -> None:
    assert issubclass(TokenMismatchError, ValueError)


# --------------------------------------------------------------------------- payloads


def test_payload_texts_contain_the_tag_and_match_content_sha256(
    experiment: Experiment, injected: RunManifest
) -> None:
    payloads = render_payloads(injected, experiment)
    assert set(payloads) == {p.placement_id for p in injected.placements}
    for p in injected.placements:
        text = payloads[p.placement_id]
        assert injected.tag is not None and injected.tag in text
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == p.content_sha256


def test_p1_text_is_one_robots_line(experiment: Experiment, injected: RunManifest) -> None:
    payloads = render_payloads(injected, experiment)
    p1 = injected.placements[0]
    assert "\n" not in payloads[p1.placement_id]


def test_template_placeholders_are_filled(experiment: Experiment, injected: RunManifest) -> None:
    payloads = render_payloads(injected, experiment)
    text = payloads[injected.placements[1].placement_id]
    assert "$" not in text
    assert f"/x-{injected.tag}" in text
    assert f"{injected.placements[1].token}.{experiment.callback_domain}" in text


def test_the_real_injector_accepts_the_rendered_inputs(
    experiment: Experiment, injected: RunManifest, control: RunManifest
) -> None:
    plan = build_plan(injected, render_payloads(injected, experiment))
    assert plan.arm is Arm.INSTRUCTION
    assert plan.robots is not None
    assert len(plan.errors) == 1
    assert build_plan(control, render_payloads(control, experiment)).arm is Arm.CONTROL


def test_payloads_are_refused_if_the_template_changed(
    experiment: Experiment, injected: RunManifest
) -> None:
    payload = experiment.arms.instruction.payload
    changed_payload = payload.model_copy(
        update={"templates": {**payload.templates, Surface.P1: "# edited $tag"}}
    )
    changed_arm = experiment.arms.instruction.model_copy(update={"payload": changed_payload})
    changed_arms = experiment.arms.model_copy(update={"instruction": changed_arm})
    changed = experiment.model_copy(update={"arms": changed_arms})
    with pytest.raises(ValueError, match="content_sha256"):
        render_payloads(injected, changed)


# --------------------------------------------------------------------------- catcher


def test_catcher_input_is_only_token_and_placement_id(injected: RunManifest) -> None:
    tokens = render_catcher_tokens(injected)
    assert tokens == [(p.token, p.placement_id) for p in injected.placements]
    assert all(isinstance(t, tuple) and len(t) == 2 for t in tokens)
    assert all(isinstance(v, str) for t in tokens for v in t)
    blob = json.dumps(tokens)
    assert injected.tag is not None and injected.tag not in blob
    assert injected.run_id not in blob
    for p in injected.placements:
        assert p.url not in blob
        assert p.content_sha256 not in blob


def test_catcher_tokens_match_what_the_catcher_indexes(injected: RunManifest) -> None:
    assert list(TokenIndex.build(injected).entries) == render_catcher_tokens(injected)


def test_the_catcher_file_is_token_only_and_the_catcher_reads_it(
    tmp_path: Path, experiment: Experiment, injected: RunManifest, control: RunManifest
) -> None:
    for manifest in (injected, control):
        data = render_catcher_file(manifest, experiment)
        doc = json.loads(data)
        assert set(doc) == {"run_id", "callback_domain", "tokens"}
        assert doc["callback_domain"] == experiment.callback_domain
        assert manifest.tag is None or manifest.tag.encode() not in data
        for p in manifest.placements:
            assert p.url.encode() not in data and p.content_sha256.encode() not in data
        path = tmp_path / f"{manifest.arm.value}.json"
        path.write_bytes(data)
        config = CatcherConfig.from_env({"LAB_TOKENS": str(path), "LAB_RUN_ID": manifest.run_id})
        assert config.tokens == TokenIndex.build(manifest)
        assert config.callback_domain == experiment.callback_domain
        for form in _forms_of_the_key(KEY):
            assert form not in data


# --------------------------------------------------------------------------- the key


def _forms_of_the_key(key: bytes) -> list[bytes]:
    return [
        key,
        key.hex().encode(),
        key.hex().upper().encode(),
        base64.b64encode(key),
        base64.urlsafe_b64encode(key),
        base64.b32encode(key),
        base64.b32encode(key).lower(),
    ]


def test_no_cell_input_contains_the_lab_key(
    experiment: Experiment, injected: RunManifest, control: RunManifest
) -> None:
    for manifest in (injected, control):
        blobs = [
            manifest.model_dump_json().encode(),
            json.dumps(render_payloads(manifest, experiment)).encode(),
            json.dumps(render_payloads(manifest, experiment), ensure_ascii=False).encode(),
            json.dumps(render_catcher_tokens(manifest)).encode(),
        ]
        for blob in blobs:
            for form in _forms_of_the_key(KEY):
                assert form not in blob


def test_the_key_is_not_kept_on_any_rendered_object(
    experiment: Experiment, injected: RunManifest
) -> None:
    assert KEY.hex() not in repr(injected)
    assert KEY.hex() not in repr(render_payloads(injected, experiment))
    assert KEY.hex() not in repr(render_catcher_tokens(injected))


# --------------------------------------------------------------------------- forbidden tags


def test_a_control_run_forbids_both_tags_of_its_block(schedule: list[ScheduledRun]) -> None:
    ctrl = _run(schedule, Arm.CONTROL)
    neu = _run(schedule, Arm.NEUTRAL)
    ins = _run(schedule, Arm.INSTRUCTION)
    assert ctrl.block_id == neu.block_id == ins.block_id
    assert forbidden_tags_for(ctrl, schedule) == {neu.tag, ins.tag}


def test_a_tagged_run_forbids_every_other_runs_tag_but_never_its_own() -> None:
    exp = _experiment()
    sched = build_schedule(exp)
    tagged = [r for r in sched if r.arm.tagged]
    for run in tagged:
        forbidden = forbidden_tags_for(run, sched)
        assert run.tag not in forbidden
        assert forbidden == {r.tag for r in tagged if r is not run}
    for run in sched:
        if run.arm is Arm.CONTROL:
            assert forbidden_tags_for(run, sched) == {r.tag for r in tagged}


def test_forbidden_tags_refuse_a_run_not_in_the_schedule(
    experiment: Experiment, schedule: list[ScheduledRun]
) -> None:
    stranger = _run(build_schedule(experiment), Arm.CONTROL)
    with pytest.raises(ValueError, match="not in the schedule"):
        forbidden_tags_for(stranger, schedule)


def test_forbidden_tags_refuse_a_control_or_neutral_run_without_its_block(
    schedule: list[ScheduledRun],
) -> None:
    ctrl = _run(schedule, Arm.CONTROL)
    with pytest.raises(ValueError, match="no neutral run of its block"):
        forbidden_tags_for(ctrl, [ctrl])
    neu = _run(schedule, Arm.NEUTRAL)
    with pytest.raises(ValueError, match="no instruction run of its block"):
        forbidden_tags_for(neu, [ctrl, neu])


def test_the_labeller_accepts_the_forbidden_marks(
    experiment: Experiment,
    schedule: list[ScheduledRun],
    injected: RunManifest,
    neutral: RunManifest,
    control: RunManifest,
) -> None:
    by_id = {r.run_id: r for r in schedule}
    for manifest in (control, neutral, injected):
        run = by_id[manifest.run_id]
        RunEvidence(
            manifest=manifest,
            forbidden_tags=forbidden_tags_for(run, schedule),
            forbidden_tokens=forbidden_tokens_for(run, schedule, experiment, KEY),
        )


def test_neutral_manifest_plants_its_own_texts_where_the_instruction_does(
    experiment: Experiment, injected: RunManifest, neutral: RunManifest
) -> None:
    assert neutral.arm is Arm.NEUTRAL and neutral.tag is not None
    assert neutral.tag != injected.tag
    pairs = list(zip(neutral.placements, injected.placements, strict=True))
    for ours, theirs in pairs:
        assert (ours.surface, ours.url, ours.locator, ours.offset_fraction) == (
            theirs.surface,
            theirs.url,
            theirs.locator,
            theirs.offset_fraction,
        )
        assert ours.payload_id == experiment.arms.neutral.payload.payload_id
        assert ours.token == derive_token(KEY, neutral.run_id, ours.placement_id)
    texts = render_payloads(neutral, experiment)
    for placement in neutral.placements:
        text = texts[placement.placement_id]
        assert neutral.tag in text
        assert "/x-" not in text and experiment.callback_domain not in text
        assert placement.token not in text
    # the injector plants a neutral run exactly like an instruction run
    plan = build_plan(neutral, texts)
    assert plan.arm is Arm.NEUTRAL
    assert plan.robots is not None and len(plan.errors) == 1
