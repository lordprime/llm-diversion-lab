"""Experiment validation for surfaces P2-P6 and P8: locators, offsets and texts."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from cell.injector.placement import BODY_SURFACES, SURFACE_LOCATORS
from control.core.models import Surface
from control.runner.experiment import (
    DEFAULT_OFFSET_FRACTION,
    MAX_PLACEMENT_MAP_BYTES,
    SUPPORTED_SURFACES,
    ByteEstimateTokenizer,
    Experiment,
    PlacementMapFile,
    PlacementSpec,
    TargetSpec,
    TextMeasure,
    check_neutral_match,
    parse_experiment,
    read_experiment,
)
from control.runner.render import render_manifest
from control.runner.schedule import build_schedule
from tests.runner.test_blocks import KEY, _doc, sync_neutral

ALL = list(Surface)
TEXTS = {
    Surface.P1: "# note $tag",
    Surface.P2: "page text $tag",
    Surface.P3: "comment text $tag",
    Surface.P4: "offscreen text $tag",
    Surface.P5: "hidden text $tag",
    Surface.P6: "description $tag",
    Surface.P7: "<p>$tag</p>",
    Surface.P8: "Security notice $tag",
}


def _placements() -> dict[str, dict[str, Any]]:
    return {
        "P1": {"url": "/robots.txt", "locator": "robots.txt:append"},
        "P2": {"url": "/private/page", "locator": SURFACE_LOCATORS[Surface.P2]},
        "P3": {"url": "/page", "locator": SURFACE_LOCATORS[Surface.P3]},
        "P4": {"url": "/page", "locator": SURFACE_LOCATORS[Surface.P4]},
        "P5": {"url": "/page", "locator": SURFACE_LOCATORS[Surface.P5]},
        "P6": {"url": "/page", "locator": SURFACE_LOCATORS[Surface.P6]},
        "P7": {"url": "/.env", "locator": "error:404"},
        "P8": {"url": "/page", "locator": SURFACE_LOCATORS[Surface.P8]},
    }


def _full(**changes: Any) -> dict[str, Any]:
    doc = _doc()
    doc["targets"] = [
        {"name": "dvga", "objective": "outbound_service", "placements": _placements()}
    ]
    doc["arms"]["instruction"]["surfaces"] = [s.value for s in ALL]
    doc["arms"]["instruction"]["payload"]["templates"] = {s.value: t for s, t in TEXTS.items()}
    doc.update(changes)
    return sync_neutral(doc)


def _valid(doc: dict[str, Any]) -> Experiment:
    """Validate ``doc`` with its neutral texts matched to whatever the test planted."""
    return Experiment.model_validate(sync_neutral(doc))


def _with(path: list[Any], value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(_full())
    node: Any = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return doc


def _offset(surface: Surface, value: Any) -> dict[str, Any]:
    return _with(["targets", 0, "placements", surface.value, "offset_fraction"], value)


def test_every_surface_is_supported_and_a_full_experiment_validates() -> None:
    assert frozenset(ALL) == SUPPORTED_SURFACES
    assert Surface.P8 in SUPPORTED_SURFACES
    exp = _valid(_full())
    spec = exp.targets[0].placements[Surface.P3]
    assert spec.offset_fraction == DEFAULT_OFFSET_FRACTION == 0.5


@pytest.mark.parametrize("surface", sorted(SURFACE_LOCATORS))
def test_a_wrong_locator_is_refused(surface: Surface) -> None:
    doc = _with(["targets", 0, "placements", surface.value, "locator"], "html:other")
    with pytest.raises(ValidationError, match="locator must be"):
        _valid(doc)


@pytest.mark.parametrize("surface", [Surface.P2, Surface.P3, Surface.P6, Surface.P8])
def test_only_p1_may_use_robots_txt(surface: Surface) -> None:
    doc = _with(["targets", 0, "placements", surface.value, "url"], "/robots.txt")
    with pytest.raises(ValidationError, match="robots"):
        _valid(doc)


@pytest.mark.parametrize("value", [0, 0.0, 0.25, 0.5, 1, 1.0])
def test_offset_fraction_accepts_the_closed_unit_interval(value: float) -> None:
    exp = _valid(_offset(Surface.P4, value))
    assert exp.targets[0].placements[Surface.P4].offset_fraction == value


@pytest.mark.parametrize(
    "value", [-0.01, 1.01, 2, float("nan"), float("inf"), "0.5", True, None, [0.5]]
)
def test_offset_fraction_refuses_anything_else(value: Any) -> None:
    with pytest.raises(ValidationError):
        _valid(_offset(Surface.P4, value))


# A dumped experiment carries the default 0.5 on every placement, so only a changed value counts.


@pytest.mark.parametrize("surface", [Surface.P1, Surface.P7, Surface.P8])
def test_offset_fraction_is_for_p2_to_p6_only(surface: Surface) -> None:
    with pytest.raises(ValidationError, match="P2-P6 only"):
        _valid(_offset(surface, 0.25))


def test_placement_spec_defaults_and_rejects_unknown_fields() -> None:
    assert PlacementSpec(url="/p", locator="html:body").offset_fraction == 0.5
    with pytest.raises(ValidationError):
        PlacementSpec.model_validate({"url": "/p", "locator": "html:body", "offset": 0.5})


def test_an_experiment_needs_a_placement_for_each_new_surface() -> None:
    doc = _full()
    del doc["targets"][0]["placements"]["P6"]
    with pytest.raises(ValidationError, match="no placement for surface P6"):
        _valid(doc)


# --------------------------------------------------------------------------- texts


def _p8(text: str, **changes: Any) -> dict[str, Any]:
    doc = _full(**changes)
    doc["arms"]["instruction"]["payload"]["templates"]["P8"] = text
    return doc


def test_p8_template_must_be_single_line_printable_ascii() -> None:
    _valid(_p8("Notice: $tag, see $decoy_path and $callback_host"))
    for bad in (
        "one\nline two $tag",
        "carriage\rreturn $tag",
        "tab\there $tag",
        "café $tag",
        "\U0001f600 $tag",
        " leading $tag",
        "trailing $tag ",
    ):
        with pytest.raises(ValidationError, match="P8"):
            _valid(_p8(bad))


def test_p8_template_is_checked_once_rendered() -> None:
    fits = "x" * (512 - 16 - 1) + " $tag"  # the tag renders to 16 bytes: exactly 512
    _valid(_p8(fits))
    with pytest.raises(ValidationError, match="512"):
        _valid(_p8("x" + fits))
    # $callback_host is <12-char token>.<callback_domain>: a long zone can push it over
    host = "$callback_host $tag " + "y" * 420
    _valid(_p8(host))
    zone = ".".join(["a" * 60] * 3) + ".test"
    with pytest.raises(ValidationError, match="512"):
        _valid(_p8(host, callback_domain=zone))


def test_p3_template_cannot_close_its_comment() -> None:
    doc = _full()
    doc["arms"]["instruction"]["payload"]["templates"]["P3"] = "x --> <script> $tag"
    with pytest.raises(ValidationError, match="P3"):
        _valid(doc)


def test_templates_for_html_surfaces_may_hold_markup_like_text() -> None:
    doc = _full()
    for surface in ("P2", "P4", "P5", "P6"):
        doc["arms"]["instruction"]["payload"]["templates"][surface] = "</div><b>x</b> & $tag"
    _valid(doc)


# --------------------------------------------------------------------------- manifest


def test_the_manifest_carries_the_registered_offset_for_in_page_surfaces() -> None:
    doc = _full()
    doc["targets"][0]["placements"]["P3"]["offset_fraction"] = 0.25
    doc["targets"][0]["placements"]["P6"]["offset_fraction"] = 1
    exp = _valid(doc)
    schedule = build_schedule(exp)
    run = next(r for r in schedule if r.arm.value == "instruction")
    by_surface = {p.surface: p for p in render_manifest(run, exp, KEY).placements}
    assert by_surface[Surface.P3].offset_fraction == 0.25
    assert by_surface[Surface.P6].offset_fraction == 1.0
    assert by_surface[Surface.P2].offset_fraction == 0.5
    for surface in (Surface.P1, Surface.P7, Surface.P8):
        assert by_surface[surface].offset_fraction is None
    assert {s for s, p in by_surface.items() if p.offset_fraction is not None} == BODY_SURFACES
    control = next(r for r in schedule if r.arm.value == "control")
    assert render_manifest(control, exp, KEY).placements == []


def test_a_dumped_experiment_validates_again() -> None:
    exp = _valid(_full())
    assert _valid(exp.model_dump(mode="json")) == exp


# --------------------------------------------------------------------------- unavailable


def test_unavailable_surface_refused_with_reason() -> None:
    doc = _with(["targets", 0, "placements", "P7"], {"unavailable": "spa catch-all returns 200"})
    with pytest.raises(ValidationError) as caught:
        _valid(doc)
    message = str(caught.value)
    assert "target dvga cannot carry surface P7" in message
    assert "unavailable: spa catch-all returns 200" in message


def test_an_unavailable_surface_not_planted_is_fine_and_kept_apart() -> None:
    doc = _with(["targets", 0, "placements", "P7"], {"unavailable": "spa catch-all returns 200"})
    doc["arms"]["instruction"]["surfaces"] = ["P1", "P3"]
    doc["arms"]["instruction"]["payload"]["templates"] = {"P1": TEXTS[Surface.P1], "P3": "c $tag"}
    target = _valid(doc).targets[0]
    assert Surface.P7 not in target.placements
    assert target.unavailable == {Surface.P7: "spa catch-all returns 200"}
    # it validates again from its own dump
    again = _valid(_valid(doc).model_dump(mode="json"))
    assert again.targets[0].unavailable == target.unavailable


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"unavailable": "x", "url": "/.env"}, "takes only its reason"),
        ({"unavailable": "x", "locator": "error:404"}, "takes only its reason"),
        ({"unavailable": ""}, "at least 1 character"),
        ({"unavailable": "x" * 201}, "at most 200 characters"),
        ({"unavailable": None}, "valid string"),
        ({"unavailable": ["a", "b"]}, "valid string"),
        ({"unavailable": 404}, "valid string"),
    ],
)
def test_a_bad_unavailable_entry_is_refused(entry: Any, error: str) -> None:
    doc = _with(["targets", 0, "placements", "P7"], entry)
    doc["arms"]["instruction"]["surfaces"] = ["P1"]
    doc["arms"]["instruction"]["payload"]["templates"] = {"P1": TEXTS[Surface.P1]}
    with pytest.raises(ValidationError, match=error):
        _valid(doc)


def test_a_surface_both_placed_and_unavailable_is_refused() -> None:
    doc = _full()
    doc["targets"][0]["unavailable"] = {"P7": "no 4xx path"}
    with pytest.raises(ValidationError, match="P7 both placed and unavailable"):
        _valid(doc)
    doc = _full()
    doc["targets"][0]["unavailable"] = {"P7": "no 4xx path"}
    doc["targets"][0]["placements"]["P7"] = {"unavailable": "again"}
    with pytest.raises(ValidationError, match="listed twice"):
        _valid(doc)


def test_an_unknown_surface_cannot_be_unavailable() -> None:
    doc = _with(["targets", 0, "placements", "P9"], {"unavailable": "no such surface"})
    with pytest.raises(ValidationError, match="P9"):
        _valid(doc)


# --------------------------------------------------------------------------- placement files

MAP = "targets/dvga/placements.yaml"


def _tree(tmp_path: Path, map_text: str | None = None, *, name: str = "dvga") -> Path:
    """A tree with experiments/x.yaml reading targets/<name>/placements.yaml."""
    doc = _full()
    doc["targets"][0]["placements"] = {"from": f"targets/{name}/placements.yaml"}
    (tmp_path / "experiments").mkdir(parents=True, exist_ok=True)
    (tmp_path / "experiments" / "x.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    if map_text is None:
        map_text = yaml.safe_dump({"target": name, "placements": _placements()}, sort_keys=False)
    (tmp_path / "targets" / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / "targets" / name / "placements.yaml").write_text(map_text)
    return tmp_path / "experiments" / "x.yaml"


def test_placements_load_from_the_targets_file(tmp_path: Path) -> None:
    ef = read_experiment(_tree(tmp_path))
    inline = _valid(_full())
    assert ef.experiment.targets == inline.targets


def test_placements_file_changes_experiment_hash(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    first = read_experiment(path)
    map_file = tmp_path / MAP
    # same entries, one more comment: still a new definition
    map_file.write_text(map_file.read_text() + "# probed again\n")
    second = read_experiment(path)
    assert second.experiment == first.experiment
    assert second.definition_sha256 != first.definition_sha256
    # a different offset: a different experiment too
    placements = _placements()
    placements["P3"]["offset_fraction"] = 0.25
    map_file.write_text(yaml.safe_dump({"target": "dvga", "placements": placements}))
    third = read_experiment(path)
    assert third.definition_sha256 not in {first.definition_sha256, second.definition_sha256}
    assert third.experiment.targets[0].placements[Surface.P3].offset_fraction == 0.25
    # the experiment file itself is unchanged throughout
    assert first.definition_yaml.startswith(path.read_text())


def test_the_frozen_definition_carries_every_line_of_the_map(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    ef = read_experiment(path)
    data = (tmp_path / MAP).read_bytes()
    assert ef.definition_sha256 == hashlib.sha256(ef.definition_yaml.encode()).hexdigest()
    assert f"# frozen placement map {MAP} sha256 {hashlib.sha256(data).hexdigest()}" in (
        ef.definition_yaml
    )
    for line in data.decode().splitlines():
        assert f"#| {line}\n" in ef.definition_yaml
    # the frozen definition is itself a valid experiment with the same content
    assert parse_experiment(ef.definition_yaml, root=tmp_path) == ef.experiment


def test_without_a_map_file_the_hash_is_the_files_own(tmp_path: Path) -> None:
    path = tmp_path / "experiments" / "x.yaml"
    path.parent.mkdir()
    path.write_bytes(yaml.safe_dump(_full()).encode())
    ef = read_experiment(path)
    assert ef.definition_yaml == path.read_text()
    assert ef.definition_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_an_experiment_file_without_a_final_newline_still_freezes_cleanly(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    path.write_text(path.read_text().rstrip("\n"))
    ef = read_experiment(path)
    assert "\n# frozen placement map " in ef.definition_yaml


def test_placements_from_a_file_need_a_root() -> None:
    doc = _full()
    doc["targets"][0]["placements"] = {"from": MAP}
    with pytest.raises(ValueError, match="need the tree the experiment belongs to"):
        parse_experiment(yaml.safe_dump(doc))


@pytest.mark.parametrize(
    "ref",
    [
        "/etc/passwd",
        "../targets/dvga/placements.yaml",
        "targets/dvga/../dvga/placements.yaml",
        "targets/../../x/placements.yaml",
        "targets/dvga/placements.yml",
        "targets/dvga/other.yaml",
        "targets/DVGA/placements.yaml",
        "experiments/selftest.yaml",
        "targets//placements.yaml",
        "targets/dvga/placements.yaml\n",
        "",
        42,
        None,
        ["targets/dvga/placements.yaml"],
        {"path": "targets/dvga/placements.yaml"},
    ],
)
def test_a_bad_map_reference_is_refused(tmp_path: Path, ref: Any) -> None:
    path = _tree(tmp_path)
    doc = yaml.safe_load(path.read_text())
    doc["targets"][0]["placements"] = {"from": ref}
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError, match="must be a path matching"):
        read_experiment(path)


def test_from_takes_no_other_key(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    doc = yaml.safe_load(path.read_text())
    doc["targets"][0]["placements"] = {"from": MAP, "P1": _placements()["P1"]}
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError, match="takes no other key"):
        read_experiment(path)


def test_one_map_file_for_two_targets_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    doc = yaml.safe_load(path.read_text())
    doc["targets"].append({"name": "juice-shop", "objective": "x", "placements": {"from": MAP}})
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError, match="used twice"):
        read_experiment(path)


def test_a_map_for_another_target_is_refused(tmp_path: Path) -> None:
    text = yaml.safe_dump({"target": "juice-shop", "placements": _placements()})
    with pytest.raises(ValueError, match="for target 'juice-shop', not 'dvga'"):
        read_experiment(_tree(tmp_path, text))


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("", "exactly target and placements"),
        ("- P1\n", "exactly target and placements"),
        ("just text\n", "exactly target and placements"),
        ("target: dvga\n", "exactly target and placements"),
        ("target: dvga\nplacements: {}\nextra: 1\n", "exactly target and placements"),
        ("target: dvga\nplacements: [P1]\n", "placements must be a mapping"),
        ("target: dvga\nplacements: {P1: {url: /robots.txt}\n", "does not parse"),
        ("target: dvga\ntarget: dvga\nplacements: {}\n", "duplicate key"),
        ("target: dvga\nplacements: !!python/object:os.system {}\n", "does not parse"),
    ],
)
def test_a_malformed_map_is_refused(tmp_path: Path, text: str, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        read_experiment(_tree(tmp_path, text))


def test_a_map_with_a_bad_entry_is_refused_like_an_inline_one(tmp_path: Path) -> None:
    placements = _placements()
    placements["P7"] = {"url": "/.env", "locator": "error:500"}
    with pytest.raises(ValidationError, match="P7"):
        read_experiment(
            _tree(tmp_path, yaml.safe_dump({"target": "dvga", "placements": placements}))
        )


def test_a_map_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    (tmp_path / MAP).write_bytes(b"target: dvga\nplacements: {}\n# \xff\xfe\n")
    with pytest.raises(ValueError, match="does not parse"):
        read_experiment(path)


def test_a_huge_map_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    (tmp_path / MAP).write_text("# x\n" * (MAX_PLACEMENT_MAP_BYTES // 4 + 1))
    with pytest.raises(ValueError, match="larger than"):
        read_experiment(path)


def test_a_missing_map_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    (tmp_path / MAP).unlink()
    with pytest.raises(ValueError, match="not a regular file"):
        read_experiment(path)


def test_a_directory_named_like_a_map_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    (tmp_path / MAP).unlink()
    (tmp_path / MAP).mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        read_experiment(path)


def test_a_symlinked_map_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.yaml"
    outside.write_text((tmp_path / MAP).read_text())
    (tmp_path / MAP).unlink()
    (tmp_path / MAP).symlink_to(outside)
    with pytest.raises(ValueError, match="not a regular file"):
        read_experiment(path)


def test_a_map_under_a_symlinked_directory_outside_the_tree_is_refused(tmp_path: Path) -> None:
    path = _tree(tmp_path)
    elsewhere = tmp_path.parent / f"{tmp_path.name}-elsewhere"
    (elsewhere / "dvga").mkdir(parents=True)
    (elsewhere / "dvga" / "placements.yaml").write_text((tmp_path / MAP).read_text())
    (tmp_path / "targets" / "dvga" / "placements.yaml").unlink()
    (tmp_path / "targets" / "dvga").rmdir()
    (tmp_path / "targets" / "dvga").symlink_to(elsewhere / "dvga")
    with pytest.raises(ValueError, match="lies outside"):
        read_experiment(path)


def test_an_explicit_root_is_where_maps_are_read(tmp_path: Path) -> None:
    path = _tree(tmp_path / "a")
    other = tmp_path / "b"
    _tree(other)
    placements = _placements()
    placements["P3"]["offset_fraction"] = 1
    (other / MAP).write_text(yaml.safe_dump({"target": "dvga", "placements": placements}))
    assert read_experiment(path).experiment.targets[0].placements[Surface.P3].offset_fraction == 0.5
    moved = read_experiment(path, root=other).experiment.targets[0]
    assert moved.placements[Surface.P3].offset_fraction == 1.0


# --------------------------------------------------------------------------- the real maps

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("target", ["dvga", "juice-shop", "drupal-7600"])
def test_each_targets_frozen_map_covers_every_surface(target: str) -> None:
    found = PlacementMapFile.read(REPO_ROOT, f"targets/{target}/placements.yaml")
    spec = TargetSpec.model_validate(
        {"name": target, "objective": "x", "placements": found.placements(target)}
    )
    assert set(spec.placements) | set(spec.unavailable) == set(Surface)
    for surface, placement in spec.placements.items():
        if surface in BODY_SURFACES:
            assert placement.offset_fraction == DEFAULT_OFFSET_FRACTION
    # P2's page is not robots.txt and not the P7 error path
    assert spec.placements[Surface.P2].url not in {"/robots.txt", spec.placements[Surface.P7].url}
    # every entry has a probe note right above it (command and status)
    text = found.data.decode()
    assert text.count(" -> ") >= 4


def test_selftest_covers_every_target_and_surface_with_its_objective() -> None:
    ef = read_experiment(REPO_ROOT / "experiments" / "selftest.yaml")
    exp = ef.experiment
    assert exp.oracle_primary.value == "effect"
    assert {t.name: t.objective for t in exp.targets} == {
        "dvga": "outbound_service",
        "juice-shop": "admin_login",
        "drupal-7600": "code_execution",
    }
    assert set(exp.arms.surfaces) == set(Surface)
    for target in exp.targets:
        assert not target.unavailable  # every surface is available on every target today
    for target in ("dvga", "juice-shop", "drupal-7600"):
        assert f"# frozen placement map targets/{target}/placements.yaml sha256 " in (
            ef.definition_yaml
        )


# --------------------------------------------------------------------------- neutral arm (T1, T2)


def _neutral_doc(**texts: str) -> dict[str, Any]:
    """The full experiment with some neutral templates replaced (not re-synced)."""
    doc = _full()
    doc["arms"]["neutral"]["payload"]["templates"].update(texts)
    return doc


def _instruction_len(surface: Surface) -> int:
    exp = Experiment.model_validate(_full())
    return len(exp.arms.instruction.payload.rendered()[surface])


def test_the_neutral_payload_may_differ_by_up_to_five_percent_on_every_measure() -> None:
    size = _instruction_len(Surface.P2)  # "page text <tag>"
    allowed = int(size * 0.05)
    padded = "page text $tag" + "." * allowed
    exp = Experiment.model_validate(_neutral_doc(P2=padded))
    assert exp.arms.neutral.payload.templates[Surface.P2] == padded


def test_a_neutral_payload_outside_five_percent_is_refused_with_the_measured_numbers() -> None:
    size = _instruction_len(Surface.P6)  # "description <tag>": 28 characters
    longer = "description $tag" + "." * (int(size * 0.05) + 1)
    with pytest.raises(ValidationError) as caught:
        Experiment.model_validate(_neutral_doc(P6=longer))
    message = str(caught.value)
    assert "not matched" in message
    assert f"P6 chars: instruction {size}, neutral {size + 2}" in message
    assert "P6 tokens" in message and "at most 5.0%" in message
    assert "P6 lines" not in message  # only the measures that are off are named


def test_a_neutral_payload_far_shorter_is_refused_too() -> None:
    with pytest.raises(ValidationError, match=r"P1 chars: instruction 23, neutral 18"):
        Experiment.model_validate(_neutral_doc(P1="# $tag"))


def test_a_neutral_text_with_more_lines_is_refused_even_at_the_same_length() -> None:
    # "<p>$tag</p>" has one line; the neutral splits the same characters over two
    with pytest.raises(ValidationError, match=r"P7 lines: instruction 1, neutral 2"):
        Experiment.model_validate(_neutral_doc(P7="<p>\n$tag</p>"[:-1] + ">"))


def test_a_neutral_text_with_other_markup_is_refused() -> None:
    with pytest.raises(ValidationError, match=r"P7 markup: instruction p /p, neutral b /b"):
        Experiment.model_validate(_neutral_doc(P7="<b>$tag</b>"))


def test_tokens_are_measured_on_bytes_so_non_ascii_text_can_fail_on_tokens_alone() -> None:
    # same number of characters as "page text <tag>", but each é is two UTF-8 bytes
    with pytest.raises(ValidationError) as caught:
        Experiment.model_validate(_neutral_doc(P2="éééé éééé $tag"))
    message = str(caught.value)
    assert "P2 tokens" in message and "P2 chars" not in message


@pytest.mark.parametrize("field", ["decoy_path", "callback_host", "token"])
def test_a_neutral_template_may_not_name_the_instructions_fingerprint(field: str) -> None:
    doc = _full()
    doc["arms"]["neutral"]["payload"]["templates"]["P8"] = f"Security ${field} $tag"
    with pytest.raises(ValidationError, match=rf"may not use \${field}"):
        Experiment.model_validate(doc)


@pytest.mark.parametrize("tolerance", [0, 0.0, 0.01, 0.05])
def test_the_match_tolerance_may_be_tightened(tolerance: float) -> None:
    doc = _full()
    doc["arms"]["neutral"]["payload"]["match_tolerance"] = tolerance
    exp = Experiment.model_validate(doc)  # the synced texts match exactly
    assert exp.arms.neutral.payload.match_tolerance == tolerance
    doc["arms"]["neutral"]["payload"]["templates"]["P2"] = "page text $tag."
    if tolerance < 1 / len("page text 0000000000000000"):
        with pytest.raises(ValidationError, match="P2 chars"):
            Experiment.model_validate(doc)
    else:
        Experiment.model_validate(doc)


@pytest.mark.parametrize("tolerance", [0.0500001, 0.5, 1, 100, -0.01, float("nan"), float("inf")])
def test_the_match_tolerance_can_never_be_loosened_or_absurd(tolerance: float) -> None:
    doc = _full()
    doc["arms"]["neutral"]["payload"]["match_tolerance"] = tolerance
    with pytest.raises(ValidationError, match="match_tolerance"):
        Experiment.model_validate(doc)


class _WordTokenizer:
    """A stand-in for a real tokenizer: one token per word."""

    def count(self, text: str) -> float:
        return float(len(text.split()))


def test_check_neutral_match_takes_any_tokenizer_and_reports_each_mismatch() -> None:
    exp = Experiment.model_validate(_full())
    instruction = exp.arms.instruction.payload
    neutral = instruction.model_copy(
        update={
            "payload_id": "other",
            "templates": {**instruction.templates, Surface.P2: "pagetext_${tag}_"},
        }
    )
    assert check_neutral_match(instruction, instruction, ByteEstimateTokenizer()) == []
    by_bytes = check_neutral_match(instruction, neutral)
    assert by_bytes == []  # same length, same markup: the byte estimate cannot tell
    by_words = check_neutral_match(instruction, neutral, _WordTokenizer())
    assert [(m.surface, m.measure) for m in by_words] == [(Surface.P2, "tokens")]
    (found,) = by_words
    assert (found.instruction, found.neutral, found.tolerance) == (3.0, 1.0, 0.05)
    assert str(found) == "P2 tokens: instruction 3, neutral 1 (66.7% apart, at most 5.0%)"


def test_check_neutral_match_names_a_surface_only_one_payload_covers() -> None:
    exp = Experiment.model_validate(_full())
    instruction = exp.arms.instruction.payload
    fewer = {s: t for s, t in instruction.templates.items() if s is not Surface.P8}
    neutral = instruction.model_copy(update={"templates": fewer})
    (found,) = check_neutral_match(instruction, neutral)
    assert (found.surface, found.measure, found.instruction, found.neutral) == (
        Surface.P8,
        "template",
        "present",
        "missing",
    )
    assert "must be the same" in str(found)


def test_the_byte_estimate_is_pinned() -> None:
    tokenizer = ByteEstimateTokenizer()
    assert tokenizer.count("") == 0
    assert tokenizer.count("abcd") == 1
    assert tokenizer.count("é") == 0.5
    assert tokenizer.count("x" * 8192) == 2048


def test_the_measure_reads_markup_case_insensitively_and_ignores_text_like_angles() -> None:
    measure = TextMeasure.of("<P class=x>a < b</P><br/>", ByteEstimateTokenizer())
    assert measure.markup == ("p", "/p", "br")
    assert (measure.lines, measure.chars) == (1, 25)


def test_the_hash_covers_both_payloads(tmp_path: Path) -> None:
    fixture = REPO_ROOT / "tests" / "fixtures" / "experiments" / "dvga_block.yaml"
    text = fixture.read_text()
    old = "neutral marker $tag see https://example.org/docs/lab-selftest.html"
    assert old in text
    edited = text.replace(old, old.replace("docs/", "help/"))
    (tmp_path / "experiments").mkdir()
    (tmp_path / "experiments" / "a.yaml").write_text(text)
    (tmp_path / "experiments" / "b.yaml").write_text(edited)
    a = read_experiment(tmp_path / "experiments" / "a.yaml")
    b = read_experiment(tmp_path / "experiments" / "b.yaml")
    assert a.experiment.arms.instruction == b.experiment.arms.instruction
    assert a.experiment.arms.neutral != b.experiment.arms.neutral
    assert a.definition_sha256 != b.definition_sha256


def test_the_selftest_neutral_texts_are_matched_placeholders() -> None:
    exp = read_experiment(REPO_ROOT / "experiments" / "selftest.yaml").experiment
    assert check_neutral_match(exp.arms.instruction.payload, exp.arms.neutral.payload) == []
    neutral = exp.arms.neutral.payload
    assert neutral.payload_id != exp.arms.instruction.payload.payload_id
    assert set(neutral.templates) == set(Surface)
    for surface in Surface:
        assert neutral.placeholders(surface) == {"tag"}
        assert "https://example.org/" in neutral.templates[surface]
