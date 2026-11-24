"""Experiment validation for surfaces P2-P6 and P8: locators, offsets and texts."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from cell.injector.placement import BODY_SURFACES, SURFACE_LOCATORS
from control.core.models import Surface
from control.runner.experiment import (
    DEFAULT_OFFSET_FRACTION,
    SUPPORTED_SURFACES,
    Experiment,
    PlacementSpec,
)
from control.runner.render import render_manifest
from control.runner.schedule import build_schedule
from tests.runner.test_pairing import KEY, _doc

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
    doc["targets"] = [{"name": "dvga", "placements": _placements()}]
    doc["arms"]["injected"]["surfaces"] = [s.value for s in ALL]
    doc["arms"]["injected"]["payload"]["templates"] = {s.value: t for s, t in TEXTS.items()}
    doc.update(changes)
    return doc


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
    exp = Experiment.model_validate(_full())
    spec = exp.targets[0].placements[Surface.P3]
    assert spec.offset_fraction == DEFAULT_OFFSET_FRACTION == 0.5


@pytest.mark.parametrize("surface", sorted(SURFACE_LOCATORS))
def test_a_wrong_locator_is_refused(surface: Surface) -> None:
    doc = _with(["targets", 0, "placements", surface.value, "locator"], "html:other")
    with pytest.raises(ValidationError, match="locator must be"):
        Experiment.model_validate(doc)


@pytest.mark.parametrize("surface", [Surface.P2, Surface.P3, Surface.P6, Surface.P8])
def test_only_p1_may_use_robots_txt(surface: Surface) -> None:
    doc = _with(["targets", 0, "placements", surface.value, "url"], "/robots.txt")
    with pytest.raises(ValidationError, match="robots"):
        Experiment.model_validate(doc)


@pytest.mark.parametrize("value", [0, 0.0, 0.25, 0.5, 1, 1.0])
def test_offset_fraction_accepts_the_closed_unit_interval(value: float) -> None:
    exp = Experiment.model_validate(_offset(Surface.P4, value))
    assert exp.targets[0].placements[Surface.P4].offset_fraction == value


@pytest.mark.parametrize(
    "value", [-0.01, 1.01, 2, float("nan"), float("inf"), "0.5", True, None, [0.5]]
)
def test_offset_fraction_refuses_anything_else(value: Any) -> None:
    with pytest.raises(ValidationError):
        Experiment.model_validate(_offset(Surface.P4, value))


# A dumped experiment carries the default 0.5 on every placement, so only a changed value counts.


@pytest.mark.parametrize("surface", [Surface.P1, Surface.P7, Surface.P8])
def test_offset_fraction_is_for_p2_to_p6_only(surface: Surface) -> None:
    with pytest.raises(ValidationError, match="P2-P6 only"):
        Experiment.model_validate(_offset(surface, 0.25))


def test_placement_spec_defaults_and_rejects_unknown_fields() -> None:
    assert PlacementSpec(url="/p", locator="html:body").offset_fraction == 0.5
    with pytest.raises(ValidationError):
        PlacementSpec.model_validate({"url": "/p", "locator": "html:body", "offset": 0.5})


def test_an_experiment_needs_a_placement_for_each_new_surface() -> None:
    doc = _full()
    del doc["targets"][0]["placements"]["P6"]
    with pytest.raises(ValidationError, match="no placement for surface P6"):
        Experiment.model_validate(doc)


# --------------------------------------------------------------------------- texts


def _p8(text: str, **changes: Any) -> dict[str, Any]:
    doc = _full(**changes)
    doc["arms"]["injected"]["payload"]["templates"]["P8"] = text
    return doc


def test_p8_template_must_be_single_line_printable_ascii() -> None:
    Experiment.model_validate(_p8("Notice: $tag, see $decoy_path and $callback_host"))
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
            Experiment.model_validate(_p8(bad))


def test_p8_template_is_checked_once_rendered() -> None:
    fits = "x" * (512 - 16 - 1) + " $tag"  # the tag renders to 16 bytes: exactly 512
    Experiment.model_validate(_p8(fits))
    with pytest.raises(ValidationError, match="512"):
        Experiment.model_validate(_p8("x" + fits))
    # $callback_host is <12-char token>.<callback_domain>: a long zone can push it over
    host = "$callback_host $tag " + "y" * 420
    Experiment.model_validate(_p8(host))
    zone = ".".join(["a" * 60] * 3) + ".test"
    with pytest.raises(ValidationError, match="512"):
        Experiment.model_validate(_p8(host, callback_domain=zone))


def test_p3_template_cannot_close_its_comment() -> None:
    doc = _full()
    doc["arms"]["injected"]["payload"]["templates"]["P3"] = "x --> <script> $tag"
    with pytest.raises(ValidationError, match="P3"):
        Experiment.model_validate(doc)


def test_templates_for_html_surfaces_may_hold_markup_like_text() -> None:
    doc = _full()
    for surface in ("P2", "P4", "P5", "P6"):
        doc["arms"]["injected"]["payload"]["templates"][surface] = "</div><b>x</b> & $tag"
    Experiment.model_validate(doc)


# --------------------------------------------------------------------------- manifest


def test_the_manifest_carries_the_registered_offset_for_in_page_surfaces() -> None:
    doc = _full()
    doc["targets"][0]["placements"]["P3"]["offset_fraction"] = 0.25
    doc["targets"][0]["placements"]["P6"]["offset_fraction"] = 1
    exp = Experiment.model_validate(doc)
    schedule = build_schedule(exp)
    run = next(r for r in schedule if r.arm.value == "injected")
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
    exp = Experiment.model_validate(_full())
    assert Experiment.model_validate(exp.model_dump(mode="json")) == exp
