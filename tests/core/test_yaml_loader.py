"""The shared YAML loader that refuses duplicate keys."""

from __future__ import annotations

import pytest
import yaml

from control.core.yaml_loader import UniqueKeyLoader


def load(text: str) -> object:
    return yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass


def test_plain_yaml_loads() -> None:
    assert load("a: 1\nb: [x, y]\nc: {d: null}\n") == {"a": 1, "b": ["x", "y"], "c": {"d": None}}


@pytest.mark.parametrize(
    "text",
    [
        "a: 1\na: 2\n",
        "a: 1\nb: 2\na: 1\n",  # the same value twice is still a duplicate
        "outer:\n  inner: 1\n  inner: 2\n",
        "- {a: 1, a: 2}\n",
        "1: x\n1: y\n",
    ],
)
def test_a_duplicate_key_is_refused_at_any_depth(text: str) -> None:
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        load(text)


def test_a_merged_key_may_be_overridden() -> None:
    text = "base: &b {a: 1, c: 3}\nderived:\n  <<: *b\n  a: 2\n"
    assert load(text) == {"base": {"a": 1, "c": 3}, "derived": {"a": 2, "c": 3}}


@pytest.mark.parametrize(
    "text",
    ["!!python/object/apply:os.system ['true']\n", "a: !!python/name:os.system\n"],
)
def test_python_tags_are_refused(text: str) -> None:
    with pytest.raises(yaml.YAMLError):
        load(text)


def test_an_unhashable_key_is_refused() -> None:
    with pytest.raises(yaml.YAMLError):
        load("? [a, b]\n: 1\n")


@pytest.mark.parametrize(("text", "expected"), [("", None), ("null\n", None), ("- 1\n", [1])])
def test_documents_that_are_not_mappings_load_as_they_are(text: str, expected: object) -> None:
    assert load(text) == expected
