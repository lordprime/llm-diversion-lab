"""Format of ``deploy/images.lock``: the logical image name -> pinned digest map.

Cells start images only by digest, so every entry must name a repository, carry a
``sha256:`` digest and list the tools a smoke check expects inside the image.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

LOCK_FILE = Path(__file__).resolve().parents[2] / "deploy" / "images.lock"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _entries() -> list[dict[str, Any]]:
    data = yaml.safe_load(LOCK_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "images.lock must be a mapping with an `images` list"
    images = data.get("images")
    assert isinstance(images, list), "images.lock must have an `images` list"
    assert images, "images.lock must have at least one entry"
    return images


def test_lock_file_parses() -> None:
    assert LOCK_FILE.is_file(), f"missing {LOCK_FILE}"
    _entries()


@pytest.mark.parametrize("index", range(len(_entries()) if LOCK_FILE.is_file() else 0))
def test_entry_format(index: int) -> None:
    entry = _entries()[index]
    assert isinstance(entry, dict), f"entry {index} is not a mapping"

    name = entry.get("name")
    assert isinstance(name, str), f"entry {index}: `name` must be a string"
    assert NAME_RE.match(name), f"entry {index}: bad name {name!r}"

    image = entry.get("image")
    assert isinstance(image, str), f"{name}: `image` (repository) must be a string"
    assert image, f"{name}: `image` must not be empty"
    assert "@" not in image, f"{name}: `image` is the repository; the digest goes in `digest`"
    assert ":" not in image.rsplit("/", 1)[-1], f"{name}: `image` must not carry a tag"

    digest = entry.get("digest")
    assert isinstance(digest, str), f"{name}: `digest` must be a string"
    assert DIGEST_RE.match(digest), f"{name}: digest {digest!r} is not sha256: + 64 hex"

    tools = entry.get("expect_tools")
    assert isinstance(tools, list), f"{name}: `expect_tools` must be a list"
    assert all(isinstance(t, str) and t for t in tools), f"{name}: tools must be names"
    assert len(set(tools)) == len(tools), f"{name}: duplicate tools"


def test_names_are_unique() -> None:
    names = [e.get("name") for e in _entries()]
    assert len(names) == len(set(names)), f"duplicate names in images.lock: {names}"
