"""A safe YAML loader that refuses duplicate keys.

PyYAML's safe loader keeps the last of two equal keys without a word, so a hand-edited
file can say one thing and mean another. :class:`UniqueKeyLoader` refuses such a file
instead. It lives in ``control.core`` so that both the runner and the agent adapters can
use it without importing each other.

``control.runner.experiment`` still has its own private copy of this loader; the two
are merged when the runner is wired to the adapters.
"""

from __future__ import annotations

from typing import Any

import yaml

__all__ = ["UniqueKeyLoader"]


class UniqueKeyLoader(yaml.SafeLoader):
    """A safe YAML loader that refuses duplicate keys in any mapping.

    Use it as ``yaml.load(text, Loader=UniqueKeyLoader)``. A duplicate key raises
    :class:`yaml.constructor.ConstructorError` (a :class:`yaml.YAMLError`). ``<<``
    merges are allowed, and an explicit key overrides a merged one, as YAML says.
    """

    def construct_unique_mapping(self, node: yaml.MappingNode) -> dict[Any, Any]:
        seen: list[Any] = []
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                hash(key)
            except TypeError:  # e.g. a list as a key: report it as a YAML error too
                problem = f"found unhashable key {key!r}"
            else:
                problem = f"found duplicate key {key!r}" if key in seen else ""
            if problem:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping", node.start_mark, problem, key_node.start_mark
                )
            seen.append(key)
        self.flatten_mapping(node)
        return dict(self.construct_pairs(node, deep=True))


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    UniqueKeyLoader.construct_unique_mapping,
)
