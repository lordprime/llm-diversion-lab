"""Finding a run's tag in evidence: request bodies and the tag-derived decoy path.

Shared by the cell (the LLM tap and the surface injector) and the control plane (the
funnel labeller), so both apply exactly the same rules. Pure functions with no I/O and
no mitmproxy dependency.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit

from pydantic import JsonValue

__all__ = [
    "decoy_prefix",
    "find_tags",
    "json_strings",
    "parse_json",
    "request_path",
    "under_decoy",
]


def parse_json(body: bytes) -> JsonValue | None:
    """Parse ``body`` as JSON, or return ``None`` (not JSON, bad encoding, too deep)."""
    if not body:
        return None
    try:
        doc: JsonValue = json.loads(body)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        return None
    return doc


def json_strings(doc: JsonValue) -> Iterator[str]:
    """Yield every string in a parsed JSON document: values and object keys."""
    stack: list[JsonValue] = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield key
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def find_tags(body: bytes, tags: Iterable[str]) -> bool:
    """Return whether any of ``tags`` occurs in a request ``body``.

    Tags are matched exactly as given (case-sensitive). The raw bytes are always
    searched. In addition, if ``body`` parses as JSON, every string in it (object keys
    included) is searched *after* JSON decoding, so a tag sent as ``\\u0061...``
    escapes is still found. The raw search covers what parsing hides: a tag in an
    earlier duplicate key (``json.loads`` keeps the last) or inside a JSON number.
    """
    wanted = [t for t in tags if t]
    if not wanted or not body:
        return False
    if any(t.encode("utf-8") in body for t in wanted):
        return True
    doc = parse_json(body)
    return doc is not None and any(t in s for s in json_strings(doc) for t in wanted)


def request_path(target: str) -> str:
    """The path of a request target or URL, without query string or fragment."""
    if target.startswith("/"):
        path = target.partition("?")[0].partition("#")[0]
    else:
        path = urlsplit(target).path
    return path or "/"


def decoy_prefix(tag: str) -> str:
    """The decoy path of a run: ``/x-<tag>``."""
    return f"/x-{tag}"


def under_decoy(path: str, prefix: str) -> bool:
    """Whether ``path`` (no query string) is the decoy path ``prefix`` or lies below it."""
    return path == prefix or path.startswith(prefix + "/")
