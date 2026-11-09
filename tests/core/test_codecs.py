"""Bounded Content-Encoding decoding (used by the labeller on untrusted request bytes)."""

from __future__ import annotations

import gzip
import tomllib
import zlib
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from control.core.codecs import DecodedTooLargeError, decode_body, decode_body_bounded

DATA = b'{"messages":[{"role":"user","content":"hello"}]}' * 50
BOMB = b"\0" * 2_000_000
LIMIT = 100_000


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def _encoders() -> dict[str, object]:
    encoders: dict[str, object] = {
        "gzip": gzip.compress,
        "x-gzip": gzip.compress,
        "deflate": zlib.compress,
        "identity": lambda b: b,
    }
    try:
        import brotli

        encoders["br"] = brotli.compress
    except ImportError:  # pragma: no cover
        pass
    try:
        from backports import zstd

        encoders["zstd"] = zstd.compress
    except ImportError:  # pragma: no cover
        pass
    return encoders


@pytest.mark.parametrize("encoding", sorted(_encoders()))
def test_bounded_decode_matches_unbounded_within_limit(encoding: str) -> None:
    encode = _encoders()[encoding]
    wire = encode(DATA)  # type: ignore[operator]
    assert decode_body_bounded(wire, encoding, max_size=LIMIT) == decode_body(wire, encoding)
    assert decode_body_bounded(wire, encoding, max_size=len(DATA)) == DATA


@pytest.mark.parametrize("encoding", sorted(_encoders()))
def test_bounded_decode_refuses_output_over_limit(encoding: str) -> None:
    encode = _encoders()[encoding]
    wire = encode(BOMB)  # type: ignore[operator]
    with pytest.raises(DecodedTooLargeError):
        decode_body_bounded(wire, encoding, max_size=LIMIT)


def test_gzip_bomb_with_bad_trailer_hits_the_limit_before_the_trailer() -> None:
    wire = gzip.compress(BOMB)
    wire = wire[:-8] + b"\xff" * 8  # bad CRC/size: an unbounded decoder fails only at the end
    assert decode_body(wire, "gzip") is None
    with pytest.raises(DecodedTooLargeError):
        decode_body_bounded(wire, "gzip", max_size=LIMIT)


def test_raw_deflate_without_zlib_wrapper() -> None:
    assert decode_body_bounded(_raw_deflate(DATA), "deflate", max_size=LIMIT) == DATA
    with pytest.raises(DecodedTooLargeError):
        decode_body_bounded(_raw_deflate(BOMB), "deflate", max_size=LIMIT)


def test_multi_member_gzip() -> None:
    wire = gzip.compress(b"abc") + gzip.compress(b"def")
    assert decode_body_bounded(wire, "gzip", max_size=LIMIT) == b"abcdef"
    with pytest.raises(DecodedTooLargeError):
        decode_body_bounded(wire, "gzip", max_size=5)


@pytest.mark.parametrize(
    ("wire", "encoding"),
    [
        (b"not gzip", "gzip"),
        (gzip.compress(DATA)[:-10], "gzip"),
        (b"\x00\x01garbage", "deflate"),
        (gzip.compress(DATA), "x-unknown"),
        (gzip.compress(DATA), "gzip, br"),
        (b"not brotli", "br"),
        (b"not zstd", "zstd"),
    ],
)
def test_bounded_decode_returns_none_when_undecodable(wire: bytes, encoding: str) -> None:
    assert decode_body_bounded(wire, encoding, max_size=LIMIT) is None


def test_identity_over_limit() -> None:
    with pytest.raises(DecodedTooLargeError):
        decode_body_bounded(b"x" * 11, None, max_size=10)


def test_br_and_zstd_decoders_are_base_dependencies() -> None:
    """The labeller runs in labctl's venv, installed without the ``cell`` extra: brotli and
    a zstd module must come from the base dependencies, not only via mitmproxy."""
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    deps = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
    by_name = {Requirement(d).name: Requirement(d) for d in deps}
    assert "brotli" in by_name
    assert by_name["brotli"].specifier.contains("1.2.0")
    assert not by_name["brotli"].specifier.contains("1.1.0")
    assert "backports-zstd" in by_name
    marker = by_name["backports-zstd"].marker
    assert marker is not None
    assert marker.evaluate({"python_version": "3.12"})
    assert not marker.evaluate({"python_version": "3.14"})  # compression.zstd there
