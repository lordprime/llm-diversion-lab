"""Content-Encoding codecs shared by the surface injector and the funnel labeller.

Pure functions with no I/O and no mitmproxy dependency. Supported encodings:
identity/none, ``gzip``, ``x-gzip``, ``deflate`` (zlib-wrapped or raw), ``br`` and
``zstd``. ``br`` needs the ``brotli`` module and ``zstd`` needs ``compression.zstd``
or ``backports.zstd``; where a module is missing that encoding is simply unsupported
(the functions return ``None``). Stacked encodings (``gzip, br``) are not supported.
"""

from __future__ import annotations

import gzip
import importlib
import zlib
from collections.abc import Callable, Mapping
from types import ModuleType
from typing import Final

__all__ = ["decode_body", "encode_body"]


def _module(*names: str) -> ModuleType | None:
    for name in names:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


def _brotli() -> ModuleType:
    mod = _module("brotli")
    if mod is None:
        raise ValueError("brotli is not available")
    return mod


def _zstd() -> ModuleType:
    mod = _module("compression.zstd", "backports.zstd")
    if mod is None:
        raise ValueError("zstd is not available")
    return mod


def _identity(data: bytes) -> bytes:
    return data


def _gzip_encode(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _deflate_decode(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:  # some servers send raw deflate without the zlib wrapper
        return zlib.decompress(data, -zlib.MAX_WBITS)


def _br_decode(data: bytes) -> bytes:
    out: bytes = _brotli().decompress(data)
    return out


def _br_encode(data: bytes) -> bytes:
    out: bytes = _brotli().compress(data)
    return out


def _zstd_decode(data: bytes) -> bytes:
    out: bytes = _zstd().decompress(data)
    return out


def _zstd_encode(data: bytes) -> bytes:
    out: bytes = _zstd().compress(data)
    return out


_Codec = tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]]
_CODECS: Final[Mapping[str, _Codec]] = {
    "identity": (_identity, _identity),
    "gzip": (gzip.decompress, _gzip_encode),
    "x-gzip": (gzip.decompress, _gzip_encode),
    "deflate": (_deflate_decode, zlib.compress),
    "br": (_br_decode, _br_encode),
    "zstd": (_zstd_decode, _zstd_encode),
}


def _codec(encoding: str | None) -> _Codec | None:
    name = (encoding or "").strip().lower() or "identity"
    return _CODECS.get(name)


def decode_body(body: bytes, encoding: str | None) -> bytes | None:
    """``body`` with Content-Encoding ``encoding`` removed, or ``None`` if impossible.

    Supported: identity/none, ``gzip``, ``x-gzip``, ``deflate``, ``br``, ``zstd``.
    Stacked encodings (``gzip, br``) are not supported.
    """
    codec = _codec(encoding)
    if codec is None:
        return None
    try:
        return codec[0](body)
    except Exception:  # any codec failure
        return None


def encode_body(decoded: bytes, encoding: str | None) -> bytes | None:
    """``decoded`` encoded with Content-Encoding ``encoding``, or ``None`` if impossible.

    The result is checked by decoding it again.
    """
    codec = _codec(encoding)
    if codec is None:
        return None
    try:
        wire = codec[1](decoded)
        return wire if codec[0](wire) == decoded else None
    except Exception:  # any codec failure
        return None
