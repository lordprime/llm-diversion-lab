"""Content-Encoding codecs shared by the surface injector and the funnel labeller.

Pure functions with no I/O and no mitmproxy dependency. Supported encodings:
identity/none, ``gzip``, ``x-gzip``, ``deflate`` (zlib-wrapped or raw), ``br`` and
``zstd``. ``br`` needs the ``brotli`` module and ``zstd`` needs ``compression.zstd``
or ``backports.zstd``; where a module is missing that encoding is simply unsupported
(the functions return ``None``). Stacked encodings (``gzip, br``) are not supported.

:func:`decode_body` (used by the injector on the app's own responses) has no output
limit. :func:`decode_body_bounded` is for untrusted bytes (the labeller decoding agent
requests the tap stored raw): it decodes incrementally and raises
:class:`DecodedTooLargeError` as soon as the output would exceed ``max_size``, so a
compression bomb is never expanded in memory.
"""

from __future__ import annotations

import gzip
import importlib
import zlib
from collections.abc import Callable, Mapping
from types import ModuleType
from typing import Final

__all__ = ["DecodedTooLargeError", "decode_body", "decode_body_bounded", "encode_body"]


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


def _encoding_name(encoding: str | None) -> str:
    return (encoding or "").strip().lower() or "identity"


def _codec(encoding: str | None) -> _Codec | None:
    return _CODECS.get(_encoding_name(encoding))


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


# --------------------------------------------------------------------------- bounded decoding


class DecodedTooLargeError(ValueError):
    """Decoding would produce more than the allowed number of bytes."""


class _UndecodableError(Exception):
    """Truncated or otherwise incomplete encoded data."""


def _check_size(out: bytearray | bytes, max_size: int) -> None:
    if len(out) > max_size:
        raise DecodedTooLargeError(f"decoded body exceeds {max_size} bytes")


def _zlib_bounded(data: bytes, wbits: int, max_size: int, *, members: bool) -> bytes:
    """Decode a zlib/gzip/raw-deflate stream (``members``: several gzip members)."""
    out = bytearray()
    while True:
        d = zlib.decompressobj(wbits)
        out += d.decompress(data, max_size - len(out) + 1)
        _check_size(out, max_size)
        if not d.eof:
            raise _UndecodableError("truncated stream")
        data = d.unused_data
        if not members or not data.strip(b"\0"):
            return bytes(out)


def _br_bounded(data: bytes, max_size: int) -> bytes:
    d = _brotli().Decompressor()
    out = bytearray(d.process(data, output_buffer_limit=max_size + 1))
    _check_size(out, max_size)
    while not d.is_finished() and not d.can_accept_more_data():
        chunk = d.process(b"", output_buffer_limit=max_size - len(out) + 1)
        if not chunk:
            break
        out += chunk
        _check_size(out, max_size)
    if not d.is_finished():
        raise _UndecodableError("truncated brotli stream")
    return bytes(out)


def _zstd_bounded(data: bytes, max_size: int) -> bytes:
    mod = _zstd()
    out = bytearray()
    while True:
        d = mod.ZstdDecompressor()
        out += d.decompress(data, max_length=max_size - len(out) + 1)
        _check_size(out, max_size)
        if not d.eof:
            raise _UndecodableError("truncated zstd frame")
        data = d.unused_data
        if not data:
            return bytes(out)


def decode_body_bounded(body: bytes, encoding: str | None, *, max_size: int) -> bytes | None:
    """Like :func:`decode_body`, but never produces more than ``max_size`` bytes.

    Returns the decoded bytes, or ``None`` if the encoding is unsupported or the data is
    corrupt or truncated. Raises :class:`DecodedTooLargeError` if the decoded output
    would exceed ``max_size`` (checked before any trailer, so a bomb with a bad CRC is
    reported as too large, not as corrupt).
    """
    name = _encoding_name(encoding)
    try:
        if name == "identity":
            out = body
        elif name in ("gzip", "x-gzip"):
            out = _zlib_bounded(body, 16 + zlib.MAX_WBITS, max_size, members=True)
        elif name == "deflate":
            try:
                out = _zlib_bounded(body, zlib.MAX_WBITS, max_size, members=False)
            except (zlib.error, _UndecodableError):  # raw deflate, no zlib wrapper
                out = _zlib_bounded(body, -zlib.MAX_WBITS, max_size, members=False)
        elif name == "br":
            out = _br_bounded(body, max_size)
        elif name == "zstd":
            out = _zstd_bounded(body, max_size)
        else:
            return None
    except DecodedTooLargeError:
        raise
    except Exception:  # any codec failure, or a codec module that is unavailable
        return None
    _check_size(out, max_size)
    return out
