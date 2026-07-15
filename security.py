"""Windows DPAPI helpers. Secrets can only be decrypted by the current user."""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect(text: str) -> str:
    if not text:
        return ""
    source, source_buffer = _blob(text.encode("utf-8"))
    result = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "StarStack Cascade Monitor", None, None, None, 0,
        ctypes.byref(result),
    ):
        raise ctypes.WinError()
    try:
        raw = ctypes.string_at(result.pbData, result.cbData)
        return base64.b64encode(raw).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)


def unprotect(encoded: str) -> str:
    if not encoded:
        return ""
    source, source_buffer = _blob(base64.b64decode(encoded))
    result = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(result)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.pbData, result.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)
