# -*- coding: utf-8 -*-
"""
Common utility functions used across operations.
Extracted to eliminate duplication across operation modules.
"""

import base64 as _b64
import binascii
import re


def text_from_data(data):
    """Decode bytes to string (UTF-8, with replacement for bad chars)."""
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def text_from_data_ignore(data):
    """Decode bytes to string (UTF-8, ignoring bad chars)."""
    if not data:
        return ""
    return data.decode("utf-8", errors="ignore")


def key_bytes(key_str, fmt="Hex"):
    """Parse a key string into bytes according to format.

    Formats: Hex, UTF8, Base64
    """
    key_str = (key_str or "").strip()
    if fmt == "Hex":
        clean = re.sub(r"[^0-9a-fA-F]", "", key_str)
        if not clean:
            return b""
        if len(clean) % 2 != 0:
            clean = "0" + clean
        return binascii.unhexlify(clean)
    if fmt == "Base64":
        if not key_str:
            return b""
        return _b64.b64decode(key_str + "=" * (-len(key_str) % 4))
    return key_str.encode("utf-8")


def bytewise_op(data, operand, fn, pad_shorter=True):
    """Apply fn(b, o) for each byte b in data, cycling operand.

    If pad_shorter=False and operand is shorter than data, remaining
    bytes pass through unchanged.
    """
    if not operand:
        return data
    out = bytearray()
    for i, b in enumerate(data):
        o = operand[i % len(operand)] if pad_shorter else (
            operand[i] if i < len(operand) else b
        )
        out.append(fn(b, o) & 0xFF)
    return bytes(out)


def parse_numbers(text):
    """Extract float/int numbers from a text string. Returns list."""
    tokens = re.findall(r"-?\d+(?:\.\d+)?", text)
    return [float(t) if "." in t else int(t) for t in tokens]


def fmt_num(n):
    """Format a number: drop .0 for integers."""
    if isinstance(n, float) and n.is_integer():
        n = int(n)
    return str(n)