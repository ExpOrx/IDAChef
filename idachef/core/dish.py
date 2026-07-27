# -*- coding: utf-8 -*-
"""
Dish
====
CyberChef passes data between operations wrapped in a "Dish" object that
knows how to present the same underlying data as a string, byte array,
number, etc. (src/core/Dish.mjs).

IDAChef keeps things simple: the recipe's canonical currency is `bytes`.
This module just provides safe, best-effort conversions in/out of that
canonical form so operations (and the UI) don't have to worry about
encoding errors blowing up the whole chain.
"""


def to_bytes(data):
    """Coerce whatever we have (str, bytes, bytearray, int, None) to bytes."""
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        try:
            return data.encode("utf-8")
        except UnicodeEncodeError:
            return data.encode("utf-8", errors="surrogateescape")
    if isinstance(data, int):
        return str(data).encode("utf-8")
    return str(data).encode("utf-8", errors="replace")


def to_str(data):
    """Best-effort readable text representation of bytes for display."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray)):
        try:
            return bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(data).decode("latin-1")
    return str(data)


class DishError(Exception):
    """Raised when an operation cannot make sense of its input."""
    pass