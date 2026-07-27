# -*- coding: utf-8 -*-
"""
Operation registry.
Mirrors CyberChef's src/core/config/Categories.json - a flat catalogue of
every available Operation class, grouped by category for the UI's
operation browser.
"""

from . import encoding, ciphers, compression, hashing, textutils, extractors, networking, codeformat, arithmetic
from . import language, other, publickey

_MODULES = [
    encoding, ciphers, compression, hashing, textutils, extractors,
    networking, codeformat, arithmetic, language, other, publickey,
]

ALL_OPERATIONS = []
for _m in _MODULES:
    ALL_OPERATIONS.extend(_m.OPERATIONS)


def get_categories():
    """Returns an ordered dict-like list of (category_name, [operation_classes])."""
    order = []
    grouped = {}
    for op_cls in ALL_OPERATIONS:
        cat = op_cls.category
        if cat not in grouped:
            grouped[cat] = []
            order.append(cat)
        grouped[cat].append(op_cls)
    return [(cat, grouped[cat]) for cat in order]


def search_operations(query):
    query = (query or "").strip().lower()
    if not query:
        return ALL_OPERATIONS
    return [
        op for op in ALL_OPERATIONS
        if query in op.name.lower() or query in op.category.lower() or query in (op.description or "").lower()
    ]