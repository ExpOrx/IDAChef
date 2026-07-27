# -*- coding: utf-8 -*-
"""
Formula / Compound Operation Engine
====================================
Allows chaining multiple arithmetic/logic operations on each byte in a single
step using an expression syntax. This solves the limitation where XOR, ADD,
SUB, AND, OR, NOT, ROL, ROR, bit shifts couldn't be combined in one pass.

Expression syntax examples:
    XOR(0x55)           -> single operation, same as the XOR op
    XOR(0x55)+ADD(3)    -> XOR with 0x55, then add 3 (mod 256)
    XOR(0xaa)-SUB(1)    -> XOR with 0xaa, then subtract 1
    NOT+ADD(1)          -> bitwise NOT, then add 1 (two's complement negation)
    ROL(1)+XOR(0xff)    -> rotate left 1, then XOR with 0xff
    SHR(1)+AND(0x7f)    -> shift right 1, then AND with 0x7f

Supported operations in the expression:
    XOR(key)   - XOR with key byte(s), repeated
    ADD(key)   - add key (mod 256)
    SUB(key)   - subtract key (mod 256)
    AND(key)   - bitwise AND with key
    OR(key)    - bitwise OR with key
    NOT        - bitwise NOT (no argument)
    ROL(n)     - rotate left n bits
    ROR(n)     - rotate right n bits
    SHL(n)     - shift left n bits
    SHR(n)     - shift right n bits
    MUL(key)   - multiply by key (mod 256)
    MOD(key)   - modulo key

The expression is parsed left-to-right. Each operation takes the result of
the previous operation as input. Keys can be specified as hex (0xNN) or
decimal integers. Multi-byte keys are repeated cyclically.
"""

import base64 as _base64
import binascii
import re


# ---------------------------------------------------------------------------
# "From" operations – applied to the *whole* input before byte-level ops
# ---------------------------------------------------------------------------
FROM_OPS = {
    "fromhex": lambda data: binascii.unhexlify(
        re.sub(r"[^0-9a-fA-F]", "", data.decode("utf-8", errors="ignore"))
    ),
    "frombase64": lambda data: _base64.b64decode(
        data.decode("utf-8", errors="ignore").strip()
    ),
}

FROM_RE = re.compile(
    r"^(FromHex|FromBase64)(?=[+\-]|$)",
    re.IGNORECASE,
)


def _parse_arg(text):
    """Parse a key argument: hex (0xNN), or decimal integer."""
    text = text.strip()
    if text.startswith("0x") or text.startswith("0X"):
        # Can be multi-byte hex string
        hex_str = re.sub(r"[^0-9a-fA-F]", "", text[2:])
        if not hex_str:
            return []
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        return list(bytes.fromhex(hex_str))
    try:
        val = int(text)
        return [val & 0xFF]
    except (ValueError, TypeError):
        raise ValueError("Invalid formula argument: %r. Use hex (0xNN...) or decimal integer." % text)


class FormulaOp(object):
    """Represents a single operation within a formula chain."""

    def __init__(self, kind, arg=0):
        self.kind = kind      # 'xor', 'add', 'sub', 'and', 'or', 'not', 'rol', 'ror', 'shl', 'shr', 'mul', 'mod'
        self.arg = arg        # int (bit count for shifts/rotates) or list of ints (key bytes)

    def apply(self, b, key_pos):
        """Apply this operation to a single byte. Returns (result, new_key_pos)."""
        if self.kind == "not":
            return ((~b) & 0xFF), key_pos
        elif self.kind == "rol":
            n = self.arg % 8
            return ((b << n) & 0xFF) | (b >> (8 - n)), key_pos
        elif self.kind == "ror":
            n = self.arg % 8
            return (b >> n) | ((b << (8 - n)) & 0xFF), key_pos
        elif self.kind == "shl":
            n = self.arg % 8
            return ((b << n) & 0xFF), key_pos
        elif self.kind == "shr":
            n = self.arg % 8
            return (b >> n), key_pos
        elif self.kind in ("mod",):
            if self.arg == 0:
                return b, key_pos
            return (b % self.arg[0]) & 0xFF, key_pos

        # Byte-coded operations with a multi-byte key
        key_bytes = self.arg
        k = key_bytes[key_pos % len(key_bytes)]
        if self.kind == "xor":
            return (b ^ k) & 0xFF, key_pos + 1
        elif self.kind == "add":
            return (b + k) & 0xFF, key_pos + 1
        elif self.kind == "sub":
            return (b - k) & 0xFF, key_pos + 1
        elif self.kind == "and":
            return (b & k) & 0xFF, key_pos + 1
        elif self.kind == "or":
            return (b | k) & 0xFF, key_pos + 1
        elif self.kind == "mul":
            return (b * k) & 0xFF, key_pos + 1
        else:
            raise ValueError("Unknown formula op kind: %s" % self.kind)


# Tokenizer patterns - matches both OP(arg) and bare OP (for NOT)
TOKEN_RE = re.compile(
    r"([A-Za-z]+)"           # operation name
    r"\s*"                   # optional whitespace
    r"(?:"                   # non-capturing group
    r"\(\s*([^)]*?)\s*\)"    # with parens: capture arg
    r"|"                     # OR
    r"(?=[+\-]|$)"           # without parens: lookahead for separator or end
    r")",
    re.IGNORECASE,
)


def parse_formula(expr):
    """Parse a formula expression string into (from_converter, op_list).

    Returns (from_fn_or_None, [FormulaOp, ...])

    "From" prefix (optional):
        FromHex+       -- decode input as hex before byte-ops
        FromBase64+    -- decode input as base64 before byte-ops
        (no prefix)    -- use input bytes as-is (no conversion)

    Byte-level operations follow optional From prefix:
        XOR(key), ADD(key), SUB(key), AND(key), OR(key), NOT,
        ROL(n), ROR(n), SHL(n), SHR(n), MUL(key), MOD(key)

    Example: "FromHex+XOR(0x55)+ADD(3)" -> (from_hex_fn, [FormulaOp('xor', [0x55]), FormulaOp('add', [3])])
    Example: "NOT+ADD(1)" -> (None, [FormulaOp('not'), FormulaOp('add', [1])])
    """
    # ---- strip optional "From" prefix ----
    from_fn = None
    m = FROM_RE.match(expr)
    if m:
        from_name = m.group(1).lower()
        from_fn = FROM_OPS.get(from_name)
        if from_fn is None:
            raise ValueError("Unsupported From operation: %r. Known: %s" % (m.group(1), ", ".join(sorted(FROM_OPS.keys()))))
        # Strip the From prefix and optional separator
        expr = expr[m.end():]
        # Strip leading '+' or '-' separator
        expr = re.sub(r"^[+\-]", "", expr)

    if not expr.strip():
        return (from_fn, [])

    # ---- parse byte-level operations ----
    ops = []
    for m in TOKEN_RE.finditer(expr):
        name = m.group(1).strip().lower()
        arg_text = (m.group(2) or "").strip()

        kind_map = {
            "xor": "xor", "add": "add", "sub": "sub",
            "and": "and", "or": "or", "not": "not",
            "rol": "rol", "ror": "ror",
            "shl": "shl", "shr": "shr",
            "mul": "mul", "mod": "mod",
        }

        if name not in kind_map:
            raise ValueError(
                "Unknown formula operation: %r. Known: %s" % (name, ", ".join(sorted(kind_map.keys())))
            )

        kind = kind_map[name]

        if kind == "not":
            ops.append(FormulaOp(kind))
            continue

        if not arg_text:
            raise ValueError("Operation %r requires an argument, e.g. %s(0x55)" % (name, name.upper()))

        key_bytes = _parse_arg(arg_text)

        if kind in ("rol", "ror", "shl", "shr"):
            # For bit operations, take the first byte value as the bit count
            ops.append(FormulaOp(kind, key_bytes[0] if key_bytes else 0))
        elif kind == "mod":
            ops.append(FormulaOp(kind, key_bytes))
        else:
            if not key_bytes:
                key_bytes = [0]
            ops.append(FormulaOp(kind, key_bytes))

    return (from_fn, ops)


def apply_formula(data, ops):
    """Apply a list of FormulaOp instances to byte data. (backward-compat)"""
    return _apply_byte_ops(data, ops)


def _apply_byte_ops(data, ops):
    """Apply a list of FormulaOp instances to byte data.

    Each byte goes through the full chain independently. Multi-byte keys
    in XOR/ADD/SUB/AND/OR/MUL cycle through all bytes of the key before
    moving to the next input byte.
    """
    if not ops:
        return data

    # The 'key_pos' is global across all ops of the same kind within the
    # chain. But each byte goes through the chain independently.
    # Key position is maintained per-byte through the chain.
    # Actually, in CyberChef's style, each op in the chain has its own
    # key position that advances with each byte. Let me implement that way:
    # Each FormulaOp tracks its own key_pos that increments when it
    # uses a byte from its key.

    out = bytearray()
    byte_pos = 0
    # Each op tracks its own key position
    key_positions = [0] * len(ops)

    for _ in range(len(data)):
        b = data[byte_pos]
        byte_pos += 1
        for i, op in enumerate(ops):
            b, kp = op.apply(b, key_positions[i])
            key_positions[i] = kp
        out.append(b)

    return bytes(out)