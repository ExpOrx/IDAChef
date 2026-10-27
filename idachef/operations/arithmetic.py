# -*- coding: utf-8 -*-
"""Arithmetic / Logic operations - cf. CyberChef's "Arithmetic / Logic"
category (Sum.mjs, Mean.mjs, XOR.mjs (bitwise variants), ANDBitwise.mjs, ...).

These work on whitespace/comma separated lists of numbers (Sum/Subtract/
Multiply/Divide/Mean/Median) or byte-wise between the input and a second
operand (AND/OR/XOR/NOT/ADD/SUB), which is handy for e.g. combining two
config blobs or applying an additive/XOR key-schedule byte-wise."""

import math
import re
import struct
import statistics as stats_mod

from ..core.operation import Operation
from ..core.formula import parse_formula, apply_formula
from ..core.utils import key_bytes, parse_numbers, fmt_num, bytewise_op, text_from_data_ignore

CATEGORY = "Arithmetic / Logic"


def _wordwise_op(data, key, fn):
    """Apply fn(u, k) & 0xFFFF to data as a stream of little-endian
    16-bit code units, cycling the key (also unpacked as LE 16-bit units).
    Any trailing odd byte is padded with 0x00 for the operation then
    trimmed back off so the output length always matches the input length.
    """
    padded = data + (b"\x00" if len(data) % 2 else b"")
    data_units = struct.unpack("<%dH" % (len(padded) // 2), padded)
    key_padded = key + (b"\x00" if len(key) % 2 else b"")
    key_units = struct.unpack("<%dH" % (len(key_padded) // 2), key_padded)
    out_units = [
        fn(u, key_units[i % len(key_units)]) & 0xFFFF
        for i, u in enumerate(data_units)
    ]
    out = struct.pack("<%dH" % len(out_units), *out_units)
    return out[:len(data)]


class Sum(Operation):
    name = "Sum"
    category = CATEGORY
    description = "Adds up a list of numbers found in the input (any delimiter)."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        return fmt_num(sum(nums)).encode()


class SubtractOp(Operation):
    name = "Subtract"
    category = CATEGORY
    description = "Subtracts each subsequent number in the list from the first."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if not nums:
            return b"0"
        result = nums[0]
        for n in nums[1:]:
            result -= n
        return fmt_num(result).encode()


class MultiplyOp(Operation):
    name = "Multiply"
    category = CATEGORY
    description = "Multiplies a list of numbers found in the input together."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        result = 1
        for n in nums:
            result *= n
        return fmt_num(result).encode()


class DivideOp(Operation):
    name = "Divide"
    category = CATEGORY
    description = "Divides the first number in the list by each subsequent number."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if not nums:
            return b"0"
        result = nums[0]
        for n in nums[1:]:
            result /= n
        return fmt_num(result).encode()


class MeanOp(Operation):
    name = "Mean"
    category = CATEGORY
    description = "Calculates the arithmetic mean of a list of numbers found in the input."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if not nums:
            return b"0"
        return fmt_num(stats_mod.mean(nums)).encode()


class MedianOp(Operation):
    name = "Median"
    category = CATEGORY
    description = "Calculates the median of a list of numbers found in the input."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if not nums:
            return b"0"
        return fmt_num(stats_mod.median(nums)).encode()


class StdDevOp(Operation):
    name = "Standard Deviation"
    category = CATEGORY
    description = "Calculates the (sample) standard deviation of a list of numbers found in the input."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if len(nums) < 2:
            return b"0"
        return fmt_num(stats_mod.stdev(nums)).encode()


class ExtendedGCD(Operation):
    name = "Extended GCD"
    category = CATEGORY
    description = "Computes the GCD of two numbers plus Bezout coefficients via the extended Euclidean algorithm."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if len(nums) < 2:
            return b"Need at least 2 numbers"
        a, b = int(nums[0]), int(nums[1])
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        while r:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
        result = "gcd(%d,%d) = %d  bezout: %d*%d + %d*%d" % (a, b, old_r, old_s, a, old_t, b)
        return result.encode()


class ModularInverse(Operation):
    name = "Modular Inverse"
    category = CATEGORY
    description = "Finds the modular multiplicative inverse of a mod m. Requires a and m to be coprime."

    def _run(self, data, args):
        nums = parse_numbers(text_from_data_ignore(data))
        if len(nums) < 2:
            return b"Need a and m"
        a, m = int(nums[0]), int(nums[1])
        try:
            inv = pow(a, -1, m)
            return ("%d^-1 mod %d = %d" % (a, m, inv)).encode()
        except ValueError:
            return ("No inverse: %d and %d are not coprime" % (a, m)).encode()


class BitwiseAND(Operation):
    name = "AND"
    category = CATEGORY
    description = (
        "ANDs the input with the given key, repeating the key as necessary. "
        "Set 'Unit' to UTF-16LE (word) for wide-string operations, where the "
        "key is ANDed against each 16-bit code unit instead of each raw byte."
    )
    args = [
        {"name": "Key", "type": "string", "value": "ff"},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Unit", "type": "option", "value": "Byte", "options": ["Byte", "UTF-16LE (word)"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", "ff"), self.get_arg(args, "Key format", "Hex"))
        unit = self.get_arg(args, "Unit", "Byte")
        if not key:
            return data
        if unit == "UTF-16LE (word)":
            return _wordwise_op(data, key, lambda a, b: a & b)
        return bytewise_op(data, key, lambda a, b: a & b)


class BitwiseOR(Operation):
    name = "OR"
    category = CATEGORY
    description = (
        "ORs the input with the given key, repeating the key as necessary. "
        "Set 'Unit' to UTF-16LE (word) for wide-string operations, where the "
        "key is ORed against each 16-bit code unit instead of each raw byte."
    )
    args = [
        {"name": "Key", "type": "string", "value": "00"},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Unit", "type": "option", "value": "Byte", "options": ["Byte", "UTF-16LE (word)"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", "00"), self.get_arg(args, "Key format", "Hex"))
        unit = self.get_arg(args, "Unit", "Byte")
        if not key:
            return data
        if unit == "UTF-16LE (word)":
            return _wordwise_op(data, key, lambda a, b: a | b)
        return bytewise_op(data, key, lambda a, b: a | b)


class BitwiseNOT(Operation):
    name = "NOT"
    category = CATEGORY
    description = "Flips every bit in the input (one's complement)."

    def _run(self, data, args):
        return bytes((~b) & 0xFF for b in data)


class AddMod256(Operation):
    name = "ADD"
    category = CATEGORY
    description = (
        "Adds the given key to the input, repeating the key as necessary. "
        "Set 'Unit' to Byte for byte-wise (mod 256) or UTF-16LE (word) for "
        "wide-string operations where the key is added to each 16-bit code "
        "unit (mod 65536). Inverse of SUB."
    )
    args = [
        {"name": "Key", "type": "string", "value": "01"},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Unit", "type": "option", "value": "Byte", "options": ["Byte", "UTF-16LE (word)"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", "01"), self.get_arg(args, "Key format", "Hex"))
        unit = self.get_arg(args, "Unit", "Byte")
        if not key:
            return data
        if unit == "UTF-16LE (word)":
            return _wordwise_op(data, key, lambda a, b: a + b)
        return bytewise_op(data, key, lambda a, b: a + b)


class SubMod256(Operation):
    name = "SUB"
    category = CATEGORY
    description = (
        "Subtracts the given key from the input, repeating the key as necessary. "
        "Set 'Unit' to Byte for byte-wise (mod 256) or UTF-16LE (word) for "
        "wide-string operations where the key is subtracted from each 16-bit "
        "code unit (mod 65536). Inverse of ADD."
    )
    args = [
        {"name": "Key", "type": "string", "value": "01"},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Unit", "type": "option", "value": "Byte", "options": ["Byte", "UTF-16LE (word)"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", "01"), self.get_arg(args, "Key format", "Hex"))
        unit = self.get_arg(args, "Unit", "Byte")
        if not key:
            return data
        if unit == "UTF-16LE (word)":
            return _wordwise_op(data, key, lambda a, b: a - b)
        return bytewise_op(data, key, lambda a, b: a - b)


class ModOp(Operation):
    name = "MOD"
    category = CATEGORY
    description = "Computes the modulo (remainder) of each byte divided by the given number."
    args = [
        {"name": "Modulo", "type": "number", "value": 256},
    ]

    def _run(self, data, args):
        m = int(self.get_arg(args, "Modulo", 256))
        if m <= 0:
            m = 256
        return bytes(b % m for b in data)


class BitShiftLeft(Operation):
    name = "Bit shift left"
    category = CATEGORY
    description = "Shifts each byte left by N bits (bits shifted out are dropped)."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes(((b << n) & 0xFF) for b in data)


class BitShiftRight(Operation):
    name = "Bit shift right"
    category = CATEGORY
    description = "Shifts each byte right by N bits."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes((b >> n) for b in data)


class RotateLeft(Operation):
    name = "Rotate left"
    category = CATEGORY
    description = "Rotates each byte left by N bits (bits wrap around)."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes(((b << n) & 0xFF) | (b >> (8 - n)) for b in data)


class RotateRight(Operation):
    name = "Rotate right"
    category = CATEGORY
    description = "Rotates each byte right by N bits (bits wrap around)."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes((b >> n) | ((b << (8 - n)) & 0xFF) for b in data)


class SetUnion(Operation):
    name = "Set Union"
    category = CATEGORY
    description = "Computes the union of items from the input (comma/newline/space separated)."

    def _run(self, data, args):
        items = re.split(r"[,\n\s]+", data.decode("utf-8", errors="ignore").strip())
        items = [x for x in items if x]
        return "\n".join(sorted(set(items))).encode()


class SetIntersection(Operation):
    name = "Set Intersection"
    category = CATEGORY
    description = "Computes the intersection of two sets (split input by a line containing '---' or two groups separated by double-newline)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n|\n\n\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two groups separated by '---' on its own line"
        set_a = set(re.split(r"[,\n\s]+", parts[0].strip()))
        set_b = set(re.split(r"[,\n\s]+", parts[1].strip()))
        set_a.discard("")
        set_b.discard("")
        return "\n".join(sorted(set_a & set_b)).encode()


class SetDifference(Operation):
    name = "Set Difference"
    category = CATEGORY
    description = "Computes A - B (items in first group not in second)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n|\n\n\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two groups separated by '---' on its own line"
        set_a = set(re.split(r"[,\n\s]+", parts[0].strip()))
        set_b = set(re.split(r"[,\n\s]+", parts[1].strip()))
        set_a.discard("")
        set_b.discard("")
        return "\n".join(sorted(set_a - set_b)).encode()


class SymmetricDifference(Operation):
    name = "Symmetric Difference"
    category = CATEGORY
    description = "Computes the symmetric difference (items in one set but not both)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n|\n\n\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two groups separated by '---' on its own line"
        set_a = set(re.split(r"[,\n\s]+", parts[0].strip()))
        set_b = set(re.split(r"[,\n\s]+", parts[1].strip()))
        set_a.discard("")
        set_b.discard("")
        return "\n".join(sorted(set_a ^ set_b)).encode()


class BytesToIntegers(Operation):
    name = "Bytes to Integers"
    category = CATEGORY
    description = "Packs the input bytes into integers of the given word size (like CyberChef's To Decimal but for 16/32/64-bit words). Handy for reading dwords/qwords out of a hex view."
    args = [
        {"name": "Word size (bytes)", "type": "option", "value": "4", "options": ["1", "2", "4", "8"]},
        {"name": "Endianness", "type": "option", "value": "Little Endian", "options": ["Little Endian", "Big Endian"]},
        {"name": "Signed", "type": "boolean", "value": False},
        {"name": "Output base", "type": "option", "value": "Decimal", "options": ["Decimal", "Hex", "Binary"]},
    ]

    def _run(self, data, args):
        word = int(self.get_arg(args, "Word size (bytes)", "4"))
        big_endian = self.get_arg(args, "Endianness", "Little Endian") == "Big Endian"
        signed = self.get_arg(args, "Signed", False)
        base = self.get_arg(args, "Output base", "Decimal")
        out = []
        for i in range(0, len(data) - (len(data) % word), word):
            chunk = data[i:i + word]
            val = int.from_bytes(chunk, "big" if big_endian else "little", signed=signed)
            if base == "Hex":
                out.append("0x%0*x" % (word * 2, val))
            elif base == "Binary":
                out.append(format(val, "b"))
            else:
                out.append(str(val))
        return "\n".join(out).encode()


class IntegersToBytes(Operation):
    name = "Integers to Bytes"
    description = "Converts a list of integers (decimal or 0x-prefixed hex) to packed bytes of the given word size."
    category = CATEGORY
    args = [
        {"name": "Word size (bytes)", "type": "option", "value": "4", "options": ["1", "2", "4", "8"]},
        {"name": "Endianness", "type": "option", "value": "Little Endian", "options": ["Little Endian", "Big Endian"]},
        {"name": "Signed", "type": "boolean", "value": False},
    ]

    def _run(self, data, args):
        word = int(self.get_arg(args, "Word size (bytes)", "4"))
        big_endian = self.get_arg(args, "Endianness", "Little Endian") == "Big Endian"
        signed = self.get_arg(args, "Signed", False)
        text = text_from_data_ignore(data)
        tokens = re.findall(r"0[xX][0-9a-fA-F]+|-?\d+", text)
        out = bytearray()
        max_val = 1 << (word * 8)
        for tok in tokens:
            val = int(tok, 16 if tok.lower().startswith("0x") else 10)
            if signed and val < 0:
                val %= max_val
            val &= max_val - 1
            out.extend(val.to_bytes(word, "big" if big_endian else "little"))
        return bytes(out)


class RotateWord(Operation):
    name = "Rotate word"
    category = CATEGORY
    description = "Rotates 8/16/32/64-bit words by N bits (unlike 'Rotate left/right', which work per-byte). Useful for computing ROR-style hashes by hand."
    args = [
        {"name": "Amount", "type": "number", "value": 13},
        {"name": "Direction", "type": "option", "value": "Right", "options": ["Right", "Left"]},
        {"name": "Word size (bits)", "type": "option", "value": "32", "options": ["8", "16", "32", "64"]},
        {"name": "Endianness", "type": "option", "value": "Little Endian", "options": ["Little Endian", "Big Endian"]},
    ]

    def _run(self, data, args):
        amount = int(self.get_arg(args, "Amount", 13))
        direction = self.get_arg(args, "Direction", "Right")
        bits = int(self.get_arg(args, "Word size (bits)", "32"))
        big_endian = self.get_arg(args, "Endianness", "Little Endian") == "Big Endian"
        word = bits // 8
        order = "big" if big_endian else "little"
        mask = (1 << bits) - 1
        amount %= bits
        out = bytearray()
        for i in range(0, len(data) - (len(data) % word), word):
            val = int.from_bytes(data[i:i + word], order)
            if direction == "Right":
                val = ((val >> amount) | (val << (bits - amount))) & mask if amount else val
            else:
                val = ((val << amount) | (val >> (bits - amount))) & mask if amount else val
            out.extend(val.to_bytes(word, order))
        return bytes(out)


class FormulaOperation(Operation):
    """Compound byte-level formula: optional FromHex/FromBase64 prefix to
    decode input, then chain XOR, ADD, SUB, AND, OR, NOT, ROL, ROR, SHL,
    SHR, MUL, MOD on every byte in a single pass.

    If no From prefix is given, input bytes are used as-is (no conversion).

    Expression examples:
      XOR(0x55)+ADD(3)
      FromHex+XOR(0x55)+ADD(3)
      FromBase64+XOR(0xaa)
      FromHex          (decode hex, no byte ops)
      NOT+ADD(1)
      ROL(1)+XOR(0xff)+SHR(2)
    """
    name = "Formula (compound)"
    category = CATEGORY
    description = (
        "Chain multiple byte-level operations in one pass. "
        "Optional FromHex/FromBase64 prefix decodes input first. "
        "Expr: XOR(0x55)+ADD(3). Supported: XOR, ADD, SUB, AND, OR, NOT, "
        "ROL, ROR, SHL, SHR, MUL, MOD. Keys in hex (0xNN) or decimal."
    )
    args = [
        {"name": "Expression", "type": "string", "value": "XOR(0x55)+ADD(3)"},
    ]

    def _run(self, data, args):
        expr = self.get_arg(args, "Expression", "XOR(0x55)")
        from_fn, ops = parse_formula(expr)
        if from_fn is not None:
            data = from_fn(data)
        return apply_formula(data, ops)


OPERATIONS = [
    SetUnion, SetIntersection, SetDifference, SymmetricDifference,
    Sum, SubtractOp, MultiplyOp, DivideOp, MeanOp, MedianOp, StdDevOp,
    ExtendedGCD, ModularInverse,
    BitwiseAND, BitwiseOR, BitwiseNOT, AddMod256, SubMod256, ModOp,
    BitShiftLeft, BitShiftRight, RotateLeft, RotateRight,
    BytesToIntegers, IntegersToBytes, RotateWord,
    FormulaOperation,
]