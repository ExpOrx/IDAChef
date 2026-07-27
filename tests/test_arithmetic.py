# -*- coding: utf-8 -*-
"""Arithmetic / Logic tests - converted from CyberChef's Arithmetic.mjs, BitwiseOp.mjs, etc."""

from test_runner import recipe_test
from idachef.operations.arithmetic import (
    Sum, SubtractOp, MultiplyOp, DivideOp, MeanOp, MedianOp, StdDevOp,
    ExtendedGCD, ModularInverse,
    BitwiseAND, BitwiseOR, BitwiseNOT, AddMod256, SubMod256, ModOp,
    BitShiftLeft, BitShiftRight, RotateLeft, RotateRight,
    SetUnion, SetIntersection, SetDifference, SymmetricDifference,
    FormulaOperation,
)

# ---- Sum ----
recipe_test("Sum: 1,2,3", [{"op_cls": Sum}], "1,2,3", "6")
recipe_test("Sum: single", [{"op_cls": Sum}], "42", "42")

# ---- Subtract ----
recipe_test("Subtract: 10,2,3", [{"op_cls": SubtractOp}], "10,2,3", "5")

# ---- Multiply ----
recipe_test("Multiply: 2,3,4", [{"op_cls": MultiplyOp}], "2,3,4", "24")

# ---- Divide ----
recipe_test("Divide: 100,2,5", [{"op_cls": DivideOp}], "100,2,5", "10")

# ---- Mean ----
recipe_test("Mean: 1,2,3,4,5", [{"op_cls": MeanOp}], "1,2,3,4,5", "3")

# ---- Median ----
recipe_test("Median: 1,3,2,5,4", [{"op_cls": MedianOp}], "1,3,2,5,4", "3")

# ---- Bitwise AND ----
recipe_test("Bitwise AND: ff & 0f", [{"op_cls": BitwiseAND, "args": ["0f", "Hex"]}], "\xff", "\x0f", input_encoding="latin-1")

# ---- Bitwise OR ----
recipe_test("Bitwise OR: 00 | 0f", [{"op_cls": BitwiseOR, "args": ["0f", "Hex"]}], "\x00", "\x0f", input_encoding="latin-1")

# ---- Bitwise NOT ----
recipe_test("Bitwise NOT: 00 -> ff", [{"op_cls": BitwiseNOT}], "\x00", "\xff", input_encoding="latin-1")

# ---- ADD ----
recipe_test("ADD: 0x01 + 0x01", [{"op_cls": AddMod256, "args": ["01", "Hex"]}], "\x01", "\x02", input_encoding="latin-1")
recipe_test("ADD: 0xff + 0x01", [{"op_cls": AddMod256, "args": ["01", "Hex"]}], "\xff", "\x00", input_encoding="latin-1")

# ---- SUB ----
recipe_test("SUB: 0x05 - 0x02", [{"op_cls": SubMod256, "args": ["02", "Hex"]}], "\x05", "\x03", input_encoding="latin-1")
recipe_test("SUB: 0x00 - 0x01", [{"op_cls": SubMod256, "args": ["01", "Hex"]}], "\x00", "\xff", input_encoding="latin-1")

# ---- MOD ----
recipe_test("MOD: 10 % 3", [{"op_cls": ModOp, "args": [3]}], [10, 20, 30], [1, 2, 0])

# ---- Bit Shift Left ----
recipe_test("Bit Shift Left: 1<<1", [{"op_cls": BitShiftLeft, "args": [1]}], "\x01", "\x02", input_encoding="latin-1")

# ---- Rotate Left ----
recipe_test("Rotate Left: 0x80 rol 1", [{"op_cls": RotateLeft, "args": [1]}], "\x80", "\x01", input_encoding="latin-1")

# ---- Rotate Right ----
recipe_test("Rotate Right: 0x01 ror 1", [{"op_cls": RotateRight, "args": [1]}], "\x01", "\x80", input_encoding="latin-1")

# ---- Extended GCD ----
recipe_test("Extended GCD: 48,18", [{"op_cls": ExtendedGCD}], "48,18", "gcd(48,18) = 6  bezout: -1*48 + 3*18")

# ---- Modular Inverse ----
recipe_test("Modular Inverse: 3,11", [{"op_cls": ModularInverse}], "3,11", "3^-1 mod 11 = 4")
recipe_test("Modular Inverse: 2,4", [{"op_cls": ModularInverse}], "2,4", "No inverse: 2 and 4 are not coprime")

# ---- Set Union ----
recipe_test("Set Union: a,b,c a,d", [{"op_cls": SetUnion}], "a\nb\nc\na\nd", "a\nb\nc\nd")

# ---- Set Intersection ----
recipe_test("Set Intersection: a,b,c --- b,c,d", [{"op_cls": SetIntersection}], "a,b,c\n---\nb,c,d", "b\nc")

# ---- Set Difference ----
recipe_test("Set Difference: a,b,c --- b,c,d", [{"op_cls": SetDifference}], "a,b,c\n---\nb,c,d", "a")

# ---- Symmetric Difference ----
recipe_test("Symmetric Diff: a,b,c --- b,c,d", [{"op_cls": SymmetricDifference}], "a,b,c\n---\nb,c,d", "a\nd")

# ---- Formula (compound) ----
recipe_test("Formula: XOR(0x55)+ADD(3)", [{"op_cls": FormulaOperation, "args": ["XOR(0x55)+ADD(3)"]}],
    "\x00\x01\x02\xff", "\x58\x57\x5a\xad", input_encoding="latin-1")
recipe_test("Formula: XOR(0xaa)-SUB(1)", [{"op_cls": FormulaOperation, "args": ["XOR(0xaa)-SUB(1)"]}],
    "\x00\x01\x02\xff", "\xa9\xaa\xa7\x54", input_encoding="latin-1")

print("[test_arithmetic] registered tests")