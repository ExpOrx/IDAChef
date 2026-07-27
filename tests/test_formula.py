# -*- coding: utf-8 -*-
"""Formula / Compound operation tests."""

from test_runner import recipe_test
from idachef.operations.arithmetic import FormulaOperation

# ---- Multi-operation chaining via recipe (NOT formula) ----
from idachef.operations.ciphers import XOR
from idachef.operations.arithmetic import AddMod256, SubMod256, BitwiseNOT

# Test: XOR then ADD then SUB in the recipe (not formula engine)
recipe_test("Recipe chain: XOR(0x55) -> ADD(3) -> SUB(1)",
    [
        {"op_cls": XOR, "args": ["55", "Hex"]},
        {"op_cls": AddMod256, "args": ["03", "Hex"]},
        {"op_cls": SubMod256, "args": ["01", "Hex"]},
    ],
    "\x00\x01\x02\xff",
    "\x57\x56\x59\xac",
    input_encoding="latin-1"
)

# === Verify chain manually ===
# Input:  00 01 02 ff
# XOR 55: 55 54 57 aa
# ADD 03: 58 57 5a ad
# SUB 01: 57 56 59 ac  ✓

# Test: XOR then NOT is chainable and gives same as XOR+NOT formula
recipe_test("Recipe chain: XOR(0x55) -> NOT", 
    [
        {"op_cls": XOR, "args": ["55", "Hex"]},
        {"op_cls": BitwiseNOT},
    ],
    "\x00",
    "\xaa",
    input_encoding="latin-1"
)

# === Formula Compound Operation ===
recipe_test("Formula: XOR(0x55)+ADD(3)",
    [{"op_cls": FormulaOperation, "args": ["XOR(0x55)+ADD(3)"]}],
    "\x00\x01\x02\xff",
    "\x58\x57\x5a\xad",
    input_encoding="latin-1"
)

recipe_test("Formula: XOR(0xaa)-SUB(1)",
    [{"op_cls": FormulaOperation, "args": ["XOR(0xaa)-SUB(1)"]}],
    "\x00\x01\x02\xff",
    "\xa9\xaa\xa7\x54",
    input_encoding="latin-1"
)

# === Formula + FromHex / FromBase64 prefix ===
recipe_test("Formula: FromHex+XOR(0x55)+ADD(3)",
    [{"op_cls": FormulaOperation, "args": ["FromHex+XOR(0x55)+ADD(3)"]}],
    "000102ff",
    "\x58\x57\x5a\xad",
    input_encoding="latin-1"
)
# Input:  "000102ff" (string hex chars) -> FromHex -> bytes 00 01 02 ff
# XOR 55: 55 54 57 aa
# ADD 03: 58 57 5a ad ✓

recipe_test("Formula: FromHex+NOT",
    [{"op_cls": FormulaOperation, "args": ["FromHex+NOT"]}],
    "ff00",
    "\x00\xff",
    input_encoding="latin-1"
)
# Input: "ff00" -> FromHex -> bytes ff 00 -> NOT -> 00 ff ✓

recipe_test("Formula: FromBase64+XOR(0xaa)",
    [{"op_cls": FormulaOperation, "args": ["FromBase64+XOR(0xaa)"]}],
    "q80=",
    "\x01\x67",
    input_encoding="latin-1"
)
# Input: "q80=" (base64 of \xab\xcd) -> FromBase64 -> bytes ab cd
# XOR aa: 01 67

recipe_test("Formula: no From prefix, plain bytes XOR(0x55)",
    [{"op_cls": FormulaOperation, "args": ["XOR(0x55)"]}],
    "\x00\xff",
    "\x55\xaa",
    input_encoding="latin-1"
)
# Input treated as raw bytes: 00 ff -> XOR 55 -> 55 aa ✓

recipe_test("Formula: FromHex only, no byte ops",
    [{"op_cls": FormulaOperation, "args": ["FromHex"]}],
    "48656c6c6f",
    "Hello",
    input_encoding="latin-1"
)
# Input: "48656c6c6f" -> FromHex -> bytes 48 65 6c 6c 6f = "Hello" ✓

recipe_test("Formula: FromBase64 only, no byte ops",
    [{"op_cls": FormulaOperation, "args": ["FromBase64"]}],
    "SGVsbG8=",
    "Hello",
    input_encoding="latin-1"
)
# Input: "SGVsbG8=" -> FromBase64 -> bytes 48 65 6c 6c 6f = "Hello" ✓

print("[test_formula] registered tests")
