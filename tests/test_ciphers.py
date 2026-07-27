# -*- coding: utf-8 -*-
"""Encryption / Encoding tests - converted from CyberChef's Ciphers.mjs tests."""

from test_runner import recipe_test
from idachef.operations.ciphers import (
    XOR, ROT13, ROT47, Atbash,
    VigenereEncode, VigenereDecode,
    BitShiftLeft, BitShiftRight,
    AffineEncode, AffineDecode, A1Z26Encode, A1Z26Decode,
    RailFenceEncode, RailFenceDecode,
    BaconEncode, BaconDecode,
    CaesarBox, Substitute,
)

# ---- XOR ----
recipe_test("XOR: hex key", [{"op_cls": XOR, "args": ["55", "Hex"]}], "\x00\x01\x02\xff", "\x55\x54\x57\xaa", input_encoding="latin-1")
recipe_test("XOR: UTF-8 key", [{"op_cls": XOR, "args": ["A", "UTF8"]}], "AAAA", "\x00\x00\x00\x00")
recipe_test("XOR: empty key", [{"op_cls": XOR, "args": ["", "Hex"]}], "test", "test")

# ---- ROT13 ----
recipe_test("ROT13: Hello", [{"op_cls": ROT13, "args": [13, False]}], "Hello", "Uryyb")
recipe_test("ROT13: Hello rot1", [{"op_cls": ROT13, "args": [1, False]}], "Hello", "Ifmmp")
recipe_test("ROT13: non-alpha", [{"op_cls": ROT13, "args": [13, False]}], "123 !@#", "123 !@#")

# ---- ROT47 ----
recipe_test("ROT47: basic", [{"op_cls": ROT47, "args": [47]}], "The Quick Brown Fox", "%96 \"F:4< qC@H? u@I")

# ---- Atbash ----
recipe_test("Atbash: Hello", [{"op_cls": Atbash}], "Hello", "Svool")
recipe_test("Atbash: ABC", [{"op_cls": Atbash}], "ABC", "ZYX")

# ---- Vigenere ----
recipe_test("Vigenere Encode: basic", [{"op_cls": VigenereEncode, "args": ["KEY"]}], "HELLO", "RIJVS")
recipe_test("Vigenere Decode: basic", [{"op_cls": VigenereDecode, "args": ["KEY"]}], "RIJVS", "HELLO")

# ---- Bit Shift ----
recipe_test("Bit Shift Left: 1", [{"op_cls": BitShiftLeft, "args": [1]}], "\x01", "\x02", input_encoding="latin-1")
recipe_test("Bit Shift Right: 1", [{"op_cls": BitShiftRight, "args": [1]}], "\x02", "\x01", input_encoding="latin-1")

# ---- Affine Cipher ----
recipe_test("Affine Encode: basic", [{"op_cls": AffineEncode, "args": [5, 8]}], "HELLO", "RCLLA")
recipe_test("Affine Decode: basic", [{"op_cls": AffineDecode, "args": [5, 8]}], "RCLLA", "HELLO")

# ---- A1Z26 ----
recipe_test("A1Z26 Encode: ABC", [{"op_cls": A1Z26Encode}], "ABC", "1 2 3")
recipe_test("A1Z26 Decode: 1 2 3", [{"op_cls": A1Z26Decode}], "1 2 3", "ABC")

# ---- Rail Fence ----
recipe_test("Rail Fence Encode: 3 rails", [{"op_cls": RailFenceEncode, "args": [3]}], "HELLOWORLD", "HOLELWRDLO")
recipe_test("Rail Fence Decode: 3 rails", [{"op_cls": RailFenceDecode, "args": [3]}], "HOLELWRDLO", "HELLOWORLD")

# ---- Bacon Cipher ----
recipe_test("Bacon Encode: A", [{"op_cls": BaconEncode}], "A", "AAAAA")
recipe_test("Bacon Encode: B", [{"op_cls": BaconEncode}], "B", "AAAAB")
recipe_test("Bacon Decode: AAAAA", [{"op_cls": BaconDecode}], "AAAAA", "A")

# ---- Caesar Box ----
recipe_test("Caesar Box: 2 width", [{"op_cls": CaesarBox, "args": [2]}], "ABCDEF", "ACEBDF")
recipe_test("Caesar Box: 3 width", [{"op_cls": CaesarBox, "args": [3]}], "ABCDEFGHI", "ADGBEHCFI")

# ---- Substitute ----
recipe_test("Substitute: basic", [{"op_cls": Substitute, "args": ["a=b c=d"]}], "abc", "bbd")

print("[test_ciphers] registered tests")