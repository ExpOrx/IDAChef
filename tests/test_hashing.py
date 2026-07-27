# -*- coding: utf-8 -*-
"""Hashing tests - converted from CyberChef's Hash.mjs, Checksum tests."""

from test_runner import recipe_test
from idachef.operations.hashing import (
    MD5, SHA1, SHA256, SHA512, SHA2,
    CRC32, XORChecksum, AnalyseHash, Entropy,
)

BASIC_STRING = "The ships hung in the sky in much the same way that bricks don't."
UTF8_STR = "\u10dc\u10e3 \u10de\u10d0\u10dc\u10d8\u10d9\u10d0\u10e1"

# ---- MD5 ----
recipe_test("MD5: Hello, World!", [{"op_cls": MD5}], "Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4")
recipe_test("MD5: empty", [{"op_cls": MD5}], "", "d41d8cd98f00b204e9800998ecf8427e")

# ---- SHA1 ----
recipe_test("SHA1: Hello, World!", [{"op_cls": SHA1}], "Hello, World!", "0a0a9f2a6772942557ab5355d76af442f8f65e01")
recipe_test("SHA1: empty", [{"op_cls": SHA1}], "", "da39a3ee5e6b4b0d3255bfef95601890afd80709")

# ---- SHA2 ----
recipe_test("SHA2 224: Hello, World!", [{"op_cls": SHA2, "args": ["SHA224"]}], "Hello, World!", "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff")
recipe_test("SHA2 256: Hello, World!", [{"op_cls": SHA2, "args": ["SHA256"]}], "Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
recipe_test("SHA2 512: Hello, World!", [{"op_cls": SHA2, "args": ["SHA512"]}], "Hello, World!", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387")

# ---- SHA256 directly ----
recipe_test("SHA256: Hello, World!", [{"op_cls": SHA256}], "Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")

# ---- SHA512 directly ----
recipe_test("SHA512: Hello, World!", [{"op_cls": SHA512}], "Hello, World!", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387")

# ---- CRC32 ----
recipe_test("CRC32: 123456789", [{"op_cls": CRC32}], "123456789", "cbf43926")
recipe_test("CRC32: empty", [{"op_cls": CRC32}], "", "00000000")

# ---- XOR Checksum ----
recipe_test("XOR Checksum: nothing", [{"op_cls": XORChecksum}], "", "00")
recipe_test("XOR Checksum: all bytes", [{"op_cls": XORChecksum}], "".join(chr(i) for i in range(256)), "00", input_encoding="latin-1")

# ---- Analyse Hash ----
recipe_test("Analyse Hash: MD5 length", [{"op_cls": AnalyseHash}], "d41d8cd98f00b204e9800998ecf8427e", 
    "Input length: 32 characters\n  Possible: MD5 / MD4 / NTLM")
recipe_test("Analyse Hash: SHA1 length", [{"op_cls": AnalyseHash}], "da39a3ee5e6b4b0d3255bfef95601890afd80709", 
    "Input length: 40 characters\n  Possible: SHA1")

# ---- Entropy ----
recipe_test("Entropy: empty", [{"op_cls": Entropy}], "", "0.0")

print("[test_hashing] registered tests")