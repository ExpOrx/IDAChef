# -*- coding: utf-8 -*-
"""Data format tests."""

import binascii
from test_runner import recipe_test
from idachef.operations.encoding import (
    ToHex, FromHex, ToHexdump, FromHexdump,
    ToBase64, FromBase64, ToBase32, FromBase32,
    ToBase45, FromBase45, ToBase58, FromBase58,
    ToBase85, FromBase85,
    ToBinary, FromBinary, ToOctal, FromOctal,
    ToDecimal, FromDecimal, ToFloat, FromFloat,
    ToCharcode, FromCharcode,
    URLEncode, URLDecode, ToHTMLEntity, FromHTMLEntity,
    ToMorseCode, FromMorseCode, QuotedPrintableEncode, QuotedPrintableDecode,
    SwapEndianness, EscapeString, UnescapeString,
    ToPunycode, FromPunycode,
    ToBCD, FromBCD, ToHexContent, FromHexContent,
)

BASIC_STRING = "The ships hung in the sky in much the same way that bricks don't."

# ---- To Hex ----
recipe_test("To Hex: nothing", [{"op_cls": ToHex, "args": ["None"]}], "", "")
recipe_test("To Hex: basic string", [{"op_cls": ToHex, "args": ["None"]}], BASIC_STRING, binascii.hexlify(BASIC_STRING.encode()).decode())
recipe_test("To Hex: 0x delimiter", [{"op_cls": ToHex, "args": ["0x"]}], "\x00\x01\x02", "0x000x010x02", input_encoding="latin-1")

# ---- From Hex ----
recipe_test("From Hex: basic", [{"op_cls": FromHex}], "6162657279737477797468", "aberystwyth")
recipe_test("From Hex: 0x with comma", [{"op_cls": FromHex}], "0x74,0x65,0x73,0x74", "test")
recipe_test("From Hex: with spaces", [{"op_cls": FromHex}], "61 62 65 72 79 73", "aberys")
recipe_test("From Hex: empty", [{"op_cls": FromHex}], "", "")

# ---- To Base64 ----
recipe_test("To Base64: nothing", [{"op_cls": ToBase64}], "", "")
recipe_test("To Base64: Hello, World!", [{"op_cls": ToBase64}], "Hello, World!", "SGVsbG8sIFdvcmxkIQ==")

# ---- From Base64 ----
recipe_test("From Base64: nothing", [{"op_cls": FromBase64}], "", "")
recipe_test("From Base64: Hello, World!", [{"op_cls": FromBase64}], "SGVsbG8sIFdvcmxkIQ==", "Hello, World!")

# ---- To/From Base32 ----
recipe_test("To Base32: basic", [{"op_cls": ToBase32}], "Hello", "JBSWY3DP")
recipe_test("From Base32: basic", [{"op_cls": FromBase32}], "JBSWY3DP", "Hello")

# ---- To/From Base85 ----
recipe_test("To Base85: basic", [{"op_cls": ToBase85}], "Hello", "NM&qnZv")
recipe_test("From Base85: basic", [{"op_cls": FromBase85}], "NM&qnZv", "Hello")

# ---- To/From Binary ----
recipe_test("To Binary: basic", [{"op_cls": ToBinary, "args": ["Space"]}], "A", "01000001")
recipe_test("To Binary: nothing", [{"op_cls": ToBinary, "args": ["Space"]}], "", "")
recipe_test("From Binary: basic", [{"op_cls": FromBinary}], "01000001", "A")
recipe_test("From Binary: with spaces", [{"op_cls": FromBinary}], "01000001 01000010", "AB")

# ---- To/From Decimal ----
recipe_test("To Decimal: basic", [{"op_cls": ToDecimal, "args": ["Space"]}], "\x00\x01\xff", "0 1 255", input_encoding="latin-1")
recipe_test("From Decimal: basic", [{"op_cls": FromDecimal}], "0 1 255", "\x00\x01\xff", input_encoding="latin-1")

# ---- URL Encode/Decode ----
recipe_test("URL Encode: basic", [{"op_cls": URLEncode}], "hello world", "hello%20world")
recipe_test("URL Decode: basic", [{"op_cls": URLDecode}], "hello%20world", "hello world")

# ---- To/From Morse ----
recipe_test("To Morse: SOS", [{"op_cls": ToMorseCode}], "SOS", "... --- ...")
recipe_test("From Morse: SOS", [{"op_cls": FromMorseCode}], "... --- ...", "SOS")

# ---- Escape/Unescape String ----
recipe_test("Escape String: newline", [{"op_cls": EscapeString}], "a\nb", "a\\nb")
recipe_test("Escape String: tab", [{"op_cls": EscapeString}], "a\tb", "a\\tb")
recipe_test("Unescape String: newline", [{"op_cls": UnescapeString}], "a\\nb", "a\nb")

# ---- Swap Endianness ----
recipe_test("Swap Endianness: 4-byte", [{"op_cls": SwapEndianness, "args": ["4"]}], "\x00\x01\x02\x03\x04\x05\x06\x07", "\x03\x02\x01\x00\x07\x06\x05\x04", input_encoding="latin-1")
recipe_test("Swap Endianness: 2-byte", [{"op_cls": SwapEndianness, "args": ["2"]}], "\x00\x01\x02\x03", "\x01\x00\x03\x02", input_encoding="latin-1")

# ---- Punycode ----
recipe_test("To Punycode: basic", [{"op_cls": ToPunycode}], "m\u00fcnchen", "xn--mnchen-3ya")
recipe_test("From Punycode: basic", [{"op_cls": FromPunycode}], "xn--mnchen-3ya", "m\u00fcnchen")

# ---- To/From BCD ----
recipe_test("To BCD: digits", [{"op_cls": ToBCD}], "1234", "\x12\x34", input_encoding="latin-1")
recipe_test("From BCD: bytes", [{"op_cls": FromBCD}], "\x12\x34", "1234", input_encoding="latin-1")

# ---- Hex Content ----
recipe_test("To Hex Content: basic", [{"op_cls": ToHexContent}], "AB", "4142")

# ---- To/From Charcode ----
recipe_test("To Charcode: hex", [{"op_cls": ToCharcode, "args": ["16"]}], "AB", "41 42")
recipe_test("From Charcode: hex", [{"op_cls": FromCharcode, "args": ["16"]}], "41 42", "AB")

# ---- To/From Float ----
recipe_test("To Float: 32-bit", [{"op_cls": ToFloat, "args": ["32-bit (float)"]}], "\x42\x48\x00\x00", "50.0", input_encoding="latin-1")
recipe_test("From Float: 32-bit", [{"op_cls": FromFloat, "args": ["32-bit (float)"]}], "50.0", "\x42\x48\x00\x00", input_encoding="latin-1")

# ---- To/From Octal ----
recipe_test("To Octal: basic", [{"op_cls": ToOctal, "args": ["Space"]}], "ABCD", "101 102 103 104")
recipe_test("From Octal: basic", [{"op_cls": FromOctal}], "101 102 103 104", "ABCD")

# ---- To/From Base58 ----
recipe_test("To Base58: basic", [{"op_cls": ToBase58}], "test", "3yZe7d", input_encoding="latin-1")
recipe_test("From Base58: basic", [{"op_cls": FromBase58}], "3yZe7d", "test", input_encoding="latin-1")

print("[test_encoding] registered tests")