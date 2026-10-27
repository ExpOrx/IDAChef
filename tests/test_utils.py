# -*- coding: utf-8 -*-
"""Utils tests."""

from test_runner import recipe_test
from idachef.operations.textutils import (
    Reverse, ToUpperCase, ToLowerCase, SwapCase, AlternatingCaps,
    ChangeCase, StripWhitespace, RemoveNullBytes, RemoveANSIEscapes,
    FindReplace, RegexSubstitution,
    SortLines, Unique, Split, FilterOp,
    Head, Tail, DropBytes, TakeBytes, PadLines,
    AddLineNumbers,
    CountOccurrences, RemoveDiacritics,
    Diff, HammingDistance, LevenshteinDistance,
    UnixTimestampToDate, JWTDecode,
)

# ---- Reverse ----
recipe_test("Reverse: byte", [{"op_cls": Reverse, "args": ["Byte"]}], "ABCD", "DCBA")
recipe_test("Reverse: line", [{"op_cls": Reverse, "args": ["Line"]}], "A\nB\nC", "C\nB\nA")

# ---- Case ----
recipe_test("To Upper: abc", [{"op_cls": ToUpperCase}], "abc def", "ABC DEF")
recipe_test("To Lower: ABC", [{"op_cls": ToLowerCase}], "ABC DEF", "abc def")
recipe_test("Swap Case: AbC", [{"op_cls": SwapCase}], "HeLLo", "hEllO")
recipe_test("Alternating Caps: hello world", [{"op_cls": AlternatingCaps}], "hello world", "HeLlO WoRlD")

# ---- Change Case ----
recipe_test("Change Case: snake_case", [{"op_cls": ChangeCase, "args": ["snake_case"]}], "HelloWorld", "hello_world")
recipe_test("Change Case: camelCase", [{"op_cls": ChangeCase, "args": ["camelCase"]}], "Hello World", "helloWorld")

# ---- Strip Whitespace ----
recipe_test("Remove whitespace: all", [{"op_cls": StripWhitespace, "args": ["All whitespace"]}], "a b c", "abc")

# ---- Remove Null Bytes ----
recipe_test("Remove null bytes: basic", [{"op_cls": RemoveNullBytes}], "a\x00b", "ab", input_encoding="latin-1")

# ---- Find / Replace ----
recipe_test("Find/Replace: simple", [{"op_cls": FindReplace, "args": ["foo", "bar", False, True]}], "foo baz", "bar baz")
recipe_test("Find/Replace: regex", [{"op_cls": FindReplace, "args": ["\\d+", "N", True, True]}], "abc 123 xyz", "abc N xyz")

# ---- Regular Expression ----
recipe_test("Regex Substitution: digits to X", [{"op_cls": RegexSubstitution, "args": ["\\d+", "X", True]}], "abc 123 xyz", "abc X xyz")

# ---- Sort ----
recipe_test("Sort: alphabetical", [{"op_cls": SortLines, "args": ["Alphabetical (A-Z)", False]}], "c\na\nb", "a\nb\nc")
recipe_test("Sort: reverse alphabetical", [{"op_cls": SortLines, "args": ["Alphabetical (Z-A)", False]}], "c\na\nb", "c\nb\na")
recipe_test("Sort: length", [{"op_cls": SortLines, "args": ["Length", False]}], "cc\naaa\nb", "b\ncc\naaa")

# ---- Unique ----
recipe_test("Unique: duplicates", [{"op_cls": Unique}], "a\nb\na", "a\nb")

# ---- Split ----
recipe_test("Split: comma", [{"op_cls": Split, "args": [","]}], "a,b,c", "a\nb\nc")

# ---- Filter ----
recipe_test("Filter: match", [{"op_cls": FilterOp, "args": ["a", False]}], "abc\ndef\nghi", "abc")
recipe_test("Filter: invert", [{"op_cls": FilterOp, "args": ["a", True]}], "abc\ndef\nghi", "def\nghi")

# ---- Head ----
recipe_test("Head: 2 lines", [{"op_cls": Head, "args": [2, "Lines"]}], "a\nb\nc\nd", "a\nb")

# ---- Tail ----
recipe_test("Tail: 2 lines", [{"op_cls": Tail, "args": [2, "Lines"]}], "a\nb\nc\nd", "c\nd")

# ---- Drop Bytes ----
recipe_test("Drop bytes: 2 from start", [{"op_cls": DropBytes, "args": [2, "Start"]}], "ABCD", "CD")
recipe_test("Drop bytes: 2 from end", [{"op_cls": DropBytes, "args": [2, "End"]}], "ABCD", "AB")

# ---- Take Bytes ----
recipe_test("Take bytes: 2 from start", [{"op_cls": TakeBytes, "args": [2, "Start"]}], "ABCD", "AB")
recipe_test("Take bytes: 2 from end", [{"op_cls": TakeBytes, "args": [2, "End"]}], "ABCD", "CD")

# ---- Pad Lines ----
recipe_test("Pad lines: prefix", [{"op_cls": PadLines, "args": ["> ", ""]}], "a\nb", "> a\n> b")

# ---- Add Line Numbers ----
recipe_test("Add line numbers", [{"op_cls": AddLineNumbers}], "a\nb\nc", "1  a\n2  b\n3  c")

# ---- Count Occurrences ----
recipe_test("Count occurrences: basic", [{"op_cls": CountOccurrences, "args": ["a", False]}], "banana", "3")
recipe_test("Count occurrences: regex", [{"op_cls": CountOccurrences, "args": ["[aeiou]", True]}], "hello", "2")

# ---- Remove Diacritics ----
recipe_test("Remove diacritics: cafe", [{"op_cls": RemoveDiacritics}], "caf\u00e9", "cafe")

# ---- Diff ----
recipe_test("Diff: basic", [{"op_cls": Diff}], "a\nb\nc\n---\na\nx\nc", "--- Input A\n+++ Input B\n@@ -1,3 +1,3 @@\n a\n-b\n+x\n c")

# ---- Hamming Distance ----
recipe_test("Hamming Distance: karolin,kathrin", [{"op_cls": HammingDistance}], "karolin\n---\nkathrin", "9")

# ---- Levenshtein Distance ----
recipe_test("Levenshtein: kitten,sitting", [{"op_cls": LevenshteinDistance}], "kitten\n---\nsitting", "3")

# ---- UNIX Timestamp ----
recipe_test("From UNIX Timestamp: 0", [{"op_cls": UnixTimestampToDate, "args": ["Seconds"]}], "0", "1970-01-01 00:00:00 UTC")

# ---- JWT Decode ----
recipe_test("JWT Decode: basic", [{"op_cls": JWTDecode}], "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dummy", '{\n  "header": {\n    "alg": "HS256"\n  },\n  "payload": {\n    "sub": "123"\n  }\n}')

print("[test_utils] registered tests")