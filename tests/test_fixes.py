# -*- coding: utf-8 -*-
"""Regression tests for bug fixes and new operations added in 1.1.

Covers:
- ROR13 (byte rotation was off by 2 bits; new 32-bit ROR13 hash mode)
- CMAC (ciphermod was None so every call raised)
- SHA0 (was silently computing SHA1; now a real SHA-0 implementation)
- Parity Bit (bit_count() broke Python 3.8/3.9; parity semantics now match
  CyberChef's corrective-bit convention)
- LM Hash (key schedule bit order was wrong; validated against the known
  LM hash of "password")
- UTC handling in Get Time / Parse DateTime / From UNIX Timestamp
- Strip HTTP headers (body slice started 2 bytes early for CRLF headers)
- Dechunk HTTP response (new op)
- De Bruijn sequence (previously always returned empty output)
- Unescape String (unicode_escape destroyed \\uXXXX beyond Latin-1)
- Escape Unicode Characters (astral chars now emit surrogate pairs)
- Strings extractor wide/UTF-16LE mode (fixed-length regex chunked runs)
- LZNT1 Decompress (replaced broken stub with a real implementation,
  verified byte-for-byte against Windows ntdll RtlDecompressBuffer output)
- LZString Compress/Decompress (replaced fake stubs with a faithful port of
  pieroxy/lz-string 1.4.5, cross-validated against the JS implementation)
- Formula MOD(0x) no longer crashes
- TEA/XTEA/XXTEA now always pad (PKCS-style) so round-trips are unambiguous
- AES CTR accepts a full 16-byte IV as the initial counter (OpenSSL interop)
- Salsa20 (new op, requires pycryptodome)
- Bytes to Integers / Integers to Bytes / Rotate word (new ops)
"""

import time

import test_runner
from test_runner import recipe_test

from idachef.operations.ciphers import (
    ROR13, TEAEncrypt, TEADecrypt, XTEAEncrypt, XTEADecrypt,
    XXTEAEncrypt, XXTEADecrypt,
)
from idachef.operations.hashing import SHA0, ParityBit
from idachef.operations.textutils import GetTime, ParseDateTime, UnixTimestampToDate
from idachef.operations.networking import StripHTTPHeaders, DechunkHTTP
from idachef.operations.encoding import UnescapeString, EscapeUnicodeChars
from idachef.operations.extractors import ExtractStrings
from idachef.operations.compression import (
    LZNT1Decompress, LZStringCompress, LZStringDecompress,
)
from idachef.operations.arithmetic import (
    FormulaOperation, BytesToIntegers, IntegersToBytes, RotateWord,
)

try:
    from Crypto.Cipher import AES
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False


def direct_test(name, fn):
    """Register a plain assertion function with the shared runner counters."""
    try:
        fn()
        test_runner._passed += 1
    except AssertionError as exc:
        test_runner._failed += 1
        test_runner._failures.append("%s: %s" % (name, exc))
    except Exception as exc:  # noqa: BLE001
        test_runner._failed += 1
        test_runner._failures.append("%s: Exception - %r" % (name, exc))


# ---- ROR13 ----
recipe_test("ROR13: byte rotation equals ROR5",
            [{"op_cls": ROR13, "args": ["Rotate (byte)"]}],
            bytes([0x81, 0x01, 0xFF]),
            bytes([(0x81 >> 5) | ((0x81 << 3) & 0xFF),
                   (0x01 >> 5) | ((0x01 << 3) & 0xFF),
                   (0xFF >> 5) | ((0xFF << 3) & 0xFF)]))
recipe_test("ROR13: 32-bit hash of 'AB' is 0x02080042",
            [{"op_cls": ROR13, "args": ["ROR13 hash (32-bit, lowercase)"]}],
            "AB", "0x02080042")

# ---- SHA0 (real implementation) ----
recipe_test("SHA0: 'abc' FIPS 180 vector",
            [{"op_cls": SHA0}], "abc",
            "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")
recipe_test("SHA0: 56-byte FIPS 180 vector",
            [{"op_cls": SHA0}], "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8")

# ---- Parity Bit (corrective bit, CyberChef semantics) ----
recipe_test("ParityBit: even parity of 'AC'", [{"op_cls": ParityBit, "args": ["Even"]}],
            "AC", "01")
recipe_test("ParityBit: odd parity of 'A'", [{"op_cls": ParityBit, "args": ["Odd"]}],
            "A", "1")


# ---- LM Hash (known vector) ----
if HAVE_PYCRYPTODOME:
    from idachef.operations.hashing import CMAC, LMHash
    recipe_test("LM Hash: known vector for 'password'",
                [{"op_cls": LMHash}], "password",
                "e52cac67419a9a224a3b108f3fa6cb6d")

    def _cmac_ref_test():
        from Crypto.Hash import CMAC as cmac_ref
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ref = cmac_ref.new(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
                           ciphermod=AES)
        ref.update(msg)
        op = CMAC()
        out = op.run(msg, [{"name": "Key", "value": "2b7e151628aed2a6abf7158809cf4f3c"},
                           {"name": "Key format", "value": "Hex"}])
        assert out == ref.hexdigest().encode(), "%r != %r" % (out, ref.hexdigest())

    direct_test("CMAC agrees with pycryptodome (ciphermod=AES)", _cmac_ref_test)


# ---- UTC date/time handling ----
recipe_test("From UNIX Timestamp: 1706702400",
            [{"op_cls": UnixTimestampToDate, "args": ["Seconds"]}],
            "1706702400", "2024-01-31 12:00:00 UTC")
recipe_test("From UNIX Timestamp: no digits guard",
            [{"op_cls": UnixTimestampToDate, "args": ["Seconds"]}],
            "no numbers here", "Could not parse a UNIX timestamp")


def _parse_datetime_utc_test():
    op = ParseDateTime()
    out = op.run(b"2024-01-31 12:00:00", op.args).decode()
    import datetime
    expected = int(datetime.datetime(2024, 1, 31, 12, tzinfo=datetime.timezone.utc).timestamp())
    assert ("UNIX (s):  %d" % expected) in out, out


direct_test("Parse DateTime uses UTC for naive input", _parse_datetime_utc_test)


def _get_time_utc_test():
    op = GetTime()
    out = op.run(b"", op.args).decode()
    unix_s = int(out.splitlines()[2].split(":")[1].strip())
    assert abs(unix_s - time.time()) < 10, "Get Time drifted %d seconds from UTC now" % (unix_s - time.time())


direct_test("Get Time reports true UTC epoch", _get_time_utc_test)

# ---- Strip HTTP headers / Dechunk HTTP response ----
recipe_test("Strip HTTP headers: CRLF",
            [{"op_cls": StripHTTPHeaders}],
            "HTTP/1.1 200 OK\r\nX: 1\r\n\r\nBODY", "BODY")
recipe_test("Strip HTTP headers: bare LF",
            [{"op_cls": StripHTTPHeaders}],
            "HTTP/1.0 200 OK\nContent-Type: text\n\nBODY2", "BODY2")
recipe_test("Dechunk HTTP response: basic",
            [{"op_cls": DechunkHTTP, "args": [False]}],
            "4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n",
            "Wikipedia in\r\n\r\nchunks.")
recipe_test("Dechunk HTTP response: extensions + trailer dropped",
            [{"op_cls": DechunkHTTP, "args": [False]}],
            "3;x-ext=1\r\nabc\r\n0\r\n\r\nTrailer: x", "abc")

# ---- De Bruijn sequence ----
def _debruijn_known_test():
    from idachef.operations.other import DeBruijnSequence
    op = DeBruijnSequence()
    op.args[0]["value"] = 2
    op.args[1]["value"] = 3
    out = op.run(b"", op.args)
    assert out == bytes([0, 0, 0, 1, 0, 1, 1, 1]), "got %s" % out.hex()


def _debruijn_uniqueness_test():
    from idachef.operations.other import DeBruijnSequence
    op = DeBruijnSequence()
    op.args[0]["value"] = 16
    op.args[1]["value"] = 4
    out = op.run(b"", op.args)
    k, n = 16, 4
    assert len(out) == k ** n, "length %d != %d" % (len(out), k ** n)
    cyclic = out + out[:n - 1]
    seen = {bytes(cyclic[i:i + n]) for i in range(len(out))}
    assert len(seen) == k ** n, "only %d unique %d-mers" % (len(seen), k ** n)


direct_test("De Bruijn(2,3) = 00010111", _debruijn_known_test)
direct_test("De Bruijn(16,4) contains every 4-mer exactly once", _debruijn_uniqueness_test)

# ---- Unescape / Escape String ----
recipe_test("Unescape String: unicode + hex escapes",
            [{"op_cls": UnescapeString}],
            "\\u4f60\\u597d\\n\\x41",
            bytes([0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD, 0x0A, 0x41]))
recipe_test("Unescape String: non-ASCII passes through unchanged",
            [{"op_cls": UnescapeString}], "café\n", "café\n")
recipe_test("Escape Unicode Characters: astral -> surrogate pair",
            [{"op_cls": EscapeUnicodeChars}],
            "a\U0001F600b", b"a\\ud83d\\ude00b")

# ---- Strings extractor, wide (UTF-16LE) mode ----
_wide_input = "HELLOWORLD".encode("utf-16-le")
recipe_test("Strings wide mode: full word extracted",
            [{"op_cls": ExtractStrings, "args": [4, "Wide (UTF-16LE)"]}],
            _wide_input, "HELLOWORLD")

# ---- LZNT1 (real format; blob produced by Windows ntdll RtlCompressBuffer) ----
_LZNT1_TEXT_BLOB = (
    b"3\xb0\x00The quic\x00k brown \x00fox jump\x00s over t\x01\x00\xf0"
    b"lazy do\x08g. \xb1\xb0"
)
recipe_test("LZNT1: decompresses ntdll-compressed text",
            [{"op_cls": LZNT1Decompress}],
            _LZNT1_TEXT_BLOB,
            b"The quick brown fox jumps over the lazy dog. " * 5)
recipe_test("LZNT1: stored (uncompressed) chunk passes through",
            [{"op_cls": LZNT1Decompress}],
            b"\x04\x30hello\x00\x00", "hello")

# ---- LZString (JS-validated vectors) ----
recipe_test("LZString Decompress: JS compressToBase64 vector",
            [{"op_cls": LZStringDecompress, "args": ["Base64"]}],
            "BIUwNmD2A0AEDqkBOYAmBCIA", "Hello, World!")
recipe_test("LZString Decompress: JS compressToEncodedURIComponent vector",
            [{"op_cls": LZStringDecompress, "args": ["URI-safe"]}],
            ("N4IgdghgtgpiBcIAuMDOSQBoQDcIBsBXNBAbQEZMAmTAZgF1sw0UATBUAaxgE8"
             "FcCxLCAgAnUWRHCARsIDGIegF8lQA"),
            '{"name":"test","values":[1,2,3],"nested":{"key":"value","arr":["a","b","c"]}}')
recipe_test("LZString Decompress: JS compressToUTF16 vector (surrogates)",
            [{"op_cls": LZStringDecompress, "args": ["UTF-16"]}],
            "ᣢహ䅎`㬰㷠渥ᥰΙ↝ᩴឣ㠠Ỵ¸ߑ䲰  ",
            "café naïve 你好 \U0001f600 done")
recipe_test("LZString: compress/decompress roundtrip",
            [{"op_cls": LZStringCompress, "args": ["Base64"]},
             {"op_cls": LZStringDecompress, "args": ["Base64"]}],
            "The quick brown fox jumps over the lazy dog. " * 5,
            "The quick brown fox jumps over the lazy dog. " * 5)

# ---- Formula robustness ----
recipe_test("Formula: MOD(0x) degrades to identity",
            [{"op_cls": FormulaOperation, "args": ["MOD(0x)"]}],
            "ABC", "ABC")

# ---- TEA / XTEA / XXTEA always-pad round-trips ----
_TEA_KEY = "00112233445566778899aabbccddeeff"
recipe_test("TEA roundtrip: data ending in 0x01",
            [{"op_cls": TEAEncrypt, "args": [_TEA_KEY, "Hex", 32]},
             {"op_cls": TEADecrypt, "args": [_TEA_KEY, "Hex", 32]}],
            "AAAAAAA\x01", "AAAAAAA\x01", input_encoding="latin-1")
recipe_test("TEA roundtrip: exactly one block",
            [{"op_cls": TEAEncrypt, "args": [_TEA_KEY, "Hex", 32]},
             {"op_cls": TEADecrypt, "args": [_TEA_KEY, "Hex", 32]}],
            "ABCDEFGH", "ABCDEFGH", input_encoding="latin-1")
recipe_test("XTEA roundtrip: data ending in 0x01",
            [{"op_cls": XTEAEncrypt, "args": [_TEA_KEY, "Hex", 32]},
             {"op_cls": XTEADecrypt, "args": [_TEA_KEY, "Hex", 32]}],
            "AAAAAAA\x01", "AAAAAAA\x01", input_encoding="latin-1")
recipe_test("XXTEA roundtrip: 4 bytes ending in 0x01",
            [{"op_cls": XXTEAEncrypt, "args": [_TEA_KEY, "Hex"]},
             {"op_cls": XXTEADecrypt, "args": [_TEA_KEY, "Hex"]}],
            "AAA\x01", "AAA\x01", input_encoding="latin-1")
recipe_test("XXTEA roundtrip: single byte",
            [{"op_cls": XXTEAEncrypt, "args": [_TEA_KEY, "Hex"]},
             {"op_cls": XXTEADecrypt, "args": [_TEA_KEY, "Hex"]}],
            "Z", "Z", input_encoding="latin-1")

# ---- AES CTR with full 16-byte IV (OpenSSL initial-counter interop) ----
if HAVE_PYCRYPTODOME:
    from idachef.operations.ciphers import AESEncrypt, Salsa20Op
    recipe_test("AES CTR: 16-byte IV used as initial counter",
                [{"op_cls": AESEncrypt,
                  "args": ["000102030405060708090a0b0c0d0e0f", "Hex",
                           "000102030405060708090a0b0c0d0e0f", "Hex", "CTR"]}],
                "Hello CTR mode",
                bytes.fromhex("42f167d92e4eb311a3e3f937a236"))

    recipe_test("Salsa20 roundtrip",
                [{"op_cls": Salsa20Op, "args": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "Hex", "0001020304050607", "Hex"]},
                 {"op_cls": Salsa20Op, "args": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "Hex", "0001020304050607", "Hex"]}],
                "Salsa20 test", "Salsa20 test")

# ---- New arithmetic ops ----
recipe_test("Bytes to Integers: LE dword",
            [{"op_cls": BytesToIntegers, "args": ["4", "Little Endian", False, "Decimal"]}],
            bytes.fromhex("01020304"), "67305985")
recipe_test("Bytes to Integers: BE dword hex",
            [{"op_cls": BytesToIntegers, "args": ["4", "Big Endian", False, "Hex"]}],
            bytes.fromhex("01020304"), "0x01020304")
recipe_test("Integers to Bytes: BE dword",
            [{"op_cls": IntegersToBytes, "args": ["4", "Big Endian", False]}],
            "16909060", bytes.fromhex("01020304"))
recipe_test("Rotate word: ROL 1 on 32-bit BE",
            [{"op_cls": RotateWord, "args": [1, "Left", "32", "Big Endian"]}],
            bytes.fromhex("01020304"), bytes.fromhex("02040608"))
recipe_test("Rotate word: ROR 13 on 32-bit BE",
            [{"op_cls": RotateWord, "args": [13, "Right", "32", "Big Endian"]}],
            bytes.fromhex("01020304"),
            bytes.fromhex("%08x" % (((0x01020304 >> 13) | (0x01020304 << 19)) & 0xFFFFFFFF)))
