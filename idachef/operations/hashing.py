# -*- coding: utf-8 -*-
"""Hashing / checksum operations - cf. CyberChef's "Hashing" category
(MD5.mjs, SHA2.mjs, SHA3.mjs, CRC32Checksum.mjs, ...)."""

import binascii
import hashlib
import re
import struct
import zlib

from ..core.operation import Operation

CATEGORY = "Hashing"


def _make_hash_op(op_name, hashlib_name):
    class _HashOp(Operation):
        name = op_name
        category = CATEGORY
        description = "Computes the %s digest of the input, output as lowercase hex." % op_name

        def _run(self, data, args):
            return hashlib.new(hashlib_name, data).hexdigest().encode()

    _HashOp.__name__ = op_name.replace(" ", "").replace("-", "")
    return _HashOp


MD2 = _make_hash_op("MD2", "md2") if "md2" in hashlib.algorithms_available else None
MD4 = _make_hash_op("MD4", "md4") if "md4" in hashlib.algorithms_available else None
MD5 = _make_hash_op("MD5", "md5")
SHA224 = _make_hash_op("SHA224", "sha224")
SHA256 = _make_hash_op("SHA256", "sha256")
SHA384 = _make_hash_op("SHA384", "sha384")
SHA512 = _make_hash_op("SHA512", "sha512")


def _sha0_digest(data):
    """Pure-python SHA-0: the original SHA as published in FIPS 180 (1993).
    Identical to SHA-1 except the message schedule omits the extra left
    rotation: W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    msg.extend(b"\x00" * ((55 - msg_len) % 64))
    msg.extend(struct.pack(">Q", msg_len * 8))
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", bytes(msg[off:off + 64])))
        for t in range(16, 80):
            w.append(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
        a, b, c, d, e = h
        for t in range(80):
            if t < 20:
                f, k = (b & c) | (~b & d), 0x5A827999
            elif t < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif t < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            tmp = (((a << 5) | (a >> 27)) + f + e + k + w[t]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, a, tmp
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e])]
    return "".join("%08x" % x for x in h).encode()


class SHA0(Operation):
    name = "SHA0"
    category = CATEGORY
    description = "Computes the original SHA-0 digest (FIPS 180, 1993; withdrawn in favour of SHA-1), output as lowercase hex."

    def _run(self, data, args):
        return _sha0_digest(data)


SHA1 = _make_hash_op("SHA1", "sha1")
SHA3_224 = _make_hash_op("SHA3-224", "sha3_224") if "sha3_224" in hashlib.algorithms_available else None
SHA3_256 = _make_hash_op("SHA3-256", "sha3_256") if "sha3_256" in hashlib.algorithms_available else None
SHA3_384 = _make_hash_op("SHA3-384", "sha3_384") if "sha3_384" in hashlib.algorithms_available else None
SHA3_512 = _make_hash_op("SHA3-512", "sha3_512") if "sha3_512" in hashlib.algorithms_available else None
BLAKE2b = _make_hash_op("BLAKE2b", "blake2b") if "blake2b" in hashlib.algorithms_available else None
BLAKE2s = _make_hash_op("BLAKE2s", "blake2s") if "blake2s" in hashlib.algorithms_available else None


class SHA2(Operation):
    """Unified SHA2 op - outputs all SHA2 variants."""
    name = "SHA2"
    category = CATEGORY
    description = "Computes all SHA2 digests (224, 256, 384, 512)."
    args = [{"name": "Variant", "type": "option", "value": "SHA256", "options": ["SHA224", "SHA256", "SHA384", "SHA512"]}]

    def _run(self, data, args):
        variant = self.get_arg(args, "Variant", "SHA256")
        return hashlib.new(variant.lower(), data).hexdigest().encode()


class SHA3(Operation):
    """Unified SHA3 op - outputs selected SHA3 variant."""
    name = "SHA3"
    category = CATEGORY
    description = "Computes the SHA3 digest (224, 256, 384, 512)."
    args = [{"name": "Variant", "type": "option", "value": "SHA3-256", "options": ["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]}]

    def _run(self, data, args):
        variant = self.get_arg(args, "Variant", "SHA3-256").lower().replace("sha3-", "sha3_")
        if variant in hashlib.algorithms_available:
            return hashlib.new(variant, data).hexdigest().encode()
        raise ValueError("%s is not available in this Python build" % variant)


class Keccak(Operation):
    name = "Keccak"
    category = CATEGORY
    description = "Computes Keccak digest (256 or 512). Requires Python 3.10+ for built-in Keccak or pycryptodome."
    args = [{"name": "Size", "type": "option", "value": "256", "options": ["256", "512"]}]

    def _run(self, data, args):
        size = self.get_arg(args, "Size", "256")
        algo = "keccak_%s" % size
        if algo in hashlib.algorithms_available:
            return hashlib.new(algo, data).hexdigest().encode()
        try:
            from Crypto.Hash import keccak
            h = keccak.new(digest_bits=int(size), data=data)
            return h.hexdigest().encode()
        except ImportError:
            raise ValueError("Keccak requires Python 3.10+ or pycryptodome")


class RIPEMD160(Operation):
    name = "RIPEMD160"
    category = CATEGORY
    description = "Computes the RIPEMD-160 digest (relies on OpenSSL support in your Python build)."

    def _run(self, data, args):
        try:
            return hashlib.new("ripemd160", data).hexdigest().encode()
        except ValueError:
            raise ValueError("RIPEMD160 is not available in this Python's OpenSSL/hashlib build")


class CRC16(Operation):
    name = "CRC16 Checksum"
    category = CATEGORY
    description = "Computes a CRC16 checksum. CCITT (0x1021) and IBM/ARC (0x8005) polynomials supported."
    args = [{"name": "Algorithm", "type": "option", "value": "CCITT (0x1021)",
             "options": ["CCITT (0x1021)", "IBM/ARC (0x8005)"]}]

    def _run(self, data, args):
        if self.get_arg(args, "Algorithm", "CCITT (0x1021)").startswith("CCITT"):
            crc = 0xFFFF
            poly = 0x1021
            for b in data:
                crc ^= b << 8
                for _ in range(8):
                    crc = ((crc << 1) ^ poly) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
        else:
            crc = 0x0000
            poly = 0x8005
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
        return ("%04x" % crc).encode()


class CRC32(Operation):
    name = "CRC32 Checksum"
    category = CATEGORY
    description = "Computes the CRC32 checksum of the input, output as hex."

    def _run(self, data, args):
        return ("%08x" % (zlib.crc32(data) & 0xFFFFFFFF)).encode()


class CRCAll(Operation):
    name = "CRC Checksum"
    category = CATEGORY
    description = "Computes CRC-8, CRC-16, CRC-32 checksums with a choice of common variants."
    args = [{"name": "CRC Variant", "type": "option", "value": "CRC-32",
             "options": ["CRC-32", "CRC-16 (CCITT)", "CRC-16 (IBM)", "CRC-16 (Modbus)", "CRC-16 (XMODEM)", "CRC-8"]}]

    def _run(self, data, args):
        variant = self.get_arg(args, "CRC Variant", "CRC-32")
        if variant == "CRC-32":
            return ("%08x" % (zlib.crc32(data) & 0xFFFFFFFF)).encode()
        elif variant == "CRC-16 (CCITT)":
            crc = 0xFFFF
            for b in data:
                crc ^= b << 8
                for _ in range(8):
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
            return ("%04x" % crc).encode()
        elif variant == "CRC-16 (XMODEM)":
            crc = 0x0000
            for b in data:
                crc ^= b << 8
                for _ in range(8):
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
            return ("%04x" % crc).encode()
        elif variant == "CRC-16 (Modbus)":
            crc = 0xFFFF
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
            return ("%04x" % crc).encode()
        elif variant == "CRC-16 (IBM)":
            crc = 0x0000
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ 0x8005 if (crc & 1) else (crc >> 1)
            return ("%04x" % crc).encode()
        else:  # CRC-8
            crc = 0
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = ((crc << 1) ^ 0x07) if (crc & 0x80) else (crc << 1)
            return ("%02x" % (crc & 0xFF)).encode()


class Adler32(Operation):
    name = "Adler-32 Checksum"
    category = CATEGORY
    description = "Computes the Adler-32 checksum of the input, output as hex."

    def _run(self, data, args):
        return ("%08x" % (zlib.adler32(data) & 0xFFFFFFFF)).encode()


class FletcherChecksum(Operation):
    name = "Fletcher Checksum"
    category = CATEGORY
    description = "Computes Fletcher checksum (8, 16, 32, or 64-bit block size)."
    args = [{"name": "Bits", "type": "option", "value": "16", "options": ["8", "16", "32", "64"]}]

    def _run(self, data, args):
        bits = int(self.get_arg(args, "Bits", "16"))
        mod = (1 << (bits // 2)) - 1
        sum1 = sum2 = 0
        for b in data:
            sum1 = (sum1 + b) % mod
            sum2 = (sum2 + sum1) % mod
        result = (sum2 << (bits // 2)) | sum1
        return ("%%0%dx" % (bits // 4) % result).encode()


class TCPIPChecksum(Operation):
    name = "TCP/IP Checksum"
    category = CATEGORY
    description = "Computes the 16-bit one's complement Internet checksum (as used in TCP/IP headers)."

    def _run(self, data, args):
        d = bytearray(data)
        if len(d) % 2:
            d.append(0)
        s = 0
        for i in range(0, len(d), 2):
            s += (d[i] << 8) + d[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        s = (~s) & 0xFFFF
        return ("%04x" % s).encode()


class XORChecksum(Operation):
    name = "XOR Checksum"
    category = CATEGORY
    description = "Computes a simple XOR checksum (byte-wise XOR of all bytes)."

    def _run(self, data, args):
        result = 0
        for b in data:
            result ^= b
        return ("%02x" % result).encode()


class LuhnChecksum(Operation):
    name = "Luhn Checksum"
    category = CATEGORY
    description = "Validates a Luhn checksum (used for credit card numbers). Input should be digits."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        digits = [int(c) for c in text if c.isdigit()]
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        valid = (total % 10 == 0)
        return ("Checksum valid: %s  (total %d mod 10 = %d)" % (valid, total, total % 10)).encode()


class ParityBit(Operation):
    name = "Parity Bit"
    category = CATEGORY
    description = "Outputs the parity bit (0 or 1) for each input byte: the bit that would make the total number of 1s (byte plus bit) even or odd."
    args = [{"name": "Parity", "type": "option", "value": "Even", "options": ["Even", "Odd"]}]

    def _run(self, data, args):
        even = self.get_arg(args, "Parity", "Even") == "Even"
        out = []
        for b in data:
            ones = bin(b).count("1")
            bit = ones % 2 if even else 1 - (ones % 2)
            out.append(str(bit))
        return "".join(out).encode()


class HMAC(Operation):
    name = "HMAC"
    category = CATEGORY
    description = "Computes an HMAC over the input using the given key and hash algorithm."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "UTF8", "options": ["UTF8", "Hex", "Base64"]},
        {"name": "Hash function", "type": "option", "value": "sha256",
         "options": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]},
    ]

    def _run(self, data, args):
        import hmac as hmac_mod
        key_str = self.get_arg(args, "Key", "")
        fmt = self.get_arg(args, "Key format", "UTF8")
        if fmt == "Hex":
            key = binascii.unhexlify(key_str)
        elif fmt == "Base64":
            import base64
            key = base64.b64decode(key_str + "=" * (-len(key_str) % 4))
        else:
            key = key_str.encode()
        algo = self.get_arg(args, "Hash function", "sha256")
        return hmac_mod.new(key, data, algo).hexdigest().encode()


class CMAC(Operation):
    name = "CMAC"
    category = CATEGORY
    description = "Computes AES-CMAC over the input. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        try:
            from Crypto.Hash import CMAC as cmac_mod
            from Crypto.Cipher import AES
        except ImportError:
            raise ImportError("pycryptodome is required for CMAC")
        key_str = self.get_arg(args, "Key", "")
        fmt = self.get_arg(args, "Key format", "Hex")
        if fmt == "Hex":
            key = binascii.unhexlify(key_str)
        elif fmt == "Base64":
            import base64
            key = base64.b64decode(key_str + "=" * (-len(key_str) % 4))
        else:
            key = key_str.encode()
        c = cmac_mod.new(key, ciphermod=AES)
        c.update(data)
        return c.hexdigest().encode()


class Entropy(Operation):
    name = "Entropy"
    category = CATEGORY
    description = "Calculates the Shannon entropy (bits/byte, 0-8) of the input. Useful for spotting packed/encrypted data."

    def _run(self, data, args):
        import math
        if not data:
            return b"0.0"
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = -sum((c / n) * math.log2(c / n) for c in freq if c)
        return ("%.4f bits/byte" % entropy).encode()


class AnalyseHash(Operation):
    name = "Analyse Hash"
    category = CATEGORY
    description = "Guesses possible hash types based on length and character set."

    HASH_PATTERNS = [
        (32, r"^[0-9a-fA-F]{32}$", "MD5 / MD4 / NTLM"),
        (40, r"^[0-9a-fA-F]{40}$", "SHA1"),
        (56, r"^[0-9a-fA-F]{56}$", "SHA224"),
        (64, r"^[0-9a-fA-F]{64}$", "SHA256 / SHA3-256 / BLAKE2s"),
        (96, r"^[0-9a-fA-F]{96}$", "SHA384"),
        (128, r"^[0-9a-fA-F]{128}$", "SHA512 / SHA3-512 / BLAKE2b / Whirlpool"),
        (8, r"^[0-9a-fA-F]{8}$", "CRC32 / Adler32"),
        (4, r"^[0-9a-fA-F]{4}$", "CRC16"),
        (2, r"^[0-9a-fA-F]{2}$", "CRC8 / XOR Checksum"),
    ]

    def _run(self, data, args):
        text = data.decode("ascii", errors="ignore").strip()
        lines = ["Input length: %d characters" % len(text)]
        for length, pattern, kinds in self.HASH_PATTERNS:
            if len(text) == length and re.match(pattern, text):
                lines.append("  Possible: %s" % kinds)
        if len(lines) == 1:
            lines.append("  Unknown / not a plain hex hash")
        return "\n".join(lines).encode()


class MurmurHash3(Operation):
    name = "MurmurHash3"
    category = CATEGORY
    description = "Computes MurmurHash3 32-bit of the input (x86, 32-bit seed=0)."

    def _run(self, data, args):
        seed = 0
        c1 = 0xCC9E2D51
        c2 = 0x1B873593
        h = seed
        for i in range(0, len(data) - 3, 4):
            k = struct.unpack_from("<I", data, i)[0]
            k = (k * c1) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
        tail = data[len(data) - (len(data) % 4):]
        for i, b in enumerate(tail):
            k = b << (i * 8)
            k = (k * c1) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            h ^= k
        h ^= len(data)
        h ^= h >> 16
        h = (h * 0x85EBCA6B) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xC2B2AE35) & 0xFFFFFFFF
        h ^= h >> 16
        return ("%08x" % h).encode()


class NTHash(Operation):
    name = "NT Hash"
    category = CATEGORY
    description = "Computes the NT Hash (MD4 of UTF-16LE encoded password) used in NTLM authentication."

    def _run(self, data, args):
        utf16le = data.decode("utf-8", errors="replace").encode("utf-16-le")
        if "md4" in hashlib.algorithms_available:
            return hashlib.new("md4", utf16le).hexdigest().encode()
        # Fallback: use a pure Python MD4 or raise
        raise ValueError("MD4 not available in this Python's hashlib - cannot compute NT Hash")


class LMHash(Operation):
    name = "LM Hash"
    category = CATEGORY
    description = "Computes the LM Hash of a password (classic LAN Manager hash). Limited to 14 chars uppercase."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace").upper()[:14]
        text = text.ljust(14, "\x00")
        key1 = _lm_key_bytes(text[:7].encode("ascii", errors="replace"))
        key2 = _lm_key_bytes(text[7:].encode("ascii", errors="replace"))
        magic = b"KGS!@#$%"
        try:
            from Crypto.Cipher import DES
            d1 = DES.new(key1, DES.MODE_ECB)
            d2 = DES.new(key2, DES.MODE_ECB)
            return (d1.encrypt(magic)[:8] + d2.encrypt(magic)[:8]).hex().encode()
        except ImportError:
            raise ImportError("pycryptodome is required for LM Hash")


def _lm_key_bytes(seven_bytes):
    """Expand 7 bytes into an 8-byte DES key with odd parity bits
    (the standard LAN Manager key schedule, cf. Samba's smb_key())."""
    b = seven_bytes
    key = [
        b[0] >> 1,
        ((b[0] & 0x01) << 6) | (b[1] >> 2),
        ((b[1] & 0x03) << 5) | (b[2] >> 3),
        ((b[2] & 0x07) << 4) | (b[3] >> 4),
        ((b[3] & 0x0F) << 3) | (b[4] >> 5),
        ((b[4] & 0x1F) << 2) | (b[5] >> 6),
        ((b[5] & 0x3F) << 1) | (b[6] >> 7),
        b[6] & 0x7F,
    ]
    out = bytearray()
    for bits in key:
        parity = 1
        for j in range(1, 8):
            parity ^= (bits >> j) & 1
        out.append(((bits << 1) | parity) & 0xFF)
    return bytes(out)


class FrequencyDistribution(Operation):
    name = "Frequency Distribution"
    category = CATEGORY
    description = "Shows a byte frequency histogram of the input."
    args = [{"name": "Top N", "type": "number", "value": 20}]

    def _run(self, data, args):
        top_n = int(self.get_arg(args, "Top N", 20))
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        total = len(data) or 1
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:top_n]
        lines = []
        for byte_val, count in sorted_freq:
            ch = chr(byte_val) if 32 <= byte_val < 127 else "."
            bar = "#" * max(1, count * 40 // max(freq.values()))
            lines.append("%02x (%s): %5d (%5.1f%%) %s" % (byte_val, ch, count, count * 100.0 / total, bar))
        return "\n".join(lines).encode()


OPERATIONS = [
    AnalyseHash, Entropy, FrequencyDistribution,
    SHA0, SHA1, SHA2, SHA3, Keccak, RIPEMD160,
    MD5, SHA224, SHA256, SHA384, SHA512,
    CRC16, CRC32, CRCAll, Adler32, FletcherChecksum, TCPIPChecksum, XORChecksum,
    LuhnChecksum, ParityBit,
    HMAC, CMAC, MurmurHash3, NTHash, LMHash,
]
# Add optional ops that may be None
if MD2:
    OPERATIONS.insert(0, MD2)
if SHA3_224:
    OPERATIONS.insert(OPERATIONS.index(SHA3), SHA3_224)
if SHA3_256:
    OPERATIONS.insert(OPERATIONS.index(SHA3), SHA3_256)
if SHA3_384:
    OPERATIONS.insert(OPERATIONS.index(SHA3), SHA3_384)
if SHA3_512:
    OPERATIONS.insert(OPERATIONS.index(SHA3), SHA3_512)
if BLAKE2b:
    OPERATIONS.append(BLAKE2b)
if BLAKE2s:
    OPERATIONS.append(BLAKE2s)