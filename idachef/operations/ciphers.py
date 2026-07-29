# -*- coding: utf-8 -*-
"""Encryption / encoding operations - cf. CyberChef's "Encryption / Encoding"
category (XOR.mjs, ROT13.mjs, AESDecrypt.mjs, RC4.mjs, ...)."""

import base64 as _b64
import binascii
import hashlib
import re
import struct

from ..core.operation import Operation
from ..core.utils import key_bytes

CATEGORY = "Encryption / Encoding"

try:
    from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish, ChaCha20, ARC2
    from Crypto.Util.Padding import pad, unpad
    HAVE_PYCRYPTODOME = True
except Exception:  # pragma: no cover - optional dependency
    HAVE_PYCRYPTODOME = False


class XOR(Operation):
    name = "XOR"
    category = CATEGORY
    description = (
        "XORs the input with the given key, repeating the key as necessary. "
        "Set 'Unit' to UTF-16LE (word) for wide-string obfuscation, where the "
        "key is XORed against each 16-bit code unit instead of each raw byte "
        "-- e.g. 0x74 0x00 XOR key 3 gives 0x77 0x00 (matches the common "
        "WCHAR-loop XOR scheme), not 0x77 0x03 as a plain byte-wise XOR would."
    )
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Unit", "type": "option", "value": "Byte", "options": ["Byte", "UTF-16LE (word)"]},
    ]

    def _run(self, data, args):
        key_str = self.get_arg(args, "Key", "")
        key_fmt = self.get_arg(args, "Key format", "Hex")
        unit = self.get_arg(args, "Unit", "Byte")
        key = key_bytes(key_str, key_fmt)
        if not key:
            return data
        if unit == "UTF-16LE (word)":
            return self._xor_utf16le(data, key)
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def _xor_utf16le(data, key):
        """XOR data as a stream of little-endian 16-bit code units. Any
        trailing odd byte is padded with 0x00 for the XOR then trimmed
        back off so the output length always matches the input length."""
        padded = data + (b"\x00" if len(data) % 2 else b"")
        data_units = struct.unpack("<%dH" % (len(padded) // 2), padded)
        key_padded = key + (b"\x00" if len(key) % 2 else b"")
        key_units = struct.unpack("<%dH" % (len(key_padded) // 2), key_padded)
        out_units = [u ^ key_units[i % len(key_units)] for i, u in enumerate(data_units)]
        out = struct.pack("<%dH" % len(out_units), *out_units)
        return out[:len(data)]


class XORBruteForce(Operation):
    name = "XOR Brute Force"
    category = CATEGORY
    description = ("Tries every single-byte XOR key (0x00-0xFF) and returns the "
                    "results whose printable-ASCII ratio is highest, one per line "
                    "prefixed with the key used.")
    args = [
        {"name": "Max results", "type": "number", "value": 10},
        {"name": "Crib (optional, case-insensitive)", "type": "string", "value": ""},
    ]

    def _run(self, data, args):
        max_results = int(self.get_arg(args, "Max results", 10))
        crib = self.get_arg(args, "Crib (optional, case-insensitive)", "").lower().encode()
        scored = []
        for key in range(256):
            out = bytes(b ^ key for b in data)
            if crib and crib not in out.lower():
                continue
            alpha_space = sum(1 for b in out if (65 <= b <= 90) or (97 <= b <= 122) or b == 32)
            printable = sum(1 for b in out if 32 <= b < 127)
            score = (alpha_space * 1.0 + (printable - alpha_space) * 0.1) / max(1, len(out))
            scored.append((score, key, out))
        scored.sort(key=lambda t: t[0], reverse=True)
        lines = []
        for score, key, out in scored[:max_results]:
            preview = out.decode("latin-1")
            preview = "".join(c if c.isprintable() else "." for c in preview)
            lines.append("Key = 0x%02x (score %.2f): %s" % (key, score, preview))
        return "\n".join(lines).encode("utf-8")


class ROT13(Operation):
    name = "ROT13"
    category = CATEGORY
    description = "Rotates alphabet characters by the given amount (Caesar cipher)."
    args = [
        {"name": "Rotation", "type": "number", "value": 13},
        {"name": "Rotate numbers too (ROT47-style digits)", "type": "boolean", "value": False},
    ]

    def _run(self, data, args):
        rot = int(self.get_arg(args, "Rotation", 13)) % 26
        rot_digits = self.get_arg(args, "Rotate numbers too (ROT47-style digits)", False)
        out = bytearray()
        for b in data:
            if 65 <= b <= 90:
                out.append((b - 65 + rot) % 26 + 65)
            elif 97 <= b <= 122:
                out.append((b - 97 + rot) % 26 + 97)
            elif rot_digits and 48 <= b <= 57:
                out.append((b - 48 + rot) % 10 + 48)
            else:
                out.append(b)
        return bytes(out)


class ROT13BruteForce(Operation):
    name = "ROT13 Brute Force"
    category = CATEGORY
    description = "Tries all 26 ROT amounts and returns each result prefixed with the amount."

    def _run(self, data, args):
        lines = []
        for rot in range(26):
            out = bytearray()
            for b in data:
                if 65 <= b <= 90:
                    out.append((b - 65 + rot) % 26 + 65)
                elif 97 <= b <= 122:
                    out.append((b - 97 + rot) % 26 + 97)
                else:
                    out.append(b)
            lines.append("ROT%02d: %s" % (rot, bytes(out).decode("latin-1")))
        return "\n".join(lines).encode("utf-8")


class ROT47(Operation):
    name = "ROT47"
    category = CATEGORY
    description = "Rotates all printable ASCII characters (33-126) by the given amount."
    args = [{"name": "Rotation", "type": "number", "value": 47}]

    def _run(self, data, args):
        rot = int(self.get_arg(args, "Rotation", 47)) % 94
        out = bytearray()
        for b in data:
            if 33 <= b <= 126:
                out.append(33 + ((b - 33 + rot) % 94))
            else:
                out.append(b)
        return bytes(out)


class ROT47BruteForce(Operation):
    name = "ROT47 Brute Force"
    category = CATEGORY
    description = "Tries all 94 ROT47 amounts and returns each result."

    def _run(self, data, args):
        lines = []
        for rot in range(1, 94):
            out = bytearray()
            for b in data:
                if 33 <= b <= 126:
                    out.append(33 + ((b - 33 + rot) % 94))
                else:
                    out.append(b)
            lines.append("ROT%02d: %s" % (rot, bytes(out).decode("latin-1")))
        return "\n".join(lines).encode("utf-8")


class ROT8000(Operation):
    name = "ROT8000"
    category = CATEGORY
    description = ("Rotates valid Unicode BMP code points (0x00-0xFFFF) by 0x8000, "
                    "mapping printable chars back and forth. Similar to CyberChef's ROT8000.")

    def _run(self, data, args):
        out = bytearray()
        text = data.decode("utf-8", errors="replace")
        for ch in text:
            cp = ord(ch)
            if cp <= 0xFFFF:
                cp = (cp + 0x8000) % 0x10000
            out.extend(chr(cp).encode("utf-8", errors="replace"))
        return bytes(out)


class ROR13(Operation):
    name = "ROR13"
    category = CATEGORY
    description = "Shifts each byte right by 13 bits (rotate right 13, same as rotate left 3)."

    def _run(self, data, args):
        return bytes(((b >> 3) | ((b << 5) & 0xFF)) for b in data)


class Atbash(Operation):
    name = "Atbash Cipher"
    category = CATEGORY
    description = "Reverses the alphabet (A<->Z, B<->Y, ...); a self-reciprocal substitution cipher."

    def _run(self, data, args):
        out = bytearray()
        for b in data:
            if 65 <= b <= 90:
                out.append(90 - (b - 65))
            elif 97 <= b <= 122:
                out.append(122 - (b - 97))
            else:
                out.append(b)
        return bytes(out)


class VigenereEncode(Operation):
    name = "Vigenere Encode"
    category = CATEGORY
    description = "Encodes using a Vigenere cipher with the given alphabetic key."
    args = [{"name": "Key", "type": "string", "value": "key"}]

    def _run(self, data, args):
        return _vigenere(data, self.get_arg(args, "Key", "key"), decode=False)


class VigenereDecode(Operation):
    name = "Vigenere Decode"
    category = CATEGORY
    description = "Decodes a Vigenere cipher with the given alphabetic key."
    args = [{"name": "Key", "type": "string", "value": "key"}]

    def _run(self, data, args):
        return _vigenere(data, self.get_arg(args, "Key", "key"), decode=True)


def _vigenere(data, key, decode):
    key = re.sub(r"[^A-Za-z]", "", key) or "A"
    key_shifts = [ord(c.upper()) - 65 for c in key]
    out = bytearray()
    ki = 0
    for b in data:
        if 65 <= b <= 90 or 97 <= b <= 122:
            base = 65 if b < 97 else 97
            shift = key_shifts[ki % len(key_shifts)]
            if decode:
                shift = -shift
            out.append((b - base + shift) % 26 + base)
            ki += 1
        else:
            out.append(b)
    return bytes(out)


# ---- Bit shift / rotate operations already in Arithmetic/Logic, but also
#      needed in this category for CyberChef parity ----
class BitShiftLeft(Operation):
    name = "Bit Shift Left"
    category = CATEGORY
    description = "Shifts each byte left by N bits (bits shifted out are dropped)."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes(((b << n) & 0xFF) for b in data)


class BitShiftRight(Operation):
    name = "Bit Shift Right"
    category = CATEGORY
    description = "Shifts each byte right by N bits."
    args = [{"name": "Amount", "type": "number", "value": 1}]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1)) % 8
        return bytes((b >> n) for b in data)


class RC4(Operation):
    name = "RC4"
    category = CATEGORY
    description = "Encrypts/decrypts using the RC4 stream cipher (symmetric). Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "UTF8", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "UTF8"))
        if not key:
            raise ValueError("RC4 requires a key")
        if HAVE_PYCRYPTODOME:
            return ARC4.new(key).encrypt(data)
        return _rc4_pure(data, key)


def _rc4_pure(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


class RC4Drop(Operation):
    name = "RC4 Drop"
    category = CATEGORY
    description = "RC4 with a configurable number of initial keystream bytes dropped."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "UTF8", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Drop bytes", "type": "number", "value": 768},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "UTF8"))
        drop = int(self.get_arg(args, "Drop bytes", 768))
        if not key:
            raise ValueError("RC4 Drop requires a key")
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        # Drop initial keystream bytes
        for _ in range(drop):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
        out = bytearray()
        for b in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) % 256])
        return bytes(out)


class AESEncrypt(Operation):
    name = "AES Encrypt"
    category = CATEGORY
    description = "Encrypts data with AES. Requires pycryptodome (pip install pycryptodome)."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": "00000000000000000000000000000000"[:32]},
        {"name": "IV format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB", "CTR", "GCM"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        mode_name = self.get_arg(args, "Mode", "CBC")
        mode = {"CBC": AES.MODE_CBC, "ECB": AES.MODE_ECB, "CTR": AES.MODE_CTR, "GCM": AES.MODE_GCM}[mode_name]
        if mode_name == "ECB":
            cipher = AES.new(key, mode)
            return cipher.encrypt(pad(data, AES.block_size))
        iv = key_bytes(self.get_arg(args, "IV", ""), self.get_arg(args, "IV format", "Hex"))
        if mode_name == "CBC":
            cipher = AES.new(key, mode, iv=iv[:16].ljust(16, b"\x00"))
            return cipher.encrypt(pad(data, AES.block_size))
        if mode_name == "CTR":
            cipher = AES.new(key, mode, nonce=iv[:8].ljust(8, b"\x00"))
            return cipher.encrypt(data)
        cipher = AES.new(key, mode, nonce=iv[:12].ljust(12, b"\x00"))
        ct, tag = cipher.encrypt_and_digest(data)
        return ct + tag


class AESDecrypt(Operation):
    name = "AES Decrypt"
    category = CATEGORY
    description = "Decrypts AES-encrypted data. Requires pycryptodome (pip install pycryptodome)."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "IV format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB", "CTR", "GCM"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        mode_name = self.get_arg(args, "Mode", "CBC")
        if mode_name == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            return unpad(cipher.decrypt(data), AES.block_size)
        iv = key_bytes(self.get_arg(args, "IV", ""), self.get_arg(args, "IV format", "Hex"))
        if mode_name == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv=iv[:16].ljust(16, b"\x00"))
            return unpad(cipher.decrypt(data), AES.block_size)
        if mode_name == "CTR":
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8].ljust(8, b"\x00"))
            return cipher.decrypt(data)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv[:12].ljust(12, b"\x00"))
        ct, tag = data[:-16], data[-16:]
        return cipher.decrypt_and_verify(ct, tag)


class AESKeyWrap(Operation):
    name = "AES Key Wrap"
    category = CATEGORY
    description = "Wraps a key using AES Key Wrap (RFC 3394). Input should be a multiple of 8 bytes."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        # Pad to multiple of 8
        if len(data) % 8:
            padding = 8 - (len(data) % 8)
            data = data + b"\x00" * padding
        if len(data) < 16:
            data = data.ljust(16, b"\x00")
        n = len(data) // 8
        A = b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"
        R = [A] + [data[i * 8:(i + 1) * 8] for i in range(n)]
        cipher = AES.new(key, AES.MODE_ECB)
        for j in range(6):
            for i in range(1, n + 1):
                B = cipher.encrypt(R[0] + R[i])
                R[0] = bytes(a ^ (((n * j) + i) >> (8 * (7 - k))) & 0xFF for k, a in enumerate(B[:8]))
                R[i] = B[8:]
        return R[0] + b"".join(R[1:])


class AESKeyUnwrap(Operation):
    name = "AES Key Unwrap"
    category = CATEGORY
    description = "Unwraps a key using AES Key Unwrap (RFC 3394)."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        n = (len(data) // 8) - 1
        A = data[:8]
        R = [A] + [data[(i + 1) * 8:(i + 2) * 8] for i in range(n)]
        cipher = AES.new(key, AES.MODE_ECB)
        for j in range(5, -1, -1):
            for i in range(n, 0, -1):
                B = cipher.decrypt(bytes(
                    a ^ (((n * j) + i) >> (8 * (7 - k))) & 0xFF for k, a in enumerate(R[0])
                ) + R[i])
                R[0] = B[:8]
                R[i] = B[8:]
        if R[0] != b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6":
            raise ValueError("AES Key Unwrap: integrity check failed (bad IV)")
        result = b"".join(R[1:])
        # Strip trailing zero padding
        result = result.rstrip(b"\x00")
        return result


class DESEncrypt(Operation):
    name = "DES Encrypt"
    category = CATEGORY
    description = "Encrypts data with DES (CBC/ECB). Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        block = DES.block_size
        mode_name = self.get_arg(args, "Mode", "CBC")
        if mode_name == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:block].ljust(block, b"\x00")
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        return cipher.encrypt(pad(data, block))


class DESDecrypt(Operation):
    name = "DES Decrypt"
    category = CATEGORY
    description = "Decrypts DES (CBC/ECB) data. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        block = DES.block_size
        mode_name = self.get_arg(args, "Mode", "CBC")
        if mode_name == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:block].ljust(block, b"\x00")
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(data), block)


class TripleDESEncrypt(Operation):
    name = "Triple DES Encrypt"
    category = CATEGORY
    description = "Encrypts data with Triple DES (CBC/ECB). Key should be 16 or 24 bytes. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "IV format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        block = DES3.block_size
        mode_name = self.get_arg(args, "Mode", "CBC")
        if mode_name == "ECB":
            cipher = DES3.new(key, DES3.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), self.get_arg(args, "IV format", "Hex"))
            iv = iv[:block].ljust(block, b"\x00")
            cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        return cipher.encrypt(pad(data, block))


class TripleDESDecrypt(Operation):
    name = "Triple DES Decrypt"
    category = CATEGORY
    description = "Decrypts Triple DES (CBC/ECB) data. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "IV format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        block = DES3.block_size
        mode_name = self.get_arg(args, "Mode", "CBC")
        if mode_name == "ECB":
            cipher = DES3.new(key, DES3.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), self.get_arg(args, "IV format", "Hex"))
            iv = iv[:block].ljust(block, b"\x00")
            cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(data), block)


class BlowfishEncrypt(Operation):
    name = "Blowfish Encrypt"
    category = CATEGORY
    description = "Encrypts data with Blowfish (CBC/ECB). Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        if self.get_arg(args, "Mode") == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:8].ljust(8, b"\x00")
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        return cipher.encrypt(pad(data, Blowfish.block_size))


class BlowfishDecrypt(Operation):
    name = "Blowfish Decrypt"
    category = CATEGORY
    description = "Decrypts Blowfish (CBC/ECB) data. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        if self.get_arg(args, "Mode") == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:8].ljust(8, b"\x00")
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(data), Blowfish.block_size)


class RC2Encrypt(Operation):
    name = "RC2 Encrypt"
    category = CATEGORY
    description = "Encrypts data with RC2 (CBC/ECB). Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        if self.get_arg(args, "Mode") == "ECB":
            cipher = ARC2.new(key, ARC2.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:8].ljust(8, b"\x00")
            cipher = ARC2.new(key, ARC2.MODE_CBC, iv=iv)
        return cipher.encrypt(pad(data, ARC2.block_size))


class RC2Decrypt(Operation):
    name = "RC2 Decrypt"
    category = CATEGORY
    description = "Decrypts RC2 (CBC/ECB) data. Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "IV", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "CBC", "options": ["CBC", "ECB"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        if self.get_arg(args, "Mode") == "ECB":
            cipher = ARC2.new(key, ARC2.MODE_ECB)
        else:
            iv = key_bytes(self.get_arg(args, "IV", ""), "Hex")[:8].ljust(8, b"\x00")
            cipher = ARC2.new(key, ARC2.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(data), ARC2.block_size)


class ChaCha20Op(Operation):
    name = "ChaCha"
    category = CATEGORY
    description = "Encrypts/decrypts using the ChaCha20 stream cipher (symmetric). Requires pycryptodome."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Nonce", "type": "string", "value": ""},
        {"name": "Nonce format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        if not HAVE_PYCRYPTODOME:
            raise ImportError("pycryptodome is not installed - run: pip install pycryptodome")
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        nonce = key_bytes(self.get_arg(args, "Nonce", ""), self.get_arg(args, "Nonce format", "Hex"))
        nonce = nonce[:8].ljust(8, b"\x00") if len(nonce) <= 8 else nonce[:12]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.encrypt(data)


# ---- TEA ----
class TEAEncrypt(Operation):
    name = "TEA Encrypt"
    category = CATEGORY
    description = "Encrypts data with TEA (Tiny Encryption Algorithm). Key should be 16 bytes."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Rounds", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        rounds = int(self.get_arg(args, "Rounds", 32))
        delta = 0x9E3779B9
        K = struct.unpack(">4I", key)
        # Pad to 8 bytes
        pad_len = (8 - (len(data) % 8)) % 8
        data = data + bytes([pad_len] * pad_len)
        blocks = [struct.unpack(">2I", data[i:i + 8]) for i in range(0, len(data), 8)]
        out = bytearray()
        for v0, v1 in blocks:
            _sum = 0
            for _ in range(rounds):
                _sum = (_sum + delta) & 0xFFFFFFFF
                v0 = (v0 + (((v1 << 4) + K[0]) ^ (v1 + _sum) ^ ((v1 >> 5) + K[1]))) & 0xFFFFFFFF
                v1 = (v1 + (((v0 << 4) + K[2]) ^ (v0 + _sum) ^ ((v0 >> 5) + K[3]))) & 0xFFFFFFFF
            out.extend(struct.pack(">2I", v0, v1))
        return bytes(out)


class TEADecrypt(Operation):
    name = "TEA Decrypt"
    category = CATEGORY
    description = "Decrypts TEA-encrypted data. Key should be 16 bytes."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Rounds", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        rounds = int(self.get_arg(args, "Rounds", 32))
        delta = 0x9E3779B9
        K = struct.unpack(">4I", key)
        blocks = [struct.unpack(">2I", data[i:i + 8]) for i in range(0, len(data), 8)]
        out = bytearray()
        for v0, v1 in blocks:
            _sum = (delta * rounds) & 0xFFFFFFFF
            for _ in range(rounds):
                v1 = (v1 - (((v0 << 4) + K[2]) ^ (v0 + _sum) ^ ((v0 >> 5) + K[3]))) & 0xFFFFFFFF
                v0 = (v0 - (((v1 << 4) + K[0]) ^ (v1 + _sum) ^ ((v1 >> 5) + K[1]))) & 0xFFFFFFFF
                _sum = (_sum - delta) & 0xFFFFFFFF
            out.extend(struct.pack(">2I", v0, v1))
        result = bytes(out)
        # Remove PKCS-style padding (last byte = pad length)
        if result:
            pad_len = result[-1]
            if 1 <= pad_len <= 8:
                if all(b == pad_len for b in result[-pad_len:]):
                    result = result[:-pad_len]
        return result


# ---- XTEA ----
class XTEAEncrypt(Operation):
    name = "XTEA Encrypt"
    category = CATEGORY
    description = "Encrypts data with XTEA (eXtended TEA). Key should be 16 bytes."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Rounds", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        rounds = int(self.get_arg(args, "Rounds", 32))
        delta = 0x9E3779B9
        K = struct.unpack(">4I", key)
        pad_len = (8 - (len(data) % 8)) % 8
        data = data + bytes([pad_len] * pad_len)
        blocks = [struct.unpack(">2I", data[i:i + 8]) for i in range(0, len(data), 8)]
        out = bytearray()
        for v0, v1 in blocks:
            _sum = 0
            for _ in range(rounds):
                v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (_sum + K[_sum & 3]))) & 0xFFFFFFFF
                _sum = (_sum + delta) & 0xFFFFFFFF
                v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (_sum + K[(_sum >> 11) & 3]))) & 0xFFFFFFFF
            out.extend(struct.pack(">2I", v0, v1))
        return bytes(out)


class XTEADecrypt(Operation):
    name = "XTEA Decrypt"
    category = CATEGORY
    description = "Decrypts XTEA-encrypted data. Key should be 16 bytes."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
        {"name": "Rounds", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        rounds = int(self.get_arg(args, "Rounds", 32))
        delta = 0x9E3779B9
        K = struct.unpack(">4I", key)
        blocks = [struct.unpack(">2I", data[i:i + 8]) for i in range(0, len(data), 8)]
        out = bytearray()
        for v0, v1 in blocks:
            _sum = (delta * rounds) & 0xFFFFFFFF
            for _ in range(rounds):
                v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (_sum + K[(_sum >> 11) & 3]))) & 0xFFFFFFFF
                _sum = (_sum - delta) & 0xFFFFFFFF
                v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (_sum + K[_sum & 3]))) & 0xFFFFFFFF
            out.extend(struct.pack(">2I", v0, v1))
        result = bytes(out)
        if result:
            pad_len = result[-1]
            if 1 <= pad_len <= 8 and all(b == pad_len for b in result[-pad_len:]):
                result = result[:-pad_len]
        return result


# ---- XXTEA ----
_XXTEA_DELTA = 0x9E3779B9


def _xxtea_mx(_sum, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((_sum ^ y) + (k[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF


class XXTEAEncrypt(Operation):
    name = "XXTEA Encrypt"
    category = CATEGORY
    description = "Encrypts data with XXTEA (Corrected Block TEA)."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        k = list(struct.unpack(">4I", key))
        pad_len = (4 - (len(data) % 4)) % 4
        data = data + bytes([pad_len] * pad_len)
        v = list(struct.unpack(">%dI" % (len(data) // 4), data))
        n = len(v)
        if n < 2:
            return data
        q = 6 + 52 // n
        _sum = 0
        z = v[n - 1]
        for _ in range(q):
            _sum = (_sum + _XXTEA_DELTA) & 0xFFFFFFFF
            e = (_sum >> 2) & 3
            for p in range(n - 1):
                y = v[p + 1]
                v[p] = (v[p] + _xxtea_mx(_sum, y, z, p, e, k)) & 0xFFFFFFFF
                z = v[p]
            y = v[0]
            v[n - 1] = (v[n - 1] + _xxtea_mx(_sum, y, z, n - 1, e, k)) & 0xFFFFFFFF
            z = v[n - 1]
        return struct.pack(">%dI" % n, *v)


class XXTEADecrypt(Operation):
    name = "XXTEA Decrypt"
    category = CATEGORY
    description = "Decrypts XXTEA-encrypted data."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Key format", "type": "option", "value": "Hex", "options": ["Hex", "UTF8", "Base64"]},
    ]

    def _run(self, data, args):
        key = key_bytes(self.get_arg(args, "Key", ""), self.get_arg(args, "Key format", "Hex"))
        key = key[:16].ljust(16, b"\x00")
        k = list(struct.unpack(">4I", key))
        v = list(struct.unpack(">%dI" % (len(data) // 4), data))
        n = len(v)
        if n < 2:
            return data
        q = 6 + 52 // n
        _sum = (_XXTEA_DELTA * q) & 0xFFFFFFFF
        y = v[0]
        for _ in range(q):
            e = (_sum >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - _xxtea_mx(_sum, y, z, p, e, k)) & 0xFFFFFFFF
                y = v[p]
            z = v[n - 1]
            v[0] = (v[0] - _xxtea_mx(_sum, y, z, 0, e, k)) & 0xFFFFFFFF
            y = v[0]
            _sum = (_sum - _XXTEA_DELTA) & 0xFFFFFFFF
        result = struct.pack(">%dI" % n, *v)
        if result:
            pad_len = result[-1]
            if 1 <= pad_len <= 4 and all(b == pad_len for b in result[-pad_len:]):
                result = result[:-pad_len]
        return result


class Substitute(Operation):
    name = "Substitute"
    category = CATEGORY
    description = "Performs a simple character substitution using a mapping string (format: 'a=b c=d ...')."

    args = [{"name": "Substitutions", "type": "text", "value": ""}]

    def _run(self, data, args):
        subs_text = self.get_arg(args, "Substitutions", "")
        mapping = {}
        for part in subs_text.split():
            if "=" in part:
                a, b = part.split("=", 1)
                mapping[a] = b
        text = data.decode("utf-8", errors="replace")
        for k, v in mapping.items():
            text = text.replace(k, v)
        return text.encode("utf-8")


class AffineEncode(Operation):
    name = "Affine Cipher Encode"
    category = CATEGORY
    description = "Classic affine cipher: each letter x -> (a*x + b) mod 26. 'a' must be coprime with 26."
    args = [{"name": "a", "type": "number", "value": 5}, {"name": "b", "type": "number", "value": 8}]

    def _run(self, data, args):
        a = int(self.get_arg(args, "a", 5))
        b = int(self.get_arg(args, "b", 8))
        out = bytearray()
        for ch in data:
            if 65 <= ch <= 90:
                out.append((a * (ch - 65) + b) % 26 + 65)
            elif 97 <= ch <= 122:
                out.append((a * (ch - 97) + b) % 26 + 97)
            else:
                out.append(ch)
        return bytes(out)


class AffineDecode(Operation):
    name = "Affine Cipher Decode"
    category = CATEGORY
    description = "Decodes a classic affine cipher: x -> a_inv*(y - b) mod 26."
    args = [{"name": "a", "type": "number", "value": 5}, {"name": "b", "type": "number", "value": 8}]

    def _run(self, data, args):
        a = int(self.get_arg(args, "a", 5))
        b = int(self.get_arg(args, "b", 8))
        a_inv = pow(a, -1, 26)
        out = bytearray()
        for ch in data:
            if 65 <= ch <= 90:
                out.append((a_inv * (ch - 65 - b)) % 26 + 65)
            elif 97 <= ch <= 122:
                out.append((a_inv * (ch - 97 - b)) % 26 + 97)
            else:
                out.append(ch)
        return bytes(out)


class A1Z26Encode(Operation):
    name = "A1Z26 Cipher Encode"
    category = CATEGORY
    description = "Encodes letters to their A1Z26 numeric equivalents (A=1, B=2, ... Z=26)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        out = []
        for ch in text:
            if 65 <= ord(ch) <= 90:
                out.append(str(ord(ch) - 64))
            elif 97 <= ord(ch) <= 122:
                out.append(str(ord(ch) - 96))
            else:
                out.append(ch)
        return " ".join(out).encode()


class A1Z26Decode(Operation):
    name = "A1Z26 Cipher Decode"
    category = CATEGORY
    description = "Decodes A1Z26 numeric equivalents back to letters."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        words = re.split(r"[,\s]+", text.strip())
        out = []
        for w in words:
            w = w.strip()
            if w.isdigit() and 1 <= int(w) <= 26:
                out.append(chr(int(w) + 64))
            else:
                out.append(w)
        return "".join(out).encode()


class RailFenceEncode(Operation):
    name = "Rail Fence Cipher Encode"
    category = CATEGORY
    description = "Encodes text using a zig-zag rail-fence transposition cipher."
    args = [{"name": "Rails", "type": "number", "value": 3}]

    def _run(self, data, args):
        rails = max(2, int(self.get_arg(args, "Rails", 3)))
        text = data.decode("utf-8", errors="replace")
        fence = [[] for _ in range(rails)]
        rail, direction = 0, 1
        for ch in text:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return "".join("".join(row) for row in fence).encode("utf-8")


class RailFenceDecode(Operation):
    name = "Rail Fence Cipher Decode"
    category = CATEGORY
    description = "Decodes a zig-zag rail-fence transposition cipher."
    args = [{"name": "Rails", "type": "number", "value": 3}]

    def _run(self, data, args):
        rails = max(2, int(self.get_arg(args, "Rails", 3)))
        text = data.decode("utf-8", errors="replace")
        n = len(text)
        pattern = []
        rail, direction = 0, 1
        for _ in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        counts = [pattern.count(r) for r in range(rails)]
        idx = 0
        rows = []
        for c in counts:
            rows.append(list(text[idx:idx + c]))
            idx += c
        row_pos = [0] * rails
        out = []
        for r in pattern:
            out.append(rows[r][row_pos[r]])
            row_pos[r] += 1
        return "".join(out).encode("utf-8")


class BaconEncode(Operation):
    name = "Bacon Cipher Encode"
    category = CATEGORY
    description = "Encodes text using Bacon's cipher (A/B or 0/1 5-bit encoding)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        out = []
        for ch in text:
            if 65 <= ord(ch) <= 90:
                val = ord(ch) - 65
                code = "".join("B" if (val >> (4 - i)) & 1 else "A" for i in range(5))
                out.append(code)
            else:
                out.append(ch)
        return " ".join(out).encode()


class BaconDecode(Operation):
    name = "Bacon Cipher Decode"
    category = CATEGORY
    description = "Decodes Bacon's cipher (A/B or 0/1 5-bit encoding) back to letters."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        words = re.split(r"\s+", text.strip())
        out = []
        for w in words:
            if len(w) == 5 and all(c in "AB01" for c in w):
                w = w.replace("0", "A").replace("1", "B")
                val = sum((1 << (4 - i)) for i, c in enumerate(w) if c == "B")
                out.append(chr(val + 65))
            else:
                out.append(w)
        return "".join(out).encode()


class BifidEncode(Operation):
    name = "Bifid Cipher Encode"
    category = CATEGORY
    description = "Encodes text using the Bifid cipher with a 5x5 Polybius square."
    args = [{"name": "Keyword", "type": "string", "value": ""}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        keyword = self.get_arg(args, "Keyword", "").upper()
        square = _build_polybius_square(keyword)
        coord_map = {}
        for r, row in enumerate(square):
            for c, ch in enumerate(row):
                if ch != " ":
                    coord_map[ch] = (r, c)
        rows = []
        cols = []
        for ch in text:
            if ch in coord_map:
                r, c = coord_map[ch]
                rows.append(r)
                cols.append(c)
        coords = rows + cols
        out = []
        for i in range(0, len(coords), 2):
            if i + 1 < len(coords):
                r, c = coords[i], coords[i + 1]
                out.append(square[r][c])
        return "".join(out).encode()


class BifidDecode(Operation):
    name = "Bifid Cipher Decode"
    category = CATEGORY
    description = "Decodes text using the Bifid cipher."
    args = [{"name": "Keyword", "type": "string", "value": ""}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        keyword = self.get_arg(args, "Keyword", "").upper()
        square = _build_polybius_square(keyword)
        coord_map = {}
        for r, row in enumerate(square):
            for c, ch in enumerate(row):
                if ch != " ":
                    coord_map[ch] = (r, c)
        coords = []
        for ch in text:
            if ch in coord_map:
                coords.extend(coord_map[ch])
        half = len(coords) // 2
        out = []
        for i in range(half):
            r, c = coords[i], coords[i + half]
            out.append(square[r][c])
        return "".join(out).encode()


def _build_polybius_square(keyword):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I/J merged
    seen = set()
    key_uniq = []
    for ch in keyword.upper():
        ch = "I" if ch == "J" else ch
        if ch in alphabet and ch not in seen:
            seen.add(ch)
            key_uniq.append(ch)
    for ch in alphabet:
        if ch not in seen:
            key_uniq.append(ch)
    return [key_uniq[i:i + 5] for i in range(0, 25, 5)]


class CaesarBox(Operation):
    name = "Caesar Box Cipher"
    category = CATEGORY
    description = "Arranges the text into a fixed-width box and reads it column by column (or vice versa)."
    args = [{"name": "Box width", "type": "number", "value": 4}]

    def _run(self, data, args):
        width = max(1, int(self.get_arg(args, "Box width", 4)))
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"[^A-Za-z]", "", text)
        height = (len(text) + width - 1) // width
        grid = [list(text[i * width:(i + 1) * width].ljust(width)) for i in range(height)]
        out = []
        for c in range(width):
            for r in range(height):
                ch = grid[r][c]
                if ch != " ":
                    out.append(ch)
        return "".join(out).encode()


class DerivePBKDF2(Operation):
    name = "Derive PBKDF2 Key"
    category = CATEGORY
    description = "Derives a key using PBKDF2-HMAC-SHA256. Output is hex-encoded."
    args = [
        {"name": "Password", "type": "string", "value": ""},
        {"name": "Salt (hex)", "type": "string", "value": ""},
        {"name": "Iterations", "type": "number", "value": 100000},
        {"name": "Key length (bytes)", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        password = self.get_arg(args, "Password", "").encode("utf-8")
        salt_hex = self.get_arg(args, "Salt (hex)", "")
        if salt_hex:
            salt = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", salt_hex))
        else:
            salt = data  # Use input as salt
        iterations = int(self.get_arg(args, "Iterations", 100000))
        dklen = int(self.get_arg(args, "Key length (bytes)", 32))
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)
        return binascii.hexlify(dk)


class DeriveHKDF(Operation):
    name = "Derive HKDF Key"
    category = CATEGORY
    description = "Derives a key using HKDF-HMAC-SHA256. Output is hex-encoded."
    args = [
        {"name": "Salt (hex, optional)", "type": "string", "value": ""},
        {"name": "Info", "type": "string", "value": ""},
        {"name": "Key length (bytes)", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        import hmac as hmac_mod
        ikm = data
        salt_hex = self.get_arg(args, "Salt (hex, optional)", "")
        if salt_hex:
            salt = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", salt_hex))
        else:
            salt = b"\x00" * 32
        info = self.get_arg(args, "Info", "").encode("utf-8")
        dklen = int(self.get_arg(args, "Key length (bytes)", 32))

        # HKDF-Extract
        prk = hmac_mod.new(salt, ikm, "sha256").digest()
        # HKDF-Expand
        n = (dklen + 31) // 32
        t = b""
        okm = bytearray()
        for i in range(1, n + 1):
            t = hmac_mod.new(prk, t + info + bytes([i]), "sha256").digest()
            okm.extend(t)
        return binascii.hexlify(bytes(okm[:dklen]))


class BCrypt(Operation):
    name = "Bcrypt"
    category = CATEGORY
    description = "Hashes input using bcrypt. Requires bcrypt package (pip install bcrypt)."

    def _run(self, data, args):
        try:
            import bcrypt
        except ImportError:
            raise ImportError("bcrypt is not installed - run: pip install bcrypt")
        if not data:
            return b""
        hashed = bcrypt.hashpw(data, bcrypt.gensalt())
        return hashed


class Scrypt(Operation):
    name = "Scrypt"
    category = CATEGORY
    description = "Derives a key using scrypt KDF. Output is hex-encoded."
    args = [
        {"name": "Salt (hex)", "type": "string", "value": ""},
        {"name": "N", "type": "number", "value": 16384},
        {"name": "r", "type": "number", "value": 8},
        {"name": "p", "type": "number", "value": 1},
        {"name": "Key length (bytes)", "type": "number", "value": 32},
    ]

    def _run(self, data, args):
        password = data
        salt_hex = self.get_arg(args, "Salt (hex)", "")
        if salt_hex:
            salt = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", salt_hex))
        else:
            salt = b"salt"
        n = int(self.get_arg(args, "N", 16384))
        r = int(self.get_arg(args, "r", 8))
        p = int(self.get_arg(args, "p", 1))
        dklen = int(self.get_arg(args, "Key length (bytes)", 32))
        dk = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
        return binascii.hexlify(dk)


OPERATIONS = [
    XOR, XORBruteForce, ROT13, ROT13BruteForce, ROT47, ROT47BruteForce,
    ROT8000, ROR13, Atbash, VigenereEncode, VigenereDecode,
    BitShiftLeft, BitShiftRight, RC4, RC4Drop,
    AESEncrypt, AESDecrypt, AESKeyWrap, AESKeyUnwrap,
    DESEncrypt, DESDecrypt, TripleDESEncrypt, TripleDESDecrypt,
    BlowfishEncrypt, BlowfishDecrypt, RC2Encrypt, RC2Decrypt, ChaCha20Op,
    TEAEncrypt, TEADecrypt, XTEAEncrypt, XTEADecrypt, XXTEAEncrypt, XXTEADecrypt,
    Substitute,
    AffineEncode, AffineDecode, A1Z26Encode, A1Z26Decode,
    RailFenceEncode, RailFenceDecode,
    BaconEncode, BaconDecode, BifidEncode, BifidDecode, CaesarBox,
    DerivePBKDF2, DeriveHKDF, BCrypt, Scrypt,
]
