# -*- coding: utf-8 -*-
"""Data format operations - cf. CyberChef's "Data format" category
(FromBase64.mjs, ToBase64.mjs, FromHex.mjs, ToHex.mjs, etc.)"""

import base64
import binascii
import csv
import html
import io
import json
import re
import struct
import urllib.parse
import uuid

from ..core.operation import Operation

CATEGORY = "Data format"


class ToHex(Operation):
    name = "To Hex"
    category = CATEGORY
    description = "Converts a byte array to a hex string."
    args = [
        {"name": "Delimiter", "type": "option", "value": "Space",
         "options": ["Space", "None", "Comma", "0x", "\\x", "Newline"]},
    ]

    DELIMS = {"Space": " ", "None": "", "Comma": ",", "0x": "0x", "\\x": "\\x", "Newline": "\n"}

    def _run(self, data, args):
        delim_name = self.get_arg(args, "Delimiter", "Space")
        hexed = [("%02x" % b) for b in data]
        if delim_name in ("0x", "\\x") and hexed:
            sep = delim_name
            return ("".join(sep + h for h in hexed)).encode()
        sep = self.DELIMS.get(delim_name, " ")
        return sep.join(hexed).encode()


class FromHex(Operation):
    name = "From Hex"
    category = CATEGORY
    description = "Converts a hex string back to raw bytes. Whitespace, 0x/\\x prefixes and commas are ignored."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        text = re.sub(r"0x|\\x|,|\n|\r|\t", " ", text)
        clean = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(clean) % 2 == 1:
            clean = clean[:-1]
        return binascii.unhexlify(clean)


class ToHexdump(Operation):
    name = "To Hexdump"
    category = CATEGORY
    description = "Creates a classic hexdump of the input (offset: hex bytes | ASCII)."
    args = [{"name": "Bytes per line", "type": "number", "value": 16}]

    def _run(self, data, args):
        bpl = max(1, int(self.get_arg(args, "Bytes per line", 16)))
        lines = []
        for i in range(0, len(data), bpl):
            chunk = data[i:i + bpl]
            hex_part = " ".join("%02x" % b for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append("%08x  %-*s |%s|" % (i, bpl * 3, hex_part, ascii_part))
        return "\n".join(lines).encode()


class FromHexdump(Operation):
    name = "From Hexdump"
    category = CATEGORY
    description = "Parses a hexdump back to raw bytes. Expects lines with hex bytes in columns."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        out = bytearray()
        for line in text.split("\n"):
            m = re.search(r"(?:\|)?\s*((?:[0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2})", line)
            if m:
                hex_str = "".join(m.group(1).split())
                out.extend(binascii.unhexlify(hex_str))
        return bytes(out)


class ToBase64(Operation):
    name = "To Base64"
    category = CATEGORY
    description = "Encodes data as Base64."
    args = [
        {"name": "Alphabet", "type": "option", "value": "Standard (A-Za-z0-9+/=)",
         "options": ["Standard (A-Za-z0-9+/=)", "URL Safe (A-Za-z0-9-_)"]},
    ]

    def _run(self, data, args):
        alpha = self.get_arg(args, "Alphabet")
        if alpha and "URL Safe" in alpha:
            return base64.urlsafe_b64encode(data)
        return base64.b64encode(data)


class FromBase64(Operation):
    name = "From Base64"
    category = CATEGORY
    description = "Decodes Base64 data. Auto-fixes missing padding."
    args = [
        {"name": "Alphabet", "type": "option", "value": "Standard (A-Za-z0-9+/=)",
         "options": ["Standard (A-Za-z0-9+/=)", "URL Safe (A-Za-z0-9-_)"]},
        {"name": "Remove non-alphabet chars", "type": "boolean", "value": True},
    ]

    def _run(self, data, args):
        alpha = self.get_arg(args, "Alphabet")
        strip = self.get_arg(args, "Remove non-alphabet chars", True)
        text = data.decode("utf-8", errors="ignore")
        if strip:
            allowed = "A-Za-z0-9\\-_=" if alpha and "URL Safe" in alpha else "A-Za-z0-9+/="
            text = re.sub("[^%s]" % allowed, "", text)
        text += "=" * (-len(text) % 4)
        if alpha and "URL Safe" in alpha:
            return base64.urlsafe_b64decode(text)
        return base64.b64decode(text)


class ToBase32(Operation):
    name = "To Base32"
    category = CATEGORY
    description = "Encodes data as Base32 (RFC 4648)."

    def _run(self, data, args):
        return base64.b32encode(data)


class FromBase32(Operation):
    name = "From Base32"
    category = CATEGORY
    description = "Decodes Base32 (RFC 4648) data."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip().upper()
        text = re.sub(r"[^A-Z2-7=]", "", text)
        text += "=" * (-len(text) % 8)
        return base64.b32decode(text)


class ToBase45(Operation):
    name = "To Base45"
    category = CATEGORY
    description = "Encodes data as Base45 (RFC 9285)."

    BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    def _run(self, data, args):
        out = []
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                n = (data[i] << 8) + data[i + 1]
                e = n % 45
                d = (n // 45) % 45
                c = n // 2025
                out.extend([self.BASE45_CHARSET[c], self.BASE45_CHARSET[d], self.BASE45_CHARSET[e]])
            else:
                n = data[i]
                d = n % 45
                c = n // 45
                out.extend([self.BASE45_CHARSET[c], self.BASE45_CHARSET[d]])
        return "".join(out).encode()


class FromBase45(Operation):
    name = "From Base45"
    category = CATEGORY
    description = "Decodes Base45 (RFC 9285) data."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        text = re.sub(r"[^0-9A-Za-z $%*+\-./:]", "", text)
        out = bytearray()
        i = 0
        while i < len(text):
            if i + 2 < len(text):
                c = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".index(text[i])
                d = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".index(text[i + 1])
                e = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".index(text[i + 2])
                n = c * 45 * 45 + d * 45 + e
                out.extend(struct.pack(">H", n))
                i += 3
            else:
                c = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".index(text[i])
                d = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".index(text[i + 1]) if i + 1 < len(text) else 0
                n = c * 45 + d
                out.append(n & 0xFF)
                i += 2
        return bytes(out)


class ToBase58(Operation):
    name = "To Base58"
    category = CATEGORY
    description = "Encodes data as Base58 (Bitcoin-style, no ambiguous chars)."

    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def _run(self, data, args):
        n = int.from_bytes(data, "big")
        if n == 0:
            return b"1"
        out = []
        while n:
            n, r = divmod(n, 58)
            out.append(self.ALPHABET[r])
        # Leading zeros
        for b in data:
            if b == 0:
                out.append("1")
            else:
                break
        return "".join(reversed(out)).encode()


class FromBase58(Operation):
    name = "From Base58"
    category = CATEGORY
    description = "Decodes Base58 (Bitcoin-style) data."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = 0
        for ch in text:
            if ch in alphabet:
                n = n * 58 + alphabet.index(ch)
        # Leading ones
        prefix = 0
        for ch in text:
            if ch == "1":
                prefix += 1
            else:
                break
        out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return b"\x00" * prefix + out


class ToBase62(Operation):
    name = "To Base62"
    category = CATEGORY
    description = "Encodes data as Base62 (0-9A-Za-z)."

    ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def _run(self, data, args):
        n = int.from_bytes(data, "big")
        if n == 0:
            return b"0"
        out = []
        while n:
            n, r = divmod(n, 62)
            out.append(self.ALPHABET[r])
        return "".join(reversed(out)).encode()


class FromBase62(Operation):
    name = "From Base62"
    category = CATEGORY
    description = "Decodes Base62 (0-9A-Za-z) data."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        n = 0
        for ch in text:
            if ch in alphabet:
                n = n * 62 + alphabet.index(ch)
        return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


class ToBinary(Operation):
    name = "To Binary"
    category = CATEGORY
    description = "Converts bytes to an 8-bit binary string."
    args = [{"name": "Delimiter", "type": "option", "value": "Space", "options": ["Space", "None", "Newline"]}]

    def _run(self, data, args):
        delim = {"Space": " ", "None": "", "Newline": "\n"}[self.get_arg(args, "Delimiter", "Space")]
        return delim.join(format(b, "08b") for b in data).encode()


class FromBinary(Operation):
    name = "From Binary"
    category = CATEGORY
    description = "Converts an 8-bit binary string back to bytes."

    def _run(self, data, args):
        text = re.sub(r"[^01]", "", data.decode("utf-8", errors="ignore"))
        text = text[: len(text) - (len(text) % 8)]
        return bytes(int(text[i:i + 8], 2) for i in range(0, len(text), 8))


class ToOctal(Operation):
    name = "To Octal"
    category = CATEGORY
    description = "Converts bytes to octal representation."
    args = [{"name": "Delimiter", "type": "option", "value": "Space", "options": ["Space", "None", "Comma"]}]

    def _run(self, data, args):
        delim = {"Space": " ", "None": "", "Comma": ","}[self.get_arg(args, "Delimiter", "Space")]
        return delim.join("%03o" % b for b in data).encode()


class FromOctal(Operation):
    name = "From Octal"
    category = CATEGORY
    description = "Converts octal representation back to bytes."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        nums = re.findall(r"[0-7]+", text)
        return bytes(int(n, 8) & 0xFF for n in nums if n)


class ToDecimal(Operation):
    name = "To Decimal"
    category = CATEGORY
    description = "Converts bytes to a list of decimal byte values."
    args = [{"name": "Delimiter", "type": "option", "value": "Space", "options": ["Space", "Comma", "Newline"]}]

    def _run(self, data, args):
        delim = {"Space": " ", "Comma": ",", "Newline": "\n"}[self.get_arg(args, "Delimiter", "Space")]
        return delim.join(str(b) for b in data).encode()


class FromDecimal(Operation):
    name = "From Decimal"
    category = CATEGORY
    description = "Converts a list of decimal byte values back to raw bytes."

    def _run(self, data, args):
        nums = re.findall(r"\d+", data.decode("utf-8", errors="ignore"))
        return bytes(int(n) & 0xFF for n in nums)


class ToFloat(Operation):
    name = "To Float"
    category = CATEGORY
    description = "Interpret bytes as IEEE 754 floats (32-bit or 64-bit)."
    args = [{"name": "Format", "type": "option", "value": "32-bit (float)", "options": ["32-bit (float)", "64-bit (double)"]}]

    def _run(self, data, args):
        fmt = self.get_arg(args, "Format", "32-bit (float)")
        if "64" in fmt:
            values = [struct.unpack(">d", data[i:i + 8])[0] for i in range(0, len(data) - 7, 8)]
        else:
            values = [struct.unpack(">f", data[i:i + 4])[0] for i in range(0, len(data) - 3, 4)]
        return "\n".join(str(v) for v in values).encode()


class FromFloat(Operation):
    name = "From Float"
    category = CATEGORY
    description = "Convert decimal float strings to IEEE 754 bytes."
    args = [{"name": "Format", "type": "option", "value": "32-bit (float)", "options": ["32-bit (float)", "64-bit (double)"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        fmt = self.get_arg(args, "Format", "32-bit (float)")
        numbers = re.findall(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", text)
        out = bytearray()
        for n in numbers:
            v = float(n)
            if "64" in fmt:
                out.extend(struct.pack(">d", v))
            else:
                out.extend(struct.pack(">f", v))
        return bytes(out)


class ToCharcode(Operation):
    name = "To Charcode"
    category = CATEGORY
    description = "Converts bytes to space separated hex character codes (like JS charCodeAt)."
    args = [{"name": "Base", "type": "option", "value": "16", "options": ["16", "10", "8", "2"]}]

    def _run(self, data, args):
        base = int(self.get_arg(args, "Base", "16"))
        fmt = {16: "%x", 10: "%d", 8: "%o", 2: "{0:b}"}
        out = []
        for b in data:
            if base == 2:
                out.append(format(b, "b"))
            else:
                out.append(fmt[base] % b)
        return " ".join(out).encode()


class FromCharcode(Operation):
    name = "From Charcode"
    category = CATEGORY
    description = "Converts space separated character codes back to bytes."
    args = [{"name": "Base", "type": "option", "value": "16", "options": ["16", "10", "8", "2"]}]

    def _run(self, data, args):
        base = int(self.get_arg(args, "Base", "16"))
        tokens = data.decode("utf-8", errors="ignore").split()
        return bytes(int(t, base) & 0xFF for t in tokens if t)


class URLEncode(Operation):
    name = "URL Encode"
    category = CATEGORY
    description = "Percent-encodes special characters for use in a URL."
    args = [{"name": "Encode all special chars", "type": "boolean", "value": False}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        if self.get_arg(args, "Encode all special chars", False):
            return urllib.parse.quote(text, safe="").encode()
        return urllib.parse.quote(text).encode()


class URLDecode(Operation):
    name = "URL Decode"
    category = CATEGORY
    description = "Decodes percent-encoded URL characters."

    def _run(self, data, args):
        return urllib.parse.unquote_to_bytes(data)


class ToHTMLEntity(Operation):
    name = "To HTML Entity"
    category = CATEGORY
    description = "Converts special characters into HTML entities."

    def _run(self, data, args):
        return html.escape(data.decode("utf-8", errors="replace"), quote=True).encode()


class FromHTMLEntity(Operation):
    name = "From HTML Entity"
    category = CATEGORY
    description = "Converts HTML entities back into characters."

    def _run(self, data, args):
        return html.unescape(data.decode("utf-8", errors="replace")).encode("utf-8")


class EscapeUnicodeChars(Operation):
    name = "Escape Unicode Characters"
    category = CATEGORY
    description = "Escapes Unicode characters to \\uXXXX notation (code points above 0xFFFF become UTF-16 surrogate pairs)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        out = []
        for ch in text:
            cp = ord(ch)
            if cp > 127:
                if cp > 0xFFFF:
                    cp -= 0x10000
                    hi = 0xD800 + (cp >> 10)
                    lo = 0xDC00 + (cp & 0x3FF)
                    out.append("\\u%04x\\u%04x" % (hi, lo))
                else:
                    out.append("\\u%04x" % cp)
            else:
                out.append(ch)
        return "".join(out).encode()


class UnescapeUnicodeChars(Operation):
    name = "Unescape Unicode Characters"
    category = CATEGORY
    description = "Unescapes \\uXXXX sequences back to Unicode characters."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text).encode("utf-8")


MORSE_MAP = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "/": "-..-.", "-": "-....-", "@": ".--.-.", "(": "-.--.", ")": "-.--.-",
}
MORSE_MAP_REV = {v: k for k, v in MORSE_MAP.items()}


class ToMorseCode(Operation):
    name = "To Morse Code"
    category = CATEGORY
    description = "Converts letters/numbers to Morse code (letters space separated, words '/' separated)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        words = text.split(" ")
        out_words = []
        for word in words:
            letters = [MORSE_MAP.get(ch, "") for ch in word if ch in MORSE_MAP]
            out_words.append(" ".join(l for l in letters if l))
        return " / ".join(out_words).encode()


class FromMorseCode(Operation):
    name = "From Morse Code"
    category = CATEGORY
    description = "Converts Morse code (letters space separated, words '/' separated) back to text."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        words = text.split("/")
        out_words = []
        for word in words:
            letters = [MORSE_MAP_REV.get(tok.strip(), "") for tok in word.strip().split(" ") if tok.strip()]
            out_words.append("".join(letters))
        return " ".join(out_words).encode()


class QuotedPrintableEncode(Operation):
    name = "To Quoted Printable"
    category = CATEGORY
    description = "Encodes data using Quoted-Printable (RFC 2045) encoding."

    def _run(self, data, args):
        import quopri
        return quopri.encodestring(data)


class QuotedPrintableDecode(Operation):
    name = "From Quoted Printable"
    category = CATEGORY
    description = "Decodes Quoted-Printable (RFC 2045) encoded data."

    def _run(self, data, args):
        import quopri
        return quopri.decodestring(data)


class ToBase85(Operation):
    name = "To Base85"
    category = CATEGORY
    description = "Encodes data as Base85 (Python's b85 alphabet, as used by e.g. git)."

    def _run(self, data, args):
        return base64.b85encode(data)


class FromBase85(Operation):
    name = "From Base85"
    category = CATEGORY
    description = "Decodes Base85 data. Supports two alphabets: b85 (RFC 1924) and Ascii85 (Adobe, e.g. Postscript/PDF)."
    args = [
        {"name": "Alphabet", "type": "option", "value": "Auto-detect",
         "options": ["Auto-detect", "b85 (RFC 1924)", "Ascii85 (Adobe)"]},
    ]

    def _run(self, data, args):
        text = re.sub(r"\s+", "", data.decode("utf-8", errors="ignore"))
        alphabet = self.get_arg(args, "Alphabet", "Auto-detect")

        if alphabet == "b85 (RFC 1924)":
            return base64.b85decode(text)

        if alphabet == "Ascii85 (Adobe)":
            return base64.a85decode(text, adobe=False)

        # Auto-detect: try b85 first, fall back to Ascii85
        try:
            return base64.b85decode(text)
        except (ValueError, base64.binascii.Error):
            pass

        try:
            return base64.a85decode(text, adobe=False)
        except (ValueError, base64.binascii.Error):
            raise ValueError(
                "Could not decode Base85. Try selecting the alphabet manually "
                "(b85 for RFC 1924, Ascii85 for Adobe/Postscript style)."
            )


class SwapEndianness(Operation):
    name = "Swap Endianness"
    category = CATEGORY
    description = "Reverses byte order within each word of the given size. Handy for flipping RE'd integers between LE/BE."
    args = [{"name": "Word length (bytes)", "type": "option", "value": "4", "options": ["2", "4", "8"]}]

    def _run(self, data, args):
        word = int(self.get_arg(args, "Word length (bytes)", "4"))
        out = bytearray()
        for i in range(0, len(data) - (len(data) % word), word):
            out.extend(data[i:i + word][::-1])
        out.extend(data[len(data) - (len(data) % word):])  # leftover, unchanged
        return bytes(out)


class EscapeString(Operation):
    name = "Escape String"
    category = CATEGORY
    description = "Escapes special characters (\\n, \\t, \\\", non-printables as \\xHH) for embedding in source code."

    def _run(self, data, args):
        out = []
        for b in data:
            if b == 0x5c:
                out.append("\\\\")
            elif b == 0x22:
                out.append('\\"')
            elif b == 0x0a:
                out.append("\\n")
            elif b == 0x0d:
                out.append("\\r")
            elif b == 0x09:
                out.append("\\t")
            elif 32 <= b < 127:
                out.append(chr(b))
            else:
                out.append("\\x%02x" % b)
        return "".join(out).encode()


class UnescapeString(Operation):
    name = "Unescape String"
    category = CATEGORY
    description = "Interprets C-style backslash escapes (\\n, \\t, \\r, \\\\, \\xHH, \\uHHHH with surrogate pairs, \\0) in the input; other characters pass through unchanged."

    ESCAPES = {
        "n": "\n", "r": "\r", "t": "\t", "0": "\0", "a": "\a",
        "b": "\b", "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"',
    }

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        out = []
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == "x" and i + 3 < n and all(c in "0123456789abcdefABCDEF" for c in text[i + 2:i + 4]):
                    out.append(chr(int(text[i + 2:i + 4], 16)))
                    i += 4
                    continue
                if nxt == "u":
                    hex_match = re.match(r"\\u([0-9a-fA-F]{4})", text[i:])
                    if hex_match:
                        cp = int(hex_match.group(1), 16)
                        i += 6
                        # Combine UTF-16 surrogate pairs
                        if 0xD800 <= cp < 0xDC00 and text[i:i + 2] == "\\u":
                            low = re.match(r"\\u([0-9a-fA-F]{4})", text[i:])
                            if low and 0xDC00 <= int(low.group(1), 16) < 0xE000:
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (int(low.group(1), 16) - 0xDC00)
                                i += 6
                        out.append(chr(cp))
                        continue
                if nxt in self.ESCAPES:
                    out.append(self.ESCAPES[nxt])
                    i += 2
                    continue
                # Unknown escape - keep the character as-is
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            i += 1
        return "".join(out).encode("utf-8")


class ToPunycode(Operation):
    name = "To Punycode"
    category = CATEGORY
    description = "Encodes a Unicode domain label to ASCII-compatible Punycode (xn--...)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace").strip()
        labels = text.split(".")
        return ".".join(label.encode("idna").decode("ascii") if any(ord(c) > 127 for c in label) else label
                         for label in labels).encode()


class FromPunycode(Operation):
    name = "From Punycode"
    category = CATEGORY
    description = "Decodes an ASCII-compatible Punycode domain label (xn--...) back to Unicode."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace").strip()
        labels = text.split(".")
        decoded = []
        for label in labels:
            if label.lower().startswith("xn--"):
                try:
                    decoded.append(label.encode("ascii").decode("idna"))
                except UnicodeError:
                    # Not valid punycode – keep original label as-is
                    decoded.append(label)
            else:
                decoded.append(label)
        return ".".join(decoded).encode("utf-8")


class ToBCD(Operation):
    name = "To BCD"
    category = CATEGORY
    description = "Converts decimal digit characters to Binary-Coded Decimal (each decimal digit to a nibble)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        digits = re.findall(r"[0-9]", text)
        out = bytearray()
        for i in range(0, len(digits) - 1, 2):
            out.append((int(digits[i]) << 4) | int(digits[i + 1]))
        if len(digits) % 2:
            out.append((int(digits[-1]) << 4))
        return bytes(out)


class FromBCD(Operation):
    name = "From BCD"
    category = CATEGORY
    description = "Converts Binary-Coded Decimal back to decimal digits."

    def _run(self, data, args):
        out = []
        for b in data:
            out.append(str((b >> 4) & 0xF))
            out.append(str(b & 0xF))
        return "".join(out).encode()


class ToHexContent(Operation):
    name = "To Hex Content"
    category = CATEGORY
    description = "Encodes data as a hex content representation (e.g., for HTTP bodies or RE hex dumps)."

    def _run(self, data, args):
        return binascii.hexlify(data)


class FromHexContent(Operation):
    name = "From Hex Content"
    category = CATEGORY
    description = "Decodes hex content representation back to bytes."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        clean = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(clean) % 2:
            clean = clean[:-1]
        return binascii.unhexlify(clean)


class CSVParsingToJSON(Operation):
    name = "CSV to JSON"
    category = CATEGORY
    description = "Converts CSV data to JSON. First row is treated as headers."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            return b"[]"
        headers = rows[0]
        result = [dict(zip(headers, row)) for row in rows[1:]]
        return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")


class JSONToCSV(Operation):
    name = "JSON to CSV"
    category = CATEGORY
    description = "Converts a JSON array of objects to CSV."

    def _run(self, data, args):
        obj = json.loads(data.decode("utf-8", errors="replace"))
        if not isinstance(obj, list) or not obj:
            return b""
        headers = list(obj[0].keys())
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in obj:
            writer.writerow([row.get(h, "") for h in headers])
        return output.getvalue().encode("utf-8")


class NormaliseUnicode(Operation):
    name = "Normalise Unicode"
    category = CATEGORY
    description = "Normalises Unicode using NFC, NFD, NFKC, or NFKD forms."
    args = [{"name": "Form", "type": "option", "value": "NFC", "options": ["NFC", "NFD", "NFKC", "NFKD"]}]

    def _run(self, data, args):
        import unicodedata
        form = self.get_arg(args, "Form", "NFC")
        text = data.decode("utf-8", errors="replace")
        return unicodedata.normalize(form, text).encode("utf-8")


class TextIntegerConversion(Operation):
    name = "Text-Integer Conversion"
    category = CATEGORY
    description = "Converts between a decimal/hex integer string and a text representation (4 or 8 byte packed)."
    args = [
        {"name": "Mode", "type": "option", "value": "Integer to Text",
         "options": ["Integer to Text", "Text to Integer"]},
        {"name": "Word size (bytes)", "type": "option", "value": "4", "options": ["4", "8"]},
        {"name": "Endianness", "type": "option", "value": "Big Endian", "options": ["Big Endian", "Little Endian"]},
    ]

    def _run(self, data, args):
        mode = self.get_arg(args, "Mode", "Integer to Text")
        word_size = int(self.get_arg(args, "Word size (bytes)", "4"))
        big_endian = self.get_arg(args, "Endianness", "Big Endian") == "Big Endian"
        if mode == "Text to Integer":
            nums = re.findall(r"-?\d+", data.decode("utf-8", errors="ignore"))
            out = bytearray()
            for s in nums:
                val = int(s)
                endian = ">" if big_endian else "<"
                fmt_char = "Q" if word_size == 8 else "I"
                out.extend(struct.pack(endian + fmt_char, val))
            return bytes(out)
        else:
            endian = ">" if big_endian else "<"
            fmt_char = "Q" if word_size == 8 else "I"
            out = []
            for i in range(0, len(data) - word_size + 1, word_size):
                val = struct.unpack(endian + fmt_char, data[i:i + word_size])[0]
                out.append(str(val))
            return "\n".join(out).encode()


class GenerateUUID(Operation):
    name = "Generate UUID"
    category = CATEGORY
    description = "Generates random UUIDs. The input data is used as a seed (or ignored if empty)."
    args = [{"name": "Count", "type": "number", "value": 1}]

    def _run(self, data, args):
        count = max(1, min(100, int(self.get_arg(args, "Count", 1))))
        uuids = [str(uuid.uuid4()) for _ in range(count)]
        return "\n".join(uuids).encode()


OPERATIONS = [
    ToHex, FromHex, ToHexdump, FromHexdump,
    ToBase64, FromBase64, ToBase32, FromBase32,
    ToBase45, FromBase45, ToBase58, FromBase58, ToBase62, FromBase62,
    ToBase85, FromBase85,
    ToBinary, FromBinary, ToOctal, FromOctal,
    ToDecimal, FromDecimal, ToFloat, FromFloat,
    ToCharcode, FromCharcode,
    URLEncode, URLDecode, ToHTMLEntity, FromHTMLEntity,
    EscapeUnicodeChars, UnescapeUnicodeChars,
    ToMorseCode, FromMorseCode, QuotedPrintableEncode, QuotedPrintableDecode,
    SwapEndianness, EscapeString, UnescapeString,
    ToPunycode, FromPunycode,
    ToBCD, FromBCD, ToHexContent, FromHexContent,
    CSVParsingToJSON, JSONToCSV, NormaliseUnicode,
    TextIntegerConversion, GenerateUUID,
]