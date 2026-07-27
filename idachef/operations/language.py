# -*- coding: utf-8 -*-
"""Language operations - cf. CyberChef's "Language" category
(Encode text.mjs, Decode text.mjs, Remove Diacritics.mjs, etc.)"""

import re

from ..core.operation import Operation

CATEGORY = "Language"

# NATO phonetic alphabet
NATO_MAP = {
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "X-ray", "Y": "Yankee",
    "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three",
    "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight",
    "9": "Niner",
}
NATO_REV = {v: k for k, v in NATO_MAP.items()}

# Leet speak mappings
LEET_TO_NORMAL = str.maketrans({
    "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "#": "h",
    "1": "i", "0": "o", "5": "s", "7": "t", "2": "z",
    "@": "a", "$": "s", "+": "t", "9": "g",
})


class ToNATOPhonetic(Operation):
    name = "Convert to NATO alphabet"
    category = CATEGORY
    description = "Converts letters to their NATO phonetic alphabet equivalents (Alpha, Bravo, ...)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").upper()
        out = []
        for ch in text:
            if ch in NATO_MAP:
                out.append(NATO_MAP[ch])
            else:
                out.append(ch)
        return " ".join(out).encode()


class FromNATOPhonetic(Operation):
    name = "Convert from NATO alphabet"
    category = CATEGORY
    description = "Converts NATO phonetic spelling words back to letters."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        words = re.split(r"\s+", text.strip())
        out = []
        for w in words:
            w_clean = w.strip(" ,;.")
            if w_clean.title() in NATO_REV:
                out.append(NATO_REV[w_clean.title()])
            else:
                out.append(w)
        return "".join(out).encode()


class LeetSpeakDecode(Operation):
    name = "Convert Leet Speak"
    category = CATEGORY
    description = "Converts basic leet speak (1337) back to normal text."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace").lower()
        return text.translate(LEET_TO_NORMAL).encode()


class EncodeText(Operation):
    name = "Encode text"
    category = CATEGORY
    description = "Encodes text using one of several character encodings (detected or specified)."
    args = [
        {"name": "Encoding", "type": "option", "value": "UTF-8",
         "options": ["UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "Latin-1", "ASCII"]},
    ]

    def _run(self, data, args):
        enc = self.get_arg(args, "Encoding", "UTF-8")
        text = data.decode("utf-8", errors="replace")
        return text.encode(enc, errors="replace")


class DecodeText(Operation):
    name = "Decode text"
    category = CATEGORY
    description = "Decodes bytes using one of several character encodings, showing the resulting text."
    args = [
        {"name": "Encoding", "type": "option", "value": "UTF-8",
         "options": ["UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "Latin-1", "ASCII"]},
    ]

    def _run(self, data, args):
        enc = self.get_arg(args, "Encoding", "UTF-8")
        return data.decode(enc, errors="replace").encode("utf-8")


class UnicodeTextFormat(Operation):
    name = "Unicode Text Format"
    category = CATEGORY
    description = "Shows Unicode properties for each character in the input (code point, name, category)."
    args = [{"name": "Verbose", "type": "boolean", "value": False}]

    def _run(self, data, args):
        import unicodedata
        verbose = self.get_arg(args, "Verbose", False)
        text = data.decode("utf-8", errors="replace")
        out = []
        for ch in text:
            cp = ord(ch)
            name = unicodedata.name(ch, "UNKNOWN")
            cat = unicodedata.category(ch)
            if verbose:
                out.append("U+%04X  %s  [%s] %s" % (cp, ch, cat, name))
            else:
                out.append("U+%04X  %s" % (cp, ch))
        return "\n".join(out).encode()


class EscapeSmartCharacters(Operation):
    name = "Escape Smart Characters"
    category = CATEGORY
    description = "Replaces Unicode smart quotes, dashes, and other typographic chars with their ASCII equivalents."

    SMART_MAP = {
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2013": "-", "\u2014": "--", "\u00a0": " ",
        "\u00ab": "<<", "\u00bb": ">>", "\u2026": "...",
        "\u00b0": "deg", "\u2122": "(TM)", "\u00ae": "(R)",
    }

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        for smart, ascii_char in self.SMART_MAP.items():
            text = text.replace(smart, ascii_char)
        return text.encode("utf-8")


OPERATIONS = [
    ToNATOPhonetic, FromNATOPhonetic, LeetSpeakDecode,
    EncodeText, DecodeText, UnicodeTextFormat, EscapeSmartCharacters,
]