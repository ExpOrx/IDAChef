# -*- coding: utf-8 -*-
"""General utility operations - cf. CyberChef's "Utils" category
(Reverse.mjs, FindReplace.mjs, CaseConversion.mjs, Diff.mjs, ...)."""

import datetime
import difflib
import math
import random
import re

from ..core.operation import Operation

CATEGORY = "Utils"


class Reverse(Operation):
    name = "Reverse"
    category = CATEGORY
    description = "Reverses the input, byte-wise or line-wise."
    args = [{"name": "By", "type": "option", "value": "Byte", "options": ["Byte", "Line"]}]

    def _run(self, data, args):
        if self.get_arg(args, "By", "Byte") == "Line":
            lines = data.split(b"\n")
            return b"\n".join(reversed(lines))
        return data[::-1]


class ToUpperCase(Operation):
    name = "To Upper case"
    category = CATEGORY
    description = "Converts text to UPPER CASE."

    def _run(self, data, args):
        return data.decode("utf-8", errors="replace").upper().encode("utf-8")


class ToLowerCase(Operation):
    name = "To Lower case"
    category = CATEGORY
    description = "Converts text to lower case."

    def _run(self, data, args):
        return data.decode("utf-8", errors="replace").lower().encode("utf-8")


class SwapCase(Operation):
    name = "Swap case"
    category = CATEGORY
    description = "Swaps the case of each letter in the input."

    def _run(self, data, args):
        return data.decode("utf-8", errors="replace").swapcase().encode("utf-8")


class AlternatingCaps(Operation):
    name = "Alternating Caps"
    category = CATEGORY
    description = "Alternates capitalization: aBcDeF..."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        out = []
        upper = True
        for ch in text:
            if ch.isalpha():
                out.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                out.append(ch)
                # Toggle on non-alpha too to get Classic CyberChef behavior
                upper = not upper
        return "".join(out).encode("utf-8")


class StripWhitespace(Operation):
    name = "Remove whitespace"
    category = CATEGORY
    description = "Removes all whitespace, or just leading/trailing whitespace per line."
    args = [{"name": "Mode", "type": "option", "value": "All whitespace",
             "options": ["All whitespace", "Trim each line", "Collapse repeats to single space"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        mode = self.get_arg(args, "Mode", "All whitespace")
        if mode == "All whitespace":
            return re.sub(r"\s+", "", text).encode("utf-8")
        if mode == "Trim each line":
            return "\n".join(line.strip() for line in text.split("\n")).encode("utf-8")
        return re.sub(r"[ \t]+", " ", text).encode("utf-8")


class RemoveNullBytes(Operation):
    name = "Remove null bytes"
    category = CATEGORY
    description = "Strips all 0x00 bytes from the input."

    def _run(self, data, args):
        return data.replace(b"\x00", b"")


class RemoveANSIEscapes(Operation):
    name = "Remove ANSI Escape Codes"
    category = CATEGORY
    description = "Strips ANSI escape sequences (color codes, etc.) from text."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
        return ansi_re.sub("", text).encode("utf-8")


class FindReplace(Operation):
    name = "Find / Replace"
    category = CATEGORY
    description = "Finds and replaces text, with optional regex and case sensitivity."
    args = [
        {"name": "Find", "type": "string", "value": ""},
        {"name": "Replace", "type": "string", "value": ""},
        {"name": "Regex", "type": "boolean", "value": False},
        {"name": "Case sensitive", "type": "boolean", "value": True},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        find = self.get_arg(args, "Find", "")
        replace = self.get_arg(args, "Replace", "")
        is_regex = self.get_arg(args, "Regex", False)
        case_sensitive = self.get_arg(args, "Case sensitive", True)
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = find if is_regex else re.escape(find)
        return re.sub(pattern, replace, text, flags=flags).encode("utf-8")


class RegexSubstitution(Operation):
    name = "Regex Substitution"
    category = CATEGORY
    description = "Applies a regex substitution (like Find/Replace but regex-only). See Extractors for the match-listing 'Regular expression' op."
    args = [
        {"name": "Regex", "type": "string", "value": ""},
        {"name": "Replace", "type": "string", "value": ""},
        {"name": "Case sensitive", "type": "boolean", "value": True},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        pattern = self.get_arg(args, "Regex", "")
        replace = self.get_arg(args, "Replace", "")
        flags = 0 if self.get_arg(args, "Case sensitive", True) else re.IGNORECASE
        return re.sub(pattern, replace, text, flags=flags).encode("utf-8")


class SortLines(Operation):
    name = "Sort"
    category = CATEGORY
    description = "Sorts lines alphabetically, numerically, by length, or randomly."
    args = [
        {"name": "Order", "type": "option", "value": "Alphabetical (A-Z)",
         "options": ["Alphabetical (A-Z)", "Alphabetical (Z-A)", "Numeric", "Length", "Random"]},
        {"name": "Unique only", "type": "boolean", "value": False},
    ]

    def _run(self, data, args):
        lines = data.decode("utf-8", errors="replace").split("\n")
        order = self.get_arg(args, "Order")
        if self.get_arg(args, "Unique only", False):
            seen = set()
            uniq_lines = []
            for l in lines:
                if l not in seen:
                    seen.add(l)
                    uniq_lines.append(l)
            lines = uniq_lines
        if order == "Alphabetical (Z-A)":
            lines.sort(reverse=True)
        elif order == "Numeric":
            lines.sort(key=lambda l: float(re.search(r"-?\d+(\.\d+)?", l).group()) if re.search(r"-?\d+(\.\d+)?", l) else 0)
        elif order == "Length":
            lines.sort(key=len)
        elif order == "Random":
            random.shuffle(lines)
        else:
            lines.sort()
        return "\n".join(lines).encode("utf-8")


class Shuffle(Operation):
    name = "Shuffle"
    category = CATEGORY
    description = "Randomly shuffles the lines of the input."

    def _run(self, data, args):
        lines = data.decode("utf-8", errors="replace").split("\n")
        random.shuffle(lines)
        return "\n".join(lines).encode()


class Unique(Operation):
    name = "Unique"
    category = CATEGORY
    description = "Removes duplicate lines, keeping only the first occurrence."

    def _run(self, data, args):
        lines = data.decode("utf-8", errors="replace").split("\n")
        seen = set()
        out = []
        for l in lines:
            if l not in seen:
                seen.add(l)
                out.append(l)
        return "\n".join(out).encode()


class Split(Operation):
    name = "Split"
    category = CATEGORY
    description = "Splits the input on a delimiter."
    args = [{"name": "Delimiter", "type": "string", "value": ","}]

    def _run(self, data, args):
        delim = self.get_arg(args, "Delimiter", ",")
        text = data.decode("utf-8", errors="replace")
        return ("\n".join(text.split(delim))).encode("utf-8")


class FilterOp(Operation):
    name = "Filter"
    category = CATEGORY
    description = "Keeps only lines that match (or don't match) a regex pattern."
    args = [
        {"name": "Regex", "type": "string", "value": ""},
        {"name": "Invert", "type": "boolean", "value": False},
    ]

    def _run(self, data, args):
        pattern = self.get_arg(args, "Regex", "")
        invert = self.get_arg(args, "Invert", False)
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\n")
        if not pattern:
            return data
        try:
            pat = re.compile(pattern)
        except re.error:
            return data
        out = [l for l in lines if bool(pat.search(l)) ^ invert]
        return "\n".join(out).encode("utf-8")


class Head(Operation):
    name = "Head"
    category = CATEGORY
    description = "Keeps only the first N lines/bytes of the input."
    args = [
        {"name": "Amount", "type": "number", "value": 10},
        {"name": "Unit", "type": "option", "value": "Lines", "options": ["Lines", "Bytes"]},
    ]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 10))
        unit = self.get_arg(args, "Unit", "Lines")
        if unit == "Bytes":
            return data[:n]
        lines = data.split(b"\n")
        return b"\n".join(lines[:n])


class Tail(Operation):
    name = "Tail"
    category = CATEGORY
    description = "Keeps only the last N lines/bytes of the input."
    args = [
        {"name": "Amount", "type": "number", "value": 10},
        {"name": "Unit", "type": "option", "value": "Lines", "options": ["Lines", "Bytes"]},
    ]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 10))
        unit = self.get_arg(args, "Unit", "Lines")
        if unit == "Bytes":
            return data[-n:] if n > 0 else b""
        lines = data.split(b"\n")
        return b"\n".join(lines[-n:] if n > 0 else [])


class DropBytes(Operation):
    name = "Drop bytes"
    category = CATEGORY
    description = "Drops N bytes from the start or end of the input."
    args = [
        {"name": "Amount", "type": "number", "value": 1},
        {"name": "From", "type": "option", "value": "Start", "options": ["Start", "End"]},
    ]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1))
        pos = self.get_arg(args, "From", "Start")
        if pos == "End":
            return data[: -n if n > 0 else None]
        return data[n:]


class TakeBytes(Operation):
    name = "Take bytes"
    category = CATEGORY
    description = "Takes N bytes from the start or end of the input."
    args = [
        {"name": "Amount", "type": "number", "value": 1},
        {"name": "From", "type": "option", "value": "Start", "options": ["Start", "End"]},
    ]

    def _run(self, data, args):
        n = int(self.get_arg(args, "Amount", 1))
        pos = self.get_arg(args, "From", "Start")
        if pos == "End":
            return data[-n:] if n > 0 else b""
        return data[:n]


class PadLines(Operation):
    name = "Pad lines"
    category = CATEGORY
    description = "Adds a prefix and/or suffix to every line of the input."
    args = [
        {"name": "Prefix", "type": "string", "value": ""},
        {"name": "Suffix", "type": "string", "value": ""},
    ]

    def _run(self, data, args):
        prefix = self.get_arg(args, "Prefix", "")
        suffix = self.get_arg(args, "Suffix", "")
        text = data.decode("utf-8", errors="replace")
        return "\n".join(prefix + line + suffix for line in text.split("\n")).encode("utf-8")


class AddLineNumbers(Operation):
    name = "Add line numbers"
    category = CATEGORY
    description = "Prepends line numbers to each line."

    def _run(self, data, args):
        lines = data.decode("utf-8", errors="replace").split("\n")
        width = max(1, len(str(len(lines))))
        return "\n".join("%s%d  %s" % (" " * (width - len(str(i + 1))), i + 1, line) for i, line in enumerate(lines)).encode()


class RemoveLineNumbers(Operation):
    name = "Remove line numbers"
    category = CATEGORY
    description = "Removes line number prefixes (e.g. '1  ', '001: ')."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        return re.sub(r"^\s*\d+[\s:.\-|]+\s*", "", text, flags=re.MULTILINE).encode()


class CountOccurrences(Operation):
    name = "Count occurrences"
    category = CATEGORY
    description = "Counts how many times a substring or regex pattern occurs in the input."
    args = [
        {"name": "Search", "type": "string", "value": ""},
        {"name": "Regex", "type": "boolean", "value": False},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        search = self.get_arg(args, "Search", "")
        if not search:
            return b"0"
        if self.get_arg(args, "Regex", False):
            count = len(re.findall(search, text))
        else:
            count = text.count(search)
        return str(count).encode()


class RemoveDiacritics(Operation):
    name = "Remove Diacritics"
    category = CATEGORY
    description = "Strips accents/diacritical marks, e.g. 'caf\u00e9' -> 'cafe'."

    def _run(self, data, args):
        import unicodedata
        text = data.decode("utf-8", errors="replace")
        normalized = unicodedata.normalize("NFKD", text)
        return "".join(c for c in normalized if not unicodedata.combining(c)).encode("utf-8")


class Diff(Operation):
    name = "Diff"
    category = CATEGORY
    description = "Computes the unified diff between two inputs (separated by '---' on its own line)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two inputs separated by '---' on its own line"
        a = parts[0].splitlines(keepends=True)
        b = parts[1].splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(a, b, fromfile="Input A", tofile="Input B"))
        return "".join(diff_lines).encode()


class HammingDistance(Operation):
    name = "Hamming Distance"
    category = CATEGORY
    description = "Computes the Hamming distance (number of differing bits) between two inputs (split by '---' line)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two inputs separated by '---' on its own line"
        a = parts[0].strip().encode()
        b = parts[1].strip().encode()
        min_len = min(len(a), len(b))
        dist = sum(bin(x ^ y).count("1") for x, y in zip(a[:min_len], b[:min_len]))
        dist += abs(len(a) - len(b)) * 8
        return str(dist).encode()


class LevenshteinDistance(Operation):
    name = "Levenshtein Distance"
    category = CATEGORY
    description = "Computes the Levenshtein edit distance between two strings (split by '---' line)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two inputs separated by '---' on its own line"
        a = parts[0].strip()
        b = parts[1].strip()
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
        return str(dp[m][n]).encode()


class UnixTimestampToDate(Operation):
    name = "From UNIX Timestamp"
    category = CATEGORY
    description = "Converts a UNIX timestamp to a human-readable UTC date/time."
    args = [{"name": "Units", "type": "option", "value": "Seconds", "options": ["Seconds", "Milliseconds"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        m = re.search(r"-?\d+(\.\d+)?", text)
        if not m:
            return b"Could not parse a UNIX timestamp"
        ts = float(m.group())
        if self.get_arg(args, "Units", "Seconds") == "Milliseconds":
            ts /= 1000.0
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return (dt.strftime("%Y-%m-%d %H:%M:%S UTC")).encode()


class DateToUnixTimestamp(Operation):
    name = "To UNIX Timestamp"
    category = CATEGORY
    description = "Converts an ISO-ish date string (YYYY-MM-DD HH:MM:SS) to a UNIX timestamp."
    args = [{"name": "Units", "type": "option", "value": "Seconds", "options": ["Seconds", "Milliseconds"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.datetime.strptime(text, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            raise ValueError("Could not parse date, expected e.g. 2024-01-31 12:00:00")
        ts = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
        if self.get_arg(args, "Units", "Seconds") == "Milliseconds":
            ts *= 1000
        return str(int(ts)).encode()


class ParseDateTime(Operation):
    name = "Parse DateTime"
    category = CATEGORY
    description = "Parses a date/time string into multiple formats."
    args = [
        {"name": "Format hint", "type": "option", "value": "Auto-detect",
         "options": ["Auto-detect", "ISO 8601", "US (MM/DD/YYYY)", "EU (DD/MM/YYYY)", "UNIX timestamp"]},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        fmt_hint = self.get_arg(args, "Format hint", "Auto-detect")
        ts = None
        if fmt_hint == "UNIX timestamp":
            ts = float(re.search(r"-?\d+(\.\d+)?", text).group())
        else:
            formats = [
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                "%Y-%m-%d",
            ]
            for f in formats:
                try:
                    dt = datetime.datetime.strptime(text, f)
                    # Input has no timezone info - treat it as UTC so the
                    # resulting timestamp and displays agree.
                    ts = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
                    break
                except ValueError:
                    pass
        if ts is None:
            return b"Could not parse date/time"
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        lines = [
            "ISO 8601:  %s" % dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "UTC:       %s" % dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "UNIX (s):  %d" % int(ts),
            "UNIX (ms): %d" % int(ts * 1000),
        ]
        return "\n".join(lines).encode()


class JWTDecode(Operation):
    name = "JWT Decode"
    category = CATEGORY
    description = "Decodes a JSON Web Token's header and payload (does NOT verify the signature)."

    def _run(self, data, args):
        import base64
        import json
        text = data.decode("utf-8", errors="ignore").strip()
        parts = text.split(".")
        if len(parts) < 2:
            raise ValueError("Not a valid JWT (expected header.payload.signature)")

        def b64url(seg):
            seg += "=" * (-len(seg) % 4)
            return base64.urlsafe_b64decode(seg)

        header = json.loads(b64url(parts[0]))
        payload = json.loads(b64url(parts[1]))
        out = {"header": header, "payload": payload}
        return json.dumps(out, indent=2).encode("utf-8")


class ChangeCase(Operation):
    name = "Change Case"
    category = CATEGORY
    description = "Converts text between snake_case, camelCase, kebab-case, PascalCase, Title Case and CONSTANT_CASE."
    args = [{"name": "To", "type": "option", "value": "snake_case",
             "options": ["snake_case", "camelCase", "kebab-case", "PascalCase", "Title Case", "CONSTANT_CASE"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        words = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+", text)
        words = [w for w in words if w]
        target = self.get_arg(args, "To")
        if target == "snake_case":
            out = "_".join(w.lower() for w in words)
        elif target == "kebab-case":
            out = "-".join(w.lower() for w in words)
        elif target == "camelCase":
            out = (words[0].lower() if words else "") + "".join(w.capitalize() for w in words[1:])
        elif target == "PascalCase":
            out = "".join(w.capitalize() for w in words)
        elif target == "Title Case":
            out = " ".join(w.capitalize() for w in words)
        else:  # CONSTANT_CASE
            out = "_".join(w.upper() for w in words)
        return out.encode("utf-8")


class GetTime(Operation):
    name = "Get Time"
    category = CATEGORY
    description = "Returns the current UTC time in various formats."

    def _run(self, data, args):
        now = datetime.datetime.now(datetime.timezone.utc)
        lines = [
            "ISO 8601:  %s" % now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "UTC:       %s" % now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "UNIX (s):  %d" % int(now.timestamp()),
            "UNIX (ms): %d" % int(now.timestamp() * 1000),
        ]
        return "\n".join(lines).encode()


class IndexOfCoincidence(Operation):
    name = "Index of Coincidence"
    category = CATEGORY
    description = "Computes the Index of Coincidence (IC) of the input text."

    def _run(self, data, args):
        text = data.decode("ascii", errors="ignore").upper()
        chars = [c for c in text if 65 <= ord(c) <= 90]
        if len(chars) < 2:
            return b"0.0"
        freq = {}
        for c in chars:
            freq[c] = freq.get(c, 0) + 1
        n = len(chars)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ("%.6f" % ic).encode()


class ChiSquare(Operation):
    name = "Chi Square"
    category = CATEGORY
    description = "Computes the Chi-squared statistic of the input byte distribution compared to uniform."

    def _run(self, data, args):
        if not data:
            return b"0.0"
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        expected = n / 256
        chi2 = sum(((f - expected) ** 2) / expected for f in freq)
        return ("%.4f" % chi2).encode()


OPERATIONS = [
    Reverse, ToUpperCase, ToLowerCase, SwapCase, AlternatingCaps,
    ChangeCase, StripWhitespace, RemoveNullBytes, RemoveANSIEscapes,
    FindReplace, RegexSubstitution,
    SortLines, Shuffle, Unique, Split, FilterOp,
    Head, Tail, DropBytes, TakeBytes, PadLines,
    AddLineNumbers, RemoveLineNumbers,
    CountOccurrences, RemoveDiacritics,
    Diff, HammingDistance, LevenshteinDistance,
    UnixTimestampToDate, DateToUnixTimestamp, ParseDateTime, GetTime,
    JWTDecode,
    IndexOfCoincidence, ChiSquare,
]