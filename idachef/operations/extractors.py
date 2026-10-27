# -*- coding: utf-8 -*-
"""Extraction operations - cf. CyberChef's "Extractors" category
(ExtractIPAddresses.mjs, ExtractURLs.mjs, ExtractEmailAddresses.mjs, ...).
Handy for pulling IOCs straight out of a decrypted config blob or string
dump inside IDA."""

import re

from ..core.operation import Operation

CATEGORY = "Extractors"

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,24}\b")
HEXSTR_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){4,}\b")
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
HASH_RE = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})\b")
FILEPATH_RE = re.compile(r"\b(?:[A-Za-z]:\\|/|\./{1,2})[/\\\w.\- ]+\.[a-zA-Z0-9]{1,6}\b")
DATE_RE = re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b")


def _make_extractor(op_name, pattern, desc, unique_default=True):
    class _Extractor(Operation):
        name = op_name
        category = CATEGORY
        description = desc
        args = [{"name": "Unique only", "type": "boolean", "value": unique_default}]

        def _run(self, data, args):
            text = data.decode("utf-8", errors="ignore")
            matches = pattern.findall(text)
            if self.get_arg(args, "Unique only", unique_default):
                seen = []
                for m in matches:
                    if m not in seen:
                        seen.append(m)
                matches = seen
            return "\n".join(matches).encode("utf-8")

    _Extractor.__name__ = op_name.replace(" ", "")
    return _Extractor


ExtractIPv4 = _make_extractor("Extract IP addresses", IPV4_RE, "Extracts all IPv4 addresses found in the input.")
ExtractIPv6 = _make_extractor("Extract IPv6 addresses", IPV6_RE, "Extracts all IPv6 addresses found in the input.")
ExtractURLs = _make_extractor("Extract URLs", URL_RE, "Extracts URLs (scheme://...) found in the input.")
ExtractEmails = _make_extractor("Extract email addresses", EMAIL_RE, "Extracts email addresses found in the input.")
ExtractDomains = _make_extractor("Extract domains", DOMAIN_RE, "Extracts domain-like names found in the input.")
ExtractHexStrings = _make_extractor("Extract Hex Strings", HEXSTR_RE, "Extracts contiguous hex-digit runs (4+ bytes) found in the input.")
ExtractMACs = _make_extractor("Extract MAC addresses", MAC_RE, "Extracts MAC addresses found in the input.")
ExtractHashes = _make_extractor("Extract hashes", HASH_RE, "Extracts potential hash values (MD5, SHA1, SHA2) from the input.")
ExtractFilepaths = _make_extractor("Extract file paths", FILEPATH_RE, "Extracts file paths (Windows and Unix style) from the input.")
ExtractDates = _make_extractor("Extract dates", DATE_RE, "Extracts ISO-like date strings (YYYY-MM-DD) from the input.")


class RegexExtract(Operation):
    name = "Regular expression"
    category = CATEGORY
    description = "Extracts (or highlights) matches of a custom regular expression."
    args = [
        {"name": "Regex", "type": "string", "value": r"\w+"},
        {"name": "Case sensitive", "type": "boolean", "value": True},
        {"name": "Output", "type": "option", "value": "List matches", "options": ["List matches", "Count matches"]},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        pattern = self.get_arg(args, "Regex", r"\w+")
        flags = 0 if self.get_arg(args, "Case sensitive", True) else re.IGNORECASE
        matches = re.findall(pattern, text, flags=flags)
        matches = [m if isinstance(m, str) else m[0] for m in matches]
        if self.get_arg(args, "Output") == "Count matches":
            return str(len(matches)).encode()
        return "\n".join(matches).encode("utf-8")


class ExtractStrings(Operation):
    name = "Strings"
    category = CATEGORY
    description = "Extracts printable ASCII/Unicode runs of at least N characters (like the `strings` utility)."
    args = [
        {"name": "Minimum length", "type": "number", "value": 4},
        {"name": "Encoding", "type": "option", "value": "ASCII", "options": ["ASCII", "Wide (UTF-16LE)"]},
    ]

    def _run(self, data, args):
        min_len = int(self.get_arg(args, "Minimum length", 4))
        enc = self.get_arg(args, "Encoding", "ASCII")
        if enc.startswith("Wide"):
            pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
            matches = pattern.findall(data)
            result = [m.decode("utf-16-le", errors="replace") for m in matches]
        else:
            pattern = re.compile(("[\\x20-\\x7e]{%d,}" % min_len).encode())
            matches = pattern.findall(data)
            result = [m.decode("ascii", errors="replace") for m in matches]
        return "\n".join(result).encode("utf-8")


class RAKE(Operation):
    name = "RAKE"
    category = CATEGORY
    description = "Extracts key phrases using RAKE (Rapid Automatic Keyword Extraction)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").lower()
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
                       "of", "with", "is", "are", "was", "were", "be", "been", "being",
                       "have", "has", "had", "do", "does", "did", "will", "would", "could",
                       "should", "may", "might", "shall", "can", "need", "dare", "ought"}
        # Split into candidate phrases
        phrases = re.split(r"[.!?\n]+", text)
        phrase_words = []
        for phrase in phrases:
            words = [w for w in re.findall(r"\b\w+\b", phrase) if w not in stop_words]
            if words:
                phrase_words.append(words)
        # Score words by degree/frequency
        word_freq = {}
        word_degree = {}
        for words in phrase_words:
            for w in words:
                word_freq[w] = word_freq.get(w, 0) + 1
                word_degree[w] = word_degree.get(w, 0) + len(words) - 1
        word_scores = {}
        for w in word_freq:
            word_scores[w] = (word_degree.get(w, 0) + word_freq[w]) / max(1, word_freq[w])
        # Score phrases
        scored = []
        for words in phrase_words:
            score = sum(word_scores.get(w, 0) for w in words)
            scored.append((score, " ".join(words)))
        scored.sort(key=lambda x: x[0], reverse=True)
        return "\n".join("%.2f  %s" % (s, p) for s, p in scored[:30]).encode()


OPERATIONS = [
    ExtractIPv4, ExtractIPv6, ExtractURLs, ExtractEmails, ExtractDomains,
    ExtractHexStrings, ExtractMACs, ExtractHashes, ExtractFilepaths, ExtractDates,
    RegexExtract, ExtractStrings, RAKE,
]