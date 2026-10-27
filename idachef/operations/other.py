# -*- coding: utf-8 -*-
"""Other / Misc operations - cf. CyberChef's "Other" category
(Magic.mjs, Entropy.mjs, Frequency Distribution.mjs, 
Index of Coincidence.mjs, Chi Square.mjs, etc.)"""

import math
import random
import re
import struct

from ..core.operation import Operation

CATEGORY = "Other"


PREDEFINED_DEBRUIJN = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9"


class PRNG(Operation):
    name = "Pseudo-Random Number Generator"
    category = CATEGORY
    description = "Generates pseudo-random bytes using Python's PRNG."
    args = [
        {"name": "Count (bytes)", "type": "number", "value": 16},
        {"name": "Seed (0 = random)", "type": "number", "value": 0},
    ]

    def _run(self, data, args):
        count = int(self.get_arg(args, "Count (bytes)", 16))
        seed = int(self.get_arg(args, "Seed (0 = random)", 0))
        if seed != 0:
            random.seed(seed)
        return bytes(random.getrandbits(8) for _ in range(count))


class PRNGPrime(Operation):
    name = "Pseudo-Random Prime Generator"
    category = CATEGORY
    description = "Generates a random prime number of the specified bit length."

    def _run(self, data, args):
        import random as rnd
        bits = int(data.decode("utf-8", errors="ignore").strip() or "128")
        bits = max(8, min(1024, bits))

        def is_probable_prime(n, k=40):
            if n < 2:
                return False
            for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
                if n % p == 0:
                    return n == p
            d = n - 1
            s = 0
            while d % 2 == 0:
                d //= 2
                s += 1
            for _ in range(k):
                a = rnd.randrange(2, n - 1)
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        while True:
            n = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(n):
                return ("%d (bits=%d)" % (n, bits)).encode()


class DeBruijnSequence(Operation):
    name = "Generate De Bruijn Sequence"
    category = CATEGORY
    description = "Generates a De Bruijn sequence for the given alphabet size and subsequence length (every possible subsequence of length n appears exactly once)."
    args = [
        {"name": "Alphabet size (k)", "type": "number", "value": 16},
        {"name": "Subsequence length (n)", "type": "number", "value": 4},
    ]

    def _run(self, data, args):
        k = max(2, min(256, int(self.get_arg(args, "Alphabet size (k)", 16))))
        n = max(1, int(self.get_arg(args, "Subsequence length (n)", 4)))
        if k ** n > 4_000_000:
            return b"Sequence too large (k^n over 4,000,000) - lower k or n"

        # Standard recursive De Bruijn construction (Fredricksen & Maiorana style)
        sequence = []
        a = [0] * (k * n + 1)

        def db(t, p):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)

        # Guard against deep recursion for large n by raising the limit
        import sys
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, n * k + 1000))
        try:
            db(1, 1)
        finally:
            sys.setrecursionlimit(old_limit)

        # Index 0..k-1 map to bytes 0..k-1 (like CyberChef's byte alphabet)
        return bytes(i for i in sequence if i < 256)


class DisassembleX86(Operation):
    name = "Disassemble x86"
    category = CATEGORY
    description = "Disassembles x86/x64 machine code. Requires capstone (pip install capstone)."
    args = [
        {"name": "Mode", "type": "option", "value": "32-bit", "options": ["16-bit", "32-bit", "64-bit"]},
        {"name": "Base address", "type": "string", "value": "0x0"},
    ]

    def _run(self, data, args):
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64
        except ImportError:
            raise ImportError("capstone is not installed - run: pip install capstone")
        mode_name = self.get_arg(args, "Mode", "32-bit")
        base = int(self.get_arg(args, "Base address", "0x0"), 16) if self.get_arg(args, "Base address", "0x0").startswith("0x") else int(self.get_arg(args, "Base address", "0x0"))
        mode_map = {"16-bit": CS_MODE_16, "32-bit": CS_MODE_32, "64-bit": CS_MODE_64}
        md = Cs(CS_ARCH_X86, mode_map[mode_name])
        lines = []
        for i in md.disasm(data, base):
            lines.append("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        return "\n".join(lines).encode()


class GenerateDeBruijn(Operation):
    name = "Generate Cyclic Pattern"
    category = CATEGORY
    description = "Generates a cyclic character pattern for RE use (Aa0Aa1Aa2...)."

    def _run(self, data, args):
        return PREDEFINED_DEBRUIJN


class GenerateLoremIpsum(Operation):
    name = "Generate Lorem Ipsum"
    category = CATEGORY
    description = "Generates a block of Lorem Ipsum placeholder text."
    args = [{"name": "Paragraphs", "type": "number", "value": 1}]

    def _run(self, data, args):
        count = max(1, int(self.get_arg(args, "Paragraphs", 1)))
        text = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud "
                "exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
        return (text + "\n\n") * count


class HaversineDistance(Operation):
    name = "Haversine Distance"
    category = CATEGORY
    description = "Computes the great-circle distance between two lat/lon coordinate pairs (input: 'lat1,lon1---lat2,lon2')."

    def _run(self, data, args):
        import math
        text = data.decode("utf-8", errors="ignore")
        parts = re.split(r"\n\s*---\s*\n|\n\n\n", text, maxsplit=1)
        if len(parts) < 2:
            return b"Need two coordinates separated by '---' on its own line"
        coord1 = re.findall(r"[-+]?\d*\.?\d+", parts[0])
        coord2 = re.findall(r"[-+]?\d*\.?\d+", parts[1])
        if len(coord1) < 2 or len(coord2) < 2:
            return b"Need two lat,lon pairs"
        lat1, lon1 = math.radians(float(coord1[0])), math.radians(float(coord1[1]))
        lat2, lon2 = math.radians(float(coord2[0])), math.radians(float(coord2[1]))
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a_val = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a_val))
        R = 6371  # km
        return ("%.2f km (%.2f miles)" % (R * c, R * c * 0.621371)).encode()


class HTMLToText(Operation):
    name = "HTML To Text"
    category = CATEGORY
    description = "Strips HTML tags and converts entities to plain text."

    def _run(self, data, args):
        import html
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"<[^>]*>", "", text)
        text = re.sub(r"\s+", " ", text)
        text = html.unescape(text)
        return text.strip().encode("utf-8")


OPERATIONS = [
    PRNG, PRNGPrime, DeBruijnSequence, GenerateDeBruijn,
    DisassembleX86, GenerateLoremIpsum, HaversineDistance, HTMLToText,
]
