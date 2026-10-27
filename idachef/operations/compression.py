# -*- coding: utf-8 -*-
"""Compression operations - cf. CyberChef's "Compression" category
(Gzip.mjs, Zlib*.mjs, Bzip2Decompress.mjs, LZMADecompress.mjs, 
RawDeflate.mjs, Tar.mjs, Zip.mjs, LZ4.mjs)."""

import bz2
import gzip
import io
import lzma
import re
import struct
import tarfile
import zipfile
import zlib

from ..core.operation import Operation

CATEGORY = "Compression"


class GzipCompress(Operation):
    name = "Gzip"
    category = CATEGORY
    description = "Compresses data using Gzip."

    def _run(self, data, args):
        return gzip.compress(data)


class GzipDecompress(Operation):
    name = "Gunzip"
    category = CATEGORY
    description = "Decompresses Gzip data."

    def _run(self, data, args):
        return gzip.decompress(data)


class ZlibDeflate(Operation):
    name = "Zlib Deflate"
    category = CATEGORY
    description = "Compresses data using zlib (with zlib header/checksum)."
    args = [{"name": "Level", "type": "number", "value": 6}]

    def _run(self, data, args):
        return zlib.compress(data, int(self.get_arg(args, "Level", 6)))


class ZlibInflate(Operation):
    name = "Zlib Inflate"
    category = CATEGORY
    description = "Decompresses zlib-compressed data."

    def _run(self, data, args):
        return zlib.decompress(data)


class RawDeflate(Operation):
    name = "Raw Deflate"
    category = CATEGORY
    description = "Compresses data using raw DEFLATE (no zlib/gzip header)."
    args = [{"name": "Level", "type": "number", "value": 9}]

    def _run(self, data, args):
        level = int(self.get_arg(args, "Level", 9))
        c = zlib.compressobj(level, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()


class RawInflate(Operation):
    name = "Raw Inflate"
    category = CATEGORY
    description = "Decompresses raw DEFLATE data (no zlib/gzip header)."

    def _run(self, data, args):
        d = zlib.decompressobj(-15)
        return d.decompress(data) + d.flush()


class Bzip2Compress(Operation):
    name = "Bzip2 Compress"
    category = CATEGORY
    description = "Compresses data using bzip2."

    def _run(self, data, args):
        return bz2.compress(data)


class Bzip2Decompress(Operation):
    name = "Bzip2 Decompress"
    category = CATEGORY
    description = "Decompresses bzip2 data."

    def _run(self, data, args):
        return bz2.decompress(data)


class LZMACompress(Operation):
    name = "LZMA Compress"
    category = CATEGORY
    description = "Compresses data using LZMA/XZ."

    def _run(self, data, args):
        return lzma.compress(data)


class LZMADecompress(Operation):
    name = "LZMA Decompress"
    category = CATEGORY
    description = "Decompresses LZMA/XZ data."

    def _run(self, data, args):
        return lzma.decompress(data)


class TarCompress(Operation):
    name = "Tar"
    category = CATEGORY
    description = "Creates a tar archive. Input format: 'filename\\ncontent' pairs, separated by '---filename---' lines."

    def _run(self, data, args):
        buf = io.BytesIO()
        tf = tarfile.open(fileobj=buf, mode="w")
        text = data.decode("utf-8", errors="replace")
        # Simple: treat first line as filename, rest as content
        lines = text.split("\n", 1)
        name = lines[0].strip() or "data.bin"
        content = lines[1].encode("utf-8") if len(lines) > 1 else data
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
        tf.close()
        return buf.getvalue()


class Untar(Operation):
    name = "Untar"
    category = CATEGORY
    description = "Extracts files from a tar archive, listing their names and sizes."

    def _run(self, data, args):
        try:
            buf = io.BytesIO(data)
            tf = tarfile.open(fileobj=buf)
            results = []
            for member in tf.getmembers():
                if member.isfile():
                    f = tf.extractfile(member)
                    if f:
                        content = f.read()
                        results.append("--- %s (%d bytes) ---" % (member.name, len(content)))
                        results.append(content.decode("utf-8", errors="replace"))
            return "\n".join(results).encode("utf-8")
        except Exception as e:
            return ("Error: %s" % e).encode()


class ZipCompress(Operation):
    name = "Zip"
    category = CATEGORY
    description = "Creates a zip archive containing the input as a file."

    def _run(self, data, args):
        buf = io.BytesIO()
        zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
        zf.writestr("data.bin", data)
        zf.close()
        return buf.getvalue()


class Unzip(Operation):
    name = "Unzip"
    category = CATEGORY
    description = "Lists and extracts files from a zip archive."

    def _run(self, data, args):
        try:
            buf = io.BytesIO(data)
            zf = zipfile.ZipFile(buf)
            results = []
            for name in zf.namelist():
                content = zf.read(name)
                results.append("--- %s (%d bytes) ---" % (name, len(content)))
                try:
                    results.append(content.decode("utf-8", errors="replace"))
                except Exception:
                    results.append(repr(content))
            return "\n".join(results).encode("utf-8")
        except Exception as e:
            return ("Error: %s" % e).encode()


class LZ4Decompress(Operation):
    name = "LZ4 Decompress"
    category = CATEGORY
    description = "Decompresses LZ4 data. Requires lz4 package (pip install lz4)."

    def _run(self, data, args):
        try:
            import lz4.block
            return lz4.block.decompress(data)
        except ImportError:
            raise ImportError("lz4 is not installed - run: pip install lz4")


class LZ4Compress(Operation):
    name = "LZ4 Compress"
    category = CATEGORY
    description = "Compresses data with LZ4. Requires lz4 package (pip install lz4)."

    def _run(self, data, args):
        try:
            import lz4.block
            return lz4.block.compress(data)
        except ImportError:
            raise ImportError("lz4 is not installed - run: pip install lz4")


# ---- LZ-String (faithful port of pieroxy/lz-string 1.4.5, WTFPL) ------------

_LZ_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_LZ_URI_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$"


def _to_utf16_units(text):
    """JS strings are UTF-16 code units; convert astral chars to surrogate pairs
    so indexing matches JavaScript's charAt/charCodeAt semantics."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _lz_compress(uncompressed, bits_per_char, get_char_from_int):
    """Port of LZString._compress. `uncompressed` is a str of UTF-16 units."""
    if uncompressed is None:
        return ""
    dictionary = {}
    dictionary_to_create = {}
    wc = ""
    w = ""
    enlarge_in = 2  # compensate for the first entry which should not count
    dict_size = 3
    num_bits = 2
    data = []
    data_val = 0
    data_position = 0

    def push_bit(bit):
        nonlocal data_val, data_position
        data_val = (data_val << 1) | bit
        if data_position == bits_per_char - 1:
            data_position = 0
            data.append(get_char_from_int(data_val))
            data_val = 0
        else:
            data_position += 1

    for c in uncompressed:
        if c not in dictionary:
            dictionary[c] = dict_size
            dict_size += 1
            dictionary_to_create[c] = True

        wc = w + c
        if wc in dictionary:
            w = wc
        else:
            if w in dictionary_to_create:
                cp = ord(w[0])
                if cp < 256:
                    for _ in range(num_bits):
                        push_bit(0)
                    value = cp
                    for _ in range(8):
                        push_bit(value & 1)
                        value >>= 1
                else:
                    for _ in range(num_bits):
                        push_bit(1)
                    value = cp
                    for _ in range(16):
                        push_bit(value & 1)
                        value >>= 1
                enlarge_in -= 1
                if enlarge_in == 0:
                    enlarge_in = 2 ** num_bits
                    num_bits += 1
                del dictionary_to_create[w]
            else:
                value = dictionary[w]
                for _ in range(num_bits):
                    push_bit(value & 1)
                    value >>= 1
            enlarge_in -= 1
            if enlarge_in == 0:
                enlarge_in = 2 ** num_bits
                num_bits += 1
            dictionary[wc] = dict_size
            dict_size += 1
            w = c

    # Output the code for w
    if w != "":
        if w in dictionary_to_create:
            cp = ord(w[0])
            if cp < 256:
                for _ in range(num_bits):
                    push_bit(0)
                value = cp
                for _ in range(8):
                    push_bit(value & 1)
                    value >>= 1
            else:
                for _ in range(num_bits):
                    push_bit(1)
                value = cp
                for _ in range(16):
                    push_bit(value & 1)
                    value >>= 1
            enlarge_in -= 1
            if enlarge_in == 0:
                enlarge_in = 2 ** num_bits
                num_bits += 1
            del dictionary_to_create[w]
        else:
            value = dictionary[w]
            for _ in range(num_bits):
                push_bit(value & 1)
                value >>= 1
        enlarge_in -= 1
        if enlarge_in == 0:
            enlarge_in = 2 ** num_bits
            num_bits += 1

    # Mark the end of the stream
    value = 2
    for _ in range(num_bits):
        push_bit(value & 1)
        value >>= 1

    # Flush the last char
    while True:
        data_val = data_val << 1
        if data_position == bits_per_char - 1:
            data.append(get_char_from_int(data_val))
            break
        data_position += 1
    return "".join(data)


def _lz_decompress(length, reset_value, get_next_value):
    """Port of LZString._decompress. Returns the decompressed str, "" when the
    stream ends cleanly, or None on corrupt input (matching the JS null)."""
    dictionary = {}
    enlarge_in = 4
    dict_size = 4
    num_bits = 3
    data_val = get_next_value(0)
    data_position = reset_value
    data_index = 1
    result = []

    def read_bits(count):
        nonlocal data_val, data_position, data_index
        bits = 0
        maxpower = 2 ** count
        power = 1
        while power != maxpower:
            resb = data_val & data_position
            data_position >>= 1
            if data_position == 0:
                data_position = reset_value
                data_val = get_next_value(data_index)
                data_index += 1
            bits |= (1 if resb > 0 else 0) * power
            power <<= 1
        return bits

    first = read_bits(2)
    if first == 0:
        c = chr(read_bits(8))
    elif first == 1:
        c = chr(read_bits(16))
    elif first == 2:
        return ""
    else:
        return None
    dictionary[3] = c
    w = c
    result.append(c)

    while True:
        if data_index > length:
            return ""
        code = read_bits(num_bits)
        if code == 0:
            dictionary[dict_size] = chr(read_bits(8))
            dict_size += 1
            c = dict_size - 1
            enlarge_in -= 1
        elif code == 1:
            dictionary[dict_size] = chr(read_bits(16))
            dict_size += 1
            c = dict_size - 1
            enlarge_in -= 1
        elif code == 2:
            return "".join(result)

        if enlarge_in == 0:
            enlarge_in = 2 ** num_bits
            num_bits += 1

        if code in (0, 1):
            # c was reassigned to the just-added dictionary index above
            entry = dictionary[c]
        elif code in dictionary:
            entry = dictionary[code]
        elif code == dict_size:
            entry = w + w[0]
        else:
            return None
        result.append(entry)

        dictionary[dict_size] = w + entry[0]
        dict_size += 1
        enlarge_in -= 1
        w = entry

        if enlarge_in == 0:
            enlarge_in = 2 ** num_bits
            num_bits += 1


def lzstring_compress(text, fmt):
    units = _to_utf16_units(text)
    if fmt == "UTF-16":
        return _lz_compress(units, 15, lambda a: chr(a + 32)) + " "
    if fmt == "URI-safe":
        return _lz_compress(units, 6, lambda a: _LZ_URI_ALPHABET[a])
    res = _lz_compress(units, 6, lambda a: _LZ_B64_ALPHABET[a])
    return res + {1: "===", 2: "==", 3: "="}.get(len(res) % 4, "")


def lzstring_decompress(text, fmt):
    """Returns the decompressed text, or None on corrupt input."""
    if fmt == "UTF-16":
        s = _lz_decompress(len(text), 16384,
                           lambda i: (ord(text[i]) - 32) if 0 <= i < len(text) else 0)
    elif fmt == "URI-safe":
        rev = {c: i for i, c in enumerate(_LZ_URI_ALPHABET)}
        s = _lz_decompress(len(text), 32,
                           lambda i: rev[text[i]] if 0 <= i < len(text) else 0)
    else:
        rev = {c: i for i, c in enumerate(_LZ_B64_ALPHABET)}
        for ch in text:
            if ch not in rev:
                raise ValueError("invalid character %r for LZString Base64 alphabet" % ch)
        s = _lz_decompress(len(text), 32,
                           lambda i: rev[text[i]] if 0 <= i < len(text) else 0)
    if s is None or s == "":
        return s
    # Collapse surrogate code units back into real characters
    try:
        return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    except UnicodeDecodeError:
        return s


class LZStringCompress(Operation):
    name = "LZString Compress"
    category = CATEGORY
    description = "Compresses text with LZ-String (pieroxy's lz-string, as used by many JS apps)."
    args = [{"name": "Format", "type": "option", "value": "Base64",
             "options": ["Base64", "UTF-16", "URI-safe"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        fmt = self.get_arg(args, "Format", "Base64")
        return lzstring_compress(text, fmt).encode("utf-8")


class LZStringDecompress(Operation):
    name = "LZString Decompress"
    category = CATEGORY
    description = "Decompresses LZ-String encoded data (pieroxy's lz-string). Supports the Base64, UTF-16 and URI-safe flavours."
    args = [{"name": "Format", "type": "option", "value": "Base64",
             "options": ["Base64", "UTF-16", "URI-safe"]}]

    def _run(self, data, args):
        text = re.sub(r"\s+", "", data.decode("utf-8", errors="ignore"))
        if not text:
            return b""
        fmt = self.get_arg(args, "Format", "Base64")
        try:
            result = lzstring_decompress(text, fmt)
        except Exception as exc:
            raise ValueError("LZString decompression failed: %s" % exc)
        if result is None:
            raise ValueError("LZString decompression failed: corrupt input for format %s" % fmt)
        return result.encode("utf-8", errors="replace")


class LZNT1Decompress(Operation):
    name = "LZNT1 Decompress"
    category = CATEGORY
    description = "Decompresses LZNT1 data (Windows NT compression as used by RtlCompressBuffer, WIM images, etc.)."

    def _run(self, data, args):
        try:
            return lznt1_decompress(data)
        except Exception as exc:
            raise ValueError("LZNT1 decompression failed: %s" % exc)


def lznt1_decompress(data):
    """LZNT1 decompression. Format (verified against Windows ntdll):
    - stream = sequence of chunks; chunk header is a 16-bit LE word:
      bits 0-11 = chunk data size minus 1, bit 15 = compressed flag,
      bits 12-14 = 3 (signature). Header 0x0000 ends the stream.
    - uncompressed chunk: stored bytes, copied verbatim.
    - compressed chunk: repeated groups of one flags byte + 8 items
      (LSB first). Item flag 0 = literal byte; flag 1 = 16-bit LE match
      token, split into (displacement, length) fields whose boundary
      depends on the position in the chunk: displacement bits grow from
      4 (position <= 16) to 12 (position >= 2049), length = stored + 3.
    """
    out = bytearray()
    pos = 0
    n = len(data)
    while pos + 1 < n:
        header = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if header == 0:
            break
        chunk_size = (header & 0x0FFF) + 1
        chunk_end = min(pos + chunk_size, n)
        chunk = data[pos:chunk_end]
        pos = chunk_end
        if header & 0x8000:
            _lznt1_decompress_chunk(chunk, out)
        else:
            out.extend(chunk)
    return bytes(out)


def _lznt1_decompress_chunk(chunk, out):
    base = len(out)
    pos = 0
    n = len(chunk)
    while pos < n:
        flags = chunk[pos]
        pos += 1
        for _ in range(8):
            if pos >= n:
                return
            if not (flags & 1):
                out.append(chunk[pos])
                pos += 1
            else:
                if pos + 1 >= n:
                    return
                token = chunk[pos] | (chunk[pos + 1] << 8)
                pos += 2
                position = len(out) - base  # bytes decompressed in this chunk so far
                disp_bits = min(12, max(4, (position - 1).bit_length()))
                len_bits = 16 - disp_bits
                displacement = (token >> len_bits) + 1
                length = (token & ((1 << len_bits) - 1)) + 3
                src = len(out) - displacement
                if src < 0:
                    raise ValueError("invalid back-reference (corrupt input?)")
                for _ in range(length):
                    out.append(out[src])
                    src += 1
            flags >>= 1


OPERATIONS = [
    GzipCompress, GzipDecompress, ZlibDeflate, ZlibInflate,
    RawDeflate, RawInflate, Bzip2Compress, Bzip2Decompress,
    LZMACompress, LZMADecompress,
    TarCompress, Untar, ZipCompress, Unzip,
    LZ4Compress, LZ4Decompress,
    LZStringCompress, LZStringDecompress,
    LZNT1Decompress,
]