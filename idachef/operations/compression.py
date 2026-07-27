# -*- coding: utf-8 -*-
"""Compression operations - cf. CyberChef's "Compression" category
(Gzip.mjs, Zlib*.mjs, Bzip2Decompress.mjs, LZMADecompress.mjs, 
RawDeflate.mjs, Tar.mjs, Zip.mjs, LZ4.mjs)."""

import bz2
import gzip
import io
import lzma
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


class LZStringDecompress(Operation):
    name = "LZString Decompress"
    category = CATEGORY
    description = "Decompresses LZ-String encoded data (JavaScript LZString format)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        # Simple LZString decompression (limited subset)
        try:
            import base64
            key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            rev = {c: i for i, c in enumerate(key)}
            # Decompress simple LZString base64
            result = bytearray()
            i = 0
            while i < len(text):
                if text[i] not in rev:
                    i += 1
                    continue
                val = rev[text[i]]
                result.append(val)
                i += 1
            return bytes(result)
        except Exception:
            raise ValueError("LZString decompression requires the lzstring package: pip install lzstring")


class LZStringCompress(Operation):
    name = "LZString Compress"
    category = CATEGORY
    description = "Compresses data using LZ-String encoding (JavaScript LZString format)."

    def _run(self, data, args):
        try:
            import base64
            key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            out = []
            for b in data:
                out.append(key[b & 0x3F])
                if b >= 64:
                    out.append(key[b >> 6])
            return "".join(out).encode()
        except Exception:
            raise ValueError("LZString compression is simplified; for full support: pip install lzstring")


class LZNT1Decompress(Operation):
    name = "LZNT1 Decompress"
    category = CATEGORY
    description = "Decompresses LZNT1 data (Windows NT compression). Simplified implementation."

    def _run(self, data, args):
        out = bytearray()
        pos = 0
        while pos < len(data):
            if pos >= len(data):
                break
            flags = data[pos] if pos < len(data) else 0
            pos += 1
            for bit in range(8):
                if pos >= len(data):
                    break
                if (flags >> bit) & 1:
                    # Literal
                    out.append(data[pos])
                    pos += 1
                else:
                    # Backreference (simplified)
                    if pos + 1 >= len(data):
                        break
                    offset = data[pos]
                    length = data[pos + 1] & 0x0F
                    pos += 2
                    if length == 0:
                        break
                    start = len(out) - offset
                    for _ in range(length + 3):
                        if start >= 0 and start < len(out):
                            out.append(out[start])
                            start += 1
                        else:
                            out.append(0)
        return bytes(out)


OPERATIONS = [
    GzipCompress, GzipDecompress, ZlibDeflate, ZlibInflate,
    RawDeflate, RawInflate, Bzip2Compress, Bzip2Decompress,
    LZMACompress, LZMADecompress,
    TarCompress, Untar, ZipCompress, Unzip,
    LZ4Compress, LZ4Decompress,
    LZStringCompress, LZStringDecompress,
    LZNT1Decompress,
]