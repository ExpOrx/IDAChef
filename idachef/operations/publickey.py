# -*- coding: utf-8 -*-
"""Public Key operations - cf. CyberChef's "Public Key" category
(PEMtoHex.mjs, ParseX509Certificate.mjs, RSAEncrypt.mjs, etc.).

Crypto operations require pycryptodome (pip install pycryptodome).
X.509/SSH parsing optionally uses the `cryptography` package.
"""

import base64
import binascii
import re
import struct
import textwrap

from ..core.operation import Operation

CATEGORY = "Public Key"

# ---- Helpers ----------------------------------------------------------------

def _pem_to_der(data):
    """Extract DER bytes from a PEM string."""
    text = data.decode("ascii", errors="ignore")
    m = re.search(r"-----BEGIN .*?-----\s*(.*?)\s*-----END .*?-----", text, re.DOTALL)
    if m:
        return base64.b64decode(m.group(1))
    return data

def _der_to_pem(der_bytes, label):
    """Wrap DER bytes in a PEM block."""
    b64 = base64.b64encode(der_bytes).decode()
    wrapped = "\n".join(textwrap.wrap(b64, 64))
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, wrapped, label)

def _try_import(modname):
    try:
        if modname == "asn1crypto":
            import asn1crypto
            return asn1crypto
        if modname == "Cryptodome":
            from Crypto.PublicKey import RSA, ECC
            from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
            from Crypto.Signature import pkcs1_15, DSS
            from Crypto.Hash import SHA256
            return True
        if modname == "cryptography":
            import cryptography
            return cryptography
    except ImportError:
        pass
    return None


# ---- PEM / DER conversion ---------------------------------------------------

class PEMToHex(Operation):
    name = "PEM to Hex"
    category = CATEGORY
    description = "Converts PEM or DER data to a hex string by extracting and hex-encoding the inner data."

    def _run(self, data, args):
        der = _pem_to_der(data)
        return binascii.hexlify(der)


class HexToPEM(Operation):
    name = "Hex to PEM"
    category = CATEGORY
    description = "Wraps hex-encoded DER data in a PEM header."
    args = [
        {"name": "PEM label", "type": "string", "value": "CERTIFICATE"},
    ]

    def _run(self, data, args):
        label = self.get_arg(args, "PEM label", "CERTIFICATE")
        text = data.decode("ascii", errors="ignore")
        clean = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(clean) % 2:
            clean = "0" + clean
        der = binascii.unhexlify(clean)
        return _der_to_pem(der, label).encode()


# ---- Object Identifier ------------------------------------------------------

_OID_MAP = {
    "2.5.4.3": "commonName (CN)",
    "2.5.4.6": "countryName (C)",
    "2.5.4.7": "localityName (L)",
    "2.5.4.8": "stateOrProvinceName (ST)",
    "2.5.4.10": "organizationName (O)",
    "2.5.4.11": "organizationalUnitName (OU)",
    "2.5.4.12": "title",
    "1.2.840.113549.1.1.1": "rsaEncryption (PKCS #1)",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.3.1.7": "secp256r1 (NIST P-256)",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


class HexToOID(Operation):
    name = "Hex to Object Identifier"
    category = CATEGORY
    description = "Converts a hex-encoded ASN.1 Object Identifier to its dotted-decimal and human-readable name (if known)."

    def _run(self, data, args):
        text = data.decode("ascii", errors="ignore")
        clean = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(clean) % 2:
            clean = "0" + clean
        der = binascii.unhexlify(clean)
        try:
            oid = _decode_oid(der)
        except Exception:
            return b"Invalid OID encoding"
        name = _OID_MAP.get(oid, "")
        if name:
            return ("%s  (%s)" % (oid, name)).encode()
        return oid.encode()


class OIDToHex(Operation):
    name = "Object Identifier to Hex"
    category = CATEGORY
    description = "Converts a dotted-decimal Object Identifier to its hex-encoded DER form."

    def _run(self, data, args):
        text = data.decode("ascii", errors="ignore").strip()
        try:
            der = _encode_oid(text)
        except Exception:
            return b"Invalid OID string"
        return binascii.hexlify(der)


def _decode_oid(der_bytes):
    """Decode DER-encoded OID bytes to dotted-decimal string."""
    parts = []
    val = 0
    for i, b in enumerate(der_bytes):
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            if i == 0:
                parts.append(val // 40)
                parts.append(val % 40)
            else:
                parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _encode_oid(oid_string):
    """Encode dotted-decimal OID string to DER bytes."""
    parts = [int(x) for x in oid_string.split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs at least 2 components")
    result = bytearray()
    result.append(parts[0] * 40 + parts[1])
    for val in parts[2:]:
        if val == 0:
            result.append(0)
            continue
        stack = []
        while val:
            stack.append((val & 0x7F) | (0x80 if stack else 0x00))
            val >>= 7
        result.extend(reversed(stack))
    return bytes(result)


# ---- ASN.1 / X.509 parsing --------------------------------------------------

class ParseASN1Hex(Operation):
    name = "Parse ASN.1 hex string"
    category = CATEGORY
    description = "Parses a hex-encoded ASN.1 DER structure into a human-readable tree."

    def _run(self, data, args):
        text = data.decode("ascii", errors="ignore")
        clean = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(clean) % 2:
            clean = "0" + clean
        der = binascii.unhexlify(clean)
        try:
            lines = _parse_der_structure(der)
            return "\n".join(lines).encode()
        except Exception as e:
            return ("ASN.1 parse error: %s" % e).encode()


def _parse_der_structure(der_bytes, indent=0):
    """Recursively parse DER structure and return list of description lines."""
    lines = []
    pos = 0
    while pos < len(der_bytes):
        if pos + 2 > len(der_bytes):
            break
        tag = der_bytes[pos]
        tag_class = tag >> 6
        tag_constructed = (tag >> 5) & 1
        tag_num = tag & 0x1F
        pos += 1
        if pos >= len(der_bytes):
            break
        length = der_bytes[pos]
        pos += 1
        if length & 0x80:
            len_bytes = length & 0x7F
            length = 0
            for _ in range(len_bytes):
                if pos >= len(der_bytes):
                    break
                length = (length << 8) | der_bytes[pos]
                pos += 1

        end = pos + length
        prefix = "  " * indent
        tag_name = _asn1_tag_name(tag_class, tag_constructed, tag_num)

        if tag_constructed:
            lines.append("%s[%s] (%d bytes)" % (prefix, tag_name, length))
            if end <= len(der_bytes):
                lines.extend(_parse_der_structure(der_bytes[pos:end], indent + 1))
        else:
            content = der_bytes[pos:end]
            if tag_num == 0x06:  # OID
                try:
                    oid_str = _decode_oid(content)
                    name = _OID_MAP.get(oid_str, "")
                    if name:
                        lines.append("%s%s = %s (%s)" % (prefix, tag_name, oid_str, name))
                    else:
                        lines.append("%s%s = %s" % (prefix, tag_name, oid_str))
                except Exception:
                    lines.append("%s%s = %d bytes" % (prefix, tag_name, length))
            elif tag_num == 0x02:  # INTEGER
                val = int.from_bytes(content, "big")
                lines.append("%s%s = %d" % (prefix, tag_name, val))
            elif tag_num == 0x0C or tag_num == 0x13:  # UTF8String or PrintableString
                try:
                    lines.append("%s%s = %r" % (prefix, tag_name, content.decode("ascii")))
                except Exception:
                    lines.append("%s%s = %d bytes" % (prefix, tag_name, length))
            elif tag_num == 0x04 and len(content) > 0 and content[0] == 0x30:
                # OCTET STRING wrapping nested DER (PKCS#8, etc.) - recurse into it
                lines.append("%s%s (%d bytes) = nested DER:" % (prefix, tag_name, length))
                lines.extend(_parse_der_structure(content, indent + 1))
            elif tag_num == 0x03 and len(content) > 1 and content[1] == 0x30:
                # BIT STRING wrapping nested DER - skip unused-bits byte, recurse
                lines.append("%s%s (%d bytes) = nested DER:" % (prefix, tag_name, length))
                lines.extend(_parse_der_structure(content[1:], indent + 1))
            else:
                if length <= 64:
                    lines.append("%s%s = %s" % (prefix, tag_name, content.hex()))
                else:
                    lines.append("%s%s = %d bytes" % (prefix, tag_name, length))
        pos = end
    return lines


def _asn1_tag_name(tag_class, constructed, tag_num):
    class_names = {0: "UNIVERSAL", 1: "APPLICATION", 2: "CONTEXT", 3: "PRIVATE"}
    cls = class_names.get(tag_class, "?")
    universal_tags = {
        1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING",
        5: "NULL", 6: "OID", 10: "ENUMERATED", 12: "UTF8String",
        16: "SEQUENCE", 17: "SET", 19: "PrintableString",
        20: "T61String", 22: "IA5String", 23: "UTCTime",
        24: "GeneralizedTime",
    }
    if tag_class == 0:
        name = universal_tags.get(tag_num, "%s %d" % (cls, tag_num))
    else:
        name = "%s %d" % (cls, tag_num)
    if constructed and tag_class == 0:
        if tag_num not in (16, 17):
            name = name + " (constructed)"
    return name


# ---- RSA operations ---------------------------------------------------------

HAVE_RSA = _try_import("Cryptodome")


class GenerateRSAKeyPair(Operation):
    name = "Generate RSA Key Pair"
    category = CATEGORY
    description = "Generates an RSA key pair (2048-bit by default). Requires pycryptodome."
    args = [
        {"name": "Key size (bits)", "type": "number", "value": 2048},
    ]

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for RSA - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        bits = int(self.get_arg(args, "Key size (bits)", 2048))
        key = RSA.generate(bits)
        priv_pem = key.export_key("PEM")
        pub_pem = key.public_key().export_key("PEM")
        return (priv_pem + b"\n" + pub_pem)


class RSAEncrypt(Operation):
    name = "RSA Encrypt"
    category = CATEGORY
    description = "Encrypts data using RSA-OAEP with SHA-256. Input: hex or PEM public key."
    args = [
        {"name": "Public key (hex)", "type": "text", "value": ""},
        {"name": "Key format", "type": "option", "value": "PEM", "options": ["PEM", "Hex DER"]},
    ]

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for RSA - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        key_text = (self.get_arg(args, "Public key (hex)", "") or "").strip() or data.decode("ascii", errors="ignore")
        fmt = self.get_arg(args, "Key format", "PEM")
        if fmt == "Hex DER":
            clean = re.sub(r"[^0-9a-fA-F]", "", key_text)
            if len(clean) % 2:
                clean = "0" + clean
            der = binascii.unhexlify(clean)
            key = RSA.import_key(der)
        else:
            key = RSA.import_key(key_text)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        max_len = key.size_in_bytes() - 2 * 32 - 2
        if len(data) > max_len:
            raise ValueError("Data too long for RSA-%d (%d > %d bytes)" % (key.size_in_bits(), len(data), max_len))
        return cipher.encrypt(data)


class RSADecrypt(Operation):
    name = "RSA Decrypt"
    category = CATEGORY
    description = "Decrypts data using RSA-OAEP with SHA-256. Input: hex or PEM private key."
    args = [
        {"name": "Private key (hex)", "type": "text", "value": ""},
        {"name": "Key format", "type": "option", "value": "PEM", "options": ["PEM", "Hex DER"]},
    ]

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for RSA - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        key_text = (self.get_arg(args, "Private key (hex)", "") or "").strip() or data.decode("ascii", errors="ignore")
        fmt = self.get_arg(args, "Key format", "PEM")
        if fmt == "Hex DER":
            clean = re.sub(r"[^0-9a-fA-F]", "", key_text)
            if len(clean) % 2:
                clean = "0" + clean
            der = binascii.unhexlify(clean)
            key = RSA.import_key(der)
        else:
            key = RSA.import_key(key_text)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        return cipher.decrypt(data)


class RSASign(Operation):
    name = "RSA Sign"
    category = CATEGORY
    description = "Signs data using RSA-PKCS1v15 with SHA-256. Input: hex or PEM private key."
    args = [
        {"name": "Private key (hex)", "type": "text", "value": ""},
        {"name": "Key format", "type": "option", "value": "PEM", "options": ["PEM", "Hex DER"]},
    ]

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for RSA - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        key_text = (self.get_arg(args, "Private key (hex)", "") or "").strip() or data.decode("ascii", errors="ignore")
        fmt = self.get_arg(args, "Key format", "PEM")
        if fmt == "Hex DER":
            clean = re.sub(r"[^0-9a-fA-F]", "", key_text)
            if len(clean) % 2:
                clean = "0" + clean
            der = binascii.unhexlify(clean)
            key = RSA.import_key(der)
        else:
            key = RSA.import_key(key_text)
        h = SHA256.new(data)
        sig = pkcs1_15.new(key).sign(h)
        return binascii.hexlify(sig)


class RSAVerify(Operation):
    name = "RSA Verify"
    category = CATEGORY
    description = "Verifies an RSA-PKCS1v15 SHA-256 signature. Input format: hex signature on first line, data below."
    args = [
        {"name": "Public key (hex)", "type": "text", "value": ""},
        {"name": "Key format", "type": "option", "value": "PEM", "options": ["PEM", "Hex DER"]},
    ]

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for RSA - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        key_text = (self.get_arg(args, "Public key (hex)", "") or "").strip() or data.decode("ascii", errors="ignore")
        fmt = self.get_arg(args, "Key format", "PEM")
        if fmt == "Hex DER":
            clean = re.sub(r"[^0-9a-fA-F]", "", key_text)
            if len(clean) % 2:
                clean = "0" + clean
            der = binascii.unhexlify(clean)
            key = RSA.import_key(der)
        else:
            key = RSA.import_key(key_text)

        text = data.decode("ascii", errors="ignore")
        parts = text.split("\n", 1)
        if len(parts) < 2:
            return b"Format: hex signature on first line, then data"
        sig_hex = re.sub(r"[^0-9a-fA-F]", "", parts[0])
        if len(sig_hex) % 2:
            sig_hex = "0" + sig_hex
        sig = binascii.unhexlify(sig_hex)
        message = parts[1].encode()

        h = SHA256.new(message)
        try:
            pkcs1_15.new(key).verify(h, sig)
            return b"Signature VALID"
        except (ValueError, TypeError):
            return b"Signature INVALID"


# ---- Public Key extraction --------------------------------------------------

HAVE_CRYPTO = _try_import("cryptography")


class PublicKeyFromCertificate(Operation):
    name = "Public Key from Certificate"
    category = CATEGORY
    description = "Extracts the public key from an X.509 certificate (PEM or DER). Requires pycryptodome."

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        der = _pem_to_der(data)
        key = RSA.import_key(der)
        return key.public_key().export_key("PEM")


class PublicKeyFromPrivateKey(Operation):
    name = "Public Key from Private Key"
    category = CATEGORY
    description = "Extracts the public key from a private key (PEM or DER). Requires pycryptodome."

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required - run: pip install pycryptodome")
        from Crypto.PublicKey import RSA
        der = _pem_to_der(data)
        key = RSA.import_key(der)
        return key.public_key().export_key("PEM")


class ParseX509(Operation):
    name = "Parse X.509 certificate"
    category = CATEGORY
    description = "Parses an X.509 certificate (PEM or DER) and displays its fields. Requires pycryptodome."

    def _run(self, data, args):
        if not HAVE_RSA:
            raise ImportError("pycryptodome is required for X.509 parsing - run: pip install pycryptodome")
        try:
            from Crypto.PublicKey import RSA
            der = _pem_to_der(data)
            # Use asn1crypto if available for detailed parsing, else basic ASN.1
            lines = ["=== X.509 Certificate ===", ""]
            lines.extend(_parse_der_structure(der))
            return "\n".join(lines).encode()
        except Exception as e:
            return ("X.509 parse error: %s" % e).encode()


OPERATIONS = [
    PEMToHex, HexToPEM,
    HexToOID, OIDToHex,
    ParseASN1Hex,
    GenerateRSAKeyPair, RSAEncrypt, RSADecrypt, RSASign, RSAVerify,
    PublicKeyFromCertificate, PublicKeyFromPrivateKey,
    ParseX509,
]