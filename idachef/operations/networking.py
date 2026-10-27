# -*- coding: utf-8 -*-
"""Networking operations - cf. CyberChef's "Networking" category
(Defang IP Addresses.mjs, Defang URL.mjs, ParseIPv6address.mjs, ...).
Particularly useful when pulling IOCs out of decoded malware configs."""

import ipaddress
import re
import struct

from ..core.operation import Operation

CATEGORY = "Networking"

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


class DefangIP(Operation):
    name = "Defang IP Addresses"
    category = CATEGORY
    description = "Defangs IPv4 addresses (1.2.3.4 -> 1[.]2[.]3[.]4) so they're safe to paste in reports/chat."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        return IPV4_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text).encode("utf-8")


class RefangIP(Operation):
    name = "Fang IP Addresses"
    category = CATEGORY
    description = "Reverses IP defanging (1[.]2[.]3[.]4 -> 1.2.3.4)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        return text.replace("[.]", ".").replace("(.)", ".").encode("utf-8")


class DefangURL(Operation):
    name = "Defang URL"
    category = CATEGORY
    description = "Defangs URLs (hxxp[://]example[.]com) so they're safe to paste in reports/chat."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"https?://", lambda m: "hxxp[://]" if m.group(0).startswith("http://") else "hxxps[://]", text)
        text = text.replace(".", "[.]")
        return text.encode("utf-8")


class RefangURL(Operation):
    name = "Fang URL"
    category = CATEGORY
    description = "Reverses URL defanging (hxxp[://]example[.]com -> http://example.com)."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        text = text.replace("[.]", ".").replace("(.)", ".")
        text = text.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
        text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
        return text.encode("utf-8")


class FormatMACAddress(Operation):
    name = "Format MAC addresses"
    category = CATEGORY
    description = "Reformats MAC addresses found in the input to a chosen delimiter/case."
    args = [
        {"name": "Delimiter", "type": "option", "value": "Colon (:)", "options": ["Colon (:)", "Hyphen (-)", "None", "Dot (Cisco)"]},
        {"name": "Case", "type": "option", "value": "Lower", "options": ["Lower", "Upper"]},
    ]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        mac_re = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}\b")
        delim_name = self.get_arg(args, "Delimiter")
        case = self.get_arg(args, "Case")

        def fmt(m):
            raw = re.sub(r"[:\-]", "", m.group(0))
            pairs = [raw[i:i + 2] for i in range(0, 12, 2)]
            if case == "Upper":
                pairs = [p.upper() for p in pairs]
            else:
                pairs = [p.lower() for p in pairs]
            if delim_name == "Colon (:)":
                return ":".join(pairs)
            if delim_name == "Hyphen (-)":
                return "-".join(pairs)
            if delim_name == "Dot (Cisco)":
                joined = "".join(pairs)
                return ".".join(joined[i:i + 4] for i in range(0, 12, 4))
            return "".join(pairs)

        return mac_re.sub(fmt, text).encode("utf-8")


class ParseIPv6(Operation):
    name = "Parse IPv6 address"
    category = CATEGORY
    description = "Expands or compresses an IPv6 address."
    args = [{"name": "Mode", "type": "option", "value": "Compress", "options": ["Compress", "Expand"]}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        addr = ipaddress.IPv6Address(text)
        if self.get_arg(args, "Mode") == "Expand":
            return addr.exploded.encode()
        return addr.compressed.encode()


class ParseIPv4Header(Operation):
    name = "Parse IPv4 header"
    category = CATEGORY
    description = "Parses a raw IPv4 header (first 20+ bytes) into its fields."

    def _run(self, data, args):
        if len(data) < 20:
            return b"Need at least 20 bytes for IPv4 header"
        ver_ihl = data[0]
        ver = ver_ihl >> 4
        ihl = ver_ihl & 0xF
        tos = data[1]
        total_len = (data[2] << 8) | data[3]
        ident = (data[4] << 8) | data[5]
        flags = data[6] >> 5
        frag_off = ((data[6] & 0x1F) << 8) | data[7]
        ttl = data[8]
        proto = data[9]
        checksum = (data[10] << 8) | data[11]
        src = ipaddress.IPv4Address(data[12:16])
        dst = ipaddress.IPv4Address(data[16:20])
        lines = [
            "Version: %d  IHL: %d (x4 = %d bytes)" % (ver, ihl, ihl * 4),
            "DSCP/ECN: 0x%02x" % tos,
            "Total Length: %d" % total_len,
            "Identification: 0x%04x" % ident,
            "Flags: 0x%x  Fragment Offset: %d" % (flags, frag_off),
            "TTL: %d" % ttl,
            "Protocol: %d" % proto,
            "Header Checksum: 0x%04x" % checksum,
            "Source: %s" % src,
            "Destination: %s" % dst,
        ]
        return "\n".join(lines).encode()


class ParseTCP(Operation):
    name = "Parse TCP"
    category = CATEGORY
    description = "Parses a raw TCP segment header (first 20+ bytes)."

    def _run(self, data, args):
        if len(data) < 20:
            return b"Need at least 20 bytes for TCP header"
        src_port = (data[0] << 8) | data[1]
        dst_port = (data[2] << 8) | data[3]
        seq = struct.unpack(">I", data[4:8])[0]
        ack = struct.unpack(">I", data[8:12])[0]
        offset = (data[12] >> 4) * 4
        flags = data[13]
        window = (data[14] << 8) | data[15]
        checksum = (data[16] << 8) | data[17]
        urg = (data[18] << 8) | data[19]
        flag_names = []
        for bit, name in [(0, "FIN"), (1, "SYN"), (2, "RST"), (3, "PSH"), (4, "ACK"), (5, "URG")]:
            if flags & (1 << (5 - bit)):
                flag_names.append(name)
        lines = [
            "Src Port: %d  Dst Port: %d" % (src_port, dst_port),
            "Seq: 0x%08x  Ack: 0x%08x" % (seq, ack),
            "Header Len: %d bytes  Flags: %s (0x%02x)" % (offset, "|".join(flag_names) or "None", flags),
            "Window: %d  Checksum: 0x%04x  Urgent: %d" % (window, checksum, urg),
        ]
        return "\n".join(lines).encode()


class ParseUDP(Operation):
    name = "Parse UDP"
    category = CATEGORY
    description = "Parses a raw UDP datagram header (first 8 bytes)."

    def _run(self, data, args):
        if len(data) < 8:
            return b"Need at least 8 bytes for UDP header"
        src_port = (data[0] << 8) | data[1]
        dst_port = (data[2] << 8) | data[3]
        length = (data[4] << 8) | data[5]
        checksum = (data[6] << 8) | data[7]
        lines = [
            "Src Port: %d  Dst Port: %d" % (src_port, dst_port),
            "Length: %d  Checksum: 0x%04x" % (length, checksum),
        ]
        return "\n".join(lines).encode()


class ParseURI(Operation):
    name = "Parse URI"
    category = CATEGORY
    description = "Parses a URI into its components (scheme, authority, path, query, fragment)."
    args = []

    def _run(self, data, args):
        import urllib.parse
        text = data.decode("utf-8", errors="replace").strip()
        parsed = urllib.parse.urlparse(text)
        lines = [
            "Scheme: %s" % parsed.scheme,
            "Authority: %s" % parsed.netloc,
            "Path: %s" % parsed.path,
            "Query: %s" % parsed.query,
            "Fragment: %s" % parsed.fragment,
        ]
        return "\n".join(lines).encode()


class DechunkHTTP(Operation):
    name = "Dechunk HTTP response"
    category = CATEGORY
    description = "Decodes an HTTP body with Transfer-Encoding: chunked, removing the per-chunk size markers and joining the chunks."
    args = [{"name": "Keep trailer", "type": "boolean", "value": False}]

    def _run(self, data, args):
        out = bytearray()
        pos = 0
        while pos < len(data):
            line_end = data.find(b"\n", pos)
            if line_end == -1:
                break
            size_text = data[pos:line_end].strip().split(b";")[0]  # drop chunk extensions
            try:
                size = int(size_text, 16)
            except ValueError:
                return b"Dechunk failed: not a chunk size at offset %d: %r" % (pos, size_text)
            pos = line_end + 1
            if size == 0:
                if self.get_arg(args, "Keep trailer", False):
                    out.extend(data[pos:])
                break
            out.extend(data[pos:pos + size])
            pos += size
            if data[pos:pos + 2] == b"\r\n":
                pos += 2
            elif data[pos:pos + 1] == b"\n":
                pos += 1
        return bytes(out)


class StripHTTPHeaders(Operation):
    name = "Strip HTTP headers"
    category = CATEGORY
    description = "Removes HTTP headers, leaving only the body (split on double CRLF)."

    def _run(self, data, args):
        crlf = data.find(b"\r\n\r\n")
        if crlf != -1:
            return data[crlf + 4:]
        lf = data.find(b"\n\n")
        if lf != -1:
            return data[lf + 2:]
        return data


class ParseIPRange(Operation):
    name = "Parse IP range"
    category = CATEGORY
    description = "Expands a CIDR network (1.2.3.0/24) or explicit range (1.2.3.4-1.2.3.10) into individual addresses."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        if "-" in text and "/" not in text:
            # Explicit range like 1.2.3.4-1.2.3.10
            start_s, _, end_s = text.partition("-")
            start = ipaddress.ip_address(start_s.strip())
            end = ipaddress.ip_address(end_s.strip())
            if start.version != end.version:
                return b"Mixed IPv4/IPv6 range"
            networks = ipaddress.summarize_address_range(start, end)
            total = sum(net.num_addresses for net in networks)
            if total > 4096:
                return ("%d addresses in %s (too many to list)" % (total, text)).encode()
            lines = []
            for net in networks:
                lines.extend(str(ip) for ip in net)
            return "\n".join(lines).encode()
        ip_range = ipaddress.ip_network(text, strict=False)
        if ip_range.num_addresses > 256:
            lines = ["%d addresses in %s (too many to list)" % (ip_range.num_addresses, text)]
        else:
            lines = [str(ip) for ip in ip_range.hosts()]
        return "\n".join(lines).encode()


class CIDRExpand(Operation):
    name = "CIDR to IP Range"
    category = CATEGORY
    description = "Expands a CIDR block into its network/broadcast/usable-range and, for small blocks, every address."
    args = [{"name": "List all addresses (blocks <= /24 only)", "type": "boolean", "value": False}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        net = ipaddress.ip_network(text, strict=False)
        lines = [
            "Network:    %s" % net.network_address,
            "Netmask:    %s" % net.netmask,
            "Broadcast:  %s" % (net.broadcast_address if net.version == 4 else "-"),
            "Total addresses: %d" % net.num_addresses,
        ]
        if self.get_arg(args, "List all addresses (blocks <= /24 only)", False) and net.num_addresses <= 256:
            lines.append("")
            lines.extend(str(ip) for ip in net.hosts())
        return "\n".join(lines).encode()


class IPv4ToDecimal(Operation):
    name = "IPv4 Address to Decimal"
    category = CATEGORY
    description = "Converts a dotted-quad IPv4 address to its 32-bit unsigned decimal representation."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        return str(int(ipaddress.IPv4Address(text))).encode()


class DecimalToIPv4(Operation):
    name = "Decimal to IPv4 Address"
    category = CATEGORY
    description = "Converts a 32-bit unsigned decimal value back to a dotted-quad IPv4 address."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore").strip()
        return str(ipaddress.IPv4Address(int(text))).encode()


class ChangeIPFormat(Operation):
    name = "Change IP format"
    category = CATEGORY
    description = "Converts IP addresses between dotted-decimal, hex, octal, and decimal representations."
    args = [
        {"name": "Output format", "type": "option", "value": "Dotted Decimal",
         "options": ["Dotted Decimal", "Hex", "Decimal", "Octal Dotted"]},
    ]

    def _run(self, data, args):
        fmt = self.get_arg(args, "Output format", "Dotted Decimal")
        text = data.decode("utf-8", errors="ignore")
        matches = IPV4_RE.findall(text)
        out = []
        for m in matches:
            octets = [int(x) for x in m]
            if fmt == "Dotted Decimal":
                out.append(".".join(str(x) for x in octets))
            elif fmt == "Hex":
                out.append("0x%08x" % ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]))
            elif fmt == "Decimal":
                out.append(str((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]))
            else:  # Octal Dotted
                out.append(".".join("%04o" % x for x in octets))
        return "\n".join(out).encode() if out else b""


class GroupIPAddresses(Operation):
    name = "Group IP addresses"
    category = CATEGORY
    description = "Groups IP addresses by their /24 subnet."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="ignore")
        matches = IPV4_RE.findall(text)
        groups = {}
        for m in matches:
            prefix = ".".join(m[:3]) + ".0/24"
            if prefix not in groups:
                groups[prefix] = []
            groups[prefix].append(".".join(m))
        lines = []
        for prefix in sorted(groups.keys()):
            lines.append(prefix + "  (%d hosts)" % len(groups[prefix]))
            for ip in groups[prefix]:
                lines.append("  " + ip)
        return "\n".join(lines).encode()


OPERATIONS = [
    DefangIP, RefangIP, DefangURL, RefangURL, FormatMACAddress,
    ParseIPv6, ParseIPv4Header, ParseTCP, ParseUDP, ParseURI,
    DechunkHTTP, StripHTTPHeaders, ParseIPRange, CIDRExpand,
    IPv4ToDecimal, DecimalToIPv4, ChangeIPFormat, GroupIPAddresses,
]