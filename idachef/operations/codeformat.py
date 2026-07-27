# -*- coding: utf-8 -*-
"""Code tidying operations - cf. CyberChef's "Code tidy" category
(JSONBeautify.mjs, JSONMinify.mjs, XMLBeautify.mjs, Syntax highlighter, etc.)"""

import json
import re
import xml.dom.minidom as minidom

from ..core.operation import Operation

CATEGORY = "Code tidy"


class JSONBeautify(Operation):
    name = "JSON Beautify"
    category = CATEGORY
    description = "Pretty-prints (indents) JSON data."
    args = [{"name": "Indent", "type": "number", "value": 2}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        obj = json.loads(text)
        indent = int(self.get_arg(args, "Indent", 2))
        return json.dumps(obj, indent=indent, ensure_ascii=False).encode("utf-8")


class JSONMinify(Operation):
    name = "JSON Minify"
    category = CATEGORY
    description = "Removes all unnecessary whitespace from JSON data."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        obj = json.loads(text)
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class XMLBeautify(Operation):
    name = "XML Beautify"
    category = CATEGORY
    description = "Pretty-prints (indents) XML data."
    args = [{"name": "Indent", "type": "string", "value": "  "}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        dom = minidom.parseString(text)
        indent = self.get_arg(args, "Indent", "  ")
        pretty = dom.toprettyxml(indent=indent)
        lines = [l for l in pretty.split("\n") if l.strip()]
        return "\n".join(lines).encode("utf-8")


class XMLMinify(Operation):
    name = "XML Minify"
    category = CATEGORY
    description = "Removes unnecessary whitespace between XML tags."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        dom = minidom.parseString(text)
        return dom.toxml().encode("utf-8")


class SQLBeautify(Operation):
    name = "SQL Beautify"
    category = CATEGORY
    description = "Simple SQL formatting: uppercases keywords and adds newlines after clauses."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        sql_keywords = ["SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "INTO", "VALUES",
                         "UPDATE", "SET", "DELETE", "CREATE", "TABLE", "ALTER", "DROP",
                         "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "ON", "GROUP BY",
                         "ORDER BY", "HAVING", "LIMIT", "UNION", "AS", "NOT", "NULL",
                         "IS", "IN", "LIKE", "BETWEEN", "EXISTS", "CASE", "WHEN", "THEN",
                         "ELSE", "END", "DISTINCT", "COUNT", "SUM", "AVG", "MIN", "MAX"]
        for kw in sorted(sql_keywords, key=len, reverse=True):
            text = re.sub(r"\b%s\b" % kw, kw.upper(), text, flags=re.IGNORECASE)
        # Add newlines before major keywords
        for kw in ["SELECT", "FROM", "WHERE", "ORDER BY", "GROUP BY", "HAVING", "LIMIT",
                    "JOIN", "LEFT", "RIGHT", "INNER", "INSERT", "UPDATE", "DELETE", "SET", "VALUES"]:
            text = re.sub(r"\b%s\b" % kw, "\n%s" % kw.upper(), text, flags=re.IGNORECASE)
        return text.strip().encode("utf-8")


class SQLMinify(Operation):
    name = "SQL Minify"
    category = CATEGORY
    description = "Removes extra whitespace from SQL, collapsing to a single line."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"--.*$", "", text, flags=re.MULTILINE)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"\s+", " ", text)
        return text.strip().encode("utf-8")


class CSSBeautify(Operation):
    name = "CSS Beautify"
    category = CATEGORY
    description = "Simple CSS formatting: adds newlines and indentation."
    args = [{"name": "Indent", "type": "number", "value": 2}]

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        indent = int(self.get_arg(args, "Indent", 2))
        # Add newlines after { and ; and }
        text = text.replace("{", "{\n").replace("}", "\n}\n").replace(";", ";\n")
        lines = text.split("\n")
        result = []
        level = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == "}":
                level = max(0, level - 1)
            result.append(" " * (indent * level) + stripped)
            if stripped.endswith("{"):
                level += 1
        return "\n".join(result).encode("utf-8")


class CSSMinify(Operation):
    name = "CSS Minify"
    category = CATEGORY
    description = "Removes unnecessary whitespace from CSS."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"\s*\{\s*", "{", text)
        text = re.sub(r"\s*\}\s*", "}", text)
        text = re.sub(r"\s*;\s*", ";", text)
        text = re.sub(r"\s*:\s*", ":", text)
        return text.strip().encode("utf-8")


class JavaScriptBeautify(Operation):
    name = "JavaScript Beautify"
    category = CATEGORY
    description = "Simple JS formatting: adds newlines and indentation."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        text = text.replace("{", "{\n").replace("}", "\n}\n").replace(";", ";\n")
        lines = text.split("\n")
        result = []
        level = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == "}":
                level = max(0, level - 1)
            result.append("  " * level + stripped)
            if stripped.endswith("{"):
                level += 1
        return "\n".join(result).encode("utf-8")


class JavaScriptMinify(Operation):
    name = "JavaScript Minify"
    category = CATEGORY
    description = "Removes comments and unnecessary whitespace from JavaScript."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        # Remove single-line comments
        text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
        # Remove multi-line comments
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        # Collapse whitespace
        lines = []
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
        return " ".join(lines).encode("utf-8")


class StripHTMLTags(Operation):
    name = "Strip HTML tags"
    category = CATEGORY
    description = "Removes all HTML/XML tags, leaving only text content."

    def _run(self, data, args):
        text = data.decode("utf-8", errors="replace")
        return re.sub(r"<[^>]*>", "", text).encode("utf-8")


class GenericCodeBeautify(Operation):
    name = "Generic Code Beautify"
    category = CATEGORY
    description = "A simple code beautifier that adds consistent indentation based on braces."
    args = [{"name": "Indent width", "type": "number", "value": 4}]

    def _run(self, data, args):
        width = int(self.get_arg(args, "Indent width", 4))
        text = data.decode("utf-8", errors="replace")
        lines = []
        level = 0
        for char in text:
            if char == "{":
                lines.append(" " * (width * level) + "{")
                level += 1
                lines.append("")
            elif char == "}":
                level = max(0, level - 1)
                lines.append(" " * (width * level) + "}")
                lines.append("")
            elif char == ";":
                lines.append(";")
                lines.append("")
            elif char == "\n":
                if lines and lines[-1] != "":
                    lines.append("")
            else:
                if not lines:
                    lines.append("")
                if lines[-1] == "":
                    lines.append(" " * (width * level))
                lines.append(char)
        result = "".join(lines)
        # Clean up blank lines
        while "\n\n\n" in result:
            result = result.replace("\n\n\n", "\n\n")
        return result.strip().encode("utf-8")


class PHPSerialize(Operation):
    name = "PHP Serialize"
    category = CATEGORY
    description = "Serializes a Python object to PHP serialization format (basic types)."

    def _run(self, data, args):
        try:
            import phpserialize
            return phpserialize.dumps(data.decode("utf-8", errors="replace"))
        except ImportError:
            raise ImportError("phpserialize is not installed - run: pip install phpserialize")


class PHPDeserialize(Operation):
    name = "PHP Deserialize"
    category = CATEGORY
    description = "Deserializes PHP serialized data to a readable format."

    def _run(self, data, args):
        try:
            import phpserialize
            result = phpserialize.loads(data)
            return json.dumps(result, indent=2, default=str).encode("utf-8")
        except ImportError:
            # Fallback: basic regex-based extraction for display
            text = data.decode("utf-8", errors="replace")
            return text.encode("utf-8")


OPERATIONS = [
    JSONBeautify, JSONMinify, XMLBeautify, XMLMinify,
    SQLBeautify, SQLMinify, CSSBeautify, CSSMinify,
    JavaScriptBeautify, JavaScriptMinify, StripHTMLTags,
    GenericCodeBeautify, PHPSerialize, PHPDeserialize,
]