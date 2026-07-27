# -*- coding: utf-8 -*-
"""
Operation
=========
Base class every IDAChef operation derives from. Mirrors the shape of
CyberChef's src/core/Operation.mjs: a name, a category, a human
description, an argument schema, and a run() method.

Argument schema
----------------
`args` is a list of dicts, each describing one configurable parameter,
e.g.:

    {"name": "Key", "type": "string", "value": "secret"}
    {"name": "Rotation", "type": "number", "value": 13}
    {"name": "Case sensitive", "type": "boolean", "value": False}
    {"name": "Alphabet", "type": "option", "value": "A-Za-z0-9+/=",
     "options": ["A-Za-z0-9+/=", "A-Za-z0-9-_"]}

Supported "type" values: string, number, boolean, option, text (multiline).
"""

import sys
import traceback


class Operation(object):
    name = "Unnamed Operation"
    category = "Uncategorised"
    description = ""
    # infoURL kept for parity with CyberChef ops that link to background reading
    info_url = ""
    args = []

    def __init__(self):
        # Give every instance its own deep-ish copy of the arg schema so
        # editing one recipe step's values doesn't affect the operation
        # catalogue / other instances.
        self.args = [dict(a) for a in self.__class__.args]

    def get_arg(self, args, name, default=None):
        for a in args:
            if a["name"] == name:
                return a.get("value", default)
        return default

    def run(self, data, args):
        """
        data: bytes  -- input from the previous step in the recipe
        args: list   -- this operation's current argument dicts (see above)
        returns: bytes
        """
        from .logger import log
        try:
            result = self._run(data, args)
            return result
        except Exception as exc:
            log.error("Operation '%s' failed: %s\n%s", self.name, exc, traceback.format_exc())
            raise

    def _run(self, data, args):
        raise NotImplementedError

    def __repr__(self):
        return "<Operation %s>" % self.name