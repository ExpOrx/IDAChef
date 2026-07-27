# -*- coding: utf-8 -*-
"""Shared test runner - holds global counters and helper functions."""

import sys
import traceback

sys.path.insert(0, ".")

from idachef.core.recipe import Recipe

_passed = 0
_failed = 0
_failures = []


def recipe_test(name, ops, input_data, expected, input_encoding="utf-8"):
    """Run a recipe-based test."""
    global _passed, _failed, _failures
    import binascii
    from idachef.core.dish import to_str, to_bytes

    try:
        r = Recipe()
        for op_def in ops:
            op_cls = op_def["op_cls"]
            op_instance = op_cls()
            if "args" in op_def:
                for i, val in enumerate(op_def["args"]):
                    if i < len(op_instance.args):
                        op_instance.args[i]["value"] = val
            r.add_step(op_instance, op_instance.args)

        if input_encoding == "hex":
            inp = binascii.unhexlify(input_data)
        elif isinstance(input_data, list):
            inp = bytes(input_data)
        elif input_encoding == "latin-1":
            inp = input_data.encode("latin-1")
        else:
            inp = to_bytes(input_data)

        result = r.bake(inp)
        if result.error:
            _failures.append("%s: Recipe error - %s" % (name, result.error))
            _failed += 1
            return

        output = to_str(result.output)
        if isinstance(expected, bytes):
            match = (result.output == expected)
        elif isinstance(expected, list):
            # For list expected values, compare bytes directly
            match = (result.output == bytes(expected))
        elif input_encoding == "latin-1":
            # For latin-1 input, the expected might need to be compared as latin-1 bytes
            output_bytes = result.output
            expected_bytes = expected.encode("latin-1")
            match = (output_bytes == expected_bytes)
        else:
            match = (output.strip() == expected.strip())

        if match:
            _passed += 1
        else:
            _failures.append(
                "%s:\n  expected: %r\n  got:      %r" % (name, expected, output)
            )
            _failed += 1
    except Exception as e:
        _failures.append("%s: Exception - %s\n%s" % (name, e, traceback.format_exc()))
        _failed += 1


def report():
    total = _passed + _failed
    print("=" * 60)
    print("IDAChef Test Results: %d/%d passed" % (_passed, total))
    print("=" * 60)
    if _failures:
        print("\nFAILURES:")
        for f in _failures:
            print("  " + f)
        print("\n%d FAILURES" % _failed)
    else:
        print("ALL TESTS PASSED!")
    return _failed == 0