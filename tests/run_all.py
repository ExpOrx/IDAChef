# -*- coding: utf-8 -*-
"""IDAChef comprehensive test runner."""

import sys
import test_encoding
import test_hashing
import test_ciphers
import test_arithmetic
import test_utils
import test_formula
from test_runner import report

ok = report()
sys.exit(0 if ok else 1)