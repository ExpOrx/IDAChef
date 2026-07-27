# -*- coding: utf-8 -*-
"""
IDAChef Logging
===============
Centralized logging module that writes to IDA Pro's output window via
`idaapi.msg()` when running inside IDA, and falls back to `print()` /
Python's `logging` module when running standalone (e.g. unit tests).

Usage in any module:
    from idachef.core.logger import log
    log.info("Something happened: %s", details)
    log.warn("Warning about: %r", value)
    log.debug("Debug: op=%s data_len=%d", op_name, len(data))
    log.error("Operation '%s' failed: %s", op_name, str(exc))
"""

import sys
import traceback

_log = None


def _get_logger():
    global _log
    if _log is not None:
        return _log

    try:
        import idaapi  # type: ignore

        class IDALogger(object):
            """Writes to IDA's output window via idaapi.msg()."""

            def _fmt(self, level, msg, *args):
                ts = __import__("time").strftime("%H:%M:%S")
                prefix = "[%s %s] " % (ts, level)
                if args:
                    msg = msg % args
                return prefix + msg

            def debug(self, msg, *args):
                idaapi.msg(self._fmt("DBG", msg, *args) + "\n")

            def info(self, msg, *args):
                idaapi.msg(self._fmt("INF", msg, *args) + "\n")

            def warn(self, msg, *args):
                idaapi.msg(self._fmt("WRN", msg, *args) + "\n")

            def error(self, msg, *args):
                idaapi.msg(self._fmt("ERR", msg, *args) + "\n")

        _log = IDALogger()
    except ImportError:
        import logging as _logging

        class FallbackLogger(object):
            """Writes to stderr via Python's logging or print."""

            def __init__(self):
                self._logger = _logging.getLogger("IDAChef")
                self._logger.setLevel(_logging.DEBUG)
                if not self._logger.handlers:
                    h = _logging.StreamHandler(sys.stderr)
                    h.setFormatter(
                        _logging.Formatter(
                            "[%(asctime)s %(levelname)s] %(message)s",
                            datefmt="%H:%M:%S",
                        )
                    )
                    self._logger.addHandler(h)

            def debug(self, msg, *args):
                self._logger.debug(msg, *args)

            def info(self, msg, *args):
                self._logger.info(msg, *args)

            def warn(self, msg, *args):
                self._logger.warning(msg, *args)

            def error(self, msg, *args):
                self._logger.error(msg, *args)

        _log = FallbackLogger()

    return _log


# Singleton instance — every module imports this same object.
log = _get_logger()


def log_exception(msg="Exception occurred"):
    """Log the current exception with full traceback."""
    exc_type, exc_val, exc_tb = sys.exc_info()
    if exc_tb is not None:
        tb_lines = traceback.format_exception(exc_type, exc_val, exc_tb)
        log.error(
            "%s: %s\n%s", msg, str(exc_val), "".join(tb_lines)
        )
    else:
        log.error(msg)