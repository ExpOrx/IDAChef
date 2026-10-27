# -*- coding: utf-8 -*-
"""Offscreen UI layout test for the resizable ChefWidget (no IDA required).

Stubs the IDA Python modules, then builds ChefWidget with a real Qt binding
in offscreen mode and verifies the splitter-based layout:
- three resizable columns (browser / recipe / I/O),
- resizable Input / Output / Batch sections in the I/O panel,
- resizable Recipe / Arguments sections in the recipe panel,
- every control survived the restructure,
- baking still works end-to-end through the UI.

Run standalone (``python tests/test_ui.py``) or via tests/run_all.py, which
skips this module when no Qt binding is available.
"""

import os
import sys
import types

sys.path.insert(0, ".")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt5 import QtCore, QtWidgets
except ImportError:
    try:
        from PySide6 import QtCore, QtWidgets
    except ImportError:
        # No Qt binding outside IDA - skip quietly (run_all reports 0 tests).
        print("[test_ui] skipped - no Qt binding available")
        sys.exit(0)

import test_runner

# ---- stub the IDA modules chef_widget imports at module level ----
idaapi = types.ModuleType("idaapi")
idaapi.PLUGIN_FIX = 1
idaapi.PLUGIN_KEEP = 2
idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
idaapi.msg = lambda s: None


class _PluginForm(object):
    def Show(self, title):
        pass


idaapi.PluginForm = _PluginForm
for name in ("idc", "ida_bytes", "ida_kernwin", "ida_nalt"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["idaapi"] = idaapi

from idachef.ui.chef_widget import ChefWidget
from idachef.operations.encoding import FromHex
from idachef.operations.ciphers import XOR


def direct_test(name, fn):
    try:
        fn()
        test_runner._passed += 1
    except AssertionError as exc:
        test_runner._failed += 1
        test_runner._failures.append("%s: %s" % (name, exc))
    except Exception as exc:  # noqa: BLE001
        test_runner._failed += 1
        test_runner._failures.append("%s: Exception - %r" % (name, exc))


_app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
_w = ChefWidget()
_w.resize(1100, 800)
_w.show()
_app.processEvents()


def _check(name, cond):
    assert cond, name


direct_test("UI: one horizontal main splitter with 3 panes", lambda: _check(
    "splitter count",
    len([s for s in _w.findChildren(QtWidgets.QSplitter)
         if s.orientation() == QtCore.Qt.Horizontal]) == 1))

_spls = _w.findChildren(QtWidgets.QSplitter)
_main = next(s for s in _spls if s.orientation() == QtCore.Qt.Horizontal)
_vert = [s for s in _spls if s.orientation() == QtCore.Qt.Vertical]
_io = next(s for s in _vert if s.count() == 3)
_recipe = next(s for s in _vert if s.count() == 2)

direct_test("UI: vertical splitters with 3 I/O and 2 recipe sections", lambda: _check(
    "section counts", sorted(s.count() for s in _vert) == [2, 3]))

direct_test("UI: splitters disallow collapsing panes away", lambda: _check(
    "collapsible", not _io.childrenCollapsible()
    and not _recipe.childrenCollapsible()
    and not _main.childrenCollapsible()))

for _attr in ("input_edit", "output_edit", "batch_table", "autobake_chk", "bake_btn",
              "addr_edit", "output_format_combo", "status_label", "recipe_list",
              "args_editor", "btn_save_recipe", "btn_load_recipe",
              "range_start_edit", "range_end_edit"):
    direct_test("UI: control present after restructure: %s" % _attr,
                lambda a=_attr: _check(a, hasattr(_w, a)))

direct_test("UI: input/bake controls live in I/O section 0", lambda: _check(
    "section 0", _w.input_edit.parentWidget() is _io.widget(0)
    and _w.autobake_chk.parentWidget() is _io.widget(0)))

direct_test("UI: output/patch controls live in I/O section 1", lambda: _check(
    "section 1", _w.output_edit.parentWidget() is _io.widget(1)
    and _w.addr_edit.parentWidget() is _io.widget(1)))

direct_test("UI: batch controls live in I/O section 2", lambda: _check(
    "section 2", _w.batch_table.parentWidget() is _io.widget(2)
    and _w.status_label.parentWidget() is _io.widget(2)))

direct_test("UI: recipe list on top, argument editor below", lambda: _check(
    "recipe sections", _w.recipe_list.parentWidget() is _recipe.widget(0)
    and _w.args_editor.parentWidget().parentWidget().parentWidget() is _recipe.widget(1)))


def _shrink_test():
    _w.resize(1100, 900)
    _app.processEvents()
    big = sum(_io.sizes())
    _w.resize(1100, 350)
    _app.processEvents()
    small = _io.sizes()
    _w.resize(1100, 900)
    _app.processEvents()
    assert sum(small) < big, "sections did not shrink: %s" % small
    assert all(s > 40 for s in small), "a section collapsed below its minimum: %s" % small


direct_test("UI: I/O sections shrink and keep minimums when dock shrinks", _shrink_test)


def _drag_test():
    _io.setSizes([600, 150, 100])
    _app.processEvents()
    got = _io.sizes()
    assert got[0] > got[1] * 2, "handle drag not respected: %s" % got
    _recipe.setSizes([300, 80])
    _app.processEvents()
    assert _recipe.sizes()[0] > _recipe.sizes()[1] * 2, "recipe drag not respected: %s" % _recipe.sizes()
    _main.setSizes([150, 250, 800])
    _app.processEvents()
    m = _main.sizes()
    assert m[0] < m[2] and m[1] < m[2], "column drag not respected: %s" % m


direct_test("UI: splitter handles are draggable (setSizes honoured)", _drag_test)


def _bake_test():
    _w.recipe.clear()
    _w.recipe_list.clear()
    _w._add_operation(FromHex)
    _w._add_operation(XOR)
    for i, val in enumerate(["55", "Hex", "Byte"]):
        if i < len(_w.recipe.steps[1][1]):
            _w.recipe.steps[1][1][i]["value"] = val
    _w.input_edit.setPlainText("41 42 43")
    _w.bake()
    _app.processEvents()
    assert _w.output_edit.toPlainText() == "14 17 16", _w.output_edit.toPlainText()


direct_test("UI: bake pipeline works end-to-end (FromHex+XOR via UI)", _bake_test)
