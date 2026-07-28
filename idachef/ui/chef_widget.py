# -*- coding: utf-8 -*-
"""
The IDAChef widget: CyberChef-style operation browser + recipe builder +
input/output panes, wired up to IDA's database (selection, patching,
comments) instead of a browser tab.

Input parsing: \\xHH escapes → plain text (no auto-detection of hex/base64).
Use explicit "From Hex" / "From Base64" recipe steps to decode input.
"""

import base64 as _base64
import binascii
import re

import idaapi
import idc
import ida_bytes
import ida_kernwin
import ida_nalt

from .qt_compat import QtCore, QtGui, QtWidgets, Qt
from ..core.recipe import Recipe
from ..core.dish import to_bytes, to_str
from ..core.logger import log
from ..operations import get_categories, search_operations

OP_ROLE = Qt.UserRole + 1

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

LENGTH_HINT_ARG_NAMES = {"key", "iv", "nonce", "salt"}
KEY_SIZE_HINTS = {16: "AES-128 / DES3-ok", 24: "AES-192 / 3DES", 32: "AES-256", 8: "DES"}


def _short_val(val, max_len=28):
    s = str(val)
    if len(s) > max_len:
        return s[:max_len - 3] + "..."
    return s


def _format_step_text(op_instance, args):
    parts = [op_instance.name]
    if not args:
        return "".join(parts)
    snippets = []
    for a in args:
        name = a["name"]
        val = a.get("value", "")
        if val == "" or val is None or val is False:
            continue
        atype = a.get("type", "string")
        if atype == "boolean":
            if val:
                snippets.append(name)
        elif atype == "option":
            snippets.append("%s" % _short_val(val, 22))
        elif atype == "number":
            if val != 0:
                snippets.append("%s=%s" % (name, _short_val(val)))
        else:
            snippets.append("%s=%s" % (name, _short_val(val)))
    if snippets:
        parts.append("  [%s]" % ", ".join(snippets))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Reusable widgets
# ---------------------------------------------------------------------------
class AutoGrowLineEdit(QtWidgets.QLineEdit):
    MIN_WIDTH = 160
    MAX_WIDTH = 520

    def __init__(self, text="", parent=None):
        super(AutoGrowLineEdit, self).__init__(text, parent)
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.setFont(font)
        self.textChanged.connect(self._resize_to_content)
        self._resize_to_content()

    def _resize_to_content(self, *_):
        metrics = QtGui.QFontMetrics(self.font())
        text_width = metrics.horizontalAdvance(self.text() or self.placeholderText())
        width = max(self.MIN_WIDTH, min(self.MAX_WIDTH, text_width + 28))
        self.setMinimumWidth(width)


class RadioOptionGroup(QtWidgets.QWidget):
    def __init__(self, options, current, parent=None):
        super(RadioOptionGroup, self).__init__(parent)
        row = QtWidgets.QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.group = QtWidgets.QButtonGroup(self)
        self.group.setExclusive(True)
        self._buttons = {}
        for opt in options:
            btn = QtWidgets.QRadioButton(opt)
            btn.setChecked(opt == current)
            self.group.addButton(btn)
            row.addWidget(btn)
            self._buttons[opt] = btn
        row.addStretch(1)

    def current_text(self):
        for text, btn in self._buttons.items():
            if btn.isChecked():
                return text
        return None

    def connect_changed(self, slot):
        self.group.buttonToggled.connect(lambda btn, checked: checked and slot(btn.text()))


# ---------------------------------------------------------------------------
# Argument editor
# ---------------------------------------------------------------------------
class ArgsEditor(QtWidgets.QWidget):
    changed = QtCore.pyqtSignal() if hasattr(QtCore, "pyqtSignal") else QtCore.Signal()
    RADIO_THRESHOLD = 6

    def __init__(self, parent=None):
        super(ArgsEditor, self).__init__(parent)
        self.form = QtWidgets.QFormLayout(self)
        self.form.setContentsMargins(4, 4, 4, 4)
        self.form.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)
        self.args = None
        self._widgets = []

    def set_args(self, args):
        while self.form.rowCount():
            self.form.removeRow(0)
        self._widgets = []
        self.args = args
        if not args:
            self.form.addRow(QtWidgets.QLabel("(no arguments)"))
            return
        for arg in args:
            label = QtWidgets.QLabel("<b>%s</b>" % arg["name"])
            atype = arg.get("type", "string")
            if atype == "boolean":
                w = QtWidgets.QCheckBox()
                w.setChecked(bool(arg.get("value", False)))
                w.stateChanged.connect(self._make_bool_handler(arg))
                self._widgets.append(w)
                self.form.addRow(label, w)
            elif atype == "option":
                options = arg.get("options", [])
                cur = arg.get("value")
                if 0 < len(options) <= self.RADIO_THRESHOLD:
                    w = RadioOptionGroup(options, cur)
                    w.connect_changed(self._make_text_handler(arg))
                else:
                    w = QtWidgets.QComboBox()
                    w.addItems(options)
                    if cur in options:
                        w.setCurrentText(cur)
                    w.currentTextChanged.connect(self._make_text_handler(arg))
                self._widgets.append(w)
                self.form.addRow(label, w)
            elif atype == "number":
                w = AutoGrowLineEdit(str(arg.get("value", 0)))
                w.setValidator(QtGui.QDoubleValidator())
                w.textChanged.connect(self._make_number_handler(arg))
                self._widgets.append(w)
                self.form.addRow(label, w)
            elif atype == "text":
                w = QtWidgets.QPlainTextEdit(str(arg.get("value", "")))
                w.setMaximumHeight(70)
                w.textChanged.connect(self._make_plaintext_handler(arg, w))
                self._widgets.append(w)
                self.form.addRow(label, w)
            else:
                w = AutoGrowLineEdit(str(arg.get("value", "")))
                w.textChanged.connect(self._make_text_handler(arg))
                self._widgets.append(w)
                if arg["name"].strip().lower() in LENGTH_HINT_ARG_NAMES:
                    self._add_field_with_length_hint(label, w, arg)
                else:
                    self.form.addRow(label, w)

    def _add_field_with_length_hint(self, label, line_edit, arg):
        container = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(container)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        v.addWidget(line_edit)
        hint = QtWidgets.QLabel("")
        hint.setStyleSheet("color: gray; font-size: 10px;")
        v.addWidget(hint)
        self.form.addRow(label, container)

        def update_hint(text=None):
            text = line_edit.text()
            fmt = self._sibling_format(arg)
            n_bytes = self._byte_length_for(text, fmt)
            note = KEY_SIZE_HINTS.get(n_bytes, "")
            hint.setText("%d chars -> %d bytes as %s%s" % (
                len(text), n_bytes, fmt, ("  (%s)" % note) if note else ""))
            hint.setStyleSheet("color: %s; font-size: 10px;" % ("#2e7d32" if note else "gray"))

        line_edit.textChanged.connect(update_hint)
        update_hint()

    def _sibling_format(self, arg):
        wanted = (arg["name"] + " format").strip().lower()
        for other in (self.args or []):
            if other["name"].strip().lower() == wanted:
                return other.get("value", "UTF8")
        return "UTF8"

    @staticmethod
    def _byte_length_for(text, fmt):
        try:
            if fmt == "Hex":
                return len(re.sub(r"[^0-9a-fA-F]", "", text)) // 2
            if fmt == "Base64":
                pad = text + "=" * (-len(text) % 4)
                return len(_base64.b64decode(pad, validate=False))
        except Exception:
            return 0
        return len(text.encode("utf-8", errors="ignore"))

    def _make_bool_handler(self, arg):
        def handler(state):
            arg["value"] = bool(state)
            self.changed.emit()
        return handler

    def _make_text_handler(self, arg):
        def handler(text):
            arg["value"] = text
            self.changed.emit()
        return handler

    def _make_number_handler(self, arg):
        def handler(text):
            try:
                arg["value"] = float(text) if "." in text else int(text)
            except ValueError:
                arg["value"] = 0
            self.changed.emit()
        return handler

    def _make_plaintext_handler(self, arg, widget):
        def handler():
            arg["value"] = widget.toPlainText()
            self.changed.emit()
        return handler


# ---------------------------------------------------------------------------
# Main widget
# ---------------------------------------------------------------------------
class ChefWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(ChefWidget, self).__init__(parent)
        self.recipe = Recipe()
        self._raw_input_bytes = None
        self._build_ui()
        self._populate_op_tree()

    # ---- UI construction -------------------------------------------------
    def _build_ui(self):
        root = QtWidgets.QHBoxLayout(self)
        splitter = QtWidgets.QSplitter(Qt.Horizontal)
        root.addWidget(splitter)
        splitter.addWidget(self._build_op_browser())
        splitter.addWidget(self._build_recipe_panel())
        splitter.addWidget(self._build_io_panel())
        splitter.setSizes([260, 360, 480])

    def _build_op_browser(self):
        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(panel)
        layout.addWidget(QtWidgets.QLabel("<b>Operations</b>  (double-click to add)"))
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search operations...")
        self.search_box.textChanged.connect(self._on_search)
        layout.addWidget(self.search_box)
        self.op_tree = QtWidgets.QTreeWidget()
        self.op_tree.setHeaderHidden(True)
        self.op_tree.itemDoubleClicked.connect(self._on_op_double_clicked)
        self.op_tree.setToolTipDuration(15000)
        layout.addWidget(self.op_tree)
        return panel

    def _build_recipe_panel(self):
        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(panel)
        layout.addWidget(QtWidgets.QLabel("<b>Recipe</b>"))
        self.recipe_list = QtWidgets.QListWidget()
        self.recipe_list.currentRowChanged.connect(self._on_recipe_selection)
        layout.addWidget(self.recipe_list)
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_up = QtWidgets.QPushButton("Up")
        self.btn_down = QtWidgets.QPushButton("Down")
        self.btn_remove = QtWidgets.QPushButton("Remove")
        self.btn_clear = QtWidgets.QPushButton("Clear")
        for b in (self.btn_up, self.btn_down, self.btn_remove, self.btn_clear):
            btn_row.addWidget(b)
        self.btn_up.clicked.connect(lambda: self._move_step(-1))
        self.btn_down.clicked.connect(lambda: self._move_step(1))
        self.btn_remove.clicked.connect(self._remove_step)
        self.btn_clear.clicked.connect(self._clear_recipe)
        layout.addLayout(btn_row)
        layout.addWidget(QtWidgets.QLabel("<b>Arguments</b>"))
        self.args_editor = ArgsEditor()
        self.args_editor.changed.connect(self._on_args_changed)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.args_editor)
        layout.addWidget(scroll, 1)
        return panel

    def _build_io_panel(self):
        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(panel)
        layout.addWidget(QtWidgets.QLabel("<b>Input</b>"))
        in_btn_row = QtWidgets.QHBoxLayout()
        btn_sel = QtWidgets.QPushButton("Get Selected Bytes")
        btn_sel.setToolTip("Reads the currently selected range in the disassembly/hex view")
        btn_sel.clicked.connect(self._get_input_from_selection)
        btn_str = QtWidgets.QPushButton("Get String @ Cursor")
        btn_str.clicked.connect(self._get_input_from_string_here)
        btn_clip = QtWidgets.QPushButton("From Clipboard")
        btn_clip.clicked.connect(self._get_input_from_clipboard)
        for b in (btn_sel, btn_str, btn_clip):
            in_btn_row.addWidget(b)
        layout.addLayout(in_btn_row)
        self.input_edit = QtWidgets.QPlainTextEdit()
        self.input_edit.setPlaceholderText(
            "Paste data here, or use the buttons above to pull bytes from IDA..."
        )
        self.input_edit.textChanged.connect(self._on_input_text_changed)
        layout.addWidget(self.input_edit, 1)

        bake_row = QtWidgets.QHBoxLayout()
        self.autobake_chk = QtWidgets.QCheckBox("Auto Bake")
        self.autobake_chk.setChecked(True)
        self.bake_btn = QtWidgets.QPushButton("Bake!")
        self.bake_btn.clicked.connect(self.bake)
        bake_row.addWidget(self.autobake_chk)
        bake_row.addStretch(1)
        bake_row.addWidget(self.bake_btn)
        layout.addLayout(bake_row)

        out_fmt_row = QtWidgets.QHBoxLayout()
        out_fmt_row.addWidget(QtWidgets.QLabel("<b>Output</b>"))
        out_fmt_row.addStretch(1)
        self.output_format_combo = QtWidgets.QComboBox()
        self.output_format_combo.addItems(
            ["Auto (hex/text)", "Hex", "UTF-8 Text", "Latin-1 Raw", "Base64", "Decimal Bytes"]
        )
        self.output_format_combo.currentTextChanged.connect(self._on_output_format_changed)
        out_fmt_row.addWidget(QtWidgets.QLabel("Format:"))
        out_fmt_row.addWidget(self.output_format_combo)
        layout.addLayout(out_fmt_row)

        self.output_edit = QtWidgets.QPlainTextEdit()
        self.output_edit.setReadOnly(True)
        layout.addWidget(self.output_edit, 1)

        out_btn_row = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton("Copy Output")
        btn_copy.clicked.connect(self._copy_output)
        btn_as_input = QtWidgets.QPushButton("Output -> Input")
        btn_as_input.clicked.connect(self._output_to_input)
        out_btn_row.addWidget(btn_copy)
        out_btn_row.addWidget(btn_as_input)
        layout.addLayout(out_btn_row)

        layout.addWidget(QtWidgets.QLabel("Target address for Patch/Comment:"))
        addr_row = QtWidgets.QHBoxLayout()
        self.addr_edit = QtWidgets.QLineEdit()
        self.addr_edit.setPlaceholderText("hex address, e.g. 0x140001000")
        btn_here = QtWidgets.QPushButton("Use Cursor")
        btn_here.clicked.connect(self._use_cursor_addr)
        addr_row.addWidget(self.addr_edit)
        addr_row.addWidget(btn_here)
        layout.addLayout(addr_row)

        act_row = QtWidgets.QHBoxLayout()
        btn_patch = QtWidgets.QPushButton("Patch Bytes at Address")
        btn_patch.setToolTip("Interprets Output as raw bytes and patches the database")
        btn_patch.clicked.connect(self._patch_output)
        btn_cmt = QtWidgets.QPushButton("Set Comment at Address")
        btn_cmt.clicked.connect(self._comment_output)
        act_row.addWidget(btn_patch)
        act_row.addWidget(btn_cmt)
        layout.addLayout(act_row)

        # ---- Batch Processing Section ----
        layout.addWidget(QtWidgets.QLabel("<b>Batch Processing — Address Range</b>"))
        range_row = QtWidgets.QHBoxLayout()
        range_row.addWidget(QtWidgets.QLabel("Start:"))
        self.range_start_edit = QtWidgets.QLineEdit()
        self.range_start_edit.setPlaceholderText("0x...")
        range_row.addWidget(self.range_start_edit)
        range_row.addWidget(QtWidgets.QLabel("End:"))
        self.range_end_edit = QtWidgets.QLineEdit()
        self.range_end_edit.setPlaceholderText("0x...")
        range_row.addWidget(self.range_end_edit)
        btn_read_range = QtWidgets.QPushButton("Read Strings in Range")
        btn_read_range.clicked.connect(self._on_read_strings_in_range)
        range_row.addWidget(btn_read_range)
        layout.addLayout(range_row)

        # Batch results table
        self.batch_table = QtWidgets.QTableWidget(0, 4)
        self.batch_table.setHorizontalHeaderLabels(["✓", "Address", "Original String", "Baked Result"])
        self.batch_table.horizontalHeader().setStretchLastSection(True)
        self.batch_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        layout.addWidget(self.batch_table)

        # Batch action buttons
        batch_btn_row = QtWidgets.QHBoxLayout()
        btn_batch_bake = QtWidgets.QPushButton("Batch Bake")
        btn_batch_bake.clicked.connect(self._on_batch_bake)
        btn_batch_patch = QtWidgets.QPushButton("Batch Patch Selected")
        btn_batch_patch.clicked.connect(self._on_batch_patch_selected)
        batch_btn_row.addWidget(btn_batch_bake)
        batch_btn_row.addWidget(btn_batch_patch)
        layout.addLayout(batch_btn_row)

        self.status_label = QtWidgets.QLabel("")
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)
        return panel

    # ---- Operation tree ----------------------------------------------------
    def _populate_op_tree(self, filtered_ops=None):
        self.op_tree.clear()
        if filtered_ops is None:
            for cat, ops in get_categories():
                cat_item = QtWidgets.QTreeWidgetItem([cat])
                cat_item.setFlags(cat_item.flags() & ~Qt.ItemIsSelectable)
                for op_cls in ops:
                    op_item = QtWidgets.QTreeWidgetItem([op_cls.name])
                    op_item.setData(0, OP_ROLE, op_cls)
                    op_item.setToolTip(0, op_cls.description)
                    cat_item.addChild(op_item)
                self.op_tree.addTopLevelItem(cat_item)
            self.op_tree.expandAll()
        else:
            for op_cls in filtered_ops:
                op_item = QtWidgets.QTreeWidgetItem(["%s  [%s]" % (op_cls.name, op_cls.category)])
                op_item.setData(0, OP_ROLE, op_cls)
                op_item.setToolTip(0, op_cls.description)
                self.op_tree.addTopLevelItem(op_item)

    def _on_search(self, text):
        if not text.strip():
            self._populate_op_tree()
        else:
            self._populate_op_tree(search_operations(text))

    def _on_op_double_clicked(self, item, _col):
        op_cls = item.data(0, OP_ROLE)
        if op_cls is None:
            return
        self._add_operation(op_cls)

    # ---- Recipe management --------------------------------------------------
    def _add_operation(self, op_cls):
        op_instance = op_cls()
        self.recipe.add_step(op_instance, op_instance.args)
        list_item = QtWidgets.QListWidgetItem(_format_step_text(op_instance, op_instance.args))
        list_item.setToolTip(op_instance.description)
        self.recipe_list.addItem(list_item)
        self.recipe_list.setCurrentRow(self.recipe_list.count() - 1)
        self._maybe_autobake()

    def _on_recipe_selection(self, row):
        if 0 <= row < len(self.recipe.steps):
            _, args = self.recipe.steps[row]
            self.args_editor.set_args(args)
        else:
            self.args_editor.set_args(None)

    def _refresh_recipe_display(self):
        for i, (op, args) in enumerate(self.recipe.steps):
            if i < self.recipe_list.count():
                item = self.recipe_list.item(i)
                item.setText(_format_step_text(op, args))

    def _on_args_changed(self):
        self._refresh_recipe_display()
        self._maybe_autobake()

    def _move_step(self, delta):
        row = self.recipe_list.currentRow()
        if row < 0:
            return
        new_row = self.recipe.move_step(row, delta)
        if new_row != row:
            item = self.recipe_list.takeItem(row)
            self.recipe_list.insertItem(new_row, item)
            self.recipe_list.setCurrentRow(new_row)
            self._maybe_autobake()

    def _remove_step(self):
        row = self.recipe_list.currentRow()
        if row < 0:
            return
        self.recipe.remove_step(row)
        self.recipe_list.takeItem(row)
        self._maybe_autobake()

    def _clear_recipe(self):
        self.recipe.clear()
        self.recipe_list.clear()
        self.args_editor.set_args(None)
        self._maybe_autobake()

    # ---- Input sources (IDA integration) ------------------------------------
    def _get_input_from_selection(self):
        try:
            ok, start, end = ida_kernwin.read_range_selection(None)
        except Exception:
            ok, start, end = False, idaapi.BADADDR, idaapi.BADADDR
        if not ok:
            ea = idc.here()
            size = idc.get_item_size(ea) or 1
            start, end = ea, ea + size
        data = ida_bytes.get_bytes(start, end - start)
        if data is None:
            self._set_status("Could not read bytes at 0x%x-0x%x" % (start, end), error=True)
            return
        # Display hex text in the input field but do NOT store raw bytes
        # via _raw_input_bytes.  The hex text flows through the normal
        # text pipeline so that recipe steps like "From Hex" can decode it
        # without double-decoding raw IDA bytes.
        self.input_edit.blockSignals(True)
        self._raw_input_bytes = None
        self.input_edit.setPlainText(binascii.hexlify(data).decode())
        self.input_edit.blockSignals(False)
        self.addr_edit.setText("0x%x" % start)
        self._set_status("Loaded %d bytes from 0x%x-0x%x as hex" % (len(data), start, end))

    def _get_input_from_string_here(self):
        ea = idc.here()
        try:
            s = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        except Exception:
            s = None
        if not s:
            self._set_status("No string literal detected at 0x%x" % ea, error=True)
            return
        self.input_edit.blockSignals(True)
        self._raw_input_bytes = s
        self.input_edit.setPlainText(to_str(s))
        self.input_edit.blockSignals(False)
        self.addr_edit.setText("0x%x" % ea)
        self._set_status("Loaded string (%d bytes) from 0x%x" % (len(s), ea))

    def _get_input_from_clipboard(self):
        clipboard = QtWidgets.QApplication.clipboard()
        self._raw_input_bytes = None
        self.input_edit.blockSignals(True)
        self.input_edit.setPlainText(clipboard.text())
        self.input_edit.blockSignals(False)
        self._set_status("Loaded input from clipboard")

    def _use_cursor_addr(self):
        self.addr_edit.setText("0x%x" % idc.here())

    # ---- Baking ---------------------------------------------------------
    def _on_input_text_changed(self):
        self._raw_input_bytes = None
        self._maybe_autobake()

    def _maybe_autobake(self):
        if self.autobake_chk.isChecked():
            self.bake()

    def bake(self):
        """Main bake pipeline."""
        if self._raw_input_bytes is not None:
            input_bytes = self._raw_input_bytes
            log.info("Input: %s", to_str(input_bytes)[:300])
        else:
            raw_text = self.input_edit.toPlainText()
            input_bytes = self._parse_input_bytes(raw_text)
            log.info("Input: %s", raw_text[:300])

        result = self.recipe.bake(input_bytes)

        output_text = self._format_output(result.output)
        self.output_edit.setPlainText(output_text)

        if result.error:
            log.error("Bake failed: %s", result.error)
            self._set_status(str(result.error), error=True)
        else:
            log.info("Result: %s", to_str(result.output)[:300])
            self._set_status("Baked OK - %d byte(s) out" % len(result.output))

    def _format_output(self, data):
        if not data:
            return ""
        fmt = self.output_format_combo.currentText()
        if fmt == "Auto (hex/text)":
            printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
            ratio = printable / max(1, len(data))
            if ratio < 0.5:
                return " ".join("%02x" % b for b in data)
            return to_str(data)
        elif fmt == "Hex":
            return " ".join("%02x" % b for b in data)
        elif fmt == "UTF-8 Text":
            return to_str(data)
        elif fmt == "Latin-1 Raw":
            return data.decode("latin-1")
        elif fmt == "Base64":
            return _base64.b64encode(data).decode()
        elif fmt == "Decimal Bytes":
            return " ".join(str(b) for b in data)
        return to_str(data)

    def _on_output_format_changed(self, _text):
        self._maybe_autobake()

    def _parse_input_bytes(self, raw_text):
        """Convert input to bytes — plain-text passthrough after \\x escapes.

        No auto-detection of hex or Base64.  The input is always treated as
        text; use explicit "From Hex" / "From Base64" recipe steps to decode.
        This prevents double-decoding when the recipe already contains those
        steps.
        """
        raw_text = raw_text.strip()
        if not raw_text:
            return b""

        # Step 1: CyberChef byte notation  ',7Fh,'  ->  \\x7F
        converted = re.sub(
            r"',([0-9a-fA-F]{2})h,'",
            lambda m: "\\x" + m.group(1),
            raw_text,
        )
        if "\\x" in converted:
            return self._unescape_text(converted)

        # Step 2: Python style \\xHH / \\n / \\t / \\r / \\\\
        if "\\" in raw_text:
            return self._unescape_text(raw_text)

        # Step 3: Plain text — recipe steps handle any further decoding
        return to_bytes(raw_text)

    def _unescape_text(self, raw_text):
        """Convert \\xHH, \\n, \\t, \\r, \\\\ and stray backslashes to bytes."""
        result = bytearray()
        i = 0
        while i < len(raw_text):
            c = raw_text[i]
            if c == "\\" and i + 1 < len(raw_text):
                nxt = raw_text[i + 1]
                if nxt == "x" and i + 3 < len(raw_text):
                    try:
                        result.append(int(raw_text[i + 2:i + 4], 16))
                        i += 4
                        continue
                    except ValueError:
                        pass
                elif nxt == "n":
                    result.append(0x0A)
                    i += 2
                    continue
                elif nxt == "t":
                    result.append(0x09)
                    i += 2
                    continue
                elif nxt == "r":
                    result.append(0x0D)
                    i += 2
                    continue
                elif nxt == "\\":
                    result.append(0x5C)
                    i += 2
                    continue
                else:
                    result.append(ord(nxt))
                    i += 2
                    continue
            else:
                result.append(ord(c))
                i += 1
        return bytes(result)

    def _set_status(self, text, error=False):
        self.status_label.setText(text)
        self.status_label.setStyleSheet("color: %s;" % ("#c0392b" if error else "gray"))

    # ---- Output actions ---------------------------------------------------
    def _copy_output(self):
        QtWidgets.QApplication.clipboard().setText(self.output_edit.toPlainText())
        self._set_status("Output copied to clipboard")

    def _output_to_input(self):
        if not self.recipe.steps:
            self.input_edit.setPlainText(self.output_edit.toPlainText())
            return
        raw_text = self.input_edit.toPlainText()
        input_bytes = self._parse_input_bytes(raw_text)
        result = self.recipe.bake(input_bytes)
        b64 = _base64.b64encode(result.output).decode()
        self.input_edit.blockSignals(True)
        self.input_edit.setPlainText(b64)
        self.input_edit.blockSignals(False)

    def _resolve_output_bytes(self):
        text = self.output_edit.toPlainText().strip()
        candidate = "".join(text.split())
        if candidate and all(c in "0123456789abcdefABCDEF" for c in candidate) and len(candidate) % 2 == 0:
            try:
                return binascii.unhexlify(candidate)
            except Exception:
                pass
        return to_bytes(text)

    def _get_target_addr(self):
        text = self.addr_edit.text().strip()
        if not text:
            raise ValueError("Enter a target address (or click 'Use Cursor') first")
        return int(text, 16) if text.lower().startswith("0x") else int(text, 16)

    def _patch_output(self):
        try:
            ea = self._get_target_addr()
            data = self._resolve_output_bytes()
            if not data:
                self._set_status("Nothing to patch (empty output)", error=True)
                return
            ida_bytes.patch_bytes(ea, data)
            self._set_status("Patched %d byte(s) at 0x%x" % (len(data), ea))
        except Exception as exc:
            self._set_status("Patch failed: %s" % exc, error=True)

    def _comment_output(self):
        try:
            ea = self._get_target_addr()
            text = self.output_edit.toPlainText()
            idc.set_cmt(ea, text, 0)
            self._set_status("Comment set at 0x%x" % ea)
        except Exception as exc:
            self._set_status("Comment failed: %s" % exc, error=True)

    # -----------------------------------------------------------------------
    # Batch processing — address range string scanning + bulk operations
    # -----------------------------------------------------------------------
    def _parse_addr(self, text):
        """Parse a hex address string (with or without 0x prefix)."""
        text = text.strip()
        if not text:
            raise ValueError("Address is empty")
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 16)

    def _on_read_strings_in_range(self):
        """Scan the [startAddress, endAddress) range for C-string literals
        and populate the batch table with them."""
        try:
            start = self._parse_addr(self.range_start_edit.text())
            end = self._parse_addr(self.range_end_edit.text())
        except ValueError as exc:
            self._set_status("Invalid address: %s" % exc, error=True)
            return

        if start >= end:
            self._set_status("Start address must be less than end address", error=True)
            return

        self.batch_table.setRowCount(0)
        count = 0
        ea = start
        while ea < end:
            try:
                s = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
            except Exception:
                s = None

            if s is not None and len(s) > 0:
                # Check that the string actually starts at 'ea' (not an
                # xref pointing into the middle of a string)
                str_ea = ea
                text = to_str(s)
                row = self.batch_table.rowCount()
                self.batch_table.insertRow(row)
                # Checkbox column
                chk_item = QtWidgets.QTableWidgetItem()
                chk_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
                chk_item.setCheckState(Qt.Checked)
                self.batch_table.setItem(row, 0, chk_item)
                # Address column
                addr_item = QtWidgets.QTableWidgetItem("0x%x" % str_ea)
                addr_item.setFlags(addr_item.flags() & ~Qt.ItemIsEditable)
                self.batch_table.setItem(row, 1, addr_item)
                # Original string column
                orig_item = QtWidgets.QTableWidgetItem(text)
                orig_item.setToolTip(text)
                orig_item.setFlags(orig_item.flags() & ~Qt.ItemIsEditable)
                self.batch_table.setItem(row, 2, orig_item)
                # Baked result column (empty initially)
                result_item = QtWidgets.QTableWidgetItem("")
                result_item.setFlags(result_item.flags() & ~Qt.ItemIsEditable)
                self.batch_table.setItem(row, 3, result_item)
                count += 1
                # Advance past this string (including null terminator)
                ea = str_ea + len(s) + 1
            else:
                ea += 1

        self.batch_table.resizeColumnsToContents()
        self._set_status("Found %d string(s) in range 0x%x – 0x%x" % (count, start, end))

    def _on_batch_bake(self):
        """Run the current recipe against every string in the batch table."""
        if not self.recipe.steps:
            self._set_status("Recipe is empty — add operations first", error=True)
            return

        row_count = self.batch_table.rowCount()
        if row_count == 0:
            self._set_status("No strings in batch table — read a range first", error=True)
            return

        processed = 0
        errors = 0
        for row in range(row_count):
            orig_item = self.batch_table.item(row, 2)
            if orig_item is None:
                continue
            orig_text = orig_item.text()
            input_bytes = to_bytes(orig_text)
            result = self.recipe.bake(input_bytes)
            if result.error:
                result_text = "ERROR: %s" % result.error
                errors += 1
            else:
                result_text = to_str(result.output)
            result_item = self.batch_table.item(row, 3)
            if result_item is None:
                result_item = QtWidgets.QTableWidgetItem(result_text)
                result_item.setFlags(result_item.flags() & ~Qt.ItemIsEditable)
                self.batch_table.setItem(row, 3, result_item)
            else:
                result_item.setText(result_text)
            processed += 1

        self.batch_table.resizeColumnsToContents()
        self._set_status("Batch baked %d string(s), %d error(s)" % (processed, errors))

    def _on_batch_patch_selected(self):
        """Patch checked rows: write the baked result bytes back to each
        checked address.  Unchecked rows are skipped."""
        row_count = self.batch_table.rowCount()
        if row_count == 0:
            self._set_status("No strings in batch table", error=True)
            return

        patched = 0
        skipped = 0
        for row in range(row_count):
            chk_item = self.batch_table.item(row, 0)
            if chk_item is None or chk_item.checkState() != Qt.Checked:
                skipped += 1
                continue

            addr_text = self.batch_table.item(row, 1).text() if self.batch_table.item(row, 1) else ""
            result_text = self.batch_table.item(row, 3).text() if self.batch_table.item(row, 3) else ""

            if not addr_text or not result_text:
                skipped += 1
                continue

            try:
                ea = self._parse_addr(addr_text)
            except ValueError:
                skipped += 1
                continue

            data = to_bytes(result_text)
            if not data:
                skipped += 1
                continue

            try:
                # Patch: write result bytes and a null terminator if the
                # original string was null-terminated
                ida_bytes.patch_bytes(ea, data + b"\x00")
                patched += 1
            except Exception as exc:
                log.error("Batch patch failed at %s: %s", addr_text, exc)

        self._set_status("Patched %d string(s), skipped %d" % (patched, skipped))


class ChefForm(idaapi.PluginForm):
    def OnCreate(self, form):
        from .qt_compat import form_to_widget
        self.parent = form_to_widget(form)
        layout = QtWidgets.QVBoxLayout()
        self.chef_widget = ChefWidget()
        layout.addWidget(self.chef_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

    def send_selection(self):
        if hasattr(self, "chef_widget"):
            self.chef_widget._get_input_from_selection()