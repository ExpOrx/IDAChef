# -*- coding: utf-8 -*-
"""
Qt compatibility shim.

IDA Pro 9.0 / 9.1 ship PyQt5 (Qt5). Starting with IDA 9.2, Hex-Rays moved
to PySide6 (Qt6) - see:
  https://docs.hex-rays.com/user-guide/plugins/migrating-pyqt5-code-to-pyside6

IDAChef targets IDA Pro 9.0's PyQt5, but this shim also tries PySide6 so
the same code keeps working if you're on a newer IDA build (PySide6 has
PyQt5-compatible signal/slot names, so only the import paths differ).
"""

import idaapi

QT_BINDING = None

try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt
    QT_BINDING = "PyQt5"
except Exception:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets
        from PySide6.QtCore import Qt
        QT_BINDING = "PySide6"
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "IDAChef could not import a Qt binding (tried PyQt5, then PySide6). "
            "Original error: %s" % exc
        )


def form_to_widget(form):
    """Wraps idaapi.PluginForm.FormToPyQtWidget / FormToPySideWidget so the
    caller doesn't need to care which binding is active."""
    if QT_BINDING == "PyQt5":
        return idaapi.PluginForm.FormToPyQtWidget(form)
    return idaapi.PluginForm.FormToPySideWidget(form)
