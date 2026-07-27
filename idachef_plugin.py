# -*- coding: utf-8 -*-
"""
IDAChef - a CyberChef-style recipe/operation toolkit inside IDA Pro.

Install:
    Copy this file AND the `idachef` folder next to it into your IDA
    `plugins` directory, e.g.:
        %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\idachef_plugin.py
        %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\idachef\\...
    (or the equivalent <ida install dir>/plugins on macOS/Linux)

Use:
    Edit -> Plugins -> IDAChef        (or press Ctrl-Alt-C)
    Select bytes in the Hex View / disassembly, then reopen/refresh
    IDAChef and click "Get Selected Bytes" to pull them into the recipe.

Requires: IDA Pro 9.0+ (Python 3, PyQt5 bundled). Some encryption
operations (AES/DES/RC4) additionally use `pycryptodome` if it is
installed in IDA's Python environment - everything else works with the
standard library alone.
"""

import idaapi

from idachef.core.logger import log

PLUGIN_NAME = "IDAChef"
PLUGIN_HOTKEY = "Ctrl-Alt-C"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "IDAChef"


def _lazy_import_chef_form():
    # Imported lazily so a failure to import Qt/pycryptodome etc. doesn't
    # break plugin *loading* - only using the "Run" action.
    from idachef.ui.chef_widget import ChefForm
    return ChefForm


class IDAChefPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "CyberChef-style recipe toolkit for IDA Pro"
    help = "Open a dockable panel to build data-transformation recipes (base64, XOR, hashes, AES, etc.) against selected bytes/strings."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self._form = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            ChefForm = _lazy_import_chef_form()
        except Exception as exc:
            log.error("IDAChef failed to load UI: %s", exc)
            idaapi.warning("IDAChef failed to load: %s" % exc)
            raise

        if self._form is None or not Compat.form_is_alive(self._form):
            self._form = ChefForm()
        self._form.Show("IDAChef")

    def term(self):
        pass


class Compat:
    @staticmethod
    def form_is_alive(form):
        # PluginForm instances don't expose a clean "is this widget still
        # valid" check across IDA/Qt versions; the cheapest safe option is
        # to just always create a fresh ChefForm and let Show() re-dock/
        # re-use the existing TWidget if IDA still has one open under this
        # title. If GetWidget errors out, treat it as dead.
        try:
            return form.GetWidget() is not None
        except Exception:
            return False


def PLUGIN_ENTRY():
    return IDAChefPlugin()
