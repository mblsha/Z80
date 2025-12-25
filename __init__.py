from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_plugin_dir = Path(__file__).resolve().parent
_plugin_dir_str = str(_plugin_dir)

# Ensure the plugin directory is importable when loaded directly by Binary Ninja.
if _plugin_dir_str not in sys.path:
    sys.path.insert(0, _plugin_dir_str)


def module_exists(module_name: str) -> bool:
    if module_name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ValueError, ImportError):
        return False


def _running_inside_binary_ninja() -> bool:
    try:
        if module_exists("binaryninjaui"):
            return True
    except Exception:
        pass

    exe = (sys.executable or "").lower()
    if "binary ninja.app" in exe:
        return True
    return os.path.basename(exe) in ("binaryninja", "binaryninja.exe")


_force_mock_requested = os.environ.get("FORCE_BINJA_MOCK", "").lower() in ("1", "true", "yes")
_running_binja = _running_inside_binary_ninja()
_skip_registration = _force_mock_requested and not _running_binja

_has_binaryninja = module_exists("binaryninja")

if _has_binaryninja and __package__ and not _skip_registration:
    from ._bn_plugin import register

    register(plugin_dir=_plugin_dir)
