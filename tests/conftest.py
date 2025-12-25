"""Pytest configuration for Z80 plugin tests."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ValueError, ImportError):
        return False


if not _running_inside_binary_ninja():
    os.environ.setdefault("FORCE_BINJA_MOCK", "1")

    # Import mock API before importing anything from `binaryninja`.
    from binja_test_mocks import (
        binja_api,  # noqa: F401  # pyright: ignore
        mock_llil,
    )

    mock_llil.set_size_lookup({1: ".b", 2: ".w"}, {"b": 1, "w": 2})


# Make the plugin importable as a package (`import Z80`) like Binary Ninja does.
_plugin_dir = Path(__file__).resolve().parents[1]
_plugins_parent = _plugin_dir.parent
if str(_plugins_parent) not in sys.path:
    sys.path.insert(0, str(_plugins_parent))


@pytest.fixture(scope="session", autouse=True)
def setup_plugin_registration() -> None:
    """Register the Z80 plugin for all tests (using the mock Binary Ninja API)."""
    from binaryninja import Architecture

    if hasattr(Architecture, "clear_registry"):
        Architecture.clear_registry()

    from Z80._bn_plugin import register

    register(plugin_dir=_plugin_dir)


@pytest.fixture
def z80_arch():
    from binaryninja import Architecture

    return Architecture["Z80"]
