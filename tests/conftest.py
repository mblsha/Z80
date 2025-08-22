"""Pytest configuration for Z80 plugin tests."""

import os
import sys
from pathlib import Path

# Ensure FORCE_BINJA_MOCK is set before any imports
os.environ["FORCE_BINJA_MOCK"] = "1"

# Add plugin directory to Python path
plugin_dir = Path(__file__).parent.parent
if str(plugin_dir) not in sys.path:
    sys.path.insert(0, str(plugin_dir))

# Import mock API before anything else
from binja_test_mocks import binja_api  # noqa: F401
