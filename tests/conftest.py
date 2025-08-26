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
import pytest

# Import Binary Ninja components after mock setup
from binaryninja import Architecture
from binja_test_mocks import binja_api  # noqa: F401


@pytest.fixture(scope="session", autouse=True)
def setup_plugin_registration():
    """Register the Z80 plugin for all tests."""
    # Clear any existing registrations for test isolation
    if hasattr(Architecture, 'clear_registry'):
        Architecture.clear_registry()

    # Import and register the Z80 plugin
    # This will run the registration code in __init__.py
    import __init__  # noqa: F401

    # Verify registration worked
    try:
        arch = Architecture["Z80"]
        assert hasattr(
            arch, "get_instruction_info"
        ), "Z80 architecture missing get_instruction_info"
        assert hasattr(
            arch, "get_instruction_text"
        ), "Z80 architecture missing get_instruction_text"
        print(f"✅ Z80 plugin registered successfully: {type(arch).__name__}")
    except Exception as e:
        pytest.fail(f"Failed to register Z80 plugin: {e}")


@pytest.fixture
def z80_arch():
    """Get the registered Z80 architecture instance."""
    return Architecture["Z80"]


@pytest.fixture
def clear_arch_registry():
    """Clear architecture registry for test isolation."""
    if hasattr(Architecture, 'clear_registry'):
        Architecture.clear_registry()
    yield
    if hasattr(Architecture, 'clear_registry'):
        Architecture.clear_registry()
