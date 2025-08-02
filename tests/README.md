# Z80 Plugin Tests

This directory contains tests for the Z80 Binary Ninja plugin using `binja-test-mocks`.

## Running Tests

### Quick Start

```bash
# Using fish shell
fish run-tests.fish

# Using pytest directly
FORCE_BINJA_MOCK=1 pytest

# With coverage
FORCE_BINJA_MOCK=1 pytest --cov
```

### Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # or venv/bin/activate.fish

# Install dependencies
pip install -e .
pip install -e /path/to/binja-test-mocks
pip install pytest pytest-cov
```

## Test Structure

- `test_disasm.py` - Tests disassembly output against known good results
- `test_il_lifting.py` - Tests IL (Intermediate Language) lifting
- `conftest.py` - Pytest configuration and test fixtures

## Writing New Tests

All test files should start with:

```python
import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_test_mocks import binja_api  # noqa: F401
```

This ensures the mock API is loaded before importing any Binary Ninja modules.