# Z80 Plugin Tests

This directory contains tests for the Z80 Binary Ninja plugin using `binja-test-mocks`.

## Running Tests

### Quick Start

```bash
# Using fish shell
fish run-tests.fish

# With uv (recommended)
uv run pytest

# Using pytest directly (tests/conftest.py enables mocks automatically)
pytest
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

Do not set `FORCE_BINJA_MOCK` or import `binja_test_mocks.binja_api` in each test file.
`tests/conftest.py` installs the mock API once for the entire test run.
