# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Binary Ninja Z80 architecture plugin that provides disassembly and IL lifting support for the Z80 processor. It includes support for multiple Z80-based platforms including ColecoVision and Sharp PC-G850. The plugin was originally written as a tutorial example for creating Binary Ninja architecture plugins.

## Common Development Commands

### Testing with uv

```bash
# Install dependencies and run tests (automatically handles FORCE_BINJA_MOCK=1)
uv sync --extra dev
uv run pytest

# Run tests with coverage
uv run pytest --cov

# Run specific test files
FORCE_BINJA_MOCK=1 uv run pytest tests/test_disasm.py
FORCE_BINJA_MOCK=1 uv run pytest tests/test_il_lifting.py
```

### Testing with Fish Shell

```bash
# Run the comprehensive test suite
fish run-tests.fish
```

### Linting and Type Checking

```bash
# Type checking
uv run pyright
uv run mypy .

# Linting and formatting
uv run ruff check .
uv run ruff format .
uv run black .
uv run isort .
```

## Architecture

### Core Components

1. **Z80Arch.py** - Main architecture implementation
   - Defines the Z80 Architecture class
   - Handles instruction decoding and disassembly
   - Maps Z80 instructions to Binary Ninja's instruction info
   - Uses z80dis library for actual disassembly

2. **Z80IL.py** - Intermediate Language lifting
   - Converts Z80 instructions to Binary Ninja's Low Level IL
   - Implements lifting for all Z80 opcodes
   - Handles flag calculations and conditional branches

3. **Binary View Implementations**:
   - **ColecoView.py** - ColecoVision ROM format support
   - **SharpPCG850View.py** - Sharp PC-G850 calculator format with custom Z80 variant
   - **RelView.py** - Z80 relocatable object file format

### Plugin Registration Flow

The `__init__.py` file orchestrates plugin initialization:
1. Sets up module path and mock API if `FORCE_BINJA_MOCK=1`
2. Registers the main Z80 architecture
3. Registers platform-specific binary views (Coleco, Sharp PC-G850, REL)
4. Configures calling conventions
5. Maps Z80 to ELF format (EM_Z80 = 220)

### Testing Infrastructure

- Uses `binja-test-mocks` package to enable testing without Binary Ninja license
- Tests are split into:
  - `test_disasm.py` - Validates disassembly against expected output
  - `test_il_lifting.py` - Tests IL lifting for various instruction categories
- Set `FORCE_BINJA_MOCK=1` environment variable to run tests with mock API

### Key Implementation Details

- **Address Size**: 16-bit (2 bytes)
- **Instruction Alignment**: 1 byte
- **Max Instruction Length**: 4 bytes
- **Register Set**: AF, BC, DE, HL (and their prime counterparts), IX, IY, SP, PC
- **Flags**: S (sign), Z (zero), H (half-carry), P/V (parity/overflow), N (add/subtract), C (carry)

### Platform-Specific Variants

**Sharp PC-G850**: Custom Z80 variant (`Z80PCG850Arch`) with:
- Extended address space (32-bit addresses for ROM banking)
- 16-bit addresses extended to 32-bit to map to same ROM bank
- Custom binary view for .BAS files