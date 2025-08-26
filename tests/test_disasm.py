#!/usr/bin/env python
"""Test Z80 disassembly against expected output."""

import os

os.environ["FORCE_BINJA_MOCK"] = "1"

import re
from pathlib import Path

from binaryninja import Architecture
from binja_test_mocks import binja_api  # noqa: F401

# Import after setting up mocks


def disasm_binja(data, addr):
    """Disassemble data using Binary Ninja Z80 architecture."""
    arch = Architecture["Z80"]
    toks_and_len = arch.get_instruction_text(data, addr)
    if not toks_and_len or toks_and_len[1] == 0:
        return ""
    toks = toks_and_len[0]
    strs = [tok.text for tok in toks]
    return "".join(strs)


def tok_vals(x):
    """Extract numeric values from token string."""
    result = set()
    if x.startswith("$"):
        x = x[1:]
    if x.startswith("0x"):
        x = x[2:]
    if re.match(r"^[A-Fa-f0-9]+$", x):
        result.add(int(x, 16))
    if re.match(r"^[0-9]+$", x):
        result.add(int(x, 10))
    return result


def is_token_equal(a, b):
    """Compare two tokens, handling numeric values specially."""
    a_vals = tok_vals(a)
    if a_vals:
        b_vals = tok_vals(b)
        if b_vals:
            return bool(a_vals.intersection(b_vals))
    return a == b


def is_disasm_equal(a, b):
    """Compare two disassembly strings token by token."""
    toks_a = re.split(r" |,", a)
    toks_b = re.split(r" |,", b)

    if len(toks_a) != len(toks_b):
        return False

    return all(is_token_equal(ta, tb) for (ta, tb) in zip(toks_a, toks_b, strict=False))


def test_z80_disassembly():
    """Test Z80 disassembly against known good output."""
    addr = 0
    test_file = Path(__file__).parent.parent / "disasm65536.txt"

    with open(test_file) as fp:
        for line_num, line in enumerate(fp.readlines(), 1):
            # Parse line: "00 0B 00 00: NOP"
            match = re.match(r"^(..) (..) (..) (..): (.*)\n$", line)
            assert match, f"Failed to parse line {line_num}: {line}"

            b0, b1, b2, b3, expected = match.groups()
            data = bytes([int(x, 16) for x in [b0, b1, b2, b3]])

            distxt = disasm_binja(data, addr)

            assert is_disasm_equal(
                distxt, expected
            ), f"Line {line_num}: Expected '{expected}', got '{distxt}' for bytes {data.hex()}"


def test_specific_instructions():
    """Test specific Z80 instructions."""
    # Test NOP
    assert disasm_binja(b"\x00\x00\x00\x00", 0) == "nop"

    # Test LD instructions
    assert disasm_binja(b"\x3e\x42\x00\x00", 0) == "ld a, 0x42"
    assert disasm_binja(b"\x01\x34\x12\x00", 0) == "ld bc, 0x1234"

    # Test JP instructions
    assert disasm_binja(b"\xc3\x56\x34\x00", 0) == "jp 0x3456"

    # Test CALL
    assert disasm_binja(b"\xcd\x78\x56\x00", 0) == "call 0x5678"

    # Test RET
    assert disasm_binja(b"\xc9\x00\x00\x00", 0) == "ret"
