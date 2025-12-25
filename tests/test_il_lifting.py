#!/usr/bin/env python
"""Test Z80 IL lifting functionality."""

from binaryninja import Architecture
from binja_test_mocks.mock_llil import MockLowLevelILFunction

# Import Z80-specific test helpers
from .test_helpers import get_operations


def get_lifted_il(data, addr=0x1000):
    """Get the lifted IL for the given instruction bytes."""
    arch = Architecture["Z80"]
    il = MockLowLevelILFunction()
    il.current_address = addr

    # Get instruction info
    info = arch.get_instruction_info(data, addr)
    if not info:
        return None

    # Lift to IL
    arch.get_instruction_low_level_il(data, addr, il)
    return il


def test_nop_lifting():
    """Test that NOP lifts to a no-operation."""
    il = get_lifted_il(b"\x00\x00\x00\x00")
    assert il is not None
    operations = get_operations(il)
    assert len(operations) == 1
    assert operations[0]["op"] == "nop"


def test_ld_immediate_lifting():
    """Test LD with immediate values."""
    # LD A, 0x42
    il = get_lifted_il(b"\x3e\x42\x00\x00")
    assert il is not None
    operations = get_operations(il)
    assert len(operations) == 1

    # Should generate: A = 0x42
    op = operations[0]
    assert op["op"] == "set_reg"
    assert op["dest"] == "a"
    assert op["src"]["op"] == "const"
    assert op["src"]["value"] == 0x42


def test_ld_16bit_immediate():
    """Test 16-bit LD instructions."""
    # LD BC, 0x1234
    il = get_lifted_il(b"\x01\x34\x12\x00")
    assert il is not None

    # Should set both B and C registers
    # C = 0x34 (low byte)
    # B = 0x12 (high byte)
    operations = get_operations(il)
    assert any(op["op"] == "set_reg" and op["dest"] == "c" for op in operations)
    assert any(op["op"] == "set_reg" and op["dest"] == "b" for op in operations)


def test_jp_lifting():
    """Test JP (jump) instruction lifting."""
    # JP 0x3456
    il = get_lifted_il(b"\xc3\x56\x34\x00", addr=0x1000)
    assert il is not None

    # Should generate a goto
    operations = get_operations(il)
    assert any(op["op"] == "goto" for op in operations)
    goto_op = next(op for op in operations if op["op"] == "goto")
    assert goto_op["dest"]["value"] == 0x3456


def test_call_lifting():
    """Test CALL instruction lifting."""
    # CALL 0x5678
    il = get_lifted_il(b"\xcd\x78\x56\x00", addr=0x1000)
    assert il is not None

    # Should generate a call
    operations = get_operations(il)
    assert any(op["op"] == "call" for op in operations)
    call_op = next(op for op in operations if op["op"] == "call")
    assert call_op["dest"]["value"] == 0x5678


def test_ret_lifting():
    """Test RET instruction lifting."""
    # RET
    il = get_lifted_il(b"\xc9\x00\x00\x00")
    assert il is not None

    # Should generate a ret
    operations = get_operations(il)
    assert any(op["op"] == "ret" for op in operations)


def test_push_pop_lifting():
    """Test PUSH/POP instructions."""
    # PUSH BC
    il = get_lifted_il(b"\xc5\x00\x00\x00")
    assert il is not None

    # Should decrement SP and store values
    operations = get_operations(il)
    assert any(op["op"] == "set_reg" and op["dest"] == "sp" for op in operations)
    assert any(op["op"] == "store" for op in operations)

    # POP BC
    il = get_lifted_il(b"\xc1\x00\x00\x00")
    assert il is not None

    # Should load values and increment SP
    operations = get_operations(il)
    assert any(op["op"] == "load" for op in operations)
    assert any(op["op"] == "set_reg" and op["dest"] in ["b", "c"] for op in operations)


def test_conditional_jump():
    """Test conditional jump instructions."""
    # JP Z, 0x1234 (jump if zero)
    il = get_lifted_il(b"\xca\x34\x12\x00", addr=0x1000)
    assert il is not None

    # Should have a conditional branch
    operations = get_operations(il)
    assert any(op["op"] in ["if", "flag_cond"] for op in operations)
