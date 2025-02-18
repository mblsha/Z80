#!/usr/bin/env python

from struct import unpack
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional, Tuple, Dict

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture, IntrinsicInfo
from binaryninja.types import Symbol, Type
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.enums import SymbolType, SegmentFlag, SectionSemantics, Endianness

from .Z80Arch import Z80
from . import Z80IL
from z80dis.z80 import *


PORT_FUNC_START = None


class IOPortDirection(Enum):
    INPUT = 0
    OUTPUT = 1


# http://park19.wakwak.com/~gadget_factory/factory/pokecom/io.html
class IOPort(Enum):
    LCD_COMMAND = 0x40
    LCD_OUT = 0x41

    ROM_EX_BANK = 0x19
    RAM_BANK = 0x1B
    ROM_BANK = 0x69

    # FIXME: what does it do??
    SHIFT_KEY_INPUT = 0x13  # Read-only

    KEY_INPUT = 0x10  # Read-only
    SET_KEY_STROBE_LO = 0x11  # Write-only
    SET_KEY_STROBE_HI = 0x12  # Write-only

    TIMER = 0x14
    XIN_ENABLED = 0x15
    INTERRUPT_FLAGS = 0x16
    INTERRUPT_MASK = 0x17

    ON_CONTROL_BY_CD_SIGNAL = 0x64
    WAIT_AFTER_M1 = 0x65
    WAIT_AFTER_IO = 0x66
    CPU_CLOCK_MODE = 0x67

    SET_1S_TIMER_PERIOD = 0x68

    GPIO_IO_OUTPUT = 0x18  # 11-pin connector
    GET_GPIO_IO = 0x1F
    GPIO_IO_MODE = 0x60
    SET_PIO_DIRECTION = 0x61
    PIO_REGISTER = 0x62

    # According to https://ver0.sakura.ne.jp/doc/pcg850vuart.html the PC-G850V has different port
    # definitions compared to the PC-G850/PC-G850S.
    UART_FLOW_REGISTER = 0x63
    UART_INPUT_SELECTION = 0x6B
    SET_UART_MODE = 0x6C
    SET_UART_COMMAND = 0x6D
    GET_UART_STATUS = 0x6E
    UART_DATA = 0x6F

    SET_BOOTROM_OFF = 0x1A
    RAM_CE_MODE = (
        0x1B  # 0: CERAM1 (internal RAM), 1: CERAM2 (external RAM on system bus)
    )
    SET_IORESET = 0x1C

    UNKNOWN_1D = 0x1D
    UNKNOWN_1E = 0x1E  # battery check mode?


def get_port_num_addr(port_num: int, direction: IOPortDirection):
    global PORT_FUNC_START
    return PORT_FUNC_START + port_num

    if direction == IOPortDirection.OUTPUT:
        return PORT_FUNC_START + port_num

    return PORT_FUNC_START + 0x100 + port_num * 4


# port + offset within the port
def addr_to_port(addr: int) -> Tuple[Optional[IOPort], Optional[int]]:
    return None, None

    if addr < PORT_FUNC_START + 0x100:
        return None, None

    addr -= PORT_FUNC_START + 0x100
    port_num = addr // 4
    port_offset = addr % 4

    try:
        return IOPort(port_num), port_offset
    except:
        return None, None


class Z80PCG850Arch(Z80):
    name = "Z80 PC-G850"

    intrinsics = {
        port.name: IntrinsicInfo(inputs=[], outputs=[Type.int(1)]) for port in IOPort
    }

    def get_instruction_low_level_il(self, data, addr, il):
        port, port_offset = addr_to_port(addr)
        if port is not None:
            if port_offset == 0:
                il.append(il.set_reg(1, "A", il.intrinsic([], port.name, [])))
                il.append(il.ret(il.pop(2)))
                return 1

        decoded = decode(data, addr)
        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None

        if decoded.op == OP.OUT:
            (oper_type, oper_val) = (
                decoded.operands[0] if decoded.operands else (None, None)
            )
            (operb_type, operb_val) = (
                decoded.operands[1] if decoded.operands[1:] else (None, None)
            )

            if oper_type == OPER_TYPE.REG_DEREF:
                addr = Z80IL.operand_to_il(oper_type, oper_val, il)
                print(f"OUT: reg deref addr: {hex(addr)}")
            else:
                addr = il.const_pointer(
                    4, get_port_num_addr(oper_val, IOPortDirection.OUTPUT)
                )
            reg = Z80IL.operand_to_il(operb_type, operb_val, il)
            il.append(il.store(1, addr, reg))
            return decoded.len
        elif decoded.op == OP.IN:
            (oper_type, oper_val) = (
                decoded.operands[0] if decoded.operands else (None, None)
            )
            (operb_type, operb_val) = (
                decoded.operands[1] if decoded.operands[1:] else (None, None)
            )

            if operb_type == OPER_TYPE.REG_DEREF:
                addr = Z80IL.operand_to_il(operb_type, operb_val, il)
                print(f"IN: reg deref addr: {hex(addr)}")
            else:
                addr = il.const_pointer(
                    4, get_port_num_addr(operb_val, IOPortDirection.INPUT)
                )

            size = Z80IL.REG_TO_SIZE[oper_val]
            # il.append(il.set_reg(size, reg2str(oper_val), il.call(addr)))
            il.append(il.set_reg(size, reg2str(oper_val), il.load(1, addr)))
            return decoded.len

        Z80IL.gen_instr_il(addr, decoded, il)

        return decoded.len


@dataclass
class Segment:
    name: str
    start: int
    size: int
    flags: SegmentFlag
    semantics: SectionSemantics


class SharpPCG850View(BinaryView):
    name = "Sharp PC-G850"
    long_name = "Sharp PC-G850 ROM"

    BANK0_ADDR = 0x8000
    BANK_SIZE = 0x4000

    @classmethod
    def is_valid_for_data(self, data):
        buf = data.read(0, 4)
        if len(buf) < 4:
            return False
        result = buf[:4] == b"\xC3\xF4\xBF\x00"
        return result

    def __init__(self, data):
        # data is a binaryninja.binaryview.BinaryView
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.arch = Architecture[Z80PCG850Arch.name]
        self.platform = Architecture[Z80PCG850Arch.name].standalone_platform

        END_ADDR = self.parent_view.end

        segments = []

        segments.append(
            Segment(
                "VectorTable",
                0,
                0x100,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
        )

        segments.append(
            Segment(
                "RAM",
                0x100,
                0x8000 - 0x100,
                SegmentFlag.SegmentReadable
                | SegmentFlag.SegmentWritable
                | SegmentFlag.SegmentExecutable,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
        )

        # count loop while BANK0_ADDR + bank_index*BANK_SIZE < END_ADDR
        for bank_index in range(0, 99):
            addr = self.BANK0_ADDR + bank_index * self.BANK_SIZE
            addr_end = addr + self.BANK_SIZE
            if addr >= END_ADDR or addr_end >= END_ADDR:
                break
            segments.append(
                Segment(
                    f"Bank{bank_index:02}",
                    addr,
                    self.BANK_SIZE,
                    SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
                    SectionSemantics.ReadOnlyCodeSectionSemantics,
                )
            )

        global PORT_FUNC_START
        PORT_FUNC_START = END_ADDR - 0x1000
        segments.append(
            Segment(
                "IO Ports",
                PORT_FUNC_START,
                0x1000,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
        )

        for s in segments:
            self.add_auto_segment(s.start, s.size, s.start, s.size, s.flags)
            self.add_user_section(s.name, s.start, s.size, s.semantics)

        for port in sorted(IOPort, key=lambda x: x.value):
            t = self.parse_type_string(f"uint8_t {port.name}")[0]
            addr = get_port_num_addr(port.value, IOPortDirection.OUTPUT)
            name = port.name
            self.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))
            self.define_user_data_var(addr, t)

            # addr = get_port_num_addr(port.value, IOPortDirection.INPUT)
            # name = f"{port.name}_IN"
            # self.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
            # self.add_function(addr)

        # # entrypoint is that start_game header member
        # self.add_entry_point(unpack("<H", self.data[0xA : 0xA + 2])[0])
        return True

    def perform_get_address_size(self) -> int:
        return 2

    def perform_get_default_endianness(self) -> Endianness:
        return Endianness.LittleEndian

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0
