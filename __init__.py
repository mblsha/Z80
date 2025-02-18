import binaryninja

from .Z80Arch import Z80
Z80.register()

from .ColecoView import ColecoView
ColecoView.register()

from .SharpPCG850View import SharpPCG850View, Z80PCG850Arch

Z80PCG850Arch.register()
SharpPCG850View.register()


from .RelView import RelView
RelView.register()

# built-in view
EM_Z80 = 220
binaryninja.BinaryViewType['ELF'].register_arch(EM_Z80, binaryninja.enums.Endianness.LittleEndian, binaryninja.Architecture['Z80'])

class ParametersInRegistersCallingConvention(binaryninja.CallingConvention):
    name = "ParametersInRegisters"


arch = binaryninja.Architecture["Z80"]
arch.register_calling_convention(
    ParametersInRegistersCallingConvention(arch, "default")
)

arch = binaryninja.Architecture["Z80 PC-G850"]
arch.register_calling_convention(
    ParametersInRegistersCallingConvention(arch, "default")
)

