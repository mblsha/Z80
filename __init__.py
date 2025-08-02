import os
import sys
from pathlib import Path

# Add plugin directory to path for imports
plugin_dir = str(Path(__file__).resolve().parent)
if plugin_dir not in sys.path:
    sys.path.insert(0, plugin_dir)

# Load mock API for testing if requested
if os.environ.get("FORCE_BINJA_MOCK") == "1":
    from binja_test_mocks import binja_api  # noqa: F401

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
    # int_return_reg = 'A'


arch = binaryninja.Architecture["Z80"]
arch.register_calling_convention(
    ParametersInRegistersCallingConvention(arch, "default")
)

arch = binaryninja.Architecture["Z80 PC-G850"]
arch.register_calling_convention(
    ParametersInRegistersCallingConvention(arch, "default")
)

