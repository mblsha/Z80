from __future__ import annotations

from pathlib import Path


def register(*, plugin_dir: Path) -> None:
    import binaryninja

    try:
        from .ColecoView import ColecoView
        from .RelView import RelView
        from .SharpPCG850View import SharpPCG850View, Z80PCG850Arch
        from .Z80Arch import Z80
    except ImportError:
        from ColecoView import ColecoView
        from RelView import RelView
        from SharpPCG850View import SharpPCG850View, Z80PCG850Arch
        from Z80Arch import Z80

    Z80.register()
    ColecoView.register()
    Z80PCG850Arch.register()
    SharpPCG850View.register()
    RelView.register()

    # built-in view
    EM_Z80 = 220
    binaryninja.BinaryViewType["ELF"].register_arch(
        EM_Z80, binaryninja.enums.Endianness.LittleEndian, binaryninja.Architecture["Z80"]
    )

    class ParametersInRegistersCallingConvention(binaryninja.CallingConvention):
        name = "ParametersInRegisters"

    arch = binaryninja.Architecture["Z80"]
    arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, "default"))

    arch = binaryninja.Architecture["Z80 PC-G850"]
    arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, "default"))
