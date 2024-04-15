#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that release executables only contain certain symbols
and are only linked against allowed libraries.

Example usage:

    find ../path/to/binaries -type f -executable | xargs python3 contrib/devtools/symbol-check.py
'''
import sys

import capstone # type: ignore
import lief

# Debian 10 (Buster) EOL: 2024. https://wiki.debian.org/LTS
#
# - libgcc version 8.3.0 (https://packages.debian.org/search?suite=buster&arch=any&searchon=names&keywords=libgcc1)
# - libc version 2.28 (https://packages.debian.org/search?suite=buster&arch=any&searchon=names&keywords=libc6)
#
# Ubuntu 18.04 (Bionic) EOL: 2028. https://wiki.ubuntu.com/ReleaseTeam
#
# - libgcc version 8.4.0 (https://packages.ubuntu.com/bionic/libgcc1)
# - libc version 2.27 (https://packages.ubuntu.com/bionic/libc6)
#
# CentOS Stream 8 EOL: 2024. https://wiki.centos.org/About/Product
#
# - libgcc version 8.5.0 (http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/)
# - libc version 2.28 (http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/)
#
# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html for more info.

MAX_VERSIONS = {
'GCC':       (4,3,0),
'GLIBC': {
    lief.ELF.ARCH.x86_64: (2,27),
    lief.ELF.ARCH.ARM:    (2,27),
    lief.ELF.ARCH.AARCH64:(2,27),
    lief.ELF.ARCH.PPC64:  (2,27),
    lief.ELF.ARCH.RISCV:  (2,27),
},
'LIBATOMIC': (1,0),
'V':         (0,5,0),  # xkb (bitcoin-qt only)
}

# Ignore symbols that are exported as part of every executable
IGNORE_EXPORTS = {
'environ', '_environ', '__environ', '_fini', '_init', 'stdin',
'stdout', 'stderr',
}

# Expected linker-loader names can be found here:
# https://sourceware.org/glibc/wiki/ABIList?action=recall&rev=16
ELF_INTERPRETER_NAMES: dict[lief.ELF.ARCH, dict[lief.ENDIANNESS, str]] = {
    lief.ELF.ARCH.x86_64:  {
        lief.ENDIANNESS.LITTLE: "/lib64/ld-linux-x86-64.so.2",
    },
    lief.ELF.ARCH.ARM:     {
        lief.ENDIANNESS.LITTLE: "/lib/ld-linux-armhf.so.3",
    },
    lief.ELF.ARCH.AARCH64: {
        lief.ENDIANNESS.LITTLE: "/lib/ld-linux-aarch64.so.1",
    },
    lief.ELF.ARCH.PPC64:   {
        lief.ENDIANNESS.BIG: "/lib64/ld64.so.1",
        lief.ENDIANNESS.LITTLE: "/lib64/ld64.so.2",
    },
    lief.ELF.ARCH.RISCV:    {
        lief.ENDIANNESS.LITTLE: "/lib/ld-linux-riscv64-lp64d.so.1",
    },
}

ELF_ABIS: dict[lief.ELF.ARCH, dict[lief.ENDIANNESS, list[int]]] = {
    lief.ELF.ARCH.x86_64: {
        lief.ENDIANNESS.LITTLE: [3,2,0],
    },
    lief.ELF.ARCH.ARM: {
        lief.ENDIANNESS.LITTLE: [3,2,0],
    },
    lief.ELF.ARCH.AARCH64: {
        lief.ENDIANNESS.LITTLE: [3,7,0],
    },
    lief.ELF.ARCH.PPC64: {
        lief.ENDIANNESS.LITTLE: [3,10,0],
        lief.ENDIANNESS.BIG: [3,2,0],
    },
    lief.ELF.ARCH.RISCV: {
        lief.ENDIANNESS.LITTLE: [4,15,0],
    },
}

# Allowed NEEDED libraries
ELF_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libgcc_s.so.1', # GCC base support
'libc.so.6', # C library
'libpthread.so.0', # threading
'libm.so.6', # math library
'libatomic.so.1',
'ld-linux-x86-64.so.2', # 64-bit dynamic linker
'ld-linux.so.2', # 32-bit dynamic linker
'ld-linux-aarch64.so.1', # 64-bit ARM dynamic linker
'ld-linux-armhf.so.3', # 32-bit ARM dynamic linker
'ld64.so.1', # POWER64 ABIv1 dynamic linker
'ld64.so.2', # POWER64 ABIv2 dynamic linker
'ld-linux-riscv64-lp64d.so.1', # 64-bit RISC-V dynamic linker
# bitcoin-qt only
'libxcb.so.1', # part of X11
'libxkbcommon.so.0', # keyboard keymapping
'libxkbcommon-x11.so.0', # keyboard keymapping
'libfontconfig.so.1', # font support
'libfreetype.so.6', # font parsing
'libdl.so.2', # programming interface to dynamic linker
'libxcb-icccm.so.4',
'libxcb-image.so.0',
'libxcb-shm.so.0',
'libxcb-keysyms.so.1',
'libxcb-randr.so.0',
'libxcb-render-util.so.0',
'libxcb-render.so.0',
'libxcb-shape.so.0',
'libxcb-sync.so.1',
'libxcb-xfixes.so.0',
'libxcb-xinerama.so.0',
'libxcb-xkb.so.1',
}

MACHO_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libc++.1.dylib', # C++ Standard Library
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
# bitcoin-qt only
'AppKit', # user interface
'ApplicationServices', # common application tasks.
'Carbon', # deprecated c back-compat API
'ColorSync',
'CoreFoundation', # low level func, data types
'CoreGraphics', # 2D rendering
'CoreServices', # operating system services
'CoreText', # interface for laying out text and handling fonts.
'CoreVideo', # video processing
'Foundation', # base layer functionality for apps/frameworks
'ImageIO', # read and write image file formats.
'IOKit', # user-space access to hardware devices and drivers.
'IOSurface', # cross process image/drawing buffers
'libobjc.A.dylib', # Objective-C runtime library
'Metal', # 3D graphics
'Security', # access control and authentication
'QuartzCore', # animation
}

PE_ALLOWED_LIBRARIES = {
'ADVAPI32.dll', # security & registry
'IPHLPAPI.DLL', # IP helper API
'KERNEL32.dll', # win32 base APIs
'msvcrt.dll', # C standard library for MSVC
'SHELL32.dll', # shell API
'WS2_32.dll', # sockets
# bitcoin-qt only
'dwmapi.dll', # desktop window manager
'GDI32.dll', # graphics device interface
'IMM32.dll', # input method editor
'NETAPI32.dll', # network management
'ole32.dll', # component object model
'OLEAUT32.dll', # OLE Automation API
'SHLWAPI.dll', # light weight shell API
'USER32.dll', # user interface
'USERENV.dll', # user management
'UxTheme.dll', # visual style
'VERSION.dll', # version checking
'WINMM.dll', # WinMM audio API
'WTSAPI32.dll', # Remote Desktop
}

def check_version(max_versions, version, arch) -> bool:
    (lib, _, ver) = version.rpartition('_')
    ver = tuple([int(x) for x in ver.split('.')])
    if not lib in max_versions:
        return False
    if isinstance(max_versions[lib], tuple):
        return ver <= max_versions[lib]
    else:
        return ver <= max_versions[lib][arch]

def check_imported_symbols(binary) -> bool:
    ok: bool = True

    for symbol in binary.imported_symbols:
        if not symbol.imported:
            continue

        version = symbol.symbol_version if symbol.has_version else None

        if version:
            aux_version = version.symbol_version_auxiliary.name if version.has_auxiliary_version else None
            if aux_version and not check_version(MAX_VERSIONS, aux_version, binary.header.machine_type):
                print(f'{filename}: symbol {symbol.name} from unsupported version {version}')
                ok = False
    return ok

def check_exported_symbols(binary) -> bool:
    ok: bool = True

    for symbol in binary.dynamic_symbols:
        if not symbol.exported:
            continue
        name = symbol.name
        if binary.header.machine_type == lief.ELF.ARCH.RISCV or name in IGNORE_EXPORTS:
            continue
        print(f'{binary.name}: export of symbol {name} not allowed!')
        ok = False
    return ok

def check_ELF_libraries(binary) -> bool:
    ok: bool = True
    for library in binary.libraries:
        if library not in ELF_ALLOWED_LIBRARIES:
            print(f'{filename}: {library} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_MACHO_libraries(binary) -> bool:
    ok: bool = True
    for dylib in binary.libraries:
        split = dylib.name.split('/')
        if split[-1] not in MACHO_ALLOWED_LIBRARIES:
            print(f'{split[-1]} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_MACHO_min_os(binary) -> bool:
    if binary.build_version.minos == [11,0,0]:
        return True
    return False

def check_MACHO_sdk(binary) -> bool:
    if binary.build_version.sdk == [14, 0, 0]:
        return True
    return False

def check_MACHO_ld64(binary) -> bool:
    if binary.build_version.tools[0].version == [711, 0, 0]:
        return True
    return False

def check_PE_libraries(binary) -> bool:
    ok: bool = True
    for dylib in binary.libraries:
        if dylib not in PE_ALLOWED_LIBRARIES:
            print(f'{dylib} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_PE_subsystem_version(binary) -> bool:
    major: int = binary.optional_header.major_subsystem_version
    minor: int = binary.optional_header.minor_subsystem_version
    if major == 6 and minor == 1:
        return True
    return False

# Intel® 64 and IA-32 Architectures Software Developer’s Manual:
#   chapter 14.9, table 14-22. Instructions Requiring Explicitly Aligned Memory
#   chapter 15.7, Table 15-6. SIMD Instructions Requiring Explicitly Aligned Memory
#
# This amounts to the following instructions:
#
# instruction                  chapter 4.3 section
# ---------------------------  ---------------------------------
# (V)MOVDQA xmm, mBBB          MOVDQA,VMOVDQA32/64—Move Aligned Packed Integer Values
# (V)MOVDQA mBBB, xmm          MOVDQA,VMOVDQA32/64—Move Aligned Packed Integer Values
# (V)MOVAPS xmm, mBBB          MOVAPS—Move Aligned Packed Single Precision Floating-Point Values
# (V)MOVAPS mBBB, xmm          MOVAPS—Move Aligned Packed Single Precision Floating-Point Values
# (V)MOVAPD xmm, mBBB          MOVAPD—Move Aligned Packed Double Precision Floating-Point Values
# (V)MOVAPD mBBB, xmm          MOVAPD—Move Aligned Packed Double Precision Floating-Point Values
# (V)MOVNTPS mBBB, xmm         MOVNTPS—Store Packed Single Precision Floating-Point Values Using Non-Temporal Hint
# (V)MOVNTPD mBBB, xmm         MOVNTPD—Store Packed Double Precision Floating-Point Values Using Non-Temporal Hint
# (V)MOVNTDQ mBBB, xmm         MOVNTDQ—Store Packed Integers Using Non-Temporal Hint
# (V)MOVNTDQA xmm, mBBB        MOVNTDQA—Load Double Quadword Non-Temporal Aligned Hint
#
# BBB is the bit size, which can be 128, 256 or 512. In our specific case we don't care about the 128 bit
# instructions, because we're looking for 16 and 32 byte alignments, however we'll consider every
# listed instruction just to be sure.
#
FORBIDDEN_VMOVA = {
    capstone.x86.X86_INS_MOVDQA,    capstone.x86.X86_INS_VMOVDQA,   capstone.x86.X86_INS_VMOVDQA32, capstone.x86.X86_INS_VMOVDQA64,
    capstone.x86.X86_INS_MOVAPS,    capstone.x86.X86_INS_VMOVAPS,
    capstone.x86.X86_INS_MOVAPD,    capstone.x86.X86_INS_VMOVAPD,
    capstone.x86.X86_INS_MOVNTPS,   capstone.x86.X86_INS_VMOVNTPS,
    capstone.x86.X86_INS_MOVNTPD,   capstone.x86.X86_INS_VMOVNTPD,
    capstone.x86.X86_INS_MOVNTDQ,   capstone.x86.X86_INS_VMOVNTDQ,
    capstone.x86.X86_INS_MOVNTDQA,  capstone.x86.X86_INS_VMOVNTDQA,
}

def check_PE_no_vmova(binary) -> bool:
    '''
    Check for vmov instructions that require alignment.
    These are a potential problem due to a stack alignment bug in GCC on Windows.
    See https://github.com/bitcoin/bitcoin/issues/28413 for specifics.
    '''
    # capstone instance with details disabled
    # disassemble without details by default, to speed up disassembly
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = False
    # capstone instance with details enabled, for closer inspection when a
    # suspect instruction is found
    cs_d = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs_d.detail = True

    found_forbidden = False

    for section in binary.sections:
        # find sections that contain code
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE):
            section_base = binary.imagebase + section.virtual_address
            # disassemble section, check every instruction
            for i in cs.disasm(section.content, section_base): # -> CsInsn
                if i.id in FORBIDDEN_VMOVA:
                    # disassemble this instruction again with details enabled, to be able
                    # to access operand information.
                    i = next(cs_d.disasm(section.content[i.address - section_base:], i.address, 1))

                    # extract register from both operands
                    reg = [op.value.reg for op in i.operands]
                    if reg[0] != 0 and reg[1] != 0:
                        continue # r->r operation, this is fine, no alignment issues
                    elif reg[0] == 0 and reg[1] != 0:
                        memidx = 0 # m->r
                    elif reg[0] != 0 and reg[1] == 0:
                        memidx = 1 # r->m
                    else:
                        raise ValueError("Invalid AVX instruction with two memory operands.")

                    # check operand size for memory operand
                    if i.operands[memidx].size <= 16:
                        continue # <=16 byte alignment is fine

                    # uncomment for verbose
                    # print(f"{binary.name}: Forbidden vmov: {i.address:08x} {i.mnemonic} {i.op_str}")
                    found_forbidden = True

    return not found_forbidden

def check_ELF_interpreter(binary) -> bool:
    expected_interpreter = ELF_INTERPRETER_NAMES[binary.header.machine_type][binary.abstract.header.endianness]

    return binary.concrete.interpreter == expected_interpreter

def check_ELF_ABI(binary) -> bool:
    expected_abi = ELF_ABIS[binary.header.machine_type][binary.abstract.header.endianness]
    note = binary.concrete.get(lief.ELF.NOTE_TYPES.ABI_TAG)
    assert note.details.abi == lief.ELF.NOTE_ABIS.LINUX
    return note.details.version == expected_abi

CHECKS = {
lief.EXE_FORMATS.ELF: [
    ('IMPORTED_SYMBOLS', check_imported_symbols),
    ('EXPORTED_SYMBOLS', check_exported_symbols),
    ('LIBRARY_DEPENDENCIES', check_ELF_libraries),
    ('INTERPRETER_NAME', check_ELF_interpreter),
    ('ABI', check_ELF_ABI),
],
lief.EXE_FORMATS.MACHO: [
    ('DYNAMIC_LIBRARIES', check_MACHO_libraries),
    ('MIN_OS', check_MACHO_min_os),
    ('SDK', check_MACHO_sdk),
    ('LD64', check_MACHO_ld64),
],
lief.EXE_FORMATS.PE: [
    ('DYNAMIC_LIBRARIES', check_PE_libraries),
    ('SUBSYSTEM_VERSION', check_PE_subsystem_version),
    ('NO_VMOVA', check_PE_no_vmova),
]
}

if __name__ == '__main__':
    retval: int = 0
    for filename in sys.argv[1:]:
        try:
            binary = lief.parse(filename)
            etype = binary.format
            if etype == lief.EXE_FORMATS.UNKNOWN:
                print(f'{filename}: unknown executable format')
                retval = 1
                continue

            failed: list[str] = []
            for (name, func) in CHECKS[etype]:
                if not func(binary):
                    failed.append(name)
            if failed:
                print(f'{filename}: failed {" ".join(failed)}')
                retval = 1
        except IOError:
            print(f'{filename}: cannot open')
            retval = 1
    sys.exit(retval)
