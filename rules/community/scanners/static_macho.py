"""
Static analysis para arquivos Mach-O (macOS).

Parser manual (sem dep externa). Cobre:
- Detecta magic (32/64-bit, BE/LE, fat universal)
- CPU type + subtype
- File type (executable, dylib, bundle, kext, etc.)
- Load commands principais:
  - LC_SEGMENT_64        (secoes + permissoes)
  - LC_LOAD_DYLIB        (dependencias)
  - LC_LOAD_WEAK_DYLIB
  - LC_RPATH             (vetor de hijacking)
  - LC_CODE_SIGNATURE    (assinado?)
  - LC_MAIN              (entry point)
  - LC_SYMTAB            (offsets de symbols)
  - LC_DYLD_INFO_ONLY    (lazy/non-lazy binds)
- Symbols importados (do __LINKEDIT)
- Capabilities mapeadas
- Flags suspeitos (no PIE, no canary, no ASLR)
"""
from __future__ import annotations
import struct
from pathlib import Path
from typing import Any, Optional

from core.capabilities_macho import detect_capabilities_macho
from core.iocs import extract_strings, extract_iocs


# Mach-O magic numbers
MAGIC_32        = 0xFEEDFACE
MAGIC_64        = 0xFEEDFACF
MAGIC_32_SWAP   = 0xCEFAEDFE
MAGIC_64_SWAP   = 0xCFFAEDFE
FAT_MAGIC       = 0xCAFEBABE
FAT_MAGIC_SWAP  = 0xBEBAFECA
FAT_MAGIC_64    = 0xCAFEBABF

ALL_MACHO_MAGICS = {MAGIC_32, MAGIC_64, MAGIC_32_SWAP, MAGIC_64_SWAP,
                    FAT_MAGIC, FAT_MAGIC_SWAP, FAT_MAGIC_64}


# CPU types (parcial)
CPU_TYPES = {
    7:           "x86",
    0x01000007:  "x86-64",
    12:          "ARM",
    0x0100000C:  "ARM64",
    18:          "PowerPC",
    0x01000012:  "PowerPC64",
}


# File types
FILE_TYPES = {
    1:  "OBJECT (.o)",
    2:  "EXECUTABLE",
    3:  "FVMLIB",
    4:  "CORE",
    5:  "PRELOAD",
    6:  "DYLIB (.dylib)",
    7:  "DYLINKER",
    8:  "BUNDLE",
    9:  "DYLIB_STUB",
    10: "DSYM",
    11: "KEXT_BUNDLE (kernel extension)",
}


# Load commands relevantes
LC_SEGMENT         = 0x01
LC_SYMTAB          = 0x02
LC_DYSYMTAB        = 0x0B
LC_LOAD_DYLIB      = 0x0C
LC_ID_DYLIB        = 0x0D
LC_LOAD_DYLINKER   = 0x0E
LC_UUID            = 0x1B
LC_SEGMENT_64      = 0x19
LC_RPATH           = 0x8000001C
LC_CODE_SIGNATURE  = 0x1D
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB  = 0x8000001F
LC_DYLD_INFO       = 0x22
LC_DYLD_INFO_ONLY  = 0x80000022
LC_MAIN            = 0x80000028
LC_ENCRYPTION_INFO   = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

# MH_* flags
MH_NOUNDEFS        = 0x1
MH_DYLDLINK        = 0x4
MH_TWOLEVEL        = 0x80
MH_WEAK_DEFINES    = 0x8000
MH_BINDS_TO_WEAK   = 0x10000
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_PIE             = 0x200000
MH_NO_HEAP_EXECUTION = 0x1000000


async def scan_static_macho(file_path: str | Path) -> dict[str, Any]:
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(8)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    if len(head) < 4:
        return {"status": "skipped", "reason": "Arquivo muito pequeno"}

    # Le magic em LE e BE pra detectar endianness
    magic_le = struct.unpack("<I", head[:4])[0]
    magic_be = struct.unpack(">I", head[:4])[0]

    if magic_le in ALL_MACHO_MAGICS:
        magic = magic_le
        endian = "<"
    elif magic_be in ALL_MACHO_MAGICS:
        magic = magic_be
        endian = ">"
    else:
        return {"status": "skipped", "reason": "Arquivo nao eh Mach-O"}

    raw = file_path.read_bytes()

    # Universal/Fat binary contem multiplos Mach-O dentro
    is_fat = magic in (FAT_MAGIC, FAT_MAGIC_SWAP, FAT_MAGIC_64)

    if is_fat:
        return _analyze_fat(raw, magic, file_path)
    else:
        return _analyze_thin(raw, magic, endian, file_path)


def _analyze_fat(raw: bytes, magic: int, file_path: Path) -> dict[str, Any]:
    """Universal binary - desempacta primeiro slice."""
    # FAT header: magic (BE) + nfat_arch (BE)
    nfat = struct.unpack(">I", raw[4:8])[0]
    archs = []

    # Cada arch entry: cputype, cpusubtype, offset, size, align (todos uint32, BE)
    entry_size = 20 if magic != FAT_MAGIC_64 else 32
    for i in range(nfat):
        off = 8 + i * entry_size
        if entry_size == 20:
            cputype, _, foff, fsize, _ = struct.unpack(">IIIII", raw[off:off+20])
        else:
            cputype, _, foff, fsize, _, _ = struct.unpack(">IIQQII", raw[off:off+32])
        archs.append({"cputype": CPU_TYPES.get(cputype, hex(cputype)), "offset": foff, "size": fsize})

    # Analisa primeiro arch
    if archs:
        first = archs[0]
        slice_data = raw[first["offset"]:first["offset"] + first["size"]]
        magic_le = struct.unpack("<I", slice_data[:4])[0]
        magic_be = struct.unpack(">I", slice_data[:4])[0]
        if magic_le in (MAGIC_32, MAGIC_64):
            slice_result = _analyze_thin(slice_data, magic_le, "<", file_path)
        elif magic_be in (MAGIC_32, MAGIC_64):
            slice_result = _analyze_thin(slice_data, magic_be, ">", file_path)
        else:
            slice_result = {"status": "error", "error": "Slice nao parseou"}

        if slice_result.get("status") == "ok":
            slice_result["is_universal"] = True
            slice_result["fat_archs"] = archs
            return slice_result

    return {
        "status": "ok",
        "found": True,
        "file_type": "Universal/Fat Mach-O",
        "is_universal": True,
        "fat_archs": archs,
        "_summary": f"Universal binary com {len(archs)} archs",
        "detections": 0,
        "suspicious": 0,
        "engines": 1,
    }


def _analyze_thin(raw: bytes, magic: int, endian: str, file_path: Path) -> dict[str, Any]:
    is_64 = magic in (MAGIC_64, MAGIC_64_SWAP)

    # mach_header(_64) tem layout fixo
    if is_64:
        # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
        hdr_fmt = endian + "IIIIIII4x"
        hdr_size = 32
    else:
        hdr_fmt = endian + "IIIIIII"
        hdr_size = 28

    fields = struct.unpack(hdr_fmt, raw[:hdr_size])
    _, cputype, _, filetype, ncmds, _, flags = fields[:7]

    arch_str = CPU_TYPES.get(cputype, hex(cputype))
    file_type_str = FILE_TYPES.get(filetype, f"type {filetype}")

    # Itera load commands
    offset = hdr_size
    needed_dylibs = []
    rpaths = []
    code_signature = False
    has_main = False
    is_encrypted = False
    imported_symbols = []
    segments = []

    for _ in range(ncmds):
        if offset + 8 > len(raw):
            break
        cmd, cmdsize = struct.unpack(endian + "II", raw[offset:offset+8])
        cmd_data = raw[offset:offset + cmdsize]

        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            # dylib_command: cmd, cmdsize, dylib.name(offset), ts, current, compat
            name_off = struct.unpack(endian + "I", cmd_data[8:12])[0]
            name_bytes = cmd_data[name_off:].split(b"\x00", 1)[0]
            needed_dylibs.append(name_bytes.decode("utf-8", errors="replace"))

        elif cmd == LC_RPATH:
            path_off = struct.unpack(endian + "I", cmd_data[8:12])[0]
            path_bytes = cmd_data[path_off:].split(b"\x00", 1)[0]
            rpaths.append(path_bytes.decode("utf-8", errors="replace"))

        elif cmd == LC_CODE_SIGNATURE:
            code_signature = True

        elif cmd == LC_MAIN:
            has_main = True

        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cryptid field nao-zero = encrypted
            cryptid = struct.unpack(endian + "I", cmd_data[16:20])[0]
            if cryptid != 0:
                is_encrypted = True

        elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
            seg_size = 56 if cmd == LC_SEGMENT else 72
            if len(cmd_data) >= seg_size:
                seg_name = cmd_data[8:24].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                if cmd == LC_SEGMENT_64:
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, _, _ = struct.unpack(
                        endian + "QQQQIIII", cmd_data[24:72]
                    )
                else:
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, _, _ = struct.unpack(
                        endian + "IIIIIIII", cmd_data[24:56]
                    )
                segments.append({
                    "name": seg_name,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "maxprot": maxprot,
                    "initprot": initprot,
                })

        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack(endian + "IIII", cmd_data[8:24])
            imported_symbols = _read_symtab(raw, symoff, nsyms, stroff, strsize, is_64, endian)

        offset += cmdsize

    # Capabilities
    capabilities = detect_capabilities_macho(imported_symbols)

    # Strings + IOCs
    strings = extract_strings(raw, max_strings=5000)
    iocs = extract_iocs(strings)

    # Flags / mitigations
    flags_arr = []
    has_pie    = bool(flags & MH_PIE)
    no_heap_x  = bool(flags & MH_NO_HEAP_EXECUTION)
    allow_stack_x = bool(flags & MH_ALLOW_STACK_EXECUTION)

    if not has_pie and filetype == 2:
        flags_arr.append("Executavel sem PIE (sem ASLR)")
    if allow_stack_x:
        flags_arr.append("Stack executavel permitido (vetor de exploit)")
    if rpaths:
        flags_arr.append(f"RPATH presente: {rpaths}  (vetor de dylib hijacking)")
    if not code_signature:
        flags_arr.append("Binario NAO assinado")
    if is_encrypted:
        flags_arr.append("Segmento encriptado (Apple FairPlay ou similar)")

    # Procura DYLD_INSERT_LIBRARIES nas strings
    if "DYLD_INSERT_LIBRARIES" in "\n".join(strings):
        flags_arr.append("String 'DYLD_INSERT_LIBRARIES' presente - possivel dyld injection")

    high   = [c for c in capabilities if c["severity"] == "high"]
    medium = [c for c in capabilities if c["severity"] == "medium"]

    detections = 0
    suspicious = len(high) + len(medium)
    if rpaths and filetype == 2:
        suspicious += 1
    if not code_signature and filetype == 2:
        suspicious += 1

    return {
        "status": "ok",
        "found": True,
        "file_type":      file_type_str,
        "architecture":   arch_str,
        "bits":           "64-bit" if is_64 else "32-bit",
        "is_universal":   False,
        "is_signed":      code_signature,
        "is_encrypted":   is_encrypted,
        "has_pie":        has_pie,
        "ncmds":          ncmds,
        "needed_dylibs":  needed_dylibs,
        "rpaths":         rpaths,
        "segments":       segments,
        "imports":        imported_symbols[:200],
        "imports_count":  len(imported_symbols),
        "capabilities":   capabilities,
        "iocs":           iocs,
        "flags":          flags_arr,
        "_summary":       _summarize(capabilities, flags_arr, file_type_str),
        "detections":     detections,
        "suspicious":     suspicious,
        "engines":        1,
    }


def _read_symtab(raw: bytes, symoff: int, nsyms: int, stroff: int, strsize: int,
                 is_64: bool, endian: str) -> list[str]:
    """Le symbol table. Retorna nomes de symbols importados (undefined externos)."""
    syms = []
    if symoff == 0 or nsyms == 0:
        return syms

    # nlist (32) ou nlist_64 - layout:
    # uint32 n_strx | uint8 n_type | uint8 n_sect | uint16 n_desc | uint32/uint64 n_value
    entry_size = 16 if is_64 else 12

    str_table = raw[stroff:stroff + strsize]

    for i in range(min(nsyms, 50000)):  # safety cap
        e = symoff + i * entry_size
        if e + entry_size > len(raw):
            break

        if is_64:
            n_strx, n_type, _, _, _ = struct.unpack(endian + "IBBHQ", raw[e:e+entry_size])
        else:
            n_strx, n_type, _, _, _ = struct.unpack(endian + "IBBHI", raw[e:e+entry_size])

        # Type masks (Mach-O): N_TYPE=0xE; N_UNDF=0x0
        # External + Undefined eh o que importamos
        # n_type & N_EXT bit 1 = external; (n_type & N_TYPE) == N_UNDF (0x0) = undefined
        N_EXT  = 0x01
        N_TYPE = 0x0E
        N_UNDF = 0x00

        is_external = bool(n_type & N_EXT)
        is_undef    = (n_type & N_TYPE) == N_UNDF

        if is_external and is_undef and n_strx < strsize:
            name = str_table[n_strx:].split(b"\x00", 1)[0]
            if name:
                s = name.decode("utf-8", errors="replace")
                # Symbols Mach-O comecam com _ - removemos
                if s.startswith("_"):
                    s = s[1:]
                syms.append(s)

    return syms


def _summarize(capabilities, flags, file_type) -> str:
    high = [c["label"] for c in capabilities if c["severity"] == "high"]
    if high:
        return f"Capacidades de alto risco: {', '.join(high[:3])}"
    medium = [c["label"] for c in capabilities if c["severity"] == "medium"]
    if medium:
        return f"Capacidades de medio risco: {', '.join(medium[:3])}"
    if flags:
        return flags[0]
    return f"Mach-O ({file_type}) sem capacidades suspeitas obvias"
