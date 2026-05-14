"""
Static analysis para ELF binaries (Linux/BSD).

Extrai sem executar:
- Architecture (x86-64, ARM, MIPS, etc.)
- Tipo (ET_EXEC, ET_DYN, ET_REL)
- Linker (interpreter) - /lib64/ld-linux-x86-64.so.2 ou musl
- Symbols importados (.dynsym) -> capacidades
- Symbols exportados
- Secoes + entropia
- Dependencias (NEEDED entries)
- RPATH/RUNPATH (vetor de hijacking)
- Stripped? (debug info presente?)
- PIE / NX / RELRO / Stack Canary (mitigations)
- Strings + IOCs
"""
from __future__ import annotations
import math
from pathlib import Path
from typing import Any

from core.capabilities_elf import detect_capabilities_elf
from core.iocs import extract_strings, extract_iocs


_ELF_MAGIC = b"\x7fELF"
ENTROPY_PACKED_THRESHOLD = 7.0


async def scan_static_elf(file_path: str | Path) -> dict[str, Any]:
    """Analisa ELF. Retorna status='skipped' se nao for ELF."""
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    if not head.startswith(_ELF_MAGIC):
        return {"status": "skipped", "reason": "Arquivo nao e ELF (Linux/BSD binary)"}

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return {"status": "error", "error": "pyelftools nao instalado"}

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            result = _analyze(elf, file_path)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao parsear ELF: {e}"}

    return result


def _analyze(elf, file_path: Path) -> dict[str, Any]:
    # ---- header info ----
    arch_map = {
        "EM_X86_64": "x86-64", "EM_386": "x86", "EM_ARM": "ARM", "EM_AARCH64": "ARM64",
        "EM_MIPS": "MIPS", "EM_PPC": "PowerPC", "EM_RISCV": "RISC-V",
    }
    type_map = {
        "ET_EXEC": "Executable", "ET_DYN": "Shared Object / PIE",
        "ET_REL": "Relocatable (.o)", "ET_CORE": "Core dump",
    }
    arch = arch_map.get(elf.header["e_machine"], elf.header["e_machine"])
    file_type = type_map.get(elf.header["e_type"], elf.header["e_type"])
    bits = "64-bit" if elf.elfclass == 64 else "32-bit"

    # ---- interpreter / dynamic linker ----
    interpreter = None
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_INTERP":
            interpreter = seg.get_interp_name()
            break

    # ---- dynamic section: dependencies + symbols ----
    needed = []
    rpath = []
    runpath = []
    imports = []
    exports = []

    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
                elif tag.entry.d_tag == "DT_RPATH":
                    rpath.append(tag.rpath)
                elif tag.entry.d_tag == "DT_RUNPATH":
                    runpath.append(tag.runpath)

        if isinstance(sec, SymbolTableSection) and sec.name in (".dynsym", ".symtab"):
            for sym in sec.iter_symbols():
                name = sym.name
                if not name:
                    continue
                # Heuristica para distinguir import (undefined) de export (defined)
                if sym.entry.st_shndx == "SHN_UNDEF":
                    if name not in imports:
                        imports.append(name)
                else:
                    if sec.name == ".dynsym" and sym.entry.st_info.bind in ("STB_GLOBAL", "STB_WEAK") and sym.entry.st_info.type == "STT_FUNC":
                        if name not in exports:
                            exports.append(name)

    # ---- sections + entropy ----
    sections = []
    high_entropy_sections = []

    raw_bytes = file_path.read_bytes()

    for sec in elf.iter_sections():
        name = sec.name
        size = sec.header.sh_size
        offset = sec.header.sh_offset
        if size == 0:
            entropy = 0.0
        else:
            data = raw_bytes[offset:offset + size] if offset + size <= len(raw_bytes) else b""
            entropy = _entropy(data) if data else 0.0
        info = {
            "name": name,
            "size": size,
            "entropy": round(entropy, 2),
            "flags": _section_flags(sec.header.sh_flags),
        }
        sections.append(info)
        if entropy >= ENTROPY_PACKED_THRESHOLD and size > 64 and "X" in info["flags"]:
            high_entropy_sections.append(name)

    # ---- mitigations (security features) ----
    is_pie = elf.header["e_type"] == "ET_DYN" and any(
        s.header.p_type == "PT_DYNAMIC" for s in elf.iter_segments()
    )
    has_nx = any(
        s.header.p_type == "PT_GNU_STACK" and not (s.header.p_flags & 1)  # X bit
        for s in elf.iter_segments()
    )
    has_relro = any(
        s.header.p_type == "PT_GNU_RELRO" for s in elf.iter_segments()
    )
    has_canary = "__stack_chk_fail" in imports or "__stack_chk_fail" in exports

    # ---- stripped? ----
    is_stripped = not any(
        s.name in (".symtab", ".strtab", ".debug_info") for s in elf.iter_sections()
    )

    # ---- capabilities ----
    capabilities = detect_capabilities_elf(imports)

    # ---- strings + IOCs ----
    try:
        strings = extract_strings(raw_bytes, max_strings=8000)
        iocs = extract_iocs(strings)
    except Exception as e:
        strings = []
        iocs = {"_error": str(e)}

    # ---- flags ----
    flags = []
    if rpath or runpath:
        flags.append(f"Tem RPATH/RUNPATH ({rpath + runpath}) - vetor de library hijacking")
    if not has_nx:
        flags.append("NX desabilitado - stack executavel (raro em binarios legitimos)")
    if not has_relro:
        flags.append("Sem RELRO - vulneravel a GOT overwrite")
    if not has_canary:
        flags.append("Sem stack canary - vulneravel a stack buffer overflow")
    if high_entropy_sections:
        flags.append(f"Secoes executaveis com alta entropia (>{ENTROPY_PACKED_THRESHOLD}): {high_entropy_sections}")
    if is_stripped and elf.header["e_type"] != "ET_DYN":
        flags.append("Binario stripped (sem symbols de debug) - comum em malware")
    if not imports and not needed:
        flags.append("Sem imports nem dependencias - estaticamente linkado ou packer")

    # ---- scoring ----
    high = [c for c in capabilities if c["severity"] == "high"]
    medium = [c for c in capabilities if c["severity"] == "medium"]

    detections = 0
    suspicious = len(high) + len(medium)
    if high_entropy_sections:
        suspicious += 1
    if rpath or runpath:
        suspicious += 1

    return {
        "status": "ok",
        "found": True,
        "file_type": file_type,
        "architecture": arch,
        "bits": bits,
        "interpreter": interpreter,
        "is_stripped": is_stripped,
        "is_pie": is_pie,
        "mitigations": {
            "nx": has_nx,
            "relro": has_relro,
            "canary": has_canary,
            "pie": is_pie,
        },
        "needed_libs": needed,
        "rpath": rpath,
        "runpath": runpath,
        "sections": sections,
        "high_entropy_sections": high_entropy_sections,
        "imports": imports[:200],
        "exports": exports[:100],
        "capabilities": capabilities,
        "iocs": iocs,
        "strings_sample": strings[:100] if strings else [],
        "flags": flags,
        "_summary": _summarize(capabilities, flags, needed),
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / total
            e -= p * math.log2(p)
    return e


def _section_flags(sh_flags: int) -> str:
    """Convert sh_flags integer em string tipo 'WAX'."""
    flags = ""
    if sh_flags & 0x4: flags += "X"   # SHF_EXECINSTR
    if sh_flags & 0x1: flags += "W"   # SHF_WRITE
    if sh_flags & 0x2: flags += "A"   # SHF_ALLOC
    return flags or "-"


def _summarize(capabilities, flags, needed) -> str:
    high = [c["label"] for c in capabilities if c["severity"] == "high"]
    if high:
        return f"Capacidades de alto risco: {', '.join(high[:3])}"
    medium = [c["label"] for c in capabilities if c["severity"] == "medium"]
    if medium:
        return f"Capacidades de medio risco: {', '.join(medium[:3])}"
    if flags:
        return flags[0]
    if not needed:
        return "Binario ELF estaticamente linkado (ou packer)"
    return "Nenhuma capacidade suspeita detectada via analise estatica"
