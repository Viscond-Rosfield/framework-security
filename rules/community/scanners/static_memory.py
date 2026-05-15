"""
Memory dump triage scanner.

Identifica o formato de memory dumps e extrai metadados essenciais
para o analista saber o que rodar com Volatility/Rekall.

Formatos suportados:
- Windows Crash Dump (PAGEDUMP / PAGEDU64) - .dmp
- Windows Minidump (MDMP) - .mdmp
- LiME (Linux Memory Extractor) - .lime
- AVML (Microsoft Azure VM Memory Locator) - ELF-based
- Raw memory dump (heuristica por tamanho)
- VMware VMEM - .vmem (raw)

Nao executa Volatility - so identifica e sugere comandos.
"""
from __future__ import annotations
import struct
from pathlib import Path
from typing import Any


# Magic signatures
PAGEDUMP_32 = b"PAGEDUMP"     # Windows crash dump 32-bit (offset 0)
PAGEDU64    = b"PAGEDU64"     # Windows crash dump 64-bit (offset 0)
MDMP        = b"MDMP\x93\xa7" # Windows Minidump
LIME_HEADER = b"\x45\x4D\x69\x4C"  # LiME magic (EMiL backwards)

# Tipos de dump Windows (DumpType field)
WIN_DUMP_TYPES = {
    0x01: "Full memory dump",
    0x02: "Kernel memory dump",
    0x03: "Small memory dump (minidump)",
    0x04: "Triage dump",
    0x05: "Bitmap kernel dump",
    0x06: "Bitmap full dump",
    0x07: "Automatic memory dump",
}


async def scan_static_memory(file_path: str | Path) -> dict[str, Any]:
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(8192)
            size = file_path.stat().st_size
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    if len(head) < 8:
        return {"status": "skipped", "reason": "Arquivo muito pequeno"}

    # 1) Windows crash dump (PAGEDUMP / PAGEDU64)
    if head.startswith(PAGEDUMP_32):
        return _analyze_windows_full(head, size, bits=32)
    if head.startswith(PAGEDU64):
        return _analyze_windows_full(head, size, bits=64)

    # 2) Windows Minidump (MDMP)
    if head.startswith(b"MDMP"):
        return _analyze_windows_minidump(head, size)

    # 3) LiME header
    if head.startswith(LIME_HEADER):
        return _analyze_lime(head, size)

    # 4) ELF coredump (Linux) - magic ELF + e_type=ET_CORE
    if head.startswith(b"\x7fELF"):
        return _analyze_elf_coredump(head, size, file_path)

    # 5) Heuristica: VMware vmem (raw memory)
    # vmem geralmente eh tamanho = potencia de 2 (256MB, 512MB, 1GB, etc.) ou alinhado
    if _looks_like_raw_memory(file_path, size):
        return _analyze_raw_memory(size, file_path)

    return {"status": "skipped", "reason": "Nao parece memory dump"}


def _analyze_windows_full(head: bytes, size: int, bits: int) -> dict[str, Any]:
    """Windows full/kernel crash dump - DUMP_HEADER struct."""
    # DUMP_HEADER (32-bit) ou DUMP_HEADER64 layout (simplificado):
    # 0x00: Signature ("PAGEDUMP" / "PAGEDU64")
    # 0x08: ValidDump ("DUMP" / "DU64")
    # 0x0C: MajorVersion (DWORD)
    # 0x10: MinorVersion (DWORD)
    # 0x14: DirectoryTableBase
    # 0x18: PfnDataBase
    # 0x1C: PsLoadedModuleList
    # 0x20: PsActiveProcessHead
    # 0x24: MachineImageType (0x14C=x86, 0x8664=x64)
    # 0x28: NumberProcessors
    # 0x2C: BugCheckCode
    # 0x30: BugCheckParameter1..4
    # 0xF80 (32) / 0xF98 (64): DumpType

    try:
        valid = head[8:12].decode("ascii", errors="replace")
        major  = struct.unpack("<I", head[0x0C:0x10])[0]
        minor  = struct.unpack("<I", head[0x10:0x14])[0]
        machine = struct.unpack("<I", head[0x24:0x28])[0]
        num_cpus = struct.unpack("<I", head[0x28:0x2C])[0]
        bug_check = struct.unpack("<I", head[0x2C:0x30])[0]

        # DumpType offset difere entre 32 e 64-bit
        dump_type_off = 0xF80 if bits == 32 else 0xF98
        if len(head) >= dump_type_off + 4:
            dump_type = struct.unpack("<I", head[dump_type_off:dump_type_off+4])[0]
        else:
            dump_type = 0
    except Exception as e:
        return {"status": "error", "error": f"Parse fail: {e}"}

    arch_str = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine, hex(machine))
    dump_str = WIN_DUMP_TYPES.get(dump_type, f"type {dump_type}")

    suggestions = [
        f"vol -f sample.dmp windows.info",
        f"vol -f sample.dmp windows.pslist",
        f"vol -f sample.dmp windows.netstat",
        f"vol -f sample.dmp windows.malfind",
        f"vol -f sample.dmp windows.cmdline",
        f"vol -f sample.dmp windows.dlllist",
    ]

    flags = []
    if dump_type in (1, 6):
        flags.append("Full memory dump - melhor pra analise completa (mas tamanho enorme)")
    if dump_type == 2:
        flags.append("Kernel-only dump - sem userland processes")
    if dump_type == 3:
        flags.append("Minidump - so o processo que crashou (info limitada)")
    if bug_check != 0:
        flags.append(f"BugCheckCode: 0x{bug_check:X}")

    return {
        "status": "ok",
        "found": True,
        "format": "Windows Crash Dump",
        "bits": bits,
        "windows_version": f"{major}.{minor}",
        "architecture": arch_str,
        "num_cpus": num_cpus,
        "dump_type_id": dump_type,
        "dump_type": dump_str,
        "bug_check_code": f"0x{bug_check:X}" if bug_check else None,
        "size_human": _human_size(size),
        "valid_marker": valid,
        "suggestions": suggestions,
        "flags": flags,
        "_summary": f"Windows {arch_str} {dump_str} (Windows {major}.{minor}, {num_cpus} CPUs, {_human_size(size)})",
        "detections": 0,
        "suspicious": 0,
        "engines": 1,
    }


def _analyze_windows_minidump(head: bytes, size: int) -> dict[str, Any]:
    """MDMP - Windows Minidump (.mdmp / crash reporter)."""
    # MINIDUMP_HEADER:
    # 0x00: Signature "MDMP"
    # 0x04: Version (DWORD)
    # 0x08: NumberOfStreams (DWORD)
    # 0x0C: StreamDirectoryRva (DWORD)
    # 0x10: CheckSum (DWORD)
    # 0x14: TimeDateStamp (DWORD - unix time)
    # 0x18: Flags (QWORD)
    version, num_streams = struct.unpack("<II", head[0x04:0x0C])
    timestamp = struct.unpack("<I", head[0x14:0x18])[0]

    from datetime import datetime, timezone
    try:
        dt = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except Exception:
        dt = "?"

    return {
        "status": "ok",
        "found": True,
        "format": "Windows Minidump (MDMP)",
        "version": hex(version),
        "num_streams": num_streams,
        "timestamp": dt,
        "size_human": _human_size(size),
        "suggestions": [
            "WinDbg: load minidump, '!analyze -v' para crash analysis",
            "vol -f sample.mdmp windows.minidump.info  (Volatility tem suporte limitado a MDMP)",
        ],
        "flags": ["Minidump captura so o processo que crashou. Util pra debug, limitado pra IR forense."],
        "_summary": f"Windows Minidump v{version:x} com {num_streams} streams ({_human_size(size)})",
        "detections": 0,
        "suspicious": 0,
        "engines": 1,
    }


def _analyze_lime(head: bytes, size: int) -> dict[str, Any]:
    """LiME dump - Linux Memory Extractor."""
    # LiME header: magic(4) version(4) s_addr(8) e_addr(8) reserved(8) = 32 bytes
    try:
        version  = struct.unpack("<I", head[4:8])[0]
        s_addr   = struct.unpack("<Q", head[8:16])[0]
        e_addr   = struct.unpack("<Q", head[16:24])[0]
    except Exception:
        version = s_addr = e_addr = 0

    return {
        "status": "ok",
        "found": True,
        "format": "LiME (Linux Memory Extractor)",
        "version": version,
        "first_segment_start": hex(s_addr),
        "first_segment_end": hex(e_addr),
        "size_human": _human_size(size),
        "suggestions": [
            "vol -f sample.lime linux.pslist",
            "vol -f sample.lime linux.bash",
            "vol -f sample.lime linux.malfind",
            "vol -f sample.lime linux.check_modules",
            "vol -f sample.lime linux.kmsg",
        ],
        "flags": ["LiME nao tem profile embedded - precisa de Volatility symbol pra esse kernel especifico"],
        "_summary": f"LiME Linux memory dump v{version} ({_human_size(size)})",
        "detections": 0,
        "suspicious": 0,
        "engines": 1,
    }


def _analyze_elf_coredump(head: bytes, size: int, file_path: Path) -> dict[str, Any]:
    """ELF coredump (Linux core file ou AVML)."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            if elf.header["e_type"] != "ET_CORE":
                return {"status": "skipped", "reason": "ELF nao eh coredump"}

            # Avml (Azure VM Memory Locator) gera ELF com notas especificas
            is_avml = False
            try:
                for seg in elf.iter_segments():
                    if seg.header.p_type == "PT_NOTE":
                        for note in seg.iter_notes():
                            if "AVML" in str(note.get("n_name", "")).upper():
                                is_avml = True
                                break
            except Exception:
                pass

            arch = elf.header["e_machine"]

            format_name = "AVML (Azure Memory Locator)" if is_avml else "ELF Coredump (Linux)"

            return {
                "status": "ok",
                "found": True,
                "format": format_name,
                "architecture": arch,
                "size_human": _human_size(size),
                "is_avml": is_avml,
                "suggestions": [
                    "vol -f sample.elf linux.pslist",
                    "vol -f sample.elf linux.bash",
                    "vol -f sample.elf linux.malfind",
                    "vol -f sample.elf linux.tty_check",
                ],
                "flags": [
                    "AVML eh formato da Microsoft pra dump em VMs Azure. Volatility 3 suporta diretamente." if is_avml
                    else "ELF coredump tradicional Linux. Use Volatility pra analise."
                ],
                "_summary": f"{format_name} ({arch}, {_human_size(size)})",
                "detections": 0,
                "suspicious": 0,
                "engines": 1,
            }
    except Exception as e:
        return {"status": "error", "error": f"ELF coredump parse: {e}"}


def _looks_like_raw_memory(file_path: Path, size: int) -> bool:
    """Heuristica pra detectar raw memory dump (vmem, etc.).
    Criterios:
    - Tamanho >= 64MB (memoria minima realista)
    - Tamanho multiplo de 4KB (page size)
    - Extensao .vmem / .raw / .mem / .bin
    """
    ext = file_path.suffix.lower()
    if ext not in (".vmem", ".raw", ".mem", ".bin", ".dump"):
        return False
    if size < 64 * 1024 * 1024:
        return False
    if size % 4096 != 0:
        return False
    return True


def _analyze_raw_memory(size: int, file_path: Path) -> dict[str, Any]:
    return {
        "status": "ok",
        "found": True,
        "format": "Raw memory dump (heuristica)",
        "size_human": _human_size(size),
        "page_count": size // 4096,
        "suggestions": [
            "vol -f sample.vmem windows.info",
            "vol -f sample.vmem windows.pslist",
            "vol -f sample.vmem windows.malfind",
            "Identifique OS primeiro com 'windows.info' ou 'linux.info' antes dos demais plugins",
        ],
        "flags": [
            "Formato raw - Volatility precisa adivinhar profile. Use --profile para acelerar.",
        ],
        "_summary": f"Raw memory dump ({_human_size(size)}, {size // 4096} pages)",
        "detections": 0,
        "suspicious": 0,
        "engines": 1,
    }


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"
