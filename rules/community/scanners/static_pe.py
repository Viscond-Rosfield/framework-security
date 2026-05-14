"""
Static analysis scanner para arquivos PE (Windows .exe/.dll).

NAO executa o arquivo. Apenas le sua estrutura interna:
- Imports (DLLs e funcoes) -> capacidades
- Exports (se for DLL)
- Secoes + entropia (detecta packing/obfuscacao)
- Packers conhecidos (UPX, ASPack, etc.)
- Strings + IOCs (URLs, IPs, mutex)
- Metadados (timestamp, machine, subsystem)
- Certificado digital (se assinado)
"""
from __future__ import annotations
import math
from pathlib import Path
from typing import Any

from core.capabilities import detect_capabilities
from core.iocs import extract_strings, extract_iocs


# Magic bytes do PE
_PE_MAGIC = b"MZ"

# Heuristica de entropia: >7.0 = possivel encryption/compression (packing)
ENTROPY_PACKED_THRESHOLD = 7.0

# Hints conhecidos de packers (substring de nome de secao)
PACKER_HINTS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", "UPX!": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".petite": "Petite",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".pec1": "PECompact", ".pec2": "PECompact",
}


async def scan_static_pe(file_path: str | Path) -> dict[str, Any]:
    """
    Roda analise estatica em arquivo PE. Se nao for PE, retorna status='skipped'.
    """
    try:
        import pefile
    except ImportError:
        return {"status": "error", "error": "pefile nao instalado"}

    file_path = Path(file_path)

    # Verifica magic bytes
    try:
        with open(file_path, "rb") as f:
            head = f.read(2)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler arquivo: {e}"}

    if head != _PE_MAGIC:
        return {
            "status": "skipped",
            "reason": "Arquivo nao e PE (Windows executable/DLL)",
        }

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
    except Exception as e:
        return {"status": "error", "error": f"pefile falhou: {e}"}

    try:
        result = _analyze(pe, file_path)
    finally:
        pe.close()

    return result


def _analyze(pe, file_path: Path) -> dict[str, Any]:
    # ----- Cabecalho / metadados -----
    is_dll  = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    is_exe  = not is_dll
    machine = pe.FILE_HEADER.Machine
    machine_str = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}.get(machine, hex(machine))
    timestamp = pe.FILE_HEADER.TimeDateStamp
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    subsystem_str = {
        1: "Native", 2: "Windows GUI", 3: "Windows Console",
        9: "Windows CE GUI", 10: "EFI Application",
    }.get(subsystem, str(subsystem))

    # ----- Secoes + entropia -----
    sections = []
    high_entropy_sections = []
    detected_packers = set()
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        entropy = section.get_entropy()
        info = {
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(entropy, 2),
            "characteristics": hex(section.Characteristics),
        }
        sections.append(info)

        if entropy >= ENTROPY_PACKED_THRESHOLD and section.SizeOfRawData > 0:
            high_entropy_sections.append(name)

        # Packer hint pelo nome da secao
        for hint, packer in PACKER_HINTS.items():
            if hint.lower() == name.lower() or name.lower().startswith(hint.lower()):
                detected_packers.add(packer)

    # ----- Imports -----
    imports = []        # [{dll, functions}]
    all_funcs = []      # flat list de nomes de funcao
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode("utf-8", errors="replace")
                    funcs.append(fname)
                    all_funcs.append(fname)
                else:
                    funcs.append(f"ord_{imp.ordinal}")
            imports.append({"dll": dll, "functions": funcs, "count": len(funcs)})

    # ----- Exports (DLL) -----
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                exports.append(sym.name.decode("utf-8", errors="replace"))

    # ----- Capacidades via mapeamento de imports -----
    capabilities = detect_capabilities(all_funcs)

    # ----- Strings + IOCs -----
    try:
        raw_bytes = file_path.read_bytes()
        strings = extract_strings(raw_bytes, max_strings=8000)
        iocs = extract_iocs(strings)
    except Exception as e:
        strings = []
        iocs = {"_error": str(e)}

    # ----- Certificado digital -----
    is_signed = False
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        is_signed = True
    elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0:
        is_signed = True

    # ----- Suspicious score / flags -----
    flags = []
    if detected_packers:
        flags.append(f"Possivel packer: {', '.join(sorted(detected_packers))}")
    if high_entropy_sections:
        flags.append(f"Secoes com alta entropia (>{ENTROPY_PACKED_THRESHOLD}): {', '.join(high_entropy_sections)}")
    if not imports:
        flags.append("Nenhum import visivel (provavel packer ou imports resolvidos dinamicamente)")
    if len(imports) < 3 and not detected_packers:
        flags.append("Muito poucos imports - suspeito em arquivos grandes")

    high_caps = [c for c in capabilities if c["severity"] == "high"]
    medium_caps = [c for c in capabilities if c["severity"] == "medium"]

    # Static analysis NUNCA marca como "malicious" sozinho.
    # Capacidades altas/medias contam como SUSPEITAS (informativo).
    detections = 0
    suspicious = len(high_caps) + len(medium_caps)
    if detected_packers:
        suspicious += 1
    if high_entropy_sections and not detected_packers:
        suspicious += 1

    return {
        "status": "ok",
        "found": True,
        "file_type": "DLL" if is_dll else "EXE",
        "architecture": machine_str,
        "subsystem": subsystem_str,
        "compiled_timestamp": timestamp,
        "is_signed": is_signed,
        "detected_packers": sorted(detected_packers),
        "high_entropy_sections": high_entropy_sections,
        "sections": sections,
        "imports": imports,
        "exports": exports[:200],  # limita pra UI
        "capabilities": capabilities,
        "iocs": iocs,
        "strings_sample": strings[:100] if strings else [],
        "flags": flags,
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
        "_summary": _summarize(capabilities, detected_packers, flags),
    }


def _summarize(capabilities, packers, flags) -> str:
    """Frase curta resumindo o que a analise encontrou."""
    high = [c["label"] for c in capabilities if c["severity"] == "high"]
    if high:
        return f"Capacidades de alto risco: {', '.join(high[:3])}"
    medium = [c["label"] for c in capabilities if c["severity"] == "medium"]
    if medium:
        return f"Capacidades de médio risco: {', '.join(medium[:3])}"
    if packers:
        return f"Possivel packer: {', '.join(sorted(packers))}"
    if flags:
        return flags[0]
    return "Nenhuma capacidade suspeita detectada via analise estatica"


def calculate_entropy(data: bytes) -> float:
    """Calcula entropia de Shannon (0-8). Util pra testes."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy
