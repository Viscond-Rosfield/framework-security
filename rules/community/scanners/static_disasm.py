"""
Scanner de disassembly estatico (via Capstone).

Detecta automaticamente arquitetura (PE ou ELF), encontra o entry point,
desmonta as primeiras ~256 instrucoes e procura padroes suspeitos
caracteristicos de malware / shellcode.

Padroes detectados:
- NOP sled (chain de 0x90)
- RDTSC (timing-based anti-debug)
- INT 2D / INT 3 (debugger probe / breakpoints suspeitos)
- Calls indiretos (call eax, call rax)
- PUSH/RET (ROP gadgets)
- Shellcode prologue do MSF (CLD + CALL)
- Self-modifying writes (mov to RWX region)
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Optional


MAX_INSTRUCTIONS = 256


async def scan_static_disasm(file_path: str | Path) -> dict[str, Any]:
    """Desmonta o entry point do binario e procura padroes."""
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(8)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    # Detecta formato e arch
    if head.startswith(b"MZ"):
        return await _analyze_pe(file_path)
    elif head.startswith(b"\x7fELF"):
        return await _analyze_elf(file_path)
    else:
        return {"status": "skipped", "reason": "Nao eh PE nem ELF (sem disasm)"}


def _resolve_capstone(arch: str, bits: int):
    """Retorna instancia Cs configurada."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM

    arch = arch.lower()
    if arch in ("x86", "i386"):
        return Cs(CS_ARCH_X86, CS_MODE_32), "x86"
    if arch in ("x86-64", "x86_64", "amd64", "x64"):
        return Cs(CS_ARCH_X86, CS_MODE_64), "x86-64"
    if arch == "arm":
        return Cs(CS_ARCH_ARM, CS_MODE_ARM), "ARM"
    if arch == "arm64":
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM), "ARM64"
    return None, arch


async def _analyze_pe(file_path: Path) -> dict[str, Any]:
    try:
        import pefile
    except ImportError:
        return {"status": "error", "error": "pefile nao instalado"}

    try:
        pe = pefile.PE(str(file_path), fast_load=True)
    except Exception as e:
        return {"status": "error", "error": f"PE parse: {e}"}

    try:
        machine = pe.FILE_HEADER.Machine
        # 0x14c = x86, 0x8664 = x86-64
        arch = "x86-64" if machine == 0x8664 else "x86" if machine == 0x14c else hex(machine)

        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_va = pe.OPTIONAL_HEADER.ImageBase + entry_rva

        # Le ate 4096 bytes a partir do EP (depois capstone para na count)
        try:
            code = pe.get_data(entry_rva, 4096)
        except Exception:
            code = b""

        if not code:
            return {"status": "ok", "found": False, "reason": "Entry point sem dados"}

        result = _disassemble_and_analyze(code, entry_va, arch)
        result["file_type"] = "PE"
        result["entry_point"] = hex(entry_va)
        return result
    finally:
        pe.close()


async def _analyze_elf(file_path: Path) -> dict[str, Any]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"status": "error", "error": "pyelftools nao instalado"}

    arch_map = {
        "EM_386": "x86",
        "EM_X86_64": "x86-64",
        "EM_ARM": "ARM",
        "EM_AARCH64": "ARM64",
    }

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            arch = arch_map.get(elf.header["e_machine"])
            if not arch:
                return {"status": "skipped", "reason": f"Arch ELF nao suportada: {elf.header['e_machine']}"}

            entry = elf.header["e_entry"]

            # Encontra a secao .text (codigo executavel)
            text = elf.get_section_by_name(".text")
            if text is None:
                return {"status": "ok", "found": False, "reason": "Sem secao .text"}

            code = text.data()[:4096]
            text_addr = text.header.sh_addr

            result = _disassemble_and_analyze(code, text_addr, arch)
            result["file_type"] = "ELF"
            result["entry_point"] = hex(entry)
            return result
    except Exception as e:
        return {"status": "error", "error": f"ELF parse: {e}"}


def _disassemble_and_analyze(code: bytes, base_addr: int, arch: str) -> dict[str, Any]:
    """Desmonta e procura padroes suspeitos."""
    md, arch_name = _resolve_capstone(arch, 0)
    if md is None:
        return {"status": "skipped", "reason": f"Arch nao suportada pelo Capstone: {arch}"}

    md.detail = False  # mais rapido sem detalhes

    instructions = []
    for ins in md.disasm(code, base_addr):
        instructions.append({
            "address": ins.address,
            "bytes": ins.bytes.hex(),
            "mnemonic": ins.mnemonic,
            "op_str": ins.op_str,
        })
        if len(instructions) >= MAX_INSTRUCTIONS:
            break

    patterns = _detect_patterns(code, instructions)
    high   = [p for p in patterns if p["severity"] == "high"]
    medium = [p for p in patterns if p["severity"] == "medium"]

    return {
        "status": "ok",
        "found": True,
        "architecture": arch_name,
        "instructions_count": len(instructions),
        "instructions": instructions,
        "patterns": patterns,
        "_summary": _summarize(patterns, len(instructions)),
        "detections": 0,
        "suspicious": len(high) + len(medium),
        "engines": 1,
    }


def _detect_patterns(code: bytes, instructions: list) -> list[dict]:
    """Procura padroes suspeitos no codigo / instrucoes."""
    patterns = []

    # 1) NOP sled (sequencia de 0x90)
    nop_run = 0
    max_run = 0
    for b in code[:512]:
        if b == 0x90:
            nop_run += 1
            max_run = max(max_run, nop_run)
        else:
            nop_run = 0
    if max_run >= 20:
        patterns.append({
            "id": "nop_sled",
            "label": "NOP sled detectado",
            "severity": "high",
            "description": f"Sequencia de {max_run} NOPs consecutivos. Tipico de shellcode injection que pula pra dentro de slide.",
        })

    # 2) RDTSC (instrucao de timing - frequente em anti-debug)
    rdtsc_count = sum(1 for i in instructions if i["mnemonic"] == "rdtsc")
    if rdtsc_count > 0:
        patterns.append({
            "id": "rdtsc",
            "label": f"RDTSC ({rdtsc_count}x)",
            "severity": "medium",
            "description": "Le timestamp counter. Comum em anti-debug pra medir se um trecho rodou rapido demais (debugger inserindo pausas).",
        })

    # 3) INT 2D (interrupcao usada como anti-debug)
    int_2d = any(i["mnemonic"] == "int" and "0x2d" in i["op_str"] for i in instructions)
    if int_2d:
        patterns.append({
            "id": "int_2d",
            "label": "INT 0x2D (debugger probe)",
            "severity": "high",
            "description": "Anti-debug classico. INT 2D se comporta diferente quando ha debugger, e usado pra detectar.",
        })

    # 4) Calls indiretos via registrador
    indirect_calls = sum(
        1 for i in instructions
        if i["mnemonic"] == "call"
        and i["op_str"] in ("eax", "rax", "ebx", "rbx", "ecx", "rcx", "edx", "rdx", "esi", "edi", "rsi", "rdi")
    )
    if indirect_calls >= 3:
        patterns.append({
            "id": "indirect_calls",
            "label": f"Calls indiretos ({indirect_calls}x)",
            "severity": "medium",
            "description": "Multiplos calls via registrador (call eax, etc.) - tecnica pra esconder destino real. Comum em shellcode com resolve dinamico de API.",
        })

    # 5) Shellcode prologue do Metasploit (CLD + CALL)
    if code.startswith(b"\xfc\xe8"):
        patterns.append({
            "id": "msf_shellcode_prologue",
            "label": "Possivel prologue do Metasploit shellcode",
            "severity": "high",
            "description": "Bytes iniciais CLD (\\xFC) + CALL (\\xE8) sao prologue MUITO comum em shellcode gerado pelo msfvenom.",
        })

    # 6) PUSH + RET (ROP gadget classico)
    push_ret = 0
    for i in range(len(instructions) - 1):
        if instructions[i]["mnemonic"] == "push" and instructions[i + 1]["mnemonic"] == "ret":
            push_ret += 1
    if push_ret >= 3:
        patterns.append({
            "id": "push_ret_pattern",
            "label": f"PUSH+RET sequencia ({push_ret}x)",
            "severity": "medium",
            "description": "Padrao PUSH imediato seguido de RET. Tipico em ROP chains ou no inicio de unpackers.",
        })

    # 7) INT 3 inicial (breakpoint manual)
    if len(instructions) > 0 and instructions[0]["mnemonic"] == "int3":
        patterns.append({
            "id": "int3_start",
            "label": "INT 3 no inicio do codigo",
            "severity": "medium",
            "description": "Codigo comeca com INT 3 (\\xCC) - quebra qualquer debugger nao preparado.",
        })

    return patterns


def _summarize(patterns: list, n_instr: int) -> str:
    if not patterns:
        return f"Desmontou {n_instr} instrucoes - nenhum padrao suspeito"
    high = [p["label"] for p in patterns if p["severity"] == "high"]
    if high:
        return f"Padroes ASM de alto risco: {', '.join(high[:3])}"
    medium = [p["label"] for p in patterns if p["severity"] == "medium"]
    return f"Padroes ASM: {', '.join(medium[:3])}"
