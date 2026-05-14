"""
Scanner local - heurísticas offline sem dependência externa.

Verifica:
- Match contra uma pequena base de hashes conhecidos como maliciosos (EICAR + customizáveis)
- Detecção da string EICAR (assinatura de teste de antivírus)
- Análise simples de extensão / "double extension" (ex.: nota.pdf.exe)
- Magic bytes para identificar tipo real do arquivo
"""
from pathlib import Path
from typing import Dict, Any, List

# Hash SHA256 do arquivo de teste EICAR
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# Pequena base de hashes conhecidos - exemplo (pode ser expandida com um feed real)
KNOWN_BAD_HASHES = {
    EICAR_SHA256: "EICAR-Test-File (arquivo padrão de teste antivírus)",
}

EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Extensões consideradas "perigosas" em e-mails/downloads
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".ps1", ".msi", ".dll", ".hta", ".cpl", ".lnk",
}

# Magic bytes -> descrição
MAGIC_BYTES = [
    (b"MZ", "PE Executable (Windows .exe/.dll)"),
    (b"\x7fELF", "ELF Executable (Linux)"),
    (b"PK\x03\x04", "ZIP / Office / JAR archive"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "Microsoft Compound File (old Office)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!", "RAR archive"),
    (b"#!", "Script (shebang)"),
]


async def scan_local(file_path: Path, hashes: Dict[str, str]) -> Dict[str, Any]:
    """Executa as heurísticas locais e retorna no formato padrão do framework."""
    flags: List[str] = []
    detections = 0
    suspicious = 0

    # 1) hash em base conhecida
    if hashes["sha256"] in KNOWN_BAD_HASHES:
        flags.append(f"Hash conhecido: {KNOWN_BAD_HASHES[hashes['sha256']]}")
        detections += 1

    # 2) Lê os primeiros bytes para magic + scan rápido por EICAR
    try:
        with open(file_path, "rb") as f:
            head = f.read(4096)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler arquivo: {e}"}

    file_type = _detect_file_type(head)

    if EICAR_SIGNATURE in head:
        flags.append("Assinatura EICAR detectada no conteúdo")
        detections += 1

    # 3) Verificação de extensão
    name = file_path.name.lower()
    real_ext = Path(name).suffix
    if real_ext in DANGEROUS_EXTENSIONS:
        suspicious += 1
        flags.append(f"Extensão potencialmente perigosa: {real_ext}")

    # 4) Double extension (ex.: foto.jpg.exe)
    parts = name.split(".")
    if len(parts) >= 3:
        penultimate = "." + parts[-2]
        if penultimate in {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".txt"} \
                and real_ext in DANGEROUS_EXTENSIONS:
            suspicious += 1
            flags.append(f"Double extension suspeita: {penultimate}{real_ext}")

    # 5) Coerência entre extensão e magic bytes
    if file_type and real_ext:
        if real_ext == ".pdf" and "PDF" not in file_type:
            suspicious += 1
            flags.append(f"Extensão .pdf mas conteúdo parece ser '{file_type}'")
        if real_ext in {".jpg", ".jpeg", ".png"} and "PE Executable" in file_type:
            detections += 1
            flags.append("Arquivo de imagem com cabeçalho de executável (PE)")

    return {
        "status": "ok",
        "found": True,
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
        "file_type": file_type or "desconhecido",
        "flags": flags,
        "message": "Análise local concluída." if flags else "Nenhuma anomalia local detectada.",
    }


def _detect_file_type(head: bytes) -> str | None:
    for magic, label in MAGIC_BYTES:
        if head.startswith(magic):
            return label
    return None
