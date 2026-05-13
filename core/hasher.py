"""
Utilitários para cálculo de hashes (MD5, SHA1, SHA256).
Hashes são a base para consultar APIs de análise sem reenviar o arquivo.
"""
import hashlib
from pathlib import Path
from typing import Dict


def compute_hashes(file_path: str | Path, chunk_size: int = 65536) -> Dict[str, str]:
    """Calcula MD5, SHA1 e SHA256 de um arquivo, lendo em blocos."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def file_size(file_path: str | Path) -> int:
    """Retorna tamanho do arquivo em bytes."""
    return Path(file_path).stat().st_size
