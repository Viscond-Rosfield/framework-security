"""
Calcula hashes criptograficos + fuzzy hashes do arquivo.

Hashes criptograficos (MD5/SHA1/SHA256):
- Determinísticos, mudar 1 bit = hash totalmente diferente
- Usados pra identificar arquivos exatos

Fuzzy hashes (ssdeep/TLSH):
- Hashes locality-sensitive: arquivos similares produzem hashes parecidos
- ssdeep: bom pra encontrar variantes leves (mesmo malware compilado de novo)
- TLSH: mais robusto, usado pela indostria de TI
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Dict, Optional


def compute_hashes(file_path: str | Path, chunk_size: int = 65536) -> Dict[str, str]:
    """Calcula MD5, SHA1, SHA256, ssdeep e TLSH de um arquivo."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Acumula bytes pra fuzzy hashes (precisam do conteudo completo)
    all_bytes = bytearray()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            all_bytes.extend(chunk)

    raw = bytes(all_bytes)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "ssdeep": _compute_ssdeep(raw) or "",
        "tlsh": _compute_tlsh(raw) or "",
    }


def _compute_ssdeep(data: bytes) -> Optional[str]:
    """ssdeep (CTPH - Context Triggered Piecewise Hashing). Returna None em falha."""
    try:
        import ppdeep
        return ppdeep.hash(data)
    except Exception:
        return None


def _compute_tlsh(data: bytes) -> Optional[str]:
    """
    TLSH (Trend Micro Locality Sensitive Hash). Mais robusto que ssdeep.
    Retorna TNULL ou hash; minimo ~50 bytes com diversidade.
    """
    try:
        import tlsh
        h = tlsh.hash(data)
        # Quando tlsh nao consegue (entropia muito baixa), retorna "TNULL"
        return h if h and h != "TNULL" else None
    except Exception:
        return None


def file_size(file_path: str | Path) -> int:
    """Retorna tamanho do arquivo em bytes."""
    return Path(file_path).stat().st_size


# ---------------------------------------------------------------------------
# Comparacao de similaridade
# ---------------------------------------------------------------------------

def ssdeep_compare(hash_a: str, hash_b: str) -> int:
    """Compara dois ssdeeps. Retorna 0-100 (100 = identicos)."""
    if not hash_a or not hash_b:
        return 0
    try:
        import ppdeep
        return ppdeep.compare(hash_a, hash_b)
    except Exception:
        return 0


def tlsh_compare(hash_a: str, hash_b: str) -> int:
    """
    Compara dois TLSHs. Retorna distancia (0 = identicos, >100 = bem diferente).
    Convertido pra escala 0-100 onde 100 = identico.
    """
    if not hash_a or not hash_b:
        return 0
    try:
        import tlsh
        diff = tlsh.diff(hash_a, hash_b)
        # Heuristica de conversao: diff 0 = 100%, diff 100+ = 0%
        score = max(0, 100 - min(diff, 100))
        return int(score)
    except Exception:
        return 0
