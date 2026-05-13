"""
Agregador de resultados.
Executa todos os scanners em paralelo e consolida o veredito final.
"""
import asyncio
from pathlib import Path
from typing import Dict, List, Any

from scanners.virustotal import scan_virustotal
from scanners.metadefender import scan_metadefender
from scanners.hybrid_analysis import scan_hybrid_analysis
from scanners.local_scanner import scan_local
from core.hasher import compute_hashes, file_size
import config


async def scan_file(file_path: str | Path, original_name: str) -> Dict[str, Any]:
    """
    Executa todos os scanners disponíveis sobre o arquivo e devolve um relatório
    consolidado contendo metadados, resultados individuais e veredito final.
    """
    file_path = Path(file_path)
    hashes = compute_hashes(file_path)
    size = file_size(file_path)

    # Dispara scanners habilitados em paralelo
    tasks = []
    labels = []

    # Local sempre roda
    tasks.append(scan_local(file_path, hashes))
    labels.append("local")

    if config.VIRUSTOTAL_API_KEY:
        tasks.append(scan_virustotal(hashes["sha256"]))
        labels.append("virustotal")

    if config.METADEFENDER_API_KEY:
        tasks.append(scan_metadefender(hashes["sha256"]))
        labels.append("metadefender")

    if config.HYBRID_ANALYSIS_API_KEY:
        tasks.append(scan_hybrid_analysis(hashes["sha256"]))
        labels.append("hybrid_analysis")

    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    results: Dict[str, Any] = {}
    for label, res in zip(labels, results_list):
        if isinstance(res, Exception):
            results[label] = {"status": "error", "error": str(res)}
        else:
            results[label] = res

    verdict = compute_verdict(results)

    return {
        "file": {
            "name": original_name,
            "size_bytes": size,
            "size_human": _human_size(size),
            **hashes,
        },
        "results": results,
        "verdict": verdict,
    }


def compute_verdict(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Consolida um veredito final a partir dos resultados de cada scanner.
    Regras simples: se qualquer scanner reportou >=1 detecção -> 'malicious';
    se houve apenas suspeito -> 'suspicious'; senão 'clean'.
    """
    total_detections = 0
    total_engines = 0
    flagged_by: List[str] = []
    suspicious_by: List[str] = []

    for name, data in results.items():
        if not isinstance(data, dict) or data.get("status") != "ok":
            continue

        detections = int(data.get("detections", 0) or 0)
        engines = int(data.get("engines", 0) or 0)
        suspicious = int(data.get("suspicious", 0) or 0)

        total_detections += detections
        total_engines += engines

        if detections > 0:
            flagged_by.append(name)
        elif suspicious > 0:
            suspicious_by.append(name)

    if total_detections > 0:
        level = "malicious"
    elif suspicious_by:
        level = "suspicious"
    else:
        level = "clean"

    return {
        "level": level,
        "total_detections": total_detections,
        "total_engines": total_engines,
        "flagged_by": flagged_by,
        "suspicious_by": suspicious_by,
    }


def _human_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"
