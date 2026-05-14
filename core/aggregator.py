"""
Agregador de resultados.
Executa todos os scanners em paralelo, com camada de cache no banco.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from scanners.virustotal import scan_virustotal
from scanners.metadefender import scan_metadefender
from scanners.local_scanner import scan_local
from scanners.static_pe import scan_static_pe
from scanners.static_pdf import scan_static_pdf
from scanners.static_office import scan_static_office
from scanners.static_elf import scan_static_elf
from scanners.static_yara import scan_static_yara
from core.hasher import compute_hashes, file_size
from core import database
from core import llm_analyst
import config


async def scan_file(
    file_path: str | Path,
    original_name: str,
    scanned_by: Optional[str] = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """
    Pipeline completo:
      1. calcula hash
      2. tenta retornar resultado do cache (se valido e nao for force_refresh)
      3. roda scanners em paralelo (incluindo static PE)
      4. calcula veredito consolidado
      5. salva no banco
    """
    file_path = Path(file_path)
    hashes = compute_hashes(file_path)
    size = file_size(file_path)

    if not force_refresh:
        cached = await database.get_cached(hashes["sha256"])
        if cached is not None:
            return cached

    tasks = []
    labels = []

    tasks.append(scan_local(file_path, hashes))
    labels.append("local")

    # Static analyses sempre rodam (sem API key necessaria)
    tasks.append(scan_static_pe(file_path))
    labels.append("static_pe")
    tasks.append(scan_static_pdf(file_path))
    labels.append("static_pdf")
    tasks.append(scan_static_office(file_path))
    labels.append("static_office")
    tasks.append(scan_static_elf(file_path))
    labels.append("static_elf")
    tasks.append(scan_static_yara(file_path))
    labels.append("static_yara")

    if config.VIRUSTOTAL_API_KEY:
        tasks.append(scan_virustotal(hashes["sha256"]))
        labels.append("virustotal")

    if config.METADEFENDER_API_KEY:
        tasks.append(scan_metadefender(hashes["sha256"]))
        labels.append("metadefender")


    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, Any] = {}
    for label, res in zip(labels, results_list):
        if isinstance(res, Exception):
            results[label] = {"status": "error", "error": str(res)}
        else:
            results[label] = res

    verdict = compute_verdict(results)

    report = {
        "file": {
            "name": original_name,
            "size_bytes": size,
            "size_human": _human_size(size),
            **hashes,
        },
        "results": results,
        "verdict": verdict,
        "_cached": False,
    }

    # LLM analyst - le o report completo e escreve uma analise em prosa
    try:
        llm_result = await llm_analyst.analyze_report(report)
        if llm_result is not None:
            report["llm_analysis"] = llm_result
    except Exception as e:
        report["llm_analysis"] = {"status": "error", "error": str(e)}

    try:
        await database.save_scan(report, scanned_by=scanned_by)
    except Exception as e:
        report["_db_error"] = str(e)

    return report


def compute_verdict(results: dict[str, Any]) -> dict[str, Any]:
    """
    Consolida veredito final.
    Regras: 1+ deteccoes -> malicious; so suspeitos -> suspicious; nada -> clean.
    """
    total_detections = 0
    total_engines = 0
    flagged_by: list[str] = []
    suspicious_by: list[str] = []

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
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
