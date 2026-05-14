"""
Scanner de arquivos embedados (binwalk-style).

Procura por magic bytes em offsets NAO-zero do arquivo - quando ha um
arquivo de tipo X dentro de um arquivo de tipo Y. Casos classicos:

- PE escondido dentro de JPG (clipboard hijacker, malware delivery)
- ELF anexado depois de zip (self-extracting installer pirata)
- Payload em PDF (DOC ou EXE dentro)
- Firmware com varias particoes
- Polyglots em CTF

Nao usa lib externa - so regex sobre os bytes.
"""
from __future__ import annotations
import struct
from pathlib import Path
from typing import Any


# Magic bytes -> (label, file_type, severity_if_embedded)
MAGIC_SIGNATURES = [
    # (magic_bytes, min_offset_to_flag, label, type, severity_embedded)
    (b"MZ",                  2,  "Windows PE (.exe/.dll)",        "pe",     "high"),
    (b"\x7fELF",             4,  "Linux/BSD ELF binary",          "elf",    "high"),
    (b"\xCF\xFA\xED\xFE",    4,  "macOS Mach-O 64-bit (LE)",      "macho",  "high"),
    (b"\xCE\xFA\xED\xFE",    4,  "macOS Mach-O 32-bit (LE)",      "macho",  "high"),
    (b"\xCA\xFE\xBA\xBE",    4,  "Java class / fat Mach-O",       "java",   "medium"),
    (b"\xCA\xFE\xD0\x0D",    4,  "Java pack200",                  "java",   "medium"),
    (b"PK\x03\x04",          4,  "ZIP / JAR / docx / apk",        "zip",    "medium"),
    (b"%PDF",                4,  "PDF document",                  "pdf",    "medium"),
    (b"\xFF\xD8\xFF",        3,  "JPEG image",                    "jpeg",   "low"),
    (b"\x89PNG",             4,  "PNG image",                     "png",    "low"),
    (b"GIF87a",              6,  "GIF image (87a)",               "gif",    "low"),
    (b"GIF89a",              6,  "GIF image (89a)",               "gif",    "low"),
    (b"7z\xBC\xAF\x27\x1C",  6,  "7-Zip archive",                 "7z",     "medium"),
    (b"Rar!\x1a\x07\x00",    7,  "RAR archive v4",                "rar",    "medium"),
    (b"Rar!\x1a\x07\x01\x00",8,  "RAR archive v5",                "rar",    "medium"),
    (b"\x1F\x8B",            2,  "GZIP archive",                  "gzip",   "medium"),
    (b"BZh",                 3,  "BZIP2 archive",                 "bz2",    "medium"),
    (b"\xFD7zXZ\x00",        6,  "XZ archive",                    "xz",     "medium"),
    (b"\xD0\xCF\x11\xE0",    4,  "OLE Compound (doc/xls antigo)", "ole",    "medium"),
    (b"{\\rtf",              5,  "RTF document",                  "rtf",    "medium"),
    (b"SQLite format 3",     16, "SQLite database",               "sqlite", "medium"),
    (b"#!/bin/sh",           9,  "Shell script (sh)",             "script", "medium"),
    (b"#!/bin/bash",         11, "Shell script (bash)",           "script", "medium"),
    (b"#!/usr/bin/env",      14, "Script (env shebang)",          "script", "medium"),
    (b"<?php",               5,  "PHP source",                    "php",    "high"),
    (b"<%@",                 3,  "JSP/ASP page",                  "jsp",    "high"),
]


# Tamanho maximo de busca - evita varrer arquivos enormes
SEARCH_LIMIT = 16 * 1024 * 1024  # 16 MB


async def scan_static_embedded(file_path: str | Path) -> dict[str, Any]:
    """Procura magic bytes dentro do arquivo (binwalk-style)."""
    file_path = Path(file_path)

    try:
        size = file_path.stat().st_size
        with open(file_path, "rb") as f:
            data = f.read(min(size, SEARCH_LIMIT))
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    if len(data) < 8:
        return {"status": "skipped", "reason": "Arquivo muito pequeno"}

    # 1) Identifica o tipo do proprio arquivo (magic byte no offset 0)
    own_type = None
    own_magic_len = 0
    for magic, _, _, ftype, _ in MAGIC_SIGNATURES:
        if data.startswith(magic):
            own_type = ftype
            own_magic_len = len(magic)
            break

    # 2) Procura outros magic bytes no resto do arquivo
    findings = []
    for magic, _, label, ftype, severity in MAGIC_SIGNATURES:
        # Skip se for o tipo do proprio arquivo no offset 0 (mas pega ocorrencias em outros offsets)
        start_search = 1 if ftype == own_type else 0
        offset = start_search
        while True:
            idx = data.find(magic, offset)
            if idx < 0:
                break
            # Embedded so se NAO for o magic do offset 0 do proprio arquivo
            if idx == 0 and ftype == own_type:
                offset = idx + 1
                continue

            # Severity ajustada: se o arquivo eh inocente (JPG) mas tem PE dentro = HIGH+
            adjusted_sev = severity
            if own_type in ("jpeg", "png", "gif", "pdf") and ftype in ("pe", "elf", "macho"):
                adjusted_sev = "high"  # PE dentro de imagem/PDF = bandeira vermelha forte

            findings.append({
                "offset":   idx,
                "offset_hex": f"0x{idx:x}",
                "label":    label,
                "type":     ftype,
                "severity": adjusted_sev,
            })
            offset = idx + len(magic)
            if len(findings) >= 50:
                break

        if len(findings) >= 50:
            break

    # 3) Heuristicas
    flags = []
    pe_findings = [f for f in findings if f["type"] == "pe"]
    if own_type in ("jpeg", "png", "gif", "pdf") and pe_findings:
        flags.append(
            f"PE escondido dentro de {own_type.upper()} - tecnica classica de delivery"
        )
    if own_type == "zip" and len(findings) > 10:
        # Muitos arquivos zip eh normal (docx, jar)
        pass

    # 4) Classifica severidade overall
    high_count   = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")

    detections = 0
    suspicious = high_count + medium_count

    return {
        "status": "ok",
        "found": len(findings) > 0,
        "own_type":     own_type or "desconhecido",
        "total_size":   size,
        "scanned_size": len(data),
        "embedded_count": len(findings),
        "findings":     findings[:30],  # limita pra UI
        "flags":        flags,
        "_summary":     _summarize(own_type, findings, flags),
        "detections":   detections,
        "suspicious":   suspicious,
        "engines":      1,
    }


def _summarize(own_type, findings, flags) -> str:
    if flags:
        return flags[0]
    if not findings:
        return "Nenhum arquivo embedado detectado"
    high = [f for f in findings if f["severity"] == "high"]
    if high:
        labels = list({f["label"] for f in high})[:3]
        return f"Embedados de alto risco: {', '.join(labels)}"
    return f"{len(findings)} magic bytes embedados encontrados"
