"""
Static analysis para arquivos PDF.

Detecta sem executar:
- JavaScript embedado (/JS, /JavaScript)
- Auto-acao ao abrir (/OpenAction, /AA)
- Execucao de programa externo (/Launch)
- Arquivos anexados/embedados (/EmbeddedFile)
- Formularios (/AcroForm, /SubmitForm)
- Conteudo Flash/3D (/RichMedia, /3D)
- Encrypted

Nao usa lib externa - parsing por regex.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any


_PDF_MAGIC = b"%PDF"


# Keywords PDF -> (label, severity)
PDF_KEYWORDS = {
    "/JS":            ("JavaScript embedado", "high"),
    "/JavaScript":    ("JavaScript embedado", "high"),
    "/OpenAction":    ("Acao automatica ao abrir", "high"),
    "/AA":            ("Acoes adicionais (auto-trigger)", "medium"),
    "/Launch":        ("Executa programa externo", "high"),
    "/EmbeddedFile":  ("Arquivos anexados", "medium"),
    "/SubmitForm":    ("Envia dados de formulario (URL externa)", "medium"),
    "/AcroForm":      ("Formulario interativo", "low"),
    "/RichMedia":     ("Conteudo Flash/3D embedado", "high"),
    "/3D":            ("Conteudo 3D embedado", "medium"),
    "/URI":           ("Links externos", "low"),
    "/GoToR":         ("Referencia remota", "medium"),
    "/JBIG2Decode":   ("Codec JBIG2 (historico de CVEs)", "medium"),
    "/XFA":           ("Formulario XFA (Adobe)", "medium"),
}


async def scan_static_pdf(file_path: str | Path) -> dict[str, Any]:
    """Analisa PDF lendo o conteudo bruto e procurando keywords suspeitas."""
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(5)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    if not head.startswith(_PDF_MAGIC):
        return {
            "status": "skipped",
            "reason": "Arquivo nao e PDF",
        }

    try:
        raw = file_path.read_bytes()
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler bytes: {e}"}

    # Conta ocorrencias de cada keyword (case-insensitive sobre bytes)
    findings = []
    raw_lower_view = raw  # PDF keywords sao case-sensitive

    for kw, (label, severity) in PDF_KEYWORDS.items():
        # Procura o keyword precedido de "/" ou em obj definitions
        count = raw_lower_view.count(kw.encode())
        if count > 0:
            findings.append({
                "keyword": kw,
                "label": label,
                "severity": severity,
                "count": count,
            })

    # Encripted?
    is_encrypted = b"/Encrypt" in raw

    # Versao PDF
    version_match = re.search(rb"%PDF-(\d\.\d)", raw[:100])
    version = version_match.group(1).decode() if version_match else "?"

    # Estatisticas estruturais
    num_objects = len(re.findall(rb"\d+\s+\d+\s+obj", raw))
    num_streams = raw.count(b"stream\n") + raw.count(b"stream\r")

    # Capacidades (similares ao PE) - severity-driven
    high   = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low    = [f for f in findings if f["severity"] == "low"]

    detections = 0
    suspicious = len(high) + len(medium)

    # Flags
    flags = []
    if is_encrypted:
        flags.append("PDF encriptado (pode esconder conteudo)")
    if any(f["keyword"] in ("/JS", "/JavaScript") for f in findings):
        if any(f["keyword"] == "/OpenAction" for f in findings):
            flags.append("JavaScript + OpenAction = auto-execucao ao abrir (CLASSICO PHISHING)")
    if any(f["keyword"] == "/Launch" for f in findings):
        flags.append("Tenta executar programa externo (raro em PDFs legitimos)")

    summary = _summarize(findings, flags)

    return {
        "status": "ok",
        "found": True,
        "file_type": "PDF",
        "version": version,
        "is_encrypted": is_encrypted,
        "num_objects": num_objects,
        "num_streams": num_streams,
        "findings": findings,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "flags": flags,
        "_summary": summary,
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
    }


def _summarize(findings, flags) -> str:
    if flags:
        return flags[0]
    high = [f["label"] for f in findings if f["severity"] == "high"]
    if high:
        return f"Capacidades de alto risco no PDF: {', '.join(high[:3])}"
    medium = [f["label"] for f in findings if f["severity"] == "medium"]
    if medium:
        return f"Capacidades de medio risco: {', '.join(medium[:3])}"
    return "PDF sem capacidades suspeitas detectadas estaticamente"
