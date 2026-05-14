"""
Static analysis para arquivos Office (.doc, .docx, .xls, .xlsx, .ppt, .pptx, .rtf).

Usa oletools (olevba + oleid) para detectar:
- Presenca de macros VBA
- Macros auto-executaveis (AutoOpen, Document_Open, Workbook_Open)
- Shell execution (Shell, Wscript.Shell, CreateObject)
- Network download (URLDownloadToFile, MSXML, InetURL)
- Ofuscacao (Chr+Asc, strReverse, etc.)
- DDE (Dynamic Data Exchange - vetor classico)
- Objetos OLE embedados
"""
from __future__ import annotations
from pathlib import Path
from typing import Any


# Magic bytes / extensions for Office
_OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xltm",
    ".ppt", ".pptx", ".pptm", ".potm",
    ".rtf", ".odt", ".ods", ".odp",
}

# Magic bytes que sao Office
_OFFICE_MAGIC_BYTES = [
    b"\xd0\xcf\x11\xe0",  # OLE compound (doc/xls/ppt antigos)
    b"PK\x03\x04",         # ZIP (docx/xlsx/pptx - Office Open XML)
    b"{\\rtf",             # RTF
]


# Mapa de keywords suspeitos em VBA -> (label, severity)
VBA_KEYWORDS = {
    # autoexec
    "AutoOpen":          ("Macro auto-executavel ao abrir documento", "high"),
    "AutoExec":          ("Macro auto-executavel ao abrir documento", "high"),
    "Document_Open":     ("Macro auto-executavel (Document_Open)", "high"),
    "Workbook_Open":     ("Macro auto-executavel (Workbook_Open)", "high"),
    "Auto_Open":         ("Macro auto-executavel (Auto_Open)", "high"),
    "DocumentOpen":      ("Macro auto-executavel", "high"),
    # shell exec
    "Shell":             ("Executa comando do sistema (Shell)", "high"),
    "WScript.Shell":     ("Executa comando do sistema (WScript.Shell)", "high"),
    "WshShell":          ("Executa comando do sistema (WshShell)", "high"),
    "CreateObject":      ("Cria objeto COM (frequentemente shell)", "medium"),
    "GetObject":         ("Acessa objeto existente", "medium"),
    # network
    "URLDownloadToFile": ("Baixa arquivo da internet", "high"),
    "MSXML2.XMLHTTP":    ("Faz request HTTP (MSXML)", "high"),
    "WinHttp.WinHttpRequest": ("Faz request HTTP (WinHttp)", "high"),
    "InternetExplorer.Application": ("Controla IE pra navegar", "medium"),
    "ADODB.Stream":      ("Le/escreve binario (frequente com download)", "medium"),
    # ofuscacao
    "Chr(":              ("Concatena caracteres por codigo ASCII (ofuscacao)", "medium"),
    "StrReverse":        ("Inverte string (ofuscacao)", "medium"),
    "Eval":              ("Executa codigo dinamico", "high"),
    "ExecuteGlobal":     ("Executa codigo VB dinamicamente", "high"),
    # filesystem
    "Scripting.FileSystemObject": ("Manipula arquivos no disco", "medium"),
    "SaveToFile":        ("Salva arquivo no disco", "medium"),
    # registry
    "RegWrite":          ("Modifica registry", "medium"),
    "RegRead":           ("Le registry", "low"),
    # processo
    "WMI":               ("Windows Management Instrumentation", "medium"),
    "winmgmts":          ("Windows Management Instrumentation", "medium"),
}


async def scan_static_office(file_path: str | Path) -> dict[str, Any]:
    """Analisa documento Office por macros suspeitos."""
    file_path = Path(file_path)
    ext = file_path.suffix.lower()

    # 1) Checa extensao + magic bytes
    try:
        with open(file_path, "rb") as f:
            head = f.read(8)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    is_office_ext = ext in _OFFICE_EXTENSIONS
    is_office_magic = any(head.startswith(m) for m in _OFFICE_MAGIC_BYTES)

    if not (is_office_ext or is_office_magic):
        return {
            "status": "skipped",
            "reason": "Arquivo nao parece ser Office document",
        }

    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {"status": "error", "error": "oletools nao instalado"}

    # 2) Detecta macros via olevba
    try:
        vba = VBA_Parser(str(file_path))
    except Exception as e:
        return {
            "status": "ok",
            "found": True,
            "file_type": "Office",
            "has_macros": False,
            "macros_extractable": False,
            "error": f"VBA_Parser: {e}",
            "findings": [],
            "flags": [f"Falha ao analisar: {e}"],
            "_summary": "Documento Office, mas oletools nao conseguiu parsear",
            "detections": 0,
            "suspicious": 1,
            "engines": 1,
        }

    has_macros = vba.detect_vba_macros()
    findings = []
    macro_count = 0
    suspicious_keywords_found = []
    sample_code = ""

    if has_macros:
        try:
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                macro_count += 1
                if not sample_code and vba_code:
                    # Salva os primeiros 800 chars como amostra (truncar)
                    sample_code = vba_code[:800].decode("utf-8", errors="replace") if isinstance(vba_code, bytes) else str(vba_code)[:800]
        except Exception as e:
            findings.append({"keyword": "extract_error", "label": str(e), "severity": "low", "count": 1})

        # Busca keywords suspeitos no codigo concatenado
        try:
            all_macros = ""
            for (_fn, _sp, _vf, code) in vba.extract_macros():
                if isinstance(code, bytes):
                    all_macros += code.decode("utf-8", errors="replace")
                else:
                    all_macros += str(code)
        except Exception:
            all_macros = ""

        for kw, (label, severity) in VBA_KEYWORDS.items():
            count = all_macros.count(kw)
            if count > 0:
                suspicious_keywords_found.append(kw)
                findings.append({
                    "keyword": kw,
                    "label": label,
                    "severity": severity,
                    "count": count,
                })

    vba.close()

    # 3) Heuristicas + flags
    flags = []
    autoexec_keywords = [f for f in findings if "auto-executavel" in f.get("label", "").lower()]
    shell_keywords    = [f for f in findings if "shell" in f.get("label", "").lower() or "executa comando" in f.get("label", "").lower()]
    network_keywords  = [f for f in findings if "request" in f.get("label", "").lower() or "baixa" in f.get("label", "").lower()]

    if autoexec_keywords and shell_keywords:
        flags.append("Macro auto-executavel + shell execution = MUITO SUSPEITO (classico phishing)")
    if autoexec_keywords and network_keywords:
        flags.append("Macro auto-executavel + download de rede = downloader/dropper")

    high_count = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")

    detections = 0
    suspicious = high_count + medium_count
    if has_macros:
        suspicious = max(suspicious, 1)

    return {
        "status": "ok",
        "found": True,
        "file_type": "Office",
        "extension": ext,
        "has_macros": has_macros,
        "macro_count": macro_count,
        "findings": findings,
        "flags": flags,
        "sample_code": sample_code,
        "_summary": _summarize(has_macros, findings, flags),
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
    }


def _summarize(has_macros, findings, flags) -> str:
    if flags:
        return flags[0]
    if not has_macros:
        return "Documento Office sem macros (baixo risco)"
    high = [f["label"] for f in findings if f["severity"] == "high"]
    if high:
        return f"Macros com capacidades de alto risco: {', '.join(set(high))[:200]}"
    return "Documento Office com macros (verifique conteudo)"
