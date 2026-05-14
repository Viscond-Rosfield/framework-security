"""
Scanner YARA - aplica regras (.yar/.yara) ao conteudo do arquivo.

Funciona pra qualquer tipo de arquivo. Regras moram em:
- rules/builtin/  (vem com o projeto, gestionadas por nos)
- rules/community/ (regras adicionais que voce adiciona)

As regras sao compiladas no startup (uma vez) e reusadas em memoria.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Optional


RULES_BASE_DIR = Path(__file__).resolve().parent.parent / "rules"

# Cache do compiler (compila uma vez, usa muitas)
_compiled_rules = None
_compile_error: Optional[str] = None


def _load_rules():
    """Compila todos os .yar/.yara dos diretorios builtin/ e community/."""
    global _compiled_rules, _compile_error

    if _compiled_rules is not None or _compile_error is not None:
        return

    try:
        import yara
    except ImportError as e:
        _compile_error = f"yara-python nao instalado: {e}"
        return

    filepaths = {}
    for sub in ("builtin", "community"):
        d = RULES_BASE_DIR / sub
        if not d.exists():
            continue
        for f in sorted(d.iterdir()):
            if f.suffix.lower() in (".yar", ".yara"):
                filepaths[f"{sub}/{f.name}"] = str(f)

    if not filepaths:
        _compile_error = "Nenhuma regra YARA encontrada"
        return

    try:
        _compiled_rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        _compile_error = f"Falha compilando YARA: {e}"


async def scan_static_yara(file_path: str | Path) -> dict[str, Any]:
    """Roda as regras YARA contra o arquivo."""
    _load_rules()

    if _compile_error:
        return {"status": "error", "error": _compile_error}
    if _compiled_rules is None:
        return {"status": "error", "error": "Rules nao carregadas"}

    file_path = Path(file_path)
    try:
        # match_callback nao precisa - matches retornam objetos diretamente
        matches = _compiled_rules.match(str(file_path), timeout=30)
    except Exception as e:
        return {"status": "error", "error": f"YARA match falhou: {e}"}

    detected = []
    for m in matches:
        meta = m.meta or {}
        detected.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags or []),
            "meta": {
                "description": meta.get("description", ""),
                "severity": meta.get("severity", "medium"),
                "category": meta.get("category", ""),
                "author": meta.get("author", ""),
                "reference": meta.get("reference", ""),
            },
            "strings_count": len(m.strings or []),
        })

    severities = [d["meta"]["severity"] for d in detected]
    high   = severities.count("high")
    medium = severities.count("medium")

    # YARA match = forte indicio. High severity vira detection real.
    detections = high
    suspicious = medium + sum(1 for s in severities if s not in ("high", "medium"))

    return {
        "status": "ok",
        "found": bool(detected),
        "matches": detected,
        "total_matches": len(detected),
        "by_severity": {"high": high, "medium": medium, "other": suspicious - medium if suspicious > medium else 0},
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
        "_summary": _summarize(detected),
    }


def _summarize(matches: list) -> str:
    if not matches:
        return "Nenhuma regra YARA matched"
    high = [m for m in matches if m["meta"]["severity"] == "high"]
    if high:
        names = [m["rule"] for m in high[:3]]
        return f"YARA HIGH: {', '.join(names)}"
    return f"{len(matches)} regra(s) YARA matched"


def reload_rules() -> dict:
    """Forca recompilacao das regras (util pra testar nova regra sem reiniciar)."""
    global _compiled_rules, _compile_error
    _compiled_rules = None
    _compile_error = None
    _load_rules()
    if _compile_error:
        return {"status": "error", "error": _compile_error}
    return {"status": "ok", "message": "Regras recompiladas"}
