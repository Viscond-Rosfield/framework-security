"""
Scanner VirusTotal - consulta por hash SHA256.
Docs: https://docs.virustotal.com/reference/file-info
"""
import httpx
import config

VT_API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


async def scan_virustotal(sha256: str) -> dict:
    """Consulta o VirusTotal pelo hash SHA256 do arquivo."""
    if not config.VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "API key not configured"}

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    url = VT_API_URL.format(sha256=sha256)

    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        return {"status": "error", "error": f"Request failed: {e}"}

    if resp.status_code == 404:
        return {
            "status": "ok",
            "found": False,
            "detections": 0,
            "engines": 0,
            "suspicious": 0,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            "message": "Arquivo não encontrado na base. Considere fazer upload no portal.",
        }

    if resp.status_code == 401:
        return {"status": "error", "error": "API key inválida"}

    if resp.status_code == 429:
        return {"status": "error", "error": "Rate limit excedido (4 req/min no plano free)"}

    if resp.status_code != 200:
        return {"status": "error", "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {}) or {}

    detections = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    engines = sum(stats.values()) if stats else 0

    return {
        "status": "ok",
        "found": True,
        "detections": detections,
        "suspicious": suspicious,
        "engines": engines,
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": data.get("reputation", 0),
        "type_description": data.get("type_description"),
        "meaningful_name": data.get("meaningful_name"),
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }
