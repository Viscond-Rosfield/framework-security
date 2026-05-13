"""
Scanner Hybrid Analysis (Falcon Sandbox) - busca por hash SHA256.
Docs: https://www.hybrid-analysis.com/docs/api/v2
"""
import httpx
import config

HA_API_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"


async def scan_hybrid_analysis(sha256: str) -> dict:
    """Consulta o Hybrid Analysis por amostras já analisadas com este hash."""
    if not config.HYBRID_ANALYSIS_API_KEY:
        return {"status": "skipped", "reason": "API key not configured"}

    headers = {
        "api-key": config.HYBRID_ANALYSIS_API_KEY,
        "user-agent": "Falcon Sandbox",
        "accept": "application/json",
    }
    data = {"hash": sha256}

    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            resp = await client.post(HA_API_URL, headers=headers, data=data)
    except httpx.RequestError as e:
        return {"status": "error", "error": f"Request failed: {e}"}

    if resp.status_code == 401 or resp.status_code == 403:
        return {"status": "error", "error": "API key inválida ou sem permissão"}

    if resp.status_code == 429:
        return {"status": "error", "error": "Rate limit excedido"}

    if resp.status_code != 200:
        return {"status": "error", "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    samples = resp.json()
    if not samples:
        return {
            "status": "ok",
            "found": False,
            "detections": 0,
            "engines": 0,
            "suspicious": 0,
            "permalink": f"https://www.hybrid-analysis.com/search?query=hash:{sha256}",
            "message": "Nenhuma amostra analisada com este hash.",
        }

    # Pega a amostra mais recente / com maior threat score
    sample = max(samples, key=lambda s: s.get("threat_score") or 0)
    threat_score = sample.get("threat_score") or 0
    verdict = (sample.get("verdict") or "unknown").lower()

    detections = 1 if verdict == "malicious" else 0
    suspicious = 1 if verdict == "suspicious" else 0

    av_detect = sample.get("av_detect")
    av_total = sample.get("total_signatures")

    return {
        "status": "ok",
        "found": True,
        "detections": detections,
        "suspicious": suspicious,
        "engines": 1,
        "verdict": verdict,
        "threat_score": threat_score,
        "threat_level": sample.get("threat_level"),
        "av_detect_percent": av_detect,
        "av_total_signatures": av_total,
        "environment": sample.get("environment_description"),
        "permalink": f"https://www.hybrid-analysis.com/sample/{sha256}",
    }
