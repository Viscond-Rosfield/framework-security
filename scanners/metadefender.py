"""
Scanner MetaDefender (OPSWAT) - consulta por hash SHA256.
Docs: https://docs.opswat.com/mdcloud/reference/get-a-hash-report
"""
import httpx
import config

MD_API_URL = "https://api.metadefender.com/v4/hash/{sha256}"


async def scan_metadefender(sha256: str) -> dict:
    """Consulta o MetaDefender Cloud pelo hash SHA256 do arquivo."""
    if not config.METADEFENDER_API_KEY:
        return {"status": "skipped", "reason": "API key not configured"}

    headers = {"apikey": config.METADEFENDER_API_KEY}
    url = MD_API_URL.format(sha256=sha256)

    try:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        return {"status": "error", "error": f"Request failed: {e}"}

    # MetaDefender retorna 404 ou um objeto com error.code=404003 quando hash desconhecido
    if resp.status_code == 404:
        return {
            "status": "ok",
            "found": False,
            "detections": 0,
            "engines": 0,
            "suspicious": 0,
            "permalink": f"https://metadefender.opswat.com/results/file/{sha256}/hash/overview",
            "message": "Hash não encontrado no MetaDefender.",
        }

    if resp.status_code == 401:
        return {"status": "error", "error": "API key inválida"}

    if resp.status_code == 429:
        return {"status": "error", "error": "Rate limit excedido"}

    if resp.status_code != 200:
        return {"status": "error", "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()

    # Quando hash desconhecido, a API às vezes retorna 200 com error
    if "error" in data:
        return {
            "status": "ok",
            "found": False,
            "detections": 0,
            "engines": 0,
            "suspicious": 0,
            "message": data["error"].get("messages", ["Não encontrado"])[0],
            "permalink": f"https://metadefender.opswat.com/results/file/{sha256}/hash/overview",
        }

    scan_results = data.get("scan_results", {}) or {}
    total_avs = int(scan_results.get("total_avs", 0))
    detections = int(scan_results.get("total_detected_avs", 0))
    scan_all_result = scan_results.get("scan_all_result_a", "Unknown")

    return {
        "status": "ok",
        "found": True,
        "detections": detections,
        "engines": total_avs,
        "suspicious": 0,
        "verdict": scan_all_result,
        "file_type": (data.get("file_info") or {}).get("display_name"),
        "permalink": f"https://metadefender.opswat.com/results/file/{sha256}/hash/overview",
    }
