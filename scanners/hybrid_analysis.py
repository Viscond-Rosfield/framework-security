"""
DEPRECATED: Hybrid Analysis scanner foi removido (exige vetting manual).

Este arquivo existe apenas pra evitar quebrar imports antigos.
"""
async def scan_hybrid_analysis(sha256: str) -> dict:
    return {"status": "skipped", "reason": "Hybrid Analysis removido do framework"}
