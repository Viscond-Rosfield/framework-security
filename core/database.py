"""
Camada SQLite assincrona para cache e historico de scans.

Schema:
  - scans: armazena cada relatorio completo (1 linha = 1 analise)
  - indexes em sha256 e created_at para buscas rapidas
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiosqlite

import config


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL,
    md5             TEXT,
    sha1            TEXT,
    original_name   TEXT    NOT NULL,
    size_bytes      INTEGER NOT NULL,
    verdict_level   TEXT    NOT NULL,
    total_detections INTEGER NOT NULL DEFAULT 0,
    total_engines   INTEGER NOT NULL DEFAULT 0,
    report_json     TEXT    NOT NULL,
    scanned_by      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_sha256     ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict    ON scans(verdict_level);
"""


async def init_db() -> None:
    """Cria a estrutura do banco se nao existir. Chamar no startup do app."""
    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def get_cached(sha256: str) -> Optional[dict[str, Any]]:
    """
    Retorna o ultimo relatorio salvo para esse hash, se ainda estiver dentro do TTL.
    Retorna None se nao houver cache valido.
    """
    if config.CACHE_TTL_HOURS <= 0:
        return None

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=config.CACHE_TTL_HOURS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT report_json, created_at
            FROM scans
            WHERE sha256 = ? AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (sha256, cutoff),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        report = json.loads(row["report_json"])
        report["_cached"] = True
        report["_cached_at"] = row["created_at"]
        return report


async def save_scan(report: dict[str, Any], scanned_by: Optional[str] = None) -> int:
    """Persiste o relatorio. Retorna o id da linha criada."""
    file_meta = report.get("file", {})
    verdict = report.get("verdict", {})

    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO scans (
                sha256, md5, sha1, original_name, size_bytes,
                verdict_level, total_detections, total_engines,
                report_json, scanned_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_meta.get("sha256", ""),
                file_meta.get("md5"),
                file_meta.get("sha1"),
                file_meta.get("name", "unknown"),
                int(file_meta.get("size_bytes", 0)),
                verdict.get("level", "unknown"),
                int(verdict.get("total_detections", 0)),
                int(verdict.get("total_engines", 0)),
                json.dumps(report, ensure_ascii=False),
                scanned_by,
            ),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def list_recent(limit: int = 50, search: Optional[str] = None) -> list[dict[str, Any]]:
    """
    Lista os scans mais recentes. Se 'search' for fornecido, filtra por nome ou hash.
    """
    query = """
        SELECT id, sha256, original_name, size_bytes, verdict_level,
               total_detections, total_engines, scanned_by, created_at
        FROM scans
    """
    params: tuple = ()
    if search:
        query += " WHERE original_name LIKE ? OR sha256 LIKE ? OR md5 LIKE ? "
        like = f"%{search}%"
        params = (like, like, like)
    query += " ORDER BY created_at DESC LIMIT ?"
    params = params + (limit,)

    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_by_id(scan_id: int) -> Optional[dict[str, Any]]:
    """Retorna o relatorio completo de um scan pelo id."""
    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT report_json, created_at, scanned_by FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        report = json.loads(row["report_json"])
        report["_scan_id"] = scan_id
        report["_persisted_at"] = row["created_at"]
        report["_scanned_by"] = row["scanned_by"]
        return report


async def stats() -> dict[str, int]:
    """Retorna contadores gerais para o dashboard."""
    async with aiosqlite.connect(config.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT
                COUNT(*)                                                AS total,
                SUM(CASE WHEN verdict_level='malicious'  THEN 1 ELSE 0 END) AS malicious,
                SUM(CASE WHEN verdict_level='suspicious' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN verdict_level='clean'      THEN 1 ELSE 0 END) AS clean,
                COUNT(DISTINCT sha256)                                  AS unique_files
            FROM scans
            """
        )
        row = await cursor.fetchone()
        return {k: int(v or 0) for k, v in dict(row).items()}
