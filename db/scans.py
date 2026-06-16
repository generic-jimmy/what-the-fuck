"""
db/scans.py
Scan history creation, findings storage, and history retrieval.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from db.database import get_db

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── scan lifecycle ────────────────────────────────────────────────────────────

async def create_scan(
    telegram_id: int,
    target: str,
    scan_type: str,
    used_token: str = "free",
) -> int:
    """Insert a scan record and return its ID."""
    async with get_db() as db:
        cursor = await db.execute(
            """
            INSERT INTO scans
                (telegram_id, target, scan_type, used_token, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (telegram_id, target, scan_type, used_token, _now()),
        )
        await db.commit()
        return cursor.lastrowid


async def update_scan_results(
    scan_id: int,
    total_files: int,
    total_leaks: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    duration_seconds: float,
) -> None:
    """Patch the scan row with final results after scanning completes."""
    async with get_db() as db:
        await db.execute(
            """
            UPDATE scans SET
                total_files      = ?,
                total_leaks      = ?,
                critical_count   = ?,
                high_count       = ?,
                medium_count     = ?,
                low_count        = ?,
                duration_seconds = ?
            WHERE id = ?
            """,
            (
                total_files,
                total_leaks,
                critical_count,
                high_count,
                medium_count,
                low_count,
                duration_seconds,
                scan_id,
            ),
        )
        await db.commit()


async def save_findings(scan_id: int, findings: list[dict]) -> None:
    """
    Bulk insert findings for a scan.

    Each finding dict should have:
        file_path, line_number, secret_type, severity, matched_value
    """
    if not findings:
        return

    async with get_db() as db:
        await db.executemany(
            """
            INSERT INTO findings
                (scan_id, file_path, line_number, secret_type, severity, matched_value, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    f["file_path"],
                    f.get("line_number"),
                    f["secret_type"],
                    f["severity"],
                    f["matched_value"],  # already masked by scanner
                    _now(),
                )
                for f in findings
            ],
        )
        await db.commit()


# ── retrieval ─────────────────────────────────────────────────────────────────

async def get_scan(scan_id: int) -> Optional[aiosqlite.Row]:
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return await cursor.fetchone()


async def get_scan_findings(scan_id: int) -> list[aiosqlite.Row]:
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, file_path",
            (scan_id,),
        )
        return await cursor.fetchall()


async def get_user_history(
    telegram_id: int,
    limit: int = 10,
) -> list[aiosqlite.Row]:
    """Return the N most recent scans for a user."""
    async with get_db() as db:
        cursor = await db.execute(
            """
            SELECT * FROM scans
            WHERE telegram_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (telegram_id, limit),
        )
        return await cursor.fetchall()


async def get_user_scan_stats(telegram_id: int) -> dict:
    """Aggregate scan stats for a user — used in /mystats and admin /userstats."""
    async with get_db() as db:
        cursor = await db.execute(
            """
            SELECT
                COUNT(*)                        AS total_scans,
                COALESCE(SUM(total_leaks), 0)   AS total_leaks,
                COALESCE(SUM(critical_count), 0) AS total_critical,
                COALESCE(SUM(high_count), 0)    AS total_high,
                COALESCE(SUM(medium_count), 0)  AS total_medium,
                COALESCE(SUM(low_count), 0)     AS total_low,
                COALESCE(AVG(duration_seconds), 0) AS avg_duration
            FROM scans
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        )
        row = await cursor.fetchone()

    if row is None:
        return {}

    return {
        "total_scans":    row["total_scans"],
        "total_leaks":    row["total_leaks"],
        "total_critical": row["total_critical"],
        "total_high":     row["total_high"],
        "total_medium":   row["total_medium"],
        "total_low":      row["total_low"],
        "avg_duration":   round(row["avg_duration"], 2),
    }
