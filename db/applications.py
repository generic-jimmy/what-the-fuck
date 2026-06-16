"""
db/applications.py
/apply system — create, approve, deny, and list applications.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from db.database import get_db

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── create ────────────────────────────────────────────────────────────────────

async def create_application(telegram_id: int, reason: str) -> int:
    """
    Insert a new pending application.
    Returns the new application ID.
    """
    async with await get_db() as db:
        cursor = await db.execute(
            """
            INSERT INTO applications (telegram_id, reason, status, created_at)
            VALUES (?, ?, 'pending', ?)
            """,
            (telegram_id, reason, _now()),
        )
        await db.commit()
        return cursor.lastrowid


async def has_pending_application(telegram_id: int) -> bool:
    """Return True if the user already has an unreviewed application."""
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT id FROM applications WHERE telegram_id = ? AND status = 'pending'",
            (telegram_id,),
        )
        return await cursor.fetchone() is not None


async def get_application_count(telegram_id: int) -> int:
    """Return total number of applications ever made by this user."""
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM applications WHERE telegram_id = ?",
            (telegram_id,),
        )
        row = await cursor.fetchone()
        return row[0] if row else 0


# ── fetch ─────────────────────────────────────────────────────────────────────

async def get_application(app_id: int) -> Optional[aiosqlite.Row]:
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT * FROM applications WHERE id = ?", (app_id,)
        )
        return await cursor.fetchone()


async def get_latest_application(telegram_id: int) -> Optional[aiosqlite.Row]:
    """Return the most recent application for a user regardless of status."""
    async with await get_db() as db:
        cursor = await db.execute(
            """
            SELECT * FROM applications
            WHERE telegram_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (telegram_id,),
        )
        return await cursor.fetchone()


async def get_pending_applications() -> list[aiosqlite.Row]:
    """All applications with status='pending', oldest first."""
    async with await get_db() as db:
        cursor = await db.execute(
            """
            SELECT a.*, u.username, u.first_name, u.free_scans_used,
                   u.total_scans_ever,
                   (SELECT COUNT(*) FROM applications
                    WHERE telegram_id = a.telegram_id) AS total_apps
            FROM applications a
            JOIN users u ON u.telegram_id = a.telegram_id
            WHERE a.status = 'pending'
            ORDER BY a.created_at ASC
            """
        )
        return await cursor.fetchall()


async def get_all_applications(limit: int = 50) -> list[aiosqlite.Row]:
    """All applications (any status), most recent first."""
    async with await get_db() as db:
        cursor = await db.execute(
            """
            SELECT a.*, u.username, u.first_name
            FROM applications a
            JOIN users u ON u.telegram_id = a.telegram_id
            ORDER BY a.created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return await cursor.fetchall()


# ── approve / deny ────────────────────────────────────────────────────────────

async def approve_application(
    telegram_id: int,
    scans_granted: int,
    reviewed_by: int,
) -> bool:
    """
    Mark the pending application as approved and credit scans.
    Returns True if a pending application was found and updated.
    """
    async with await get_db() as db:
        cursor = await db.execute(
            """
            UPDATE applications
            SET status        = 'approved',
                scans_granted = ?,
                reviewed_by   = ?,
                reviewed_at   = ?
            WHERE telegram_id = ? AND status = 'pending'
            """,
            (scans_granted, reviewed_by, _now(), telegram_id),
        )
        await db.commit()

        if cursor.rowcount == 0:
            return False

        # Credit scans to the user
        await db.execute(
            """
            UPDATE users
            SET approved_scans_remaining = approved_scans_remaining + ?
            WHERE telegram_id = ?
            """,
            (scans_granted, telegram_id),
        )
        await db.commit()

    logger.info(
        "✅ Application approved — user %s granted %s scans by admin %s",
        telegram_id,
        scans_granted,
        reviewed_by,
    )
    return True


async def deny_application(
    telegram_id: int,
    reviewed_by: int,
    admin_note: Optional[str] = None,
) -> bool:
    """
    Mark the pending application as denied.
    Returns True if a pending application was found.
    """
    async with await get_db() as db:
        cursor = await db.execute(
            """
            UPDATE applications
            SET status      = 'denied',
                admin_note  = ?,
                reviewed_by = ?,
                reviewed_at = ?
            WHERE telegram_id = ? AND status = 'pending'
            """,
            (admin_note, reviewed_by, _now(), telegram_id),
        )
        await db.commit()

    if cursor.rowcount == 0:
        return False

    logger.info(
        "❌ Application denied — user %s by admin %s: %s",
        telegram_id,
        reviewed_by,
        admin_note,
    )
    return True
