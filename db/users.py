"""
db/users.py
User CRUD operations, block/unblock, GitHub token management,
and scan quota logic.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from db.database import get_db

logger = logging.getLogger(__name__)

FREE_SCAN_LIMIT = 3


# ── helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── upsert / fetch ────────────────────────────────────────────────────────────

async def upsert_user(
    telegram_id: int,
    username: Optional[str],
    first_name: Optional[str],
) -> None:
    """Insert a new user or update their username/name and last_seen timestamp."""
    async with get_db() as db:
        await db.execute(
            """
            INSERT INTO users (telegram_id, username, first_name, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username     = excluded.username,
                first_name   = excluded.first_name,
                last_seen_at = excluded.last_seen_at
            """,
            (telegram_id, username, first_name, _now()),
        )
        await db.commit()


async def get_user(telegram_id: int) -> Optional[aiosqlite.Row]:
    """Return the user row or None."""
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
        )
        return await cursor.fetchone()


async def get_all_users(include_blocked: bool = True) -> list[aiosqlite.Row]:
    """Return all users, optionally filtering out blocked ones."""
    async with get_db() as db:
        if include_blocked:
            cursor = await db.execute("SELECT * FROM users ORDER BY created_at DESC")
        else:
            cursor = await db.execute(
                "SELECT * FROM users WHERE is_blocked = 0 ORDER BY created_at DESC"
            )
        return await cursor.fetchall()


# ── block / unblock ───────────────────────────────────────────────────────────

async def block_user(telegram_id: int, reason: Optional[str] = None) -> None:
    async with get_db() as db:
        await db.execute(
            """
            UPDATE users
            SET is_blocked = 1, block_reason = ?, blocked_at = ?
            WHERE telegram_id = ?
            """,
            (reason, _now(), telegram_id),
        )
        await db.commit()
    logger.info("🚫 Blocked user %s — %s", telegram_id, reason)


async def unblock_user(telegram_id: int) -> None:
    async with get_db() as db:
        await db.execute(
            """
            UPDATE users
            SET is_blocked = 0, block_reason = NULL, blocked_at = NULL
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        )
        await db.commit()
    logger.info("✅ Unblocked user %s", telegram_id)


# ── scan quota ────────────────────────────────────────────────────────────────

async def can_scan(telegram_id: int) -> tuple[bool, str]:
    """
    Returns (allowed, reason).

    reason values:
        'free'          – using free quota
        'approved'      – using approved quota with valid token
        'blocked'       – user is blocked
        'needs_token'   – approved but no verified token yet
        'apply'         – free quota exhausted, must /apply
        'unknown'       – user not found (shouldn't happen)
    """
    user = await get_user(telegram_id)
    if user is None:
        return False, "unknown"

    if user["is_blocked"]:
        return False, "blocked"

    if user["free_scans_used"] < FREE_SCAN_LIMIT:
        return True, "free"

    if user["approved_scans_remaining"] > 0:
        if user["token_verified"]:
            return True, "approved"
        return False, "needs_token"

    return False, "apply"


async def consume_scan(telegram_id: int, scan_type: str) -> None:
    """Decrement the appropriate scan counter after a successful scan."""
    user = await get_user(telegram_id)
    if user is None:
        return

    async with get_db() as db:
        if user["free_scans_used"] < FREE_SCAN_LIMIT:
            await db.execute(
                """
                UPDATE users
                SET free_scans_used   = free_scans_used + 1,
                    total_scans_ever  = total_scans_ever + 1
                WHERE telegram_id = ?
                """,
                (telegram_id,),
            )
        else:
            await db.execute(
                """
                UPDATE users
                SET approved_scans_remaining = approved_scans_remaining - 1,
                    total_scans_ever         = total_scans_ever + 1
                WHERE telegram_id = ?
                """,
                (telegram_id,),
            )
        await db.commit()


async def get_scan_balance(telegram_id: int) -> dict:
    """Return a dict with scan balance info for display."""
    user = await get_user(telegram_id)
    if not user:
        return {}

    free_remaining = max(0, FREE_SCAN_LIMIT - user["free_scans_used"])
    return {
        "free_used":         user["free_scans_used"],
        "free_remaining":    free_remaining,
        "free_limit":        FREE_SCAN_LIMIT,
        "approved_remaining": user["approved_scans_remaining"],
        "token_verified":    bool(user["token_verified"]),
        "total_ever":        user["total_scans_ever"],
    }


# ── GitHub token ──────────────────────────────────────────────────────────────

async def save_github_token(telegram_id: int, encrypted_token: str) -> None:
    async with get_db() as db:
        await db.execute(
            """
            UPDATE users
            SET github_token = ?, token_verified = 1
            WHERE telegram_id = ?
            """,
            (encrypted_token, telegram_id),
        )
        await db.commit()


async def get_github_token(telegram_id: int) -> Optional[str]:
    """Return the raw encrypted token string, or None."""
    user = await get_user(telegram_id)
    if user and user["token_verified"]:
        return user["github_token"]
    return None


async def revoke_github_token(telegram_id: int) -> None:
    async with get_db() as db:
        await db.execute(
            """
            UPDATE users
            SET github_token = NULL, token_verified = 0
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        )
        await db.commit()
    logger.info("🔑 Revoked GitHub token for user %s", telegram_id)


# ── admin helpers ─────────────────────────────────────────────────────────────

async def set_approved_scans(telegram_id: int, count: int) -> None:
    """Directly set a user's approved scan count (admin use)."""
    async with get_db() as db:
        await db.execute(
            "UPDATE users SET approved_scans_remaining = ? WHERE telegram_id = ?",
            (count, telegram_id),
        )
        await db.commit()


async def add_approved_scans(telegram_id: int, count: int) -> None:
    """Add N scans on top of existing approved balance."""
    async with get_db() as db:
        await db.execute(
            """
            UPDATE users
            SET approved_scans_remaining = approved_scans_remaining + ?
            WHERE telegram_id = ?
            """,
            (count, telegram_id),
        )
        await db.commit()


async def get_global_stats() -> dict:
    """Return platform-wide stats for admin /globalstats."""
    async with get_db() as db:
        total_users   = (await (await db.execute("SELECT COUNT(*) FROM users")).fetchone())[0]
        blocked_users = (await (await db.execute("SELECT COUNT(*) FROM users WHERE is_blocked=1")).fetchone())[0]
        total_scans   = (await (await db.execute("SELECT COUNT(*) FROM scans")).fetchone())[0]
        total_leaks   = (await (await db.execute("SELECT COALESCE(SUM(total_leaks),0) FROM scans")).fetchone())[0]
        pending_apps  = (await (await db.execute("SELECT COUNT(*) FROM applications WHERE status='pending'")).fetchone())[0]
        token_users   = (await (await db.execute("SELECT COUNT(*) FROM users WHERE token_verified=1")).fetchone())[0]

    return {
        "total_users":   total_users,
        "blocked_users": blocked_users,
        "total_scans":   total_scans,
        "total_leaks":   total_leaks,
        "pending_apps":  pending_apps,
        "token_users":   token_users,
    }
