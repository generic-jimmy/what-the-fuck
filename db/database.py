"""
db/database.py
Database initialization, schema creation, and migration logic.
Uses aiosqlite for async SQLite access.
"""

import aiosqlite
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "data/leakhunter.db")


async def get_db() -> aiosqlite.Connection:
    """Return an open database connection with row_factory set."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    return conn


async def init_db() -> None:
    """Create all tables if they don't exist and run any pending migrations."""
    async with await get_db() as db:
        await _create_tables(db)
        await _run_migrations(db)
        await db.commit()
    logger.info("✅ Database initialised at %s", DB_PATH)


async def _create_tables(db: aiosqlite.Connection) -> None:
    """Create all tables."""

    # ── users ────────────────────────────────────────────────────────────────
    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id                 INTEGER UNIQUE NOT NULL,
            username                    TEXT,
            first_name                  TEXT,
            is_blocked                  INTEGER DEFAULT 0,
            block_reason                TEXT,
            blocked_at                  TIMESTAMP,
            free_scans_used             INTEGER DEFAULT 0,
            approved_scans_remaining    INTEGER DEFAULT 0,
            github_token                TEXT,
            token_verified              INTEGER DEFAULT 0,
            total_scans_ever            INTEGER DEFAULT 0,
            created_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── applications ─────────────────────────────────────────────────────────
    await db.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id     INTEGER NOT NULL,
            reason          TEXT NOT NULL,
            status          TEXT DEFAULT 'pending',
            scans_granted   INTEGER DEFAULT 0,
            admin_note      TEXT,
            reviewed_by     INTEGER,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at     TIMESTAMP,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    """)

    # ── scans ─────────────────────────────────────────────────────────────────
    await db.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id         INTEGER NOT NULL,
            target              TEXT NOT NULL,
            scan_type           TEXT NOT NULL,
            used_token          TEXT DEFAULT 'free',
            total_files         INTEGER DEFAULT 0,
            total_leaks         INTEGER DEFAULT 0,
            critical_count      INTEGER DEFAULT 0,
            high_count          INTEGER DEFAULT 0,
            medium_count        INTEGER DEFAULT 0,
            low_count           INTEGER DEFAULT 0,
            duration_seconds    REAL,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    """)

    # ── findings ──────────────────────────────────────────────────────────────
    await db.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL,
            file_path       TEXT,
            line_number     INTEGER,
            secret_type     TEXT,
            severity        TEXT,
            matched_value   TEXT,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # ── migrations tracker ────────────────────────────────────────────────────
    await db.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER PRIMARY KEY,
            applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── indexes ───────────────────────────────────────────────────────────────
    await db.execute("CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_telegram_id ON scans(telegram_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_apps_telegram_id  ON applications(telegram_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_apps_status       ON applications(status)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id)")


async def _run_migrations(db: aiosqlite.Connection) -> None:
    """
    Apply numbered migrations in order.
    Add new migrations as (version, sql) tuples below.
    """
    migrations: list[tuple[int, str]] = [
        # (1, "ALTER TABLE users ADD COLUMN new_col TEXT"),
        # future migrations go here
    ]

    cursor = await db.execute("SELECT version FROM schema_migrations")
    applied = {row[0] for row in await cursor.fetchall()}

    for version, sql in migrations:
        if version not in applied:
            await db.execute(sql)
            await db.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)", (version,)
            )
            logger.info("✅ Applied migration v%s", version)
