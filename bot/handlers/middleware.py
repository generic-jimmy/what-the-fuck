"""
bot/handlers/middleware.py
Pre-handler checks: block detection, rate limiting, quota enforcement.
All checks are async and return (allowed: bool, reason: str).
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Callable

from telegram import Update
from telegram.ext import ContextTypes

from db.users import can_scan, upsert_user, get_user

logger = logging.getLogger(__name__)

ADMIN_IDS: set[int] = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}

# Rate limit window (non-admin users)
RATE_WINDOW_MINUTES = 60
RATE_LIMIT_COUNT    = 3       # max scans per window


def is_admin(telegram_id: int) -> bool:
    return telegram_id in ADMIN_IDS


# ── decorators ────────────────────────────────────────────────────────────────

def require_registered(func: Callable):
    """Ensure the user exists in the DB before handling any command."""
    @wraps(func)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user:
            return
        await upsert_user(user.id, user.username, user.first_name)
        return await func(update, ctx, *args, **kwargs)
    return wrapper


def require_not_blocked(func: Callable):
    """Silently drop commands from blocked users."""
    @wraps(func)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user:
            return
        db_user = await get_user(user.id)
        if db_user and db_user["is_blocked"]:
            await update.message.reply_text("❌ You are not authorized to use this bot.")
            logger.info("Blocked user %s attempted command", user.id)
            return
        return await func(update, ctx, *args, **kwargs)
    return wrapper


def require_admin(func: Callable):
    """Only allow admins to run this handler."""
    @wraps(func)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user or not is_admin(user.id):
            await update.message.reply_text("⛔ Admin only command.")
            return
        return await func(update, ctx, *args, **kwargs)
    return wrapper


def scan_guard(func: Callable):
    """
    Full pre-scan gate:
      1. Register user
      2. Reject blocked users
      3. Check scan quota
      4. Enforce rate limit (non-admin)
    Injects 'scan_token_type' into ctx.user_data.
    """
    @wraps(func)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user:
            return

        await upsert_user(user.id, user.username, user.first_name)

        # Admins bypass everything
        if is_admin(user.id):
            ctx.user_data["scan_token_type"] = "admin"
            return await func(update, ctx, *args, **kwargs)

        # Block check
        db_user = await get_user(user.id)
        if db_user and db_user["is_blocked"]:
            await update.message.reply_text("❌ You are not authorized to use this bot.")
            return

        # Quota check
        allowed, reason = await can_scan(user.id)

        if not allowed:
            if reason == "blocked":
                await update.message.reply_text("❌ You are not authorized to use this bot.")
            elif reason == "needs_token":
                from reports.text_report import format_needs_token
                await update.message.reply_text(
                    format_needs_token(), parse_mode="HTML"
                )
            elif reason in ("apply", "unknown"):
                from reports.text_report import format_no_scans_left
                from db.users import get_scan_balance
                balance = await get_scan_balance(user.id)
                await update.message.reply_text(
                    format_no_scans_left(balance), parse_mode="HTML"
                )
            return

        ctx.user_data["scan_token_type"] = reason  # "free" or "approved"
        return await func(update, ctx, *args, **kwargs)
    return wrapper
