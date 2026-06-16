"""
bot/main.py
LeakHunterBot — entry point.
Initialises the database, registers all handlers, and starts long-polling.
"""

import asyncio
import logging
import os

from dotenv import load_dotenv
from telegram import BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
)

load_dotenv()

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Quiet noisy libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("aiosqlite").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def post_init(application: Application) -> None:
    """Run once after the bot connects — set bot commands menu."""
    user_commands = [
        BotCommand("start",       "Welcome & scan balance"),
        BotCommand("scan",        "Scan a single repo"),
        BotCommand("scanuser",    "Scan all repos of a GitHub user"),
        BotCommand("scanenv",     "Scan .env files only"),
        BotCommand("history",     "Your last 10 scans"),
        BotCommand("mystats",     "Your stats & quota"),
        BotCommand("apply",       "Request more scans"),
        BotCommand("addtoken",    "Submit your GitHub PAT"),
        BotCommand("revoketoken", "Remove your GitHub token"),
        BotCommand("help",        "Command reference"),
    ]
    await application.bot.set_my_commands(user_commands)
    logger.info("✅ Bot commands menu set.")


def build_application() -> Application:
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN environment variable is not set.")

    app = (
        Application.builder()
        .token(token)
        .post_init(post_init)
        .build()
    )

    # ── import handlers ───────────────────────────────────────────────────────
    from bot.handlers.user_handlers import (
        cmd_start,
        cmd_help,
        cmd_scan,
        cmd_scanuser,
        cmd_scanenv,
        cmd_history,
        cmd_mystats,
        cmd_revoketoken,
    )
    from bot.handlers.admin_handlers import (
        cmd_approve,
        cmd_deny,
        cmd_block,
        cmd_unblock,
        cmd_listusers,
        cmd_listapps,
        cmd_userstats,
        cmd_admin_revoketoken,
        cmd_setscans,
        cmd_broadcast,
        cmd_globalstats,
        cmd_forcescan,
    )
    from bot.handlers.apply_handlers import (
        apply_conversation,
        addtoken_conversation,
    )

    # ── user commands ─────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("start",       cmd_start))
    app.add_handler(CommandHandler("help",        cmd_help))
    app.add_handler(CommandHandler("scan",        cmd_scan))
    app.add_handler(CommandHandler("scanuser",    cmd_scanuser))
    app.add_handler(CommandHandler("scanenv",     cmd_scanenv))
    app.add_handler(CommandHandler("history",     cmd_history))
    app.add_handler(CommandHandler("mystats",     cmd_mystats))
    app.add_handler(CommandHandler("revoketoken", cmd_revoketoken))

    # ── conversation flows ────────────────────────────────────────────────────
    app.add_handler(apply_conversation)
    app.add_handler(addtoken_conversation)

    # ── admin commands ────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("approve",     cmd_approve))
    app.add_handler(CommandHandler("deny",        cmd_deny))
    app.add_handler(CommandHandler("block",       cmd_block))
    app.add_handler(CommandHandler("unblock",     cmd_unblock))
    app.add_handler(CommandHandler("listusers",   cmd_listusers))
    app.add_handler(CommandHandler("listapps",    cmd_listapps))
    app.add_handler(CommandHandler("userstats",   cmd_userstats))
    app.add_handler(CommandHandler("setscans",    cmd_setscans))
    app.add_handler(CommandHandler("broadcast",   cmd_broadcast))
    app.add_handler(CommandHandler("globalstats", cmd_globalstats))
    app.add_handler(CommandHandler("forcescan",   cmd_forcescan))

    # /revoketoken — admin variant (with user_id arg) vs user self-service
    # The admin version is registered separately to avoid conflict
    app.add_handler(CommandHandler("adminrevoketoken", cmd_admin_revoketoken))

    return app


async def main() -> None:
    # Initialise database
    from db.database import init_db
    await init_db()

    app = build_application()

    logger.info("🧬 LeakHunterBot starting (long-polling)…")
    async with app:
        await app.start()
        await app.updater.start_polling(
            allowed_updates=["message", "callback_query"],
            drop_pending_updates=True,
        )
        logger.info("✅ Bot is running. Press Ctrl+C to stop.")
        # Keep running until interrupted
        await asyncio.Event().wait()

    logger.info("👋 Bot stopped.")


if __name__ == "__main__":
    asyncio.run(main())
