"""
bot/handlers/apply_handlers.py
Handles the /apply conversation flow and GitHub token submission.

States:
    APPLY_REASON   – waiting for user to type their reason
    AWAIT_TOKEN    – waiting for user to paste their GitHub PAT
"""

import logging
import os

from telegram import Update
from telegram.ext import (
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
from telegram.constants import ParseMode

from bot.handlers.middleware import require_not_blocked, require_registered
from core.scanner import verify_github_token
from db.applications import (
    create_application,
    has_pending_application,
    get_application_count,
)
from db.users import (
    get_user,
    get_scan_balance,
    save_github_token,
)
from utils.crypto import encrypt_token

logger = logging.getLogger(__name__)

ADMIN_IDS: set[int] = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}

# ConversationHandler states
APPLY_REASON = 1
AWAIT_TOKEN  = 2


# ─────────────────────────────────────────────────────────────────────────────
# /apply — start
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def apply_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    user    = update.effective_user
    balance = await get_scan_balance(user.id)

    # Still has free scans
    if balance.get("free_remaining", 0) > 0:
        await update.message.reply_text(
            f"ℹ️ You still have <b>{balance['free_remaining']}</b> free scan(s) remaining.\n\n"
            "Use /scan, /scanuser, or /scanenv — no application needed yet.",
            parse_mode=ParseMode.HTML,
        )
        return ConversationHandler.END

    # Still has approved scans
    if balance.get("approved_remaining", 0) > 0:
        await update.message.reply_text(
            f"ℹ️ You have <b>{balance['approved_remaining']}</b> approved scan(s) remaining.\n\n"
            "You don't need to apply yet.",
            parse_mode=ParseMode.HTML,
        )
        return ConversationHandler.END

    # Already has a pending application
    if await has_pending_application(user.id):
        await update.message.reply_text(
            "⏳ You already have a pending application.\n"
            "Please wait for the admin to review it."
        )
        return ConversationHandler.END

    prev_apps = await get_application_count(user.id)
    history_note = (
        f"\n\n📋 <i>This is your application #{prev_apps + 1}.</i>"
        if prev_apps > 0 else ""
    )

    await update.message.reply_text(
        "📋 <b>Scan Application</b>\n\n"
        "You've used all your available scans. To request more, "
        "briefly explain your use case below.\n\n"
        "What will you be scanning and why?"
        f"{history_note}",
        parse_mode=ParseMode.HTML,
    )
    return APPLY_REASON


async def apply_receive_reason(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    """Receive the user's reason and forward to admin(s)."""
    user   = update.effective_user
    reason = update.message.text.strip()

    if len(reason) < 10:
        await update.message.reply_text(
            "Please provide a bit more detail (at least 10 characters)."
        )
        return APPLY_REASON

    if len(reason) > 500:
        await update.message.reply_text(
            "Please keep it under 500 characters. Try again."
        )
        return APPLY_REASON

    app_id    = await create_application(user.id, reason)
    db_user   = await get_user(user.id)
    prev_apps = await get_application_count(user.id) - 1  # excluding current

    uname  = f"@{user.username}" if user.username else f"#{user.id}"
    fname  = user.first_name or "Unknown"

    admin_msg = (
        f"📋 <b>New Scan Application #{app_id}</b>\n\n"
        f"<b>User:</b>         {uname} (<code>{user.id}</code>)\n"
        f"<b>Name:</b>         {fname}\n"
        f"<b>Free scans:</b>   {db_user['free_scans_used']}/3 used\n"
        f"<b>Total scans:</b>  {db_user['total_scans_ever']} ever\n"
        f"<b>Past apps:</b>    {prev_apps}\n\n"
        f"<b>Reason:</b>\n<i>{reason}</i>\n\n"
        f"<code>/approve {user.id} &lt;count&gt;</code>\n"
        f"<code>/deny {user.id} [reason]</code>"
    )

    notified = 0
    for admin_id in ADMIN_IDS:
        try:
            await ctx.bot.send_message(admin_id, admin_msg, parse_mode=ParseMode.HTML)
            notified += 1
        except Exception as e:
            logger.warning("Could not notify admin %s: %s", admin_id, e)

    await update.message.reply_text(
        "✅ <b>Application submitted!</b>\n\n"
        "The admin has been notified and will review your request.\n"
        "You'll receive a message here once a decision is made.",
        parse_mode=ParseMode.HTML,
    )
    return ConversationHandler.END


async def apply_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Application cancelled.")
    return ConversationHandler.END


# ─────────────────────────────────────────────────────────────────────────────
# /addtoken — GitHub PAT submission
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def addtoken_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    user    = update.effective_user
    balance = await get_scan_balance(user.id)

    if balance.get("approved_remaining", 0) == 0:
        await update.message.reply_text(
            "ℹ️ You don't have any approved scans pending a token.\n"
            "Use /apply to request more scans first."
        )
        return ConversationHandler.END

    db_user = await get_user(user.id)
    if db_user and db_user["token_verified"]:
        await update.message.reply_text(
            "✅ You already have a verified GitHub token.\n"
            "To replace it, use /revoketoken first, then /addtoken."
        )
        return ConversationHandler.END

    await update.message.reply_text(
        "🔑 <b>GitHub Personal Access Token</b>\n\n"
        "Please send your GitHub PAT now.\n\n"
        "Generate one at: github.com/settings/tokens\n"
        "Required scopes: <code>public_repo</code> (read-only is fine)\n\n"
        "⚠️ Send it as a plain message — it will be deleted immediately after verification.\n\n"
        "Type /cancel to abort.",
        parse_mode=ParseMode.HTML,
    )
    return AWAIT_TOKEN


async def addtoken_receive(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    """Validate the submitted token, encrypt it, store it."""
    user  = update.effective_user
    token = update.message.text.strip()

    # Delete the user's message so the token isn't sitting in chat
    try:
        await update.message.delete()
    except Exception:
        pass  # No delete permission — best effort

    # Show "verifying" status
    status_msg = await ctx.bot.send_message(
        user.id, "🔄 Verifying token with GitHub…"
    )

    valid = await verify_github_token(token)

    if not valid:
        await status_msg.edit_text(
            "❌ <b>Invalid token.</b>\n\n"
            "The token couldn't be verified with GitHub.\n"
            "Make sure it has <code>public_repo</code> scope and hasn't expired.\n\n"
            "Try again with /addtoken.",
            parse_mode=ParseMode.HTML,
        )
        return ConversationHandler.END

    encrypted = encrypt_token(token)
    await save_github_token(user.id, encrypted)

    balance = await get_scan_balance(user.id)
    await status_msg.edit_text(
        "✅ <b>Token verified and stored securely.</b>\n\n"
        f"You now have <b>{balance.get('approved_remaining', 0)}</b> scan(s) available.\n\n"
        "Use /scan, /scanuser, or /scanenv to start scanning!",
        parse_mode=ParseMode.HTML,
    )
    return ConversationHandler.END


async def addtoken_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Token submission cancelled.")
    return ConversationHandler.END


# ─────────────────────────────────────────────────────────────────────────────
# ConversationHandlers (imported by main.py)
# ─────────────────────────────────────────────────────────────────────────────

apply_conversation = ConversationHandler(
    entry_points=[CommandHandler("apply", apply_start)],
    states={
        APPLY_REASON: [
            MessageHandler(filters.TEXT & ~filters.COMMAND, apply_receive_reason),
        ],
    },
    fallbacks=[CommandHandler("cancel", apply_cancel)],
    per_user=True,
    per_chat=True,
)

addtoken_conversation = ConversationHandler(
    entry_points=[CommandHandler("addtoken", addtoken_start)],
    states={
        AWAIT_TOKEN: [
            MessageHandler(filters.TEXT & ~filters.COMMAND, addtoken_receive),
        ],
    },
    fallbacks=[CommandHandler("cancel", addtoken_cancel)],
    per_user=True,
    per_chat=True,
)
