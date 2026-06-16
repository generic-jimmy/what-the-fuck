"""
bot/handlers/user_handlers.py
All user-facing command handlers:
    /start  /scan  /scanuser  /scanenv  /history  /mystats  /help  /revoketoken
"""

import io
import logging
import os

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from bot.handlers.middleware import (
    is_admin,
    require_not_blocked,
    require_registered,
    scan_guard,
)
from core.scanner import scan_repo, scan_user, ScanResult
from db.scans import (
    create_scan,
    get_user_history,
    get_user_scan_stats,
    save_findings,
    update_scan_results,
)
from db.users import (
    consume_scan,
    get_github_token,
    get_scan_balance,
    get_user,
    revoke_github_token,
)
from reports.pdf_report import generate_pdf
from reports.text_report import (
    format_findings_chunks,
    format_history_message,
    format_mystats_message,
    format_scan_summary,
)
from utils.crypto import decrypt_token

logger = logging.getLogger(__name__)

ADMIN_IDS: set[int] = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}


# ─────────────────────────────────────────────────────────────────────────────
# /start
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user    = update.effective_user
    balance = await get_scan_balance(user.id)
    admin   = is_admin(user.id)

    admin_note = "\n👑 <b>Admin mode — unlimited scans.</b>" if admin else ""

    await update.message.reply_text(
        f"🧬 <b>Welcome to LeakHunterBot{', Admin' if admin else ''}!</b>{admin_note}\n\n"
        "I scan GitHub repositories for accidentally exposed secrets:\n"
        "API keys, passwords, SSH keys, database URIs, tokens and more.\n\n"
        "<b>Your scan balance:</b>\n"
        f"  🎟️ Free scans remaining:    <b>{balance.get('free_remaining', 0)}</b>\n"
        f"  ✅ Approved scans remaining: <b>{balance.get('approved_remaining', 0)}</b>\n\n"
        "<b>Commands:</b>\n"
        "  /scan &lt;repo_url&gt;        — scan a single repo\n"
        "  /scanuser &lt;username&gt;   — scan all public repos\n"
        "  /scanenv &lt;repo_url&gt;    — scan .env files only\n"
        "  /history                   — your recent scans\n"
        "  /mystats                   — your stats & balance\n"
        "  /apply                     — request more scans\n"
        "  /addtoken                  — submit your GitHub PAT\n"
        "  /help                      — full command reference",
        parse_mode=ParseMode.HTML,
    )


# ─────────────────────────────────────────────────────────────────────────────
# /help
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    admin = is_admin(update.effective_user.id)
    text  = (
        "🧬 <b>LeakHunterBot — Command Reference</b>\n\n"
        "<b>Scanning</b>\n"
        "  /scan &lt;github_url or owner/repo&gt;\n"
        "        Scan a single repository for leaked secrets.\n\n"
        "  /scanuser &lt;github_username&gt;\n"
        "        Scan all public repos of a GitHub user (max 10).\n\n"
        "  /scanenv &lt;github_url or owner/repo&gt;\n"
        "        Only scan .env and sensitive config files.\n\n"
        "<b>Account</b>\n"
        "  /mystats      — scan balance, quota, all-time stats\n"
        "  /history      — your last 10 scans\n"
        "  /apply        — request more scans from admin\n"
        "  /addtoken     — submit your GitHub PAT (after approval)\n"
        "  /revoketoken  — remove your stored GitHub token\n\n"
        "<b>Tips</b>\n"
        "  • You get 3 free scans to start.\n"
        "  • After that, /apply and explain your use case.\n"
        "  • Approved users must provide a GitHub PAT.\n"
        "  • Reports are sent as text + downloadable PDF.\n"
    )

    if admin:
        text += (
            "\n<b>Admin Commands</b>\n"
            "  /approve &lt;user_id&gt; &lt;count&gt;  — approve + grant N scans\n"
            "  /deny &lt;user_id&gt; [reason]     — deny application\n"
            "  /block &lt;user_id&gt; [reason]     — block a user\n"
            "  /unblock &lt;user_id&gt;            — unblock a user\n"
            "  /listusers                       — all users\n"
            "  /listapps                        — pending applications\n"
            "  /userstats &lt;user_id&gt;          — user profile\n"
            "  /revoketoken &lt;user_id&gt;        — remove user token\n"
            "  /setscans &lt;user_id&gt; &lt;count&gt;  — set scan count\n"
            "  /broadcast &lt;message&gt;           — message all users\n"
            "  /globalstats                     — platform stats\n"
            "  /forcescan &lt;repo&gt;              — unlimited scan\n"
        )

    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# Shared scan runner
# ─────────────────────────────────────────────────────────────────────────────

async def _resolve_token(telegram_id: int) -> str | None:
    """Return decrypted GitHub token for user, or env fallback for admins."""
    if is_admin(telegram_id):
        return os.getenv("GITHUB_TOKEN")
    enc = await get_github_token(telegram_id)
    if enc:
        return decrypt_token(enc)
    return os.getenv("GITHUB_TOKEN")   # fallback to bot token for free scans


async def _run_and_report(
    update:    Update,
    ctx:       ContextTypes.DEFAULT_TYPE,
    result:    ScanResult,
    scan_id:   int,
    user_name: str,
) -> None:
    """Persist results, send text report, send PDF."""
    # Persist to DB
    await update_scan_results(
        scan_id,
        total_files=result.total_files,
        total_leaks=result.total_leaks,
        critical_count=result.critical_count,
        high_count=result.high_count,
        medium_count=result.medium_count,
        low_count=result.low_count,
        duration_seconds=result.duration,
    )
    if result.findings:
        await save_findings(
            scan_id,
            [
                {
                    "file_path":     f.file_path,
                    "line_number":   f.line_number,
                    "secret_type":   f.secret_type,
                    "severity":      f.severity,
                    "matched_value": f.matched_value,
                }
                for f in result.findings
            ],
        )

    # ── Text summary ──────────────────────────────────────────────────────────
    summary = format_scan_summary(result)
    await update.message.reply_text(summary, parse_mode=ParseMode.HTML)

    # ── Finding chunks ────────────────────────────────────────────────────────
    for chunk in format_findings_chunks(result):
        await update.message.reply_text(chunk, parse_mode=ParseMode.HTML)

    # ── PDF ───────────────────────────────────────────────────────────────────
    pdf_bytes = generate_pdf(result, requester_name=user_name)
    pdf_io    = io.BytesIO(pdf_bytes)
    safe_name = result.target.replace("/", "_").replace(".", "_")
    await update.message.reply_document(
        document=pdf_io,
        filename=f"leakhunter_{safe_name}.pdf",
        caption="📄 Full scan report",
    )


# ─────────────────────────────────────────────────────────────────────────────
# /scan
# ─────────────────────────────────────────────────────────────────────────────

@scan_guard
async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    args = ctx.args

    if not args:
        await update.message.reply_text(
            "Usage: /scan &lt;github_url or owner/repo&gt;\n\n"
            "Example: <code>/scan https://github.com/octocat/Hello-World</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    repo_url   = args[0].strip()
    token      = await _resolve_token(user.id)
    token_type = ctx.user_data.get("scan_token_type", "free")

    msg = await update.message.reply_text(
        f"🔍 Scanning <code>{repo_url}</code>…\nThis may take a moment.",
        parse_mode=ParseMode.HTML,
    )

    scan_id = await create_scan(user.id, repo_url, "repo", token_type)

    try:
        result = await scan_repo(repo_url, token=token, env_only=False)
    except Exception as e:
        logger.exception("Scan error for %s", repo_url)
        await msg.edit_text(f"❌ Scan failed: {e}")
        return

    await msg.delete()

    if not is_admin(user.id):
        await consume_scan(user.id, "repo")

    user_label = f"@{user.username}" if user.username else user.first_name or str(user.id)
    await _run_and_report(update, ctx, result, scan_id, user_label)


# ─────────────────────────────────────────────────────────────────────────────
# /scanuser
# ─────────────────────────────────────────────────────────────────────────────

@scan_guard
async def cmd_scanuser(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    args = ctx.args

    if not args:
        await update.message.reply_text(
            "Usage: /scanuser &lt;github_username&gt;\n\n"
            "Example: <code>/scanuser torvalds</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    username   = args[0].strip().lstrip("@")
    token      = await _resolve_token(user.id)
    token_type = ctx.user_data.get("scan_token_type", "free")

    msg = await update.message.reply_text(
        f"🔍 Scanning all public repos of <b>{username}</b>…\n"
        "This may take a while (up to 10 repos).",
        parse_mode=ParseMode.HTML,
    )

    scan_id = await create_scan(user.id, f"github.com/{username}", "user", token_type)

    try:
        result = await scan_user(username, token=token)
    except Exception as e:
        logger.exception("User scan error for %s", username)
        await msg.edit_text(f"❌ Scan failed: {e}")
        return

    await msg.delete()

    if not is_admin(user.id):
        await consume_scan(user.id, "user")

    user_label = f"@{user.username}" if user.username else user.first_name or str(user.id)
    await _run_and_report(update, ctx, result, scan_id, user_label)


# ─────────────────────────────────────────────────────────────────────────────
# /scanenv
# ─────────────────────────────────────────────────────────────────────────────

@scan_guard
async def cmd_scanenv(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    args = ctx.args

    if not args:
        await update.message.reply_text(
            "Usage: /scanenv &lt;github_url or owner/repo&gt;\n\n"
            "Example: <code>/scanenv https://github.com/octocat/Hello-World</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    repo_url   = args[0].strip()
    token      = await _resolve_token(user.id)
    token_type = ctx.user_data.get("scan_token_type", "free")

    msg = await update.message.reply_text(
        f"🔍 Scanning <code>{repo_url}</code> for .env and sensitive config files…",
        parse_mode=ParseMode.HTML,
    )

    scan_id = await create_scan(user.id, repo_url, "env", token_type)

    try:
        result = await scan_repo(repo_url, token=token, env_only=True)
    except Exception as e:
        logger.exception("Env scan error for %s", repo_url)
        await msg.edit_text(f"❌ Scan failed: {e}")
        return

    await msg.delete()

    if not is_admin(user.id):
        await consume_scan(user.id, "env")

    user_label = f"@{user.username}" if user.username else user.first_name or str(user.id)
    await _run_and_report(update, ctx, result, scan_id, user_label)


# ─────────────────────────────────────────────────────────────────────────────
# /history
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def cmd_history(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    scans = await get_user_history(update.effective_user.id, limit=10)
    await update.message.reply_text(
        format_history_message(scans), parse_mode=ParseMode.HTML
    )


# ─────────────────────────────────────────────────────────────────────────────
# /mystats
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def cmd_mystats(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user    = update.effective_user
    balance = await get_scan_balance(user.id)
    stats   = await get_user_scan_stats(user.id)
    text    = format_mystats_message(balance, stats, user.username or user.first_name)
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /revoketoken (user self-service)
# ─────────────────────────────────────────────────────────────────────────────

@require_registered
@require_not_blocked
async def cmd_revoketoken(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user    = update.effective_user
    db_user = await get_user(user.id)

    if not db_user or not db_user["token_verified"]:
        await update.message.reply_text("ℹ️ You don't have a stored GitHub token.")
        return

    await revoke_github_token(user.id)
    await update.message.reply_text(
        "🗑️ Your GitHub token has been removed.\n\n"
        "To add a new one, use /addtoken."
    )
