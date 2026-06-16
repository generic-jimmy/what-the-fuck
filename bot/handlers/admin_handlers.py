"""
bot/handlers/admin_handlers.py
All admin-only command handlers.
"""

import io
import logging
import os

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from bot.handlers.middleware import require_admin
from core.scanner import scan_repo, scan_user
from db.applications import (
    approve_application,
    deny_application,
    get_all_applications,
    get_pending_applications,
)
from db.scans import create_scan, save_findings, update_scan_results, get_user_scan_stats
from db.users import (
    add_approved_scans,
    block_user,
    get_all_users,
    get_global_stats,
    get_scan_balance,
    get_user,
    revoke_github_token,
    set_approved_scans,
    unblock_user,
)
from reports.pdf_report import generate_pdf
from reports.text_report import format_findings_chunks, format_scan_summary

logger = logging.getLogger(__name__)

ADMIN_IDS: set[int] = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}


def _parse_args(ctx) -> list[str]:
    return ctx.args or []


# ─────────────────────────────────────────────────────────────────────────────
# /approve <user_id> <count>
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_approve(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if len(args) < 2 or not args[0].isdigit() or not args[1].isdigit():
        await update.message.reply_text("Usage: /approve &lt;user_id&gt; &lt;count&gt;", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    count     = int(args[1])
    admin_id  = update.effective_user.id

    db_user = await get_user(target_id)
    if not db_user:
        await update.message.reply_text("❌ User not found.")
        return

    approved = await approve_application(target_id, count, reviewed_by=admin_id)
    if not approved:
        await update.message.reply_text("⚠️ No pending application found for that user.")
        return

    uname = f"@{db_user['username']}" if db_user["username"] else f"#{target_id}"

    # Notify the user
    needs_token = not db_user["token_verified"]
    user_msg = (
        f"🎉 <b>Your application was approved!</b>\n\n"
        f"You've been granted <b>{count}</b> additional scan(s).\n\n"
    )
    if needs_token:
        user_msg += (
            "⚠️ To use them, you must provide your GitHub Personal Access Token.\n\n"
            "Generate one at: github.com/settings/tokens\n"
            "Required scope: <code>public_repo</code> (read-only)\n\n"
            "Then use /addtoken to submit it."
        )
    else:
        user_msg += "You can now use /scan, /scanuser, or /scanenv to start scanning!"

    try:
        await ctx.bot.send_message(target_id, user_msg, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.warning("Could not notify user %s: %s", target_id, e)

    await update.message.reply_text(
        f"✅ Approved. {uname} granted <b>{count}</b> scan(s).\n"
        f"{'Token not yet set — user prompted.' if needs_token else 'Token already on file.'}",
        parse_mode=ParseMode.HTML,
    )


# ─────────────────────────────────────────────────────────────────────────────
# /deny <user_id> [reason]
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_deny(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args or not args[0].isdigit():
        await update.message.reply_text("Usage: /deny &lt;user_id&gt; [reason]", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    reason    = " ".join(args[1:]) if len(args) > 1 else None
    admin_id  = update.effective_user.id

    db_user = await get_user(target_id)
    if not db_user:
        await update.message.reply_text("❌ User not found.")
        return

    denied = await deny_application(target_id, reviewed_by=admin_id, admin_note=reason)
    if not denied:
        await update.message.reply_text("⚠️ No pending application found for that user.")
        return

    user_msg = "❌ <b>Your scan application was not approved.</b>"
    if reason:
        user_msg += f"\n\n<i>Reason: {reason}</i>"
    user_msg += "\n\nYou can apply again with /apply if your situation changes."

    try:
        await ctx.bot.send_message(target_id, user_msg, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.warning("Could not notify user %s: %s", target_id, e)

    uname = f"@{db_user['username']}" if db_user["username"] else f"#{target_id}"
    await update.message.reply_text(f"❌ Application denied for {uname}.")


# ─────────────────────────────────────────────────────────────────────────────
# /block <user_id> [reason]
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_block(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args or not args[0].isdigit():
        await update.message.reply_text("Usage: /block &lt;user_id&gt; [reason]", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    reason    = " ".join(args[1:]) if len(args) > 1 else None

    if target_id in ADMIN_IDS:
        await update.message.reply_text("⛔ Cannot block an admin.")
        return

    await block_user(target_id, reason)
    await update.message.reply_text(f"🚫 User <code>{target_id}</code> blocked.", parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /unblock <user_id>
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_unblock(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args or not args[0].isdigit():
        await update.message.reply_text("Usage: /unblock &lt;user_id&gt;", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    await unblock_user(target_id)
    await update.message.reply_text(f"✅ User <code>{target_id}</code> unblocked.", parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /listusers
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_listusers(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    users = await get_all_users(include_blocked=True)
    if not users:
        await update.message.reply_text("No users yet.")
        return

    lines = [f"<b>👥 All Users ({len(users)})</b>\n"]
    for u in users[:50]:  # Cap at 50 to avoid message length issues
        status = "🚫" if u["is_blocked"] else "✅"
        uname  = f"@{u['username']}" if u["username"] else u["first_name"] or "—"
        lines.append(
            f"{status} <code>{u['telegram_id']}</code> {uname}\n"
            f"   Free: {u['free_scans_used']}/3  |  Approved: {u['approved_scans_remaining']}  |  "
            f"Token: {'✅' if u['token_verified'] else '❌'}\n"
        )

    if len(users) > 50:
        lines.append(f"\n<i>...and {len(users) - 50} more.</i>")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /listapps
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_listapps(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    apps = await get_pending_applications()
    if not apps:
        await update.message.reply_text("✅ No pending applications.")
        return

    lines = [f"<b>📋 Pending Applications ({len(apps)})</b>\n"]
    for app in apps:
        uname = f"@{app['username']}" if app["username"] else app["first_name"] or "—"
        lines.append(
            f"📌 <b>App #{app['id']}</b> — {uname} (<code>{app['telegram_id']}</code>)\n"
            f"   <i>{app['reason'][:100]}</i>\n"
            f"   <code>/approve {app['telegram_id']} &lt;n&gt;</code>  |  "
            f"<code>/deny {app['telegram_id']}</code>\n"
        )

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /userstats <user_id>
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_userstats(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args or not args[0].isdigit():
        await update.message.reply_text("Usage: /userstats &lt;user_id&gt;", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    db_user   = await get_user(target_id)
    if not db_user:
        await update.message.reply_text("❌ User not found.")
        return

    balance = await get_scan_balance(target_id)
    stats   = await get_user_scan_stats(target_id)
    uname   = f"@{db_user['username']}" if db_user["username"] else db_user["first_name"] or "—"

    text = (
        f"<b>👤 User Profile — {uname}</b>\n\n"
        f"<b>Telegram ID:</b>    <code>{target_id}</code>\n"
        f"<b>Status:</b>         {'🚫 Blocked' if db_user['is_blocked'] else '✅ Active'}\n"
        f"<b>Block reason:</b>   {db_user['block_reason'] or '—'}\n"
        f"<b>Joined:</b>         {str(db_user['created_at'])[:16]}\n"
        f"<b>Last seen:</b>      {str(db_user['last_seen_at'])[:16]}\n\n"
        f"<b>🎟️ Quota</b>\n"
        f"  Free used:          {balance.get('free_used', 0)}/3\n"
        f"  Approved remaining: {balance.get('approved_remaining', 0)}\n"
        f"  GitHub token:       {'✅ Verified' if balance.get('token_verified') else '❌ None'}\n\n"
        f"<b>📊 Scan Stats</b>\n"
        f"  Total scans:   {stats.get('total_scans', 0)}\n"
        f"  Total leaks:   {stats.get('total_leaks', 0)}\n"
        f"  🔴 Critical:   {stats.get('total_critical', 0)}\n"
        f"  🟠 High:       {stats.get('total_high', 0)}\n"
        f"  🟡 Medium:     {stats.get('total_medium', 0)}\n"
        f"  🔵 Low:        {stats.get('total_low', 0)}\n"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /revoketoken <user_id>  (admin revokes another user's token)
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_admin_revoketoken(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args or not args[0].isdigit():
        await update.message.reply_text("Usage: /revoketoken &lt;user_id&gt;", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    await revoke_github_token(target_id)
    await update.message.reply_text(
        f"🗑️ GitHub token revoked for user <code>{target_id}</code>.",
        parse_mode=ParseMode.HTML,
    )

    try:
        await ctx.bot.send_message(
            target_id,
            "⚠️ Your GitHub token has been removed by an admin.\nUse /addtoken to submit a new one.",
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# /setscans <user_id> <count>
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_setscans(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if len(args) < 2 or not args[0].isdigit() or not args[1].isdigit():
        await update.message.reply_text("Usage: /setscans &lt;user_id&gt; &lt;count&gt;", parse_mode=ParseMode.HTML)
        return

    target_id = int(args[0])
    count     = int(args[1])
    await set_approved_scans(target_id, count)
    await update.message.reply_text(
        f"✅ User <code>{target_id}</code> scan count set to <b>{count}</b>.",
        parse_mode=ParseMode.HTML,
    )


# ─────────────────────────────────────────────────────────────────────────────
# /globalstats
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_globalstats(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    s = await get_global_stats()
    text = (
        "<b>📊 Platform Stats</b>\n\n"
        f"<b>Users</b>\n"
        f"  Total:           {s['total_users']}\n"
        f"  Blocked:         {s['blocked_users']}\n"
        f"  With token:      {s['token_users']}\n\n"
        f"<b>Scans</b>\n"
        f"  Total scans:     {s['total_scans']}\n"
        f"  Total leaks:     {s['total_leaks']}\n\n"
        f"<b>Applications</b>\n"
        f"  Pending:         {s['pending_apps']}\n"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────────────────────────────────────────
# /broadcast <message>
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args:
        await update.message.reply_text("Usage: /broadcast &lt;message&gt;", parse_mode=ParseMode.HTML)
        return

    message = " ".join(args)
    users   = await get_all_users(include_blocked=False)

    sent = failed = 0
    for u in users:
        try:
            await ctx.bot.send_message(u["telegram_id"], f"📢 {message}")
            sent += 1
        except Exception:
            failed += 1

    await update.message.reply_text(
        f"📢 Broadcast complete.\n✅ Sent: {sent}  |  ❌ Failed: {failed}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# /forcescan <repo>  — admin unlimited scan
# ─────────────────────────────────────────────────────────────────────────────

@require_admin
async def cmd_forcescan(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    args = _parse_args(ctx)
    if not args:
        await update.message.reply_text("Usage: /forcescan &lt;repo_url or owner/repo&gt;", parse_mode=ParseMode.HTML)
        return

    repo_url = args[0].strip()
    token    = os.getenv("GITHUB_TOKEN")
    user     = update.effective_user

    msg = await update.message.reply_text(
        f"⚡ Force scanning <code>{repo_url}</code>…", parse_mode=ParseMode.HTML
    )

    scan_id = await create_scan(user.id, repo_url, "repo", "admin")

    try:
        result = await scan_repo(repo_url, token=token)
    except Exception as e:
        await msg.edit_text(f"❌ Scan failed: {e}")
        return

    await msg.delete()

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
        await save_findings(scan_id, [
            {
                "file_path":     f.file_path,
                "line_number":   f.line_number,
                "secret_type":   f.secret_type,
                "severity":      f.severity,
                "matched_value": f.matched_value,
            }
            for f in result.findings
        ])

    summary = format_scan_summary(result)
    await update.message.reply_text(summary, parse_mode=ParseMode.HTML)

    for chunk in format_findings_chunks(result):
        await update.message.reply_text(chunk, parse_mode=ParseMode.HTML)

    pdf_bytes = generate_pdf(result, requester_name=f"Admin @{user.username or user.id}")
    pdf_io    = io.BytesIO(pdf_bytes)
    safe_name = result.target.replace("/", "_").replace(".", "_")
    await update.message.reply_document(
        document=pdf_io,
        filename=f"leakhunter_{safe_name}.pdf",
        caption="📄 Force scan report",
    )
