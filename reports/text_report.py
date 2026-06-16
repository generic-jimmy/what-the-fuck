"""
reports/text_report.py
Format scan results as Telegram-friendly messages (HTML parse mode).
Telegram message limit is 4096 chars — long reports are chunked.
"""

from core.scanner import ScanResult, Finding

MAX_MSG_LEN  = 4000   # leave headroom for Telegram's 4096 limit
MAX_FINDINGS = 30     # max findings shown inline before "see PDF"

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

SCAN_TYPE_LABEL = {
    "repo": "Single Repository",
    "user": "GitHub User (all repos)",
    "env":  "Environment Files",
}


def _severity_bar(result: ScanResult) -> str:
    parts = []
    if result.critical_count: parts.append(f"🔴 {result.critical_count} Critical")
    if result.high_count:     parts.append(f"🟠 {result.high_count} High")
    if result.medium_count:   parts.append(f"🟡 {result.medium_count} Medium")
    if result.low_count:      parts.append(f"🔵 {result.low_count} Low")
    return "  |  ".join(parts) if parts else "✅ None"


def format_scan_summary(result: ScanResult) -> str:
    """
    Return the top-level summary message (always short enough for one message).
    """
    scan_label = SCAN_TYPE_LABEL.get(result.scan_type, result.scan_type)
    status     = "🚨 LEAKS FOUND" if result.total_leaks else "✅ CLEAN"

    lines = [
        f"<b>🧬 Scan Complete — {status}</b>",
        "",
        f"<b>Target:</b>    <code>{result.target}</code>",
        f"<b>Scan type:</b> {scan_label}",
        f"<b>Files:</b>     {result.total_files}",
        f"<b>Duration:</b>  {result.duration}s",
        "",
    ]

    if result.total_leaks:
        lines += [
            f"<b>Total leaks:</b>  <b>{result.total_leaks}</b>",
            f"<b>Severity:</b>    {_severity_bar(result)}",
        ]
    else:
        lines.append("No secrets detected in scanned files.")

    if result.errors:
        lines.append("")
        lines.append("⚠️ <b>Warnings:</b>")
        for err in result.errors[:3]:
            lines.append(f"  • {err}")

    return "\n".join(lines)


def format_findings_chunks(result: ScanResult) -> list[str]:
    """
    Return a list of Telegram message strings, each under MAX_MSG_LEN.
    Each chunk covers a group of findings sorted by severity.
    """
    if not result.findings:
        return []

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number or 0),
    )

    # Cap displayed findings
    displayed    = sorted_findings[:MAX_FINDINGS]
    truncated    = len(sorted_findings) - MAX_FINDINGS
    chunks:      list[str] = []
    current      = []
    current_len  = 0

    for idx, finding in enumerate(displayed, 1):
        block = _format_finding_block(idx, finding)
        if current_len + len(block) > MAX_MSG_LEN and current:
            chunks.append("\n".join(current))
            current     = []
            current_len = 0
        current.append(block)
        current_len += len(block)

    if current:
        chunks.append("\n".join(current))

    if truncated > 0:
        note = f"\n⚠️ <i>+{truncated} more findings — see the PDF report for full details.</i>"
        chunks[-1] += note

    return chunks


def _format_finding_block(idx: int, finding: Finding) -> str:
    emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
    lines = [
        f"{emoji} <b>#{idx} — {finding.secret_type}</b>",
        f"  📄 <code>{finding.file_path}</code>",
    ]
    if finding.line_number:
        lines.append(f"  📍 Line {finding.line_number}")
    lines.append(f"  🔑 <code>{finding.matched_value}</code>")
    lines.append("")
    return "\n".join(lines)


def format_history_message(scans: list) -> str:
    """Format /history output."""
    if not scans:
        return "📭 No scan history yet. Use /scan to get started."

    lines = ["<b>📋 Your Recent Scans</b>", ""]
    for s in scans:
        leaks = s["total_leaks"]
        emoji = "🚨" if leaks else "✅"
        lines.append(
            f"{emoji} <code>{s['target'][:40]}</code>\n"
            f"   Leaks: {leaks}  |  Files: {s['total_files']}  |  "
            f"{_format_dt(s['created_at'])}\n"
        )
    return "\n".join(lines)


def format_mystats_message(balance: dict, stats: dict, username: str) -> str:
    """Format /mystats output."""
    lines = [
        f"<b>📊 Your Stats — @{username or 'User'}</b>",
        "",
        "<b>🎟️ Scan Quota</b>",
        f"  Free scans:     {balance.get('free_used', 0)}/{balance.get('free_limit', 3)} used",
        f"  Free remaining: {balance.get('free_remaining', 0)}",
        f"  Approved scans: {balance.get('approved_remaining', 0)} remaining",
        f"  GitHub token:   {'✅ Verified' if balance.get('token_verified') else '❌ Not set'}",
        "",
        "<b>🔍 All-Time Stats</b>",
        f"  Total scans:    {stats.get('total_scans', 0)}",
        f"  Total leaks:    {stats.get('total_leaks', 0)}",
        f"  🔴 Critical:    {stats.get('total_critical', 0)}",
        f"  🟠 High:        {stats.get('total_high', 0)}",
        f"  🟡 Medium:      {stats.get('total_medium', 0)}",
        f"  🔵 Low:         {stats.get('total_low', 0)}",
        f"  Avg scan time:  {stats.get('avg_duration', 0)}s",
    ]
    return "\n".join(lines)


def format_no_scans_left(balance: dict) -> str:
    """Message shown when user has exhausted all scans."""
    lines = [
        "⛔ <b>You have no scans remaining.</b>",
        "",
        f"  Free scans used:    {balance.get('free_used', 0)}/{balance.get('free_limit', 3)}",
        f"  Approved remaining: {balance.get('approved_remaining', 0)}",
        "",
        "To request more scans, use /apply and explain your use case.",
        "The admin will review your request and grant additional scans if approved.",
    ]
    return "\n".join(lines)


def format_needs_token() -> str:
    return (
        "🔑 <b>GitHub Token Required</b>\n\n"
        "Your scan request was approved, but you haven't submitted your "
        "GitHub Personal Access Token yet.\n\n"
        "Use /addtoken to submit your token and unlock your approved scans."
    )


def _format_dt(dt_str: str) -> str:
    """Trim datetime string to a readable short form."""
    if not dt_str:
        return "—"
    return dt_str[:16].replace("T", " ")
