"""
reports/pdf_report.py
Generate a professional PDF scan report using ReportLab.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.scanner import ScanResult, Finding

# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK      = colors.HexColor("#0D1117")
C_SURFACE   = colors.HexColor("#161B22")
C_BORDER    = colors.HexColor("#30363D")
C_TEXT      = colors.HexColor("#E6EDF3")
C_MUTED     = colors.HexColor("#8B949E")
C_CRITICAL  = colors.HexColor("#FF4444")
C_HIGH      = colors.HexColor("#FF8C00")
C_MEDIUM    = colors.HexColor("#FFD700")
C_LOW       = colors.HexColor("#4493F8")
C_GREEN     = colors.HexColor("#3FB950")
C_ACCENT    = colors.HexColor("#238636")

SEVERITY_COLOUR = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=C_TEXT,
            spaceAfter=4,
            alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_MUTED,
            spaceAfter=2,
            alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=C_TEXT,
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_TEXT,
            spaceAfter=2,
            leading=13,
        ),
        "code": ParagraphStyle(
            "code",
            fontName="Courier",
            fontSize=8,
            textColor=C_LOW,
            spaceAfter=2,
            leftIndent=8,
        ),
        "muted": ParagraphStyle(
            "muted",
            fontName="Helvetica",
            fontSize=8,
            textColor=C_MUTED,
            spaceAfter=2,
        ),
        "finding_type": ParagraphStyle(
            "finding_type",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=C_TEXT,
        ),
    }


def _severity_badge_colour(severity: str) -> colors.Color:
    return SEVERITY_COLOUR.get(severity, C_MUTED)


def _hr(width="100%") -> HRFlowable:
    return HRFlowable(width=width, thickness=0.5, color=C_BORDER, spaceAfter=6, spaceBefore=6)


def generate_pdf(result: ScanResult, requester_name: str = "User") -> bytes:
    """
    Generate a PDF report for a ScanResult.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="Leak Hunter Report",
        author="LeakHunterBot",
    )

    st      = _styles()
    story   = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Cover header ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("🧬 API Leak Hunter", st["title"]))
    story.append(Paragraph("Secret & Credential Exposure Report", st["subtitle"]))
    story.append(Paragraph(f"Generated: {now_str}", st["subtitle"]))
    story.append(Spacer(1, 6 * mm))
    story.append(_hr())

    # ── Summary table ─────────────────────────────────────────────────────────
    story.append(Paragraph("Scan Summary", st["section"]))

    clean  = result.total_leaks == 0
    status = "✅  CLEAN" if clean else f"🚨  {result.total_leaks} LEAKS FOUND"

    summary_data = [
        ["Target",     result.target],
        ["Scan Type",  result.scan_type.upper()],
        ["Files Scanned", str(result.total_files)],
        ["Duration",   f"{result.duration}s"],
        ["Status",     status],
        ["Critical 🔴", str(result.critical_count)],
        ["High 🟠",     str(result.high_count)],
        ["Medium 🟡",   str(result.medium_count)],
        ["Low 🔵",      str(result.low_count)],
        ["Requested by", requester_name],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[50 * mm, PAGE_W - 2 * MARGIN - 50 * mm],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
        ("TEXTCOLOR",   (0, 0), (0, -1),  C_MUTED),
        ("TEXTCOLOR",   (1, 0), (1, -1),  C_TEXT),
        ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1),  "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_SURFACE, C_DARK]),
        ("BOX",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",   (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    # ── Clean exit ────────────────────────────────────────────────────────────
    if clean:
        story.append(_hr())
        story.append(Paragraph(
            "✅  No secrets or credentials were detected in the scanned repository.",
            st["body"],
        ))
        if result.errors:
            story.append(Spacer(1, 4 * mm))
            story.append(Paragraph("Warnings", st["section"]))
            for err in result.errors:
                story.append(Paragraph(f"⚠  {err}", st["muted"]))
        doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
        return buffer.getvalue()

    # ── Findings ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Findings", st["section"]))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number or 0),
    )

    for idx, finding in enumerate(sorted_findings, 1):
        sev_colour = _severity_badge_colour(finding.severity)

        finding_data = [
            [f"#{idx}", f"{finding.severity}  —  {finding.secret_type}"],
            ["File",     finding.file_path],
            ["Line",     str(finding.line_number) if finding.line_number else "—"],
            ["Value",    finding.matched_value],
        ]
        if finding.raw_line:
            finding_data.append(["Context", finding.raw_line[:120]])

        finding_table = Table(
            finding_data,
            colWidths=[22 * mm, PAGE_W - 2 * MARGIN - 22 * mm],
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, -1),  C_SURFACE),
            ("BACKGROUND",     (0, 0), (0, 0),    sev_colour),
            ("TEXTCOLOR",      (0, 0), (0, 0),    colors.white),
            ("TEXTCOLOR",      (1, 0), (1, 0),    C_TEXT),
            ("FONTNAME",       (0, 0), (0, 0),    "Helvetica-Bold"),
            ("FONTNAME",       (1, 0), (1, 0),    "Helvetica-Bold"),
            ("FONTNAME",       (0, 1), (0, -1),   "Helvetica-Bold"),
            ("FONTNAME",       (1, 1), (1, -1),   "Helvetica"),
            ("TEXTCOLOR",      (0, 1), (0, -1),   C_MUTED),
            ("TEXTCOLOR",      (1, 1), (1, -1),   C_TEXT),
            ("FONTSIZE",       (0, 0), (-1, -1),  8),
            ("BOX",            (0, 0), (-1, -1),  0.8, sev_colour),
            ("INNERGRID",      (0, 0), (-1, -1),  0.3, C_BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1),  4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1),  4),
            ("LEFTPADDING",    (0, 0), (-1, -1),  6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),  [C_SURFACE, C_DARK]),
        ]))

        story.append(finding_table)
        story.append(Spacer(1, 3 * mm))

        # Page break every 6 findings to avoid overflow
        if idx % 6 == 0 and idx < len(sorted_findings):
            story.append(PageBreak())
            story.append(Paragraph(f"Findings (continued — page {idx // 6 + 2})", st["section"]))

    # ── Errors / warnings ─────────────────────────────────────────────────────
    if result.errors:
        story.append(Spacer(1, 4 * mm))
        story.append(_hr())
        story.append(Paragraph("Warnings", st["section"]))
        for err in result.errors:
            story.append(Paragraph(f"⚠  {err}", st["muted"]))

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(_hr())
    story.append(Paragraph(
        "⚠  This report is generated automatically. False positives may occur. "
        "Always verify findings manually before taking action. "
        "Immediately rotate any confirmed leaked credentials.",
        st["muted"],
    ))

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return buffer.getvalue()


def _page_footer(canvas, doc):
    """Draw a subtle footer on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(
        PAGE_W / 2,
        10 * mm,
        f"LeakHunterBot — Confidential  |  Page {doc.page}",
    )
    canvas.restoreState()
