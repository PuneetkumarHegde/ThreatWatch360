"""
AlertIQ 2.0 - Phase 5 PDF Report Generator
------------------------------------------------
Generates a branded, print-ready PDF incident summary report using
reportlab (pure-Python, no system dependencies like wkhtmltopdf/Chromium
required - important for a tool that needs to run reliably on a SOC
analyst's laptop without extra install steps).

Report contents:
  - Title page: report window, generation timestamp, summary counts
  - Severity/category breakdown table
  - Top attackers table
  - Full incident table (attack type, source/dest, severity, risk, status)
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Palette matching the SOC portal's dark "signal blue" theme, adapted for
# a light printable page (dark backgrounds don't print/scan well).
NAVY = colors.HexColor("#0b0f16")
SIGNAL = colors.HexColor("#2f5fd6")
SEV_COLORS = {
    "LOW": colors.HexColor("#4c8bf5"),
    "MEDIUM": colors.HexColor("#c78a1a"),
    "HIGH": colors.HexColor("#d9611f"),
    "CRITICAL": colors.HexColor("#c92a2a"),
}
GREY = colors.HexColor("#57667c")
LIGHT_GREY = colors.HexColor("#e9ecf2")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ReportTitle", fontSize=22, leading=26, textColor=NAVY, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("ReportSubtitle", fontSize=11, leading=15, textColor=GREY))
    styles.add(ParagraphStyle("SectionHeading", fontSize=13, leading=18, textColor=NAVY, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8))
    styles.add(ParagraphStyle("CellText", fontSize=8, leading=10))
    return styles


def generate_incident_report_pdf(
    *,
    incidents: list[dict],
    stats: dict,
    window_label: str,
    generated_by: str = "AlertIQ 2.0",
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
    )
    styles = _styles()
    story = []

    # -- Title page --------------------------------------------------
    story.append(Paragraph("AlertIQ 2.0 — Incident Report", styles["ReportTitle"]))
    story.append(Spacer(1, 4))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Report window: {window_label} &nbsp;|&nbsp; Generated: {generated_at}", styles["ReportSubtitle"]))
    story.append(Spacer(1, 18))

    summary_data = [
        ["Total Incidents", "Critical", "High", "Medium", "Low"],
        [
            str(stats.get("total_incidents", 0)),
            str(stats.get("by_severity", {}).get("CRITICAL", 0)),
            str(stats.get("by_severity", {}).get("HIGH", 0)),
            str(stats.get("by_severity", {}).get("MEDIUM", 0)),
            str(stats.get("by_severity", {}).get("LOW", 0)),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[1.9 * inch] + [1.05 * inch] * 4)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BACKGROUND", (0, 1), (-1, 1), LIGHT_GREY),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d5dd")),
            ]
        )
    )
    story.append(summary_table)

    # -- Category breakdown -------------------------------------------
    story.append(Paragraph("Incidents by Category", styles["SectionHeading"]))
    cat_rows = [["Category", "Count"]] + [[k, str(v)] for k, v in stats.get("by_category", {}).items()]
    if len(cat_rows) == 1:
        cat_rows.append(["No incidents in this window", "0"])
    cat_table = Table(cat_rows, colWidths=[4.5 * inch, 1.5 * inch])
    cat_table.setStyle(_data_table_style())
    story.append(cat_table)

    # -- Top attackers ---------------------------------------------------
    story.append(Paragraph("Top Attackers", styles["SectionHeading"]))
    top_rows = [["Source IP", "Incident Count"]] + [
        [a["ip"], str(a["count"])] for a in stats.get("top_attackers", [])
    ]
    if len(top_rows) == 1:
        top_rows.append(["No attacker data in this window", "0"])
    top_table = Table(top_rows, colWidths=[4.5 * inch, 1.5 * inch])
    top_table.setStyle(_data_table_style())
    story.append(top_table)

    # -- Full incident table ------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Incident Detail", styles["SectionHeading"]))

    header = ["Time (UTC)", "Attack", "Source", "Destination", "Severity", "Risk", "Status"]
    rows = [header]
    for inc in incidents:
        ts = datetime.fromtimestamp(inc["timestamp"], tz=timezone.utc).strftime("%m-%d %H:%M")
        dest = inc["destination_ip"] or "—"
        rows.append([
            ts,
            inc["attack_type"],
            inc["source_ip"],
            dest,
            inc["severity"],
            str(inc["risk_score"]),
            inc["status"],
        ])

    incident_table = Table(rows, colWidths=[0.85 * inch, 1.35 * inch, 1.15 * inch, 1.15 * inch, 0.75 * inch, 0.55 * inch, 0.95 * inch], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_idx, inc in enumerate(incidents, start=1):
        color = SEV_COLORS.get(inc["severity"])
        if color:
            style_commands.append(("TEXTCOLOR", (4, row_idx), (4, row_idx), color))
            style_commands.append(("FONTNAME", (4, row_idx), (4, row_idx), "Helvetica-Bold"))
    incident_table.setStyle(TableStyle(style_commands))
    story.append(incident_table)

    if not incidents:
        story.append(Spacer(1, 12))
        story.append(Paragraph("No incidents were recorded in this reporting window.", styles["ReportSubtitle"]))

    doc.build(story)
    return buffer.getvalue()


def _data_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2431")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
    )
