"""
reporter.py  —  FirewallX Audit Report Generator
Reads firewallx_events.json and produces:
  - firewallx_audit.json   (clean structured JSON)
  - firewallx_report.pdf   (formatted PDF for judges / reviewers)
"""

import json
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── File paths ────────────────────────────────────────────────────────────────
EVENTS_FILE  = "firewallx_events.json"
CHAIN_FILE   = "firewallx_chain.json"
JSON_OUT     = "firewallx_audit.json"
PDF_OUT      = "firewallx_report.pdf"

# ── Colours (dark-ops palette) ────────────────────────────────────────────────
C_BLACK      = colors.HexColor("#080d14")
C_NAVY       = colors.HexColor("#0d1b2a")
C_STEEL      = colors.HexColor("#1e3a5f")
C_BLUE_MID   = colors.HexColor("#4a7fa5")
C_GREEN      = colors.HexColor("#00c96e")
C_RED        = colors.HexColor("#ff3c3c")
C_AMBER      = colors.HexColor("#ffb400")
C_WHITE      = colors.HexColor("#c8d8e8")
C_LIGHT      = colors.HexColor("#e8f0f8")
C_GREY       = colors.HexColor("#7a9ab8")


# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = dict(fontName="Helvetica", leading=14, textColor=C_WHITE)

    return {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=28,
            textColor=C_GREEN,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=C_BLUE_MID,
            spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=12,
            textColor=C_BLUE_MID,
            spaceBefore=14,
            spaceAfter=4,
            borderPad=0,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=8,
            leading=12,
            textColor=C_WHITE,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=7,
            leading=10,
            textColor=C_LIGHT,
        ),
        "label_ok": ParagraphStyle(
            "label_ok",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=C_GREEN,
        ),
        "label_bad": ParagraphStyle(
            "label_bad",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=C_RED,
        ),
        "label_amber": ParagraphStyle(
            "label_amber",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=C_AMBER,
        ),
        "right": ParagraphStyle(
            "right",
            fontName="Helvetica",
            fontSize=7,
            leading=10,
            textColor=C_GREY,
            alignment=TA_RIGHT,
        ),
        "center": ParagraphStyle(
            "center",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=12,
            textColor=C_WHITE,
            alignment=TA_CENTER,
        ),
    }


# ── Helper: table style factory ───────────────────────────────────────────────
def dark_table_style(header_rows=1):
    return TableStyle([
        # Header
        ("BACKGROUND",  (0, 0), (-1, header_rows - 1), C_STEEL),
        ("TEXTCOLOR",   (0, 0), (-1, header_rows - 1), C_WHITE),
        ("FONTNAME",    (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, header_rows - 1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, header_rows - 1), 6),
        ("TOPPADDING",  (0, 0), (-1, header_rows - 1), 6),
        # Body
        ("BACKGROUND",  (0, header_rows), (-1, -1), C_NAVY),
        ("TEXTCOLOR",   (0, header_rows), (-1, -1), C_LIGHT),
        ("FONTNAME",    (0, header_rows), (-1, -1), "Courier"),
        ("FONTSIZE",    (0, header_rows), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, header_rows), (-1, -1),
         [C_NAVY, colors.HexColor("#0a1420")]),
        ("BOTTOMPADDING",(0, header_rows), (-1, -1), 4),
        ("TOPPADDING",  (0, header_rows), (-1, -1), 4),
        # Grid
        ("GRID",        (0, 0), (-1, -1), 0.4, C_STEEL),
        ("LINEBELOW",   (0, 0), (-1, 0),  0.8, C_BLUE_MID),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ])


# ── Page template (header/footer) ─────────────────────────────────────────────
def on_page(canvas, doc):
    W, H = A4
    canvas.saveState()

    # Top bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, H - 28*mm, W, 28*mm, fill=1, stroke=0)
    canvas.setFillColor(C_GREEN)
    canvas.rect(0, H - 29*mm, W, 1.2, fill=1, stroke=0)

    # Logo text
    canvas.setFillColor(C_GREEN)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawString(15*mm, H - 16*mm, "FIREWALLX")
    canvas.setFillColor(C_BLUE_MID)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15*mm, H - 21*mm, "AI THREAT DETECTION & BLOCKCHAIN AUDIT  //  MINISTRY OF DEFENCE")

    # Classified stamp
    canvas.setFillColor(C_RED)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawRightString(W - 15*mm, H - 14*mm, "CLASSIFIED // SECRET")
    canvas.setFillColor(C_GREY)
    canvas.setFont("Helvetica", 6)
    canvas.drawRightString(W - 15*mm, H - 20*mm,
                           f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Bottom bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, 0, W, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(C_STEEL)
    canvas.rect(0, 14*mm, W, 0.8, fill=1, stroke=0)
    canvas.setFillColor(C_GREY)
    canvas.setFont("Helvetica", 6)
    canvas.drawString(15*mm, 5*mm, "FirewallX Automated Audit Report  |  Restricted Distribution")
    canvas.drawRightString(W - 15*mm, 5*mm, f"Page {doc.page}")

    canvas.restoreState()


# ── JSON export ───────────────────────────────────────────────────────────────
def export_json(events, chain, tamper_log):
    threats   = [e for e in events if e.get("is_threat")]
    normals   = [e for e in events if not e.get("is_threat")]

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "system": "FirewallX v1.0 — MoD Prototype",
            "classification": "RESTRICTED",
        },
        "summary": {
            "total_events":    len(events),
            "total_threats":   len(threats),
            "total_normal":    len(normals),
            "chain_valid":     len(tamper_log) == 0,
            "tamper_events":   len(tamper_log),
        },
        "all_events":    events,
        "threats":       threats,
        "tamper_log":    tamper_log,
        "blockchain":    chain,
    }

    with open(JSON_OUT, "w") as f:
        json.dump(report, f, indent=2)

    return report


# ── PDF export ────────────────────────────────────────────────────────────────
def export_pdf(report):
    S = make_styles()
    W, H = A4

    doc = SimpleDocTemplate(
        PDF_OUT,
        pagesize=A4,
        leftMargin=15*mm,
        rightMargin=15*mm,
        topMargin=35*mm,
        bottomMargin=20*mm,
        title="FirewallX Audit Report",
        author="FirewallX System",
    )

    story = []
    meta  = report["report_metadata"]
    summ  = report["summary"]

    # ── Cover block ───────────────────────────────────────────────────────────
    story.append(Paragraph("AUDIT &amp; THREAT INTELLIGENCE REPORT", S["title"]))
    story.append(Paragraph(
        f"Classification: RESTRICTED  ·  System: {meta['system']}  ·  "
        f"Generated: {datetime.now().strftime('%d %b %Y  %H:%M UTC')}",
        S["subtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=0.8,
                             color=C_STEEL, spaceAfter=10))

    # ── Summary KPI table ─────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", S["section"]))

    chain_status = ("VALID — INTEGRITY CONFIRMED" if summ["chain_valid"]
                    else "COMPROMISED — TAMPERING DETECTED")
    chain_style  = S["label_ok"] if summ["chain_valid"] else S["label_bad"]

    kpi_data = [
        ["METRIC", "VALUE"],
        ["Total Events Processed", str(summ["total_events"])],
        ["Threats Detected",       str(summ["total_threats"])],
        ["Normal Events",          str(summ["total_normal"])],
        ["Tamper Events",          str(summ["tamper_events"])],
        ["Blockchain Integrity",   chain_status],
    ]

    kpi_table = Table(kpi_data, colWidths=[90*mm, 90*mm])
    kpi_table.setStyle(dark_table_style())
    # Colour the chain integrity cell
    ci_row = 5
    ci_col = 1
    kpi_table.setStyle(TableStyle([
        ("TEXTCOLOR", (ci_col, ci_row), (ci_col, ci_row),
         C_GREEN if summ["chain_valid"] else C_RED),
        ("FONTNAME",  (ci_col, ci_row), (ci_col, ci_row), "Helvetica-Bold"),
    ]))
    story.append(kpi_table)

    # ── Tamper evidence ───────────────────────────────────────────────────────
    story.append(Paragraph("TAMPER EVIDENCE LOG", S["section"]))

    tamper_log = report.get("tamper_log", [])
    if tamper_log:
        t_data = [["TIMESTAMP", "BLOCK INDEX", "ORIGINAL HASH", "NOTES"]]
        for ev in tamper_log:
            t_data.append([
                str(ev.get("timestamp", "—"))[:19],
                str(ev.get("block_index", "—")),
                str(ev.get("original_hash", "—"))[:24] + "…",
                str(ev.get("notes", "Manual tamper simulation")),
            ])
        t_table = Table(t_data, colWidths=[38*mm, 22*mm, 60*mm, 60*mm])
        t_table.setStyle(dark_table_style())
        t_table.setStyle(TableStyle([
            ("TEXTCOLOR", (0, 1), (-1, -1), C_RED),
        ]))
        story.append(t_table)
    else:
        story.append(Paragraph(
            "● No tamper events recorded. Blockchain integrity maintained throughout session.",
            S["label_ok"]
        ))

    story.append(Spacer(1, 6))

    # ── All events table ──────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("FULL EVENT LOG", S["section"]))
    story.append(Paragraph(
        f"Total events: {summ['total_events']}  ·  "
        f"Threats: {summ['total_threats']}  ·  "
        f"Normal: {summ['total_normal']}",
        S["body"]
    ))
    story.append(Spacer(1, 4))

    ev_data = [["TIMESTAMP", "USER", "TYPE", "IP ADDRESS", "RISK", "THREAT", "LOCATION"]]
    for ev in report["all_events"]:
        is_threat = ev.get("is_threat", False)
        ev_data.append([
            str(ev.get("timestamp", "—"))[:19],
            str(ev.get("user", "—")),
            str(ev.get("type", "—")),
            str(ev.get("ip_address", "—")),
            f"{ev.get('risk_score', 0):.2f}",
            "YES" if is_threat else "no",
            str(ev.get("location", "—")),
        ])

    ev_table = Table(
        ev_data,
        colWidths=[35*mm, 18*mm, 18*mm, 32*mm, 14*mm, 14*mm, 22*mm],
        repeatRows=1,
    )
    ev_table.setStyle(dark_table_style())

    # Colour threat rows red
    for i, ev in enumerate(report["all_events"], start=1):
        if ev.get("is_threat"):
            ev_table.setStyle(TableStyle([
                ("TEXTCOLOR", (0, i), (-1, i), C_RED),
                ("FONTNAME",  (0, i), (-1, i), "Helvetica-Bold"),
            ]))

    story.append(ev_table)

    # ── Blockchain audit trail ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("BLOCKCHAIN AUDIT TRAIL", S["section"]))
    story.append(Paragraph(
        "Each block contains a SHA-256 hash of its data and the previous block's hash, "
        "forming a tamper-evident chain. Any modification breaks hash continuity.",
        S["body"]
    ))
    story.append(Spacer(1, 6))

    for block in report.get("blockchain", []):
        b_data = [
            ["FIELD", "VALUE"],
            ["Block Index",    str(block.get("index", "—"))],
            ["Timestamp",      str(block.get("timestamp", "—"))[:19]],
            ["Previous Hash",  str(block.get("previous_hash", "—"))[:48]],
            ["Block Hash",     str(block.get("hash", "—"))[:48]],
            ["Event Count",    str(len(block.get("data", [])))],
        ]
        b_table = Table(b_data, colWidths=[38*mm, 142*mm])
        b_table.setStyle(dark_table_style())
        story.append(b_table)
        story.append(Spacer(1, 5))

    # ── Sign-off ──────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.8,
                             color=C_STEEL, spaceBefore=16, spaceAfter=8))
    story.append(Paragraph(
        "This report was generated automatically by FirewallX v1.0. "
        "For verification queries contact the system administrator. "
        "Unauthorised disclosure is prohibited.",
        S["subtitle"]
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_reports():
    """Load persisted data and write JSON + PDF outputs. Returns (json_path, pdf_path)."""

    events     = []
    chain      = []
    tamper_log = []

    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE) as f:
            events = json.load(f)

    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE) as f:
            data = json.load(f)
            chain      = data.get("chain", [])
            tamper_log = data.get("tamper_log", [])

    report = export_json(events, chain, tamper_log)
    export_pdf(report)

    return JSON_OUT, PDF_OUT


if __name__ == "__main__":
    j, p = generate_reports()
    print(f"JSON → {j}")
    print(f"PDF  → {p}")
