from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "ot-sentinel-demonstration-report.pdf"
DATA = ROOT / "data" / "demo_events.jsonl"
SCREENSHOT = ROOT / "docs" / "assets" / "dashboard.png"

INK = colors.HexColor("#10201d")
MUTED = colors.HexColor("#587069")
GREEN = colors.HexColor("#168565")
MINT = colors.HexColor("#65f6c8")
PALE = colors.HexColor("#eaf8f3")
AMBER = colors.HexColor("#b87b16")
LINE = colors.HexColor("#d4e3de")


def read_events() -> list[dict]:
    with DATA.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def page_chrome(canvas, document) -> None:
    canvas.saveState()
    width, height = A4
    if document.page == 1:
        canvas.setFillColor(colors.HexColor("#07100f"))
        canvas.rect(0, 0, width, height, fill=1, stroke=0)
        canvas.setFillColor(MINT)
        canvas.rect(0, height - 8 * mm, width, 8 * mm, fill=1, stroke=0)
    else:
        canvas.setStrokeColor(LINE)
        canvas.line(18 * mm, height - 15 * mm, width - 18 * mm, height - 15 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, height - 11 * mm, "OT SENTINEL / DEMONSTRATION RESEARCH BRIEF")
        canvas.drawRightString(width - 18 * mm, 10 * mm, f"{document.page:02d}")
    canvas.restoreState()


def bar_table(title: str, counts: Counter, total: int, styles) -> KeepTogether:
    rows = []
    for name, count in counts.most_common():
        pct = count / total if total else 0
        blocks = max(1, round(pct * 24))
        bar = "|" * blocks
        rows.append(
            [
                Paragraph(name, styles["BodySmall"]),
                Paragraph(f"<font color='#168565'>{bar}</font>", styles["Mono"]),
                Paragraph(f"{count} / {pct:.0%}", styles["Mono"]),
            ]
        )
    table = Table(rows, colWidths=[47 * mm, 75 * mm, 30 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.35, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return KeepTogether([Paragraph(title, styles["H2"]), Spacer(1, 3 * mm), table])


def build() -> None:
    events = read_events()
    protocols = Counter(event["protocol"] for event in events)
    operations = Counter(event["decoded"]["operation"] for event in events)
    techniques = Counter(
        technique["technique_id"]
        for event in events
        for technique in event.get("techniques", [])
    )
    sessions = len({event["session_id"] for event in events})
    sources = len({event["source_id"] for event in events})
    control_ops = {
        "write_single",
        "write_multiple",
        "single_command",
        "setpoint_command",
        "program_download",
    }
    command_count = sum(event["decoded"]["operation"] in control_ops for event in events)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "CoverKicker",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=MINT,
            tracking=2,
            spaceAfter=8 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=34,
            leading=37,
            alignment=TA_LEFT,
            textColor=colors.white,
            spaceAfter=6 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "CoverDeck",
            parent=styles["Normal"],
            fontSize=13,
            leading=19,
            textColor=colors.HexColor("#b4cbc3"),
            spaceAfter=10 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "CoverNotice",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=14,
            textColor=colors.HexColor("#f3cf7a"),
            backColor=colors.HexColor("#2b2615"),
            borderColor=colors.HexColor("#806a2d"),
            borderWidth=0.7,
            borderPadding=10,
            spaceAfter=12 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "H1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=INK,
            spaceBefore=3 * mm,
            spaceAfter=5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=GREEN,
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "Body",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=14.5,
            textColor=INK,
            spaceAfter=3.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            "BodySmall",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=INK,
        )
    )
    styles.add(
        ParagraphStyle(
            "Mono",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            "Callout",
            parent=styles["BodyText"],
            fontSize=9,
            leading=14,
            textColor=INK,
            backColor=PALE,
            borderColor=colors.HexColor("#a9d9ca"),
            borderWidth=0.7,
            borderPadding=9,
            spaceBefore=3 * mm,
            spaceAfter=4 * mm,
        )
    )

    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title="OT Sentinel - Demonstration Research Brief",
        author="Mir Afnan Ali",
        subject="Synthetic validation of an OT/ICS honeypot analytics pipeline",
    )

    story = [
        Spacer(1, 33 * mm),
        Paragraph("OT / ICS THREAT RESEARCH", styles["CoverKicker"]),
        Paragraph("OT Sentinel", styles["CoverTitle"]),
        Paragraph(
            "Demonstration research brief for a low-interaction Modbus, S7 and IEC-104 observatory hosted with a UAE-region deployment model.",
            styles["CoverDeck"],
        ),
        Paragraph(
            "SYNTHETIC DATA NOTICE - All quantitative findings in this brief are generated demonstration observations. They validate the pipeline and presentation, but they are not real attacker measurements.",
            styles["CoverNotice"],
        ),
    ]
    metric_data = [
        ["EVENTS", "SESSIONS", "SOURCES", "CONTROL ATTEMPTS"],
        [f"{len(events):,}", f"{sessions:,}", f"{sources:,}", f"{command_count:,}"],
    ]
    metrics = Table(metric_data, colWidths=[39 * mm] * 4, rowHeights=[8 * mm, 14 * mm])
    metrics.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#10221e")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#28473f")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#28473f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#86a59a")),
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, 1), "Courier-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 6.8),
                ("FONTSIZE", (0, 1), (-1, 1), 15),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend([metrics, Spacer(1, 42 * mm)])
    story.append(
        Paragraph(
            "Prepared by Mir Afnan Ali  |  August 2026  |  Research build 0.1.0  |  Times and locations are illustrative",
            ParagraphStyle(
                "CoverFooter",
                parent=styles["Mono"],
                textColor=colors.HexColor("#759088"),
                alignment=TA_CENTER,
            ),
        )
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("Executive summary", styles["H1"]),
            Paragraph(
                "OT Sentinel is a low-interaction industrial protocol observatory designed to capture a narrow set of network behaviors without executing attacker instructions or connecting to a real process. The project demonstrates the complete path from protocol telemetry to privacy-reviewed public intelligence.",
                styles["Body"],
            ),
            Paragraph(
                "This release uses a deterministic synthetic dataset so that reviewers can run the dashboard immediately and verify every transformation. Live research will begin only after an isolated cloud deployment is authorized, cost-protected and tested.",
                styles["Body"],
            ),
            Paragraph(
                "The strongest engineering result is not a high attack count. It is the evidence model: a TCP connection is recorded but not labeled as exploitation, while protocol writes, controller commands and program-transfer operations receive explicit ATT&amp;CK hypotheses with confidence and rationale.",
                styles["Callout"],
            ),
            Paragraph("Demonstration composition", styles["H2"]),
            bar_table("Events by protocol", protocols, len(events), styles),
            Spacer(1, 5 * mm),
            bar_table("Leading decoded operations", operations, len(events), styles),
            Spacer(1, 6 * mm),
            Paragraph("Interpretation", styles["H2"]),
            Paragraph(
                f"The fixture contains {len(events):,} events across {sessions:,} sessions and {sources:,} pseudonymous sources. {command_count:,} events contain synthetic write, command, setpoint or program-transfer operations. These proportions are deliberately varied to exercise dashboard filters; they must not be treated as prevalence estimates.",
                styles["Body"],
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("System and analytical design", styles["H1"]),
            Paragraph(
                "The Internet-facing surface is intentionally smaller than a conventional SIEM deployment. A single unprivileged Python service reads a bounded payload, performs shallow protocol decoding, emits an inert reply when appropriate and writes an append-only JSON event. It cannot execute a program, invoke a shell or forward an attacker payload.",
                styles["Body"],
            ),
            Paragraph("Collection path", styles["H2"]),
        ]
    )
    pipeline = Table(
        [
            ["01", "COLLECT", "Bounded Modbus, S7 and IEC-104 telemetry"],
            ["02", "NORMALIZE", "One versioned event schema"],
            ["03", "MAP", "Evidence-qualified ATT&CK hypotheses"],
            ["04", "SANITIZE", "Salted source IDs; payload removal"],
            ["05", "PUBLISH", "Public JSONL, dashboard and report"],
        ],
        colWidths=[12 * mm, 32 * mm, 108 * mm],
    )
    pipeline.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), GREEN),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("TEXTCOLOR", (1, 0), (1, -1), GREEN),
                ("FONTNAME", (0, 0), (1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LINEBELOW", (1, 0), (-1, -2), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([pipeline, Spacer(1, 6 * mm), Paragraph("Public dashboard", styles["H2"])])
    if SCREENSHOT.exists():
        screenshot = Image(str(SCREENSHOT), width=160 * mm, height=90 * mm)
        story.extend([screenshot, Spacer(1, 2 * mm)])
    story.append(
        Paragraph(
            "The dashboard exposes a global source overview, activity cadence, ATT&amp;CK intensity layer, sanitized session ledger and methodology panel. A permanent banner distinguishes synthetic fixtures from sanitized observations.",
            styles["Body"],
        )
    )

    mapping_names = {
        "T0846.001": "Remote System Discovery: Port Scan",
        "T0877": "I/O Image",
        "T1692.001": "Unauthorized Message: Command Message",
        "T0836": "Modify Parameter",
        "T0843": "Program Download",
        "T0866": "Exploitation of Remote Services",
    }
    mapping_rows = [["TECHNIQUE", "INTERPRETATION", "MATCHES"]]
    for technique_id, count in techniques.most_common():
        mapping_rows.append([technique_id, mapping_names.get(technique_id, "Unknown"), str(count)])
    mapping = Table(mapping_rows, colWidths=[30 * mm, 100 * mm, 23 * mm], repeatRows=1)
    mapping.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (0, -1), "Courier-Bold"),
                ("TEXTCOLOR", (0, 1), (0, -1), GREEN),
                ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend(
        [
            PageBreak(),
            Paragraph("ATT&amp;CK evidence layer", styles["H1"]),
            Paragraph(
                "Technique counts below are pipeline test outputs, not claims about a threat population. Multiple techniques may map to one event, so counts are not mutually exclusive.",
                styles["Body"],
            ),
            mapping,
            Spacer(1, 6 * mm),
            Paragraph("Confidence controls", styles["H2"]),
            Paragraph(
                "A protocol-aware probe may support Remote System Discovery at medium confidence. A Modbus read receives only a low-confidence I/O Image hypothesis because an isolated read does not establish intent. A control write receives high-confidence Unauthorized Command Message and medium-confidence Modify Parameter hypotheses. Exploitation of Remote Services is reserved for a documented signature; it is never inferred from a connection alone.",
                styles["Body"],
            ),
            Paragraph(
                "This distinction improves analytical honesty and makes the output useful for review. Analysts and defenders can inspect not only what was mapped, but why it was mapped and what the evidence cannot prove.",
                styles["Callout"],
            ),
            Paragraph("Safety and privacy", styles["H2"]),
            Paragraph(
                "The deployment drops Linux capabilities, uses a read-only container filesystem, applies CPU, memory and process limits, and attaches the sensor to an internal Docker network. Raw source IPs and bounded payloads remain private. Publication replaces IPs with salted identifiers, removes payloads and runs an automated forbidden-field check.",
                styles["Body"],
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            Paragraph("Live research plan", styles["H1"]),
            Paragraph(
                "The live phase will use one isolated Linux VM in Azure UAE North, funded by Azure for Students or introductory credit. The subscription spending limit will remain active. The experiment will avoid paid Marketplace images, managed SIEM services, Defender upgrades and Log Analytics ingestion.",
                styles["Body"],
            ),
            Paragraph("Collection gates", styles["H2"]),
        ]
    )
    gates = [
        ["GATE", "REQUIRED EVIDENCE BEFORE PROCEEDING"],
        ["Cost", "Active subscription spending limit and 25/50/75 percent alerts"],
        ["Isolation", "SSH restricted to administrator /32; only ICS decoy ports public"],
        ["Safety", "No outbound route from sensor container; no execution capability"],
        ["Quality", "Known-safe protocol probes create expected events and responses"],
        ["Privacy", "Sanitizer and leakage validator pass; manual review completed"],
        ["Shutdown", "Resource-group deletion tested and collection end date recorded"],
    ]
    gate_table = Table(gates, colWidths=[28 * mm, 125 * mm], repeatRows=1)
    gate_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 1), (0, -1), GREEN),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend(
        [
            gate_table,
            Spacer(1, 6 * mm),
            Paragraph("Publication language", styles["H2"]),
            Paragraph(
                "The final report will say: 'Activity observed by an Internet-exposed ICS decoy hosted in Azure UAE North during the stated collection window.' It will not label sources as UAE attackers, claim the observations represent UAE critical infrastructure, or infer physical location from IP geolocation.",
                styles["Callout"],
            ),
            Paragraph("Next edition", styles["H2"]),
            Paragraph(
                "After a two-to-four-week window, the same report pipeline will replace this demonstration brief with sanitized observed metrics, a stated sample window, data-quality notes, protocol distributions, evidence-qualified ATT&amp;CK results and reproducible limitations. The raw dataset will remain private.",
                styles["Body"],
            ),
            Paragraph("References", styles["H2"]),
            Paragraph(
                "MITRE ATT&amp;CK for ICS: https://attack.mitre.org/matrices/ics/<br/>"
                "ATT&amp;CK STIX data: https://github.com/mitre-attack/attack-stix-data<br/>"
                "Conpot: https://github.com/mushorg/conpot<br/>"
                "Azure spending limits: https://learn.microsoft.com/azure/cost-management-billing/manage/spending-limit<br/>"
                "Streamlit Community Cloud: https://docs.streamlit.io/deploy/streamlit-community-cloud",
                styles["BodySmall"],
            ),
        ]
    )

    document.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    print(f"Created {OUTPUT}")


if __name__ == "__main__":
    build()
