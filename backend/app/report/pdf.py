"""Renders a report_data dict (see builder.py) into a multi-page PDF using reportlab's
Platypus layer, per the project brief's report format: header summary, timeline,
evidence, MITRE ATT&CK mapping, AI investigation narrative, RAG sources, and
recommended actions.
"""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (ListFlowable, ListItem, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

SEVERITY_COLORS = {
    "LOW": colors.HexColor("#2e7d32"), "MEDIUM": colors.HexColor("#b8860b"),
    "HIGH": colors.HexColor("#d84315"), "CRITICAL": colors.HexColor("#b71c1c"),
}
VERDICT_COLORS = {
    "supported": colors.HexColor("#2e7d32"), "potential": colors.HexColor("#b8860b"),
    "weak": colors.HexColor("#757575"),
}


def _esc(text) -> str:
    """Escape &, <, > for reportlab's Paragraph markup parser. Mandatory for any
    dynamic text (LLM output, log-derived values) - without it, a stray '&' or '<'
    corrupts rendering or breaks the parser outright. This was caught as a real bug:
    a hardcoded "MITRE ATT&CK Mapping" heading rendered as "MITRE ATT&CK; Mapping"
    before this fix, and the same issue would hit any LLM-generated justification or
    narrative text that happens to contain '&', '<', or '>'.
    """
    return _xml_escape(str(text).replace("\u2011", "-")) if text is not None else ""


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=20,
                              spaceAfter=4))
    styles.add(ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=10,
                              textColor=colors.grey, spaceAfter=16))
    styles.add(ParagraphStyle("SectionHeading", parent=styles["Heading1"], fontSize=13,
                              spaceBefore=18, spaceAfter=8,
                              textColor=colors.HexColor("#1a1a2e")))
    styles.add(ParagraphStyle("SubHeading", parent=styles["Heading2"], fontSize=10.5,
                              spaceBefore=8, spaceAfter=4))
    styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13.5))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8,
                              textColor=colors.grey))
    return styles


def _severity_badge(severity: str, styles) -> Paragraph:
    color = SEVERITY_COLORS.get(severity, colors.grey).hexval()
    return Paragraph(f'<font color="{color}"><b>{_esc(severity)}</b></font>', styles["Body"])


def _summary_table(data: dict, styles) -> Table:
    rows = [
        ["Incident ID", _esc(data["incident_id"]), "Severity",
         _severity_badge(data["severity"], styles)],
        ["Incident Type", _esc(data["title"]), "Status", _esc(data["status"].title())],
        ["Detection Time", _esc(data["detection_time"]), "Last Activity",
         _esc(data["last_activity_time"])],
        ["Affected User(s)", _esc(", ".join(data["affected_users"])) or "n/a",
         "Affected Host(s)", _esc(", ".join(data["affected_hosts"])) or "n/a"],
        ["Source IP(s)", _esc(", ".join(data["source_ips"])) or "n/a",
         "Destination IP(s)", _esc(", ".join(data["destination_ips"])) or "n/a"],
    ]
    table = Table(rows, colWidths=[1.15 * inch, 2.15 * inch, 1.15 * inch, 2.15 * inch])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#444444")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#444444")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f7fa")),
    ]))
    return table


def _timeline_table(timeline: list[dict], styles) -> Table:
    header = ["Step", "Phase", "Time Range", "Description"]
    rows = [header]
    for p in timeline:
        desc = _esc(p["description"])
        if p["gap_note"]:
            desc += f"<br/><i>{_esc(p['gap_note'])}</i>"
        time_range = _esc(p["time_range"]).replace(" - ", "<br/>-")
        rows.append([
            str(p["step"]), Paragraph(_esc(p["phase"]), styles["Body"]),
            Paragraph(time_range, styles["Small"]),
            Paragraph(desc, styles["Body"]),
        ])
    table = Table(rows, colWidths=[0.4 * inch, 1.3 * inch, 1.1 * inch, 3.7 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7fa")]),
    ]))
    return table


def _mitre_table(techniques: list[dict], styles) -> Table:
    header = ["Technique", "Verdict", "Justification"]
    rows = [header]
    for t in techniques:
        color = VERDICT_COLORS.get(t["verdict"], colors.grey).hexval()
        technique_cell = Paragraph(
            f"<b>{_esc(t['technique_id'])}</b> - {_esc(t['technique_name'])}", styles["Body"])
        verdict_cell = Paragraph(
            f'<font color="{color}"><b>{_esc(t["verdict_label"])}</b></font>', styles["Small"])
        justification_cell = Paragraph(_esc(t["justification"]), styles["Body"])
        rows.append([technique_cell, verdict_cell, justification_cell])
    table = Table(rows, colWidths=[1.8 * inch, 1.5 * inch, 3.2 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7fa")]),
    ]))
    return table


def _indicators_table(indicators: dict, styles) -> Table:
    def cell(label, values):
        text = _esc(", ".join(str(v) for v in values)) if values else "none observed"
        return [Paragraph(f"<b>{_esc(label)}</b>", styles["Small"]), Paragraph(text, styles["Body"])]

    rows = [
        cell("Source IP(s)", indicators["source_ips"]),
        cell("Destination IP(s)", indicators["destination_ips"]),
        cell("Username(s)", indicators["usernames"]),
        cell("Hostname(s)", indicators["hostnames"]),
        cell("Process(es)", indicators["processes"]),
        cell("File hash(es)", indicators["file_hashes"]),
        cell("Destination port(s)", indicators["destination_ports"]),
    ]
    table = Table(rows, colWidths=[1.3 * inch, 5.2 * inch])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eeeeee")),
    ]))
    return table


def render_pdf(report_data: dict, output_path: str) -> str:
    """Renders the PDF to `output_path` and returns that same path."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.55 * inch, rightMargin=0.55 * inch,
                            title=f"{report_data['incident_id']} Incident Report")
    story = []

    story.append(Paragraph(_esc(report_data["report_title"]).upper(), styles["ReportTitle"]))
    story.append(Paragraph(
        f"Incident {_esc(report_data['incident_id'])} - Generated "
        f"{_esc(report_data['generated_at'])} - AI Cybersecurity Investigator",
        styles["ReportSubtitle"]))
    story.append(_summary_table(report_data, styles))

    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.append(Paragraph(_esc(report_data["executive_summary"]), styles["Body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"<b>Initial hypothesis</b> (confidence: {_esc(report_data['detection_confidence'])}): "
        f"{_esc(report_data['initial_hypothesis'])}", styles["Body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"<b>Recommended priority:</b> {_esc(report_data['recommended_priority'].upper())}",
        styles["Body"]))

    if report_data["timeline"]:
        story.append(Paragraph("Incident Timeline", styles["SectionHeading"]))
        story.append(_timeline_table(report_data["timeline"], styles))

    story.append(Paragraph("Evidence", styles["SectionHeading"]))
    evidence_items = []
    for item in report_data["evidence_items"]:
        evidence_items.append(ListItem(Paragraph(
            f'<font name="Helvetica-Bold">{_esc(item["evidence_id"])}</font> '
            f'[{_esc(item["category"])}] {_esc(item["statement"])}', styles["Body"]),
            leftIndent=4))
    if evidence_items:
        story.append(ListFlowable(evidence_items, bulletType="bullet", start="circle",
                                  leftIndent=14))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Indicators of Compromise", styles["SubHeading"]))
    story.append(_indicators_table(report_data["indicators"], styles))

    story.append(Paragraph("MITRE ATT&amp;CK Mapping", styles["SectionHeading"]))
    if report_data["mitre_techniques"]:
        story.append(_mitre_table(report_data["mitre_techniques"], styles))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "Verdicts reflect the Threat Intelligence agent's assessment of how well "
            "the observed evidence supports each technique - not a guarantee. See "
            "\"Gaps and Uncertainty\" below.", styles["Small"]))
    else:
        story.append(Paragraph("No MITRE ATT&amp;CK techniques met the retrieval "
                               "confidence threshold for this incident.", styles["Body"]))

    story.append(Paragraph("AI Investigation", styles["SectionHeading"]))
    story.append(Paragraph("Attack Sequence", styles["SubHeading"]))
    story.append(Paragraph(_esc(report_data["attack_sequence_narrative"]) or "Not available.",
                           styles["Body"]))
    story.append(Paragraph("Affected Scope", styles["SubHeading"]))
    story.append(Paragraph(_esc(report_data["affected_scope"]) or "Not available.", styles["Body"]))
    story.append(Paragraph("Gaps and Uncertainty", styles["SubHeading"]))
    story.append(Paragraph(_esc(report_data["gaps_and_uncertainty"]) or "Not available.",
                           styles["Body"]))

    if report_data["rag_sources"]:
        story.append(Paragraph("RAG Sources", styles["SectionHeading"]))
        story.append(Paragraph(
            "Knowledge retrieved from the local knowledge base in support of this "
            "investigation:", styles["Body"]))
        source_items = [
            ListItem(Paragraph(
                f'{_esc(s["title"])} <font color="#888888">({_esc(s["source"])})</font>',
                styles["Body"]), leftIndent=4)
            for s in report_data["rag_sources"]
        ]
        story.append(ListFlowable(source_items, bulletType="bullet", start="circle",
                                  leftIndent=14))

    story.append(Paragraph("Recommended Actions", styles["SectionHeading"]))
    action_items = [ListItem(Paragraph(_esc(a), styles["Body"]), leftIndent=4)
                    for a in report_data["recommended_actions"]]
    story.append(ListFlowable(action_items, bulletType="1", leftIndent=14))

    story.append(Spacer(1, 20))
    trace_text = "; ".join(f"{_esc(t['agent'])}: {_esc(t['generated_by'])}"
                           for t in report_data["agent_trace"])
    story.append(Paragraph(
        f"Generated using LLM provider '{_esc(report_data['llm_provider'])}' via the "
        f"'{_esc(report_data['graph_backend'])}' agent graph. Agent trace - {trace_text}.",
        styles["Small"]))

    doc.build(story)
    return output_path
