"""Render persisted daily security digests as compact PDF reports."""

from __future__ import annotations

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.digest import DailyDigest


def render_digest_pdf(digest: DailyDigest) -> bytes:
    """Return a self-contained PDF representation of one persisted digest."""
    output = BytesIO()
    document = BaseDocTemplate(
        output,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"WardHound Daily Security Digest {digest.id}",
        author="WardHound",
    )
    frame = Frame(document.leftMargin, document.bottomMargin, document.width, document.height)
    document.addPageTemplates(PageTemplate(id="digest", frames=[frame], onPage=_page_footer))
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(
        ParagraphStyle(
            name="Meta",
            parent=styles["BodyText"],
            textColor=colors.HexColor("#475569"),
        )
    )
    story: list[Flowable] = [
        Paragraph("WardHound Daily Security Digest", styles["Title"]),
        Paragraph(
            f"Period: {_timestamp(digest.period_start)} to {_timestamp(digest.period_end)}<br/>"
            f"Generated: {_timestamp(digest.generated_at)}",
            styles["Meta"],
        ),
        Spacer(1, 6 * mm),
    ]
    if digest.narrative is not None:
        story.extend(
            [
                Paragraph("Executive summary", styles["Heading2"]),
                Paragraph(digest.narrative.executive_summary, styles["BodyText"]),
                Paragraph("Highlights", styles["Heading3"]),
                *_bullets(digest.narrative.highlights, styles["BodyText"]),
                Paragraph("Recommended follow-up", styles["Heading3"]),
                *_bullets(digest.narrative.recommended_follow_up, styles["BodyText"]),
                Spacer(1, 4 * mm),
            ]
        )
    story.extend([Paragraph("Aggregate statistics", styles["Heading2"])])
    stat_rows: list[list[object]] = [["Metric", "Label", "Count", "Rank"]]
    stat_rows.extend(
        [stat.name, stat.label, str(stat.count), str(stat.rank or "-")]
        for stat in digest.aggregate_stats
    )
    story.extend([_table(stat_rows, [72 * mm, 67 * mm, 18 * mm, 16 * mm]), Spacer(1, 5 * mm)])
    story.append(Paragraph("Incidents", styles["Heading2"]))
    incident_rows: list[list[object]] = [["Title", "Severity", "Risk", "Created (UTC)"]]
    incident_rows.extend(
        [
            Paragraph(incident.title, styles["Small"]),
            incident.severity.value,
            str(incident.risk_score),
            _timestamp(incident.created_at),
        ]
        for incident in digest.incidents
    )
    if len(incident_rows) == 1:
        incident_rows.append(["No incidents in this period", "-", "-", "-"])
    story.append(_table(incident_rows, [82 * mm, 25 * mm, 18 * mm, 48 * mm]))
    document.build(story)
    return output.getvalue()


def _table(rows: list[list[object]], widths: list[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _bullets(items: list[str], style: ParagraphStyle) -> list[Paragraph]:
    if not items:
        return [Paragraph("None", style)]
    return [Paragraph(item, style, bulletText="-") for item in items]


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _page_footer(canvas: Canvas, document: BaseDocTemplate) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(document.leftMargin, 10 * mm, "WardHound - Daily Security Digest")
    canvas.drawRightString(A4[0] - document.rightMargin, 10 * mm, f"Page {document.page}")
    canvas.restoreState()
