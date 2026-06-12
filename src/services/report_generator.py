"""Report generation — real CSV and PDF export.

Backs the README claim "Exportable alert, incident, and executive
reports in CSV/JSON/PDF". Every query is tenant-scoped; PDF rendering
uses reportlab (pure Python, no system deps).
"""

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.alert import Alert
from src.models.incident import Incident

logger = get_logger(__name__)

ALERT_COLUMNS = [
    "id", "title", "severity", "status", "source", "category",
    "source_ip", "destination_ip", "hostname", "username",
    "assigned_to", "incident_id", "created_at", "resolved_at",
]

INCIDENT_COLUMNS = [
    "id", "title", "severity", "status", "incident_type", "priority",
    "impact", "assigned_to", "detected_at", "contained_at",
    "resolved_at", "created_at",
]


def _cell(obj, column: str) -> str:
    value = getattr(obj, column, None)
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class ReportGenerator:
    """Tenant-scoped alert/incident/executive report generation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # -- data ----------------------------------------------------------

    async def _alerts(self, organization_id: Optional[str], days: int) -> list[Alert]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        q = (
            select(Alert)
            .where(
                Alert.organization_id == organization_id,
                Alert.created_at >= cutoff.replace(tzinfo=None),
            )
            .order_by(Alert.created_at.desc())
            .limit(10_000)
        )
        return (await self.db.execute(q)).scalars().all()

    async def _incidents(self, organization_id: Optional[str], days: int) -> list[Incident]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        q = (
            select(Incident)
            .where(
                Incident.organization_id == organization_id,
                Incident.created_at >= cutoff.replace(tzinfo=None),
            )
            .order_by(Incident.created_at.desc())
            .limit(10_000)
        )
        return (await self.db.execute(q)).scalars().all()

    # -- CSV -----------------------------------------------------------

    @staticmethod
    def _to_csv(rows: list, columns: list[str]) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: _cell(row, c) for c in columns})
        return buf.getvalue()

    async def alerts_csv(self, organization_id: Optional[str], days: int = 30) -> str:
        return self._to_csv(await self._alerts(organization_id, days), ALERT_COLUMNS)

    async def incidents_csv(self, organization_id: Optional[str], days: int = 30) -> str:
        return self._to_csv(await self._incidents(organization_id, days), INCIDENT_COLUMNS)

    # -- PDF -----------------------------------------------------------

    @staticmethod
    def _pdf_document(title: str, subtitle: str, table_header: list[str], table_rows: list[list[str]]) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=landscape(letter),
            title=title,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
        )
        styles = getSampleStyleSheet()
        story = [
            Paragraph(title, styles["Title"]),
            Paragraph(subtitle, styles["Normal"]),
            Spacer(1, 12),
        ]

        if table_rows:
            body_style = styles["BodyText"]
            body_style.fontSize = 7
            data = [table_header] + [
                [Paragraph(str(cell)[:300], body_style) for cell in row]
                for row in table_rows
            ]
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No records in the selected period.", styles["Italic"]))

        doc.build(story)
        return buf.getvalue()

    async def alerts_pdf(self, organization_id: Optional[str], days: int = 30) -> bytes:
        alerts = await self._alerts(organization_id, days)
        columns = ["title", "severity", "status", "source", "source_ip", "hostname", "created_at"]
        rows = [[_cell(a, c) for c in columns] for a in alerts]
        return self._pdf_document(
            "PySOAR Alerts Report",
            f"Last {days} days — {len(alerts)} alerts — generated "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            [c.replace("_", " ").title() for c in columns],
            rows,
        )

    async def incidents_pdf(self, organization_id: Optional[str], days: int = 30) -> bytes:
        incidents = await self._incidents(organization_id, days)
        columns = ["title", "severity", "status", "incident_type", "priority", "detected_at", "resolved_at"]
        rows = [[_cell(i, c) for c in columns] for i in incidents]
        return self._pdf_document(
            "PySOAR Incidents Report",
            f"Last {days} days — {len(incidents)} incidents — generated "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            [c.replace("_", " ").title() for c in columns],
            rows,
        )

    async def _executive_rows(self, organization_id: Optional[str], days: int) -> list[list[str]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(tzinfo=None)

        async def _count_by(model, column):
            q = (
                select(column, func.count(model.id))
                .where(
                    model.organization_id == organization_id,
                    model.created_at >= cutoff,
                )
                .group_by(column)
            )
            return dict((await self.db.execute(q)).all())

        alerts_by_sev = await _count_by(Alert, Alert.severity)
        alerts_by_status = await _count_by(Alert, Alert.status)
        incidents_by_sev = await _count_by(Incident, Incident.severity)
        incidents_by_status = await _count_by(Incident, Incident.status)

        rows = []
        for label, counts in (
            ("Alerts by severity", alerts_by_sev),
            ("Alerts by status", alerts_by_status),
            ("Incidents by severity", incidents_by_sev),
            ("Incidents by status", incidents_by_status),
        ):
            if not counts:
                rows.append([label, "—", "0"])
            for key, count in sorted(counts.items(), key=lambda kv: -kv[1]):
                rows.append([label, str(key or "unknown"), str(count)])
        return rows

    async def executive_csv(self, organization_id: Optional[str], days: int = 30) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["metric", "bucket", "count"])
        writer.writerows(await self._executive_rows(organization_id, days))
        return buf.getvalue()

    async def executive_pdf(self, organization_id: Optional[str], days: int = 30) -> bytes:
        rows = await self._executive_rows(organization_id, days)
        total_alerts = sum(int(r[2]) for r in rows if r[0] == "Alerts by severity" and r[2].isdigit())
        total_incidents = sum(int(r[2]) for r in rows if r[0] == "Incidents by severity" and r[2].isdigit())
        return self._pdf_document(
            "PySOAR Executive Summary",
            f"Security posture, last {days} days — alerts: {total_alerts}, "
            f"incidents: {total_incidents} — generated "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            ["Metric", "Bucket", "Count"],
            rows,
        )
