"""Report export endpoints — real CSV and PDF downloads, tenant-scoped."""

from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Query, Response

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.services.report_generator import ReportGenerator

logger = get_logger(__name__)

router = APIRouter(tags=["reports"])


class ReportType(str, Enum):
    ALERTS = "alerts"
    INCIDENTS = "incidents"
    EXECUTIVE = "executive"


class ExportFormat(str, Enum):
    CSV = "csv"
    PDF = "pdf"


@router.get("/reports/{report_type}/export")
async def export_report(
    report_type: ReportType,
    format: ExportFormat = Query(...),
    days: int = Query(30, ge=1, le=365),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Download a report as a real CSV or PDF file."""
    org_id = getattr(current_user, "organization_id", None)
    gen = ReportGenerator(db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"pysoar-{report_type.value}-{stamp}"

    if format is ExportFormat.CSV:
        if report_type is ReportType.ALERTS:
            body = await gen.alerts_csv(org_id, days)
        elif report_type is ReportType.INCIDENTS:
            body = await gen.incidents_csv(org_id, days)
        else:
            body = await gen.executive_csv(org_id, days)
        return Response(
            content=body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )

    if report_type is ReportType.ALERTS:
        pdf = await gen.alerts_pdf(org_id, days)
    elif report_type is ReportType.INCIDENTS:
        pdf = await gen.incidents_pdf(org_id, days)
    else:
        pdf = await gen.executive_pdf(org_id, days)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )
