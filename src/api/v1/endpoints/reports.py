"""Report export endpoints — real CSV and PDF downloads, tenant-scoped."""

from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Query, Request, Response

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId
from src.core.logging import get_logger
from src.models.audit import AuditLog
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
    org_id: OrganizationId,
    format: ExportFormat = Query(...),
    days: int = Query(30, ge=1, le=365),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    request: Request = None,
):
    """Download one of the caller's tenant reports as a real CSV or PDF file (audited)."""
    gen = ReportGenerator(db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"pysoar-{report_type.value}-{stamp}"
    # Exports carry tenant data out of the platform: record who took what.
    db.add(AuditLog(
        user_id=str(current_user.id),
        organization_id=org_id,
        action="report_export",
        resource_type="report",
        resource_id=report_type.value,
        description=f"Exported {report_type.value} report as {format.value} (last {days} days)",
        ip_address=(request.client.host if request and request.client else None),
        user_agent=(request.headers.get("user-agent") if request else None),
        success=True,
    ))
    await db.flush()

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
