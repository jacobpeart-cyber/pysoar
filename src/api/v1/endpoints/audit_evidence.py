"""
Audit & Evidence Collection REST API Endpoints

REST endpoints for audit logging, evidence collection, packaging,
continuous monitoring, and audit readiness checking.
"""

import os
from typing import Annotated, Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Body, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, require_role, OrganizationId
from src.core.database import get_db
from src.core.logging import get_logger
from src.models.user import User, UserRole
from src.audit_evidence.engine import (
    AuditLogger,
    EvidenceCollector,
    ContinuousMonitor,
    AuditReadinessChecker,
)
from src.audit_evidence.models import (
    AuditTrail,
    EvidencePackage,
    AutomatedEvidenceRule,
)
from src.schemas.audit_evidence import (
    AuditTrailResponse,
    AuditSearchRequest,
    EvidencePackageResponse,
    EvidencePackageCreateRequest,
    AuditReportResponse,
    SuspiciousActivityResponse,
    ConMonReportResponse,
    AuditReadinessResponse,
    EvidenceCoverageResponse,
    EvidenceFreshnessResponse,
    AssessorPackageResponse,
    AuditDashboardStats,
    AutomatedEvidenceRuleResponse,
    AutomatedRuleCreateRequest,
    AuditLogRequest,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/audit-evidence", tags=["audit-evidence"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

# The only directory compliance evidence files are written to (by
# POST /audit-evidence/evidence/upload, under <root>/<org>/<control>/) and
# therefore the only directory the download route will serve from. Before
# 2026-10-08 POST /compliance/evidence stored any client-supplied file_path
# and the download route streamed it, so "/opt/pysoar/.env" was one request
# away. Remote evidence is limited to these object-URL schemes.
EVIDENCE_UPLOAD_ROOT = os.getenv("EVIDENCE_UPLOAD_DIR", "uploads/evidence")
REMOTE_EVIDENCE_SCHEMES = ("https://", "s3://")


def _evidence_org_root(org_id: Optional[str]) -> str:
    return os.path.realpath(os.path.join(EVIDENCE_UPLOAD_ROOT, str(org_id or "unknown")))


def local_evidence_path(location: str, org_id: Optional[str]) -> str:
    """Resolve a stored local evidence path; 403 unless it lies inside the
    caller's organisation directory under EVIDENCE_UPLOAD_ROOT."""
    root = _evidence_org_root(org_id)
    real = os.path.realpath(location)
    if not real.startswith(root + os.sep):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "evidence_path_outside_storage_root",
                "detail": "this evidence item points outside the evidence storage root and cannot be served",
            },
        )
    return real



# ============================================================================
# Audit Trail Endpoints
# ============================================================================


@router.post("/audit/log", response_model=AuditTrailResponse)
async def log_audit_event(
    request: AuditLogRequest,
    http_request: Request,
    current_user: AnalystUser,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Log an audit event as the calling user.

    The actor (id and type) is always the authenticated caller and the IP is
    the connection's client address; the ``actor_id``, ``actor_type`` and
    ``actor_ip`` fields of the request body are ignored, so a caller cannot
    write audit rows attributed to someone else (fixed 2026-10-08).
    """
    ignored = [
        f for f in ("actor_id", "actor_type", "actor_ip")
        if getattr(request, f, None) not in (None, "")
    ]
    if ignored:
        logger.info(
            "audit.log: ignoring client-supplied actor fields",
            user_id=str(current_user.id),
            ignored_fields=ignored,
        )
    client = getattr(http_request, "client", None)
    try:
        audit_logger = AuditLogger(db, org_id)
        trail = await audit_logger.log_event(
            event_type=request.event_type,
            action=request.action,
            actor_type="user",
            actor_id=str(current_user.id),
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            description=request.description,
            old_value=request.old_value,
            new_value=request.new_value,
            result=request.result,
            risk_level=request.risk_level,
            actor_ip=getattr(client, "host", None),
        )
        # AuditLogger only flushes (design v2 §7); the request owns the commit.
        await db.commit()
        return trail
    except Exception as e:
        logger.error(f"Error logging audit event: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/audit/search", response_model=list[AuditTrailResponse])
async def search_audit_trail(
    request: AuditSearchRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Search audit trail with filters (read-only: viewers allowed)."""
    try:
        audit_logger = AuditLogger(db, org_id)

        filters = {}
        if request.event_type:
            filters["event_type"] = request.event_type
        if request.actor_id:
            filters["actor_id"] = request.actor_id
        if request.resource_type:
            filters["resource_type"] = request.resource_type
        if request.result:
            filters["result"] = request.result
        if request.risk_level:
            filters["risk_level"] = request.risk_level
        if request.date_from:
            filters["date_from"] = request.date_from
        if request.date_to:
            filters["date_to"] = request.date_to

        # Paged in SQL (it used to load every matching row and slice).
        return await audit_logger.search_audit_trail(filters, offset=request.skip, limit=request.limit)
    except Exception as e:
        logger.error(f"Error searching audit trail: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/audit/export", response_model=None)
async def export_audit_trail(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    format: str = Query("json", pattern="^(json|csv|xml)$"),
    days: int = Query(30, ge=1, le=365),
):
    """Export audit trail"""
    try:
        audit_logger = AuditLogger(db, org_id)

        date_from = datetime.now(timezone.utc) - timedelta(days=days)
        date_to = datetime.now(timezone.utc)

        report = await audit_logger.generate_audit_report(
            date_range=(date_from, date_to)
        )

        return {
            "export_format": format,
            "date_range": {
                "from": date_from.isoformat(),
                "to": date_to.isoformat(),
            },
            "audit_report": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error exporting audit trail: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/audit/suspicious-activity", response_model=list[dict])
async def detect_suspicious_activity(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    actor_id: str = Query(...),
):
    """Detect suspicious activity for actor"""
    try:
        audit_logger = AuditLogger(db, org_id)
        activities = await audit_logger.detect_suspicious_activity(actor_id)
        return activities
    except Exception as e:
        logger.error(f"Error detecting suspicious activity: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Evidence Collection Endpoints
# ============================================================================


@router.post("/evidence/upload", response_model=None)
async def upload_evidence_file(
    org_id: OrganizationId,
    file: UploadFile = File(...),
    control_id: str = Form(...),
    title: str = Form(...),
    evidence_type: str = Form("document"),
    description: str = Form(""),
    db: DatabaseSession = None,
    current_user: AnalystUser = None,
):
    """Upload a real evidence artifact for a specific compliance control.

    Stores the file under ``uploads/evidence/<org>/<control_id>/<uuid>_<filename>``,
    computes a SHA-512 hash, and creates a ``ComplianceEvidence`` row tied to
    the referenced ``ComplianceControl``. Raises 404 if the control doesn't
    exist for the caller's org so users can't upload evidence into a
    non-existent or cross-tenant control.
    """
    import hashlib
    import os
    import uuid as _uuid

    from src.compliance.models import ComplianceControl, ComplianceEvidence


    # Verify control exists and belongs to the caller's org
    ctrl_result = await db.execute(
        select(ComplianceControl).where(
            and_(
                ComplianceControl.id == control_id,
                ComplianceControl.organization_id == org_id,
            )
        )
    )
    control = ctrl_result.scalar_one_or_none()
    if not control:
        raise HTTPException(
            status_code=404,
            detail="Compliance control not found for this organization",
        )

    # Persist file to disk under an org + control namespaced directory
    target_dir = os.path.join(EVIDENCE_UPLOAD_ROOT, str(org_id or "unknown"), control_id)
    os.makedirs(target_dir, exist_ok=True)

    safe_name = (file.filename or "evidence").replace("/", "_").replace("\\", "_")
    unique = f"{_uuid.uuid4().hex}_{safe_name}"
    dest_path = os.path.join(target_dir, unique)

    hasher = hashlib.sha512()
    total_bytes = 0
    file_written = False
    try:
        with open(dest_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                hasher.update(chunk)
                f.write(chunk)
        file_written = True

        evidence = ComplianceEvidence(
            control_id_ref=control_id,
            evidence_type=evidence_type,
            title=title,
            description=description or None,
            file_path=dest_path,
            file_hash=hasher.hexdigest(),
            collected_at=datetime.now(timezone.utc),
            # The uploader's id (separation of duties compares it with the approver).
            collected_by=str(current_user.id),
            is_automated=False,
            is_valid=True,
            review_status="pending",
            tags=[],
            organization_id=org_id,
        )
        db.add(evidence)
        await db.flush()
        await db.refresh(evidence)
    except Exception:
        # Roll back the disk write if the DB insert (or anything else) fails
        # so we don't leak an orphan file with no row referencing it.
        if file_written:
            try:
                os.remove(dest_path)
            except OSError:
                logger.warning(f"Failed to remove orphan evidence file: {dest_path}")
        raise

    return {
        "status": "uploaded",
        "evidence_id": evidence.id,
        "control_id": control_id,
        "file_path": dest_path,
        "file_hash": evidence.file_hash,
        "file_size_bytes": total_bytes,
        "title": title,
        "uploaded_at": evidence.collected_at.isoformat(),
    }


@router.get("/evidence/{evidence_id}/download")
async def download_evidence_file(
    evidence_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Stream a previously uploaded evidence artifact back to the caller.

    Tenant-scoped via organization_id — a user in org A cannot download
    evidence from org B even by ID.
    """
    from fastapi.responses import FileResponse, RedirectResponse
    from src.compliance.models import ComplianceEvidence

    result = await db.execute(
        select(ComplianceEvidence).where(
            and_(
                ComplianceEvidence.id == evidence_id,
                ComplianceEvidence.organization_id == org_id,
            )
        )
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    loc = evidence.file_path or ""
    if not loc:
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")
    # Remote object URL: redirect, but only to the schemes a client may register.
    if loc.startswith(REMOTE_EVIDENCE_SCHEMES):
        return RedirectResponse(url=loc)
    if "://" in loc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_storage_location", "detail": "only https:// and s3:// evidence URLs are served"},
        )
    # Local path: must resolve inside this organisation's evidence root (403 otherwise).
    path = local_evidence_path(loc, org_id)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail="Evidence file missing on disk",
        )
    original_name = os.path.basename(path).split("_", 1)[-1] or "evidence"
    return FileResponse(
        path=path,
        media_type="application/octet-stream",
        filename=original_name,
    )


@router.get("/reports/monthly")
async def download_monthly_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Generate and stream a monthly FedRAMP ConMon report as a JSON download.

    Runs the real ``ContinuousMonitor.generate_conmon_report()`` and wraps
    it in a FedRAMP-shaped monthly report envelope: report metadata, the
    30-day window, the real control check summary, and POA&M progress.
    Returns the document as a StreamingResponse so the browser saves it
    as a dated filename instead of rendering JSON in a tab.
    """
    import io
    import json as _json
    from fastapi.responses import StreamingResponse

    try:
        monitor = ContinuousMonitor(db, org_id)
        conmon = await monitor.generate_conmon_report()
        last_cycle = await monitor.latest_cycle()
    except Exception as exc:
        logger.error(f"Monthly report generation failed: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate monthly report",
        )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=30)

    document = {
        "report_type": "FedRAMP Continuous Monitoring Monthly Report",
        "generated_at": now.isoformat(),
        "reporting_period": {
            "start": window_start.isoformat(),
            "end": now.isoformat(),
            "days": 30,
        },
        "organization_id": org_id,
        "conmon_report": conmon,
        "last_stored_cycle": (
            {k: last_cycle[k] for k in ("assessment_id", "ran_at", "overall_status")} if last_cycle else None
        ),
    }

    content = _json.dumps(document, indent=2, default=str)
    filename = f"pysoar_conmon_monthly_{now.strftime('%Y-%m')}.json"

    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/evidence/collect", response_model=None)
async def collect_evidence(
    org_id: OrganizationId,
    request: dict = Body(...),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Run one automated evidence rule.

    ``status`` is the collector's real outcome: ``collected`` (evidence rows
    written), ``no_matching_controls``, ``awaiting_integration`` (api_query
    rules) or ``failed`` with the reason. It used to answer "success" around
    collectors that collected nothing.
    """
    rule_id = request.get("rule_id")
    if not rule_id:
        raise HTTPException(status_code=422, detail={"error": "rule_id_required", "field": "rule_id"})
    try:
        collector = EvidenceCollector(db, org_id)
        result = await collector.collect_evidence(rule_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Evidence rule not found") from e
    return {
        "status": result["status"],
        "evidence": result,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/evidence/collect-all", response_model=None)
async def collect_all_automated_evidence(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
    request: Optional[dict] = Body(None),
):
    """Run every enabled automated evidence rule.

    An optional ``{"family": "AC"}`` body limits the run to rules mapped to
    controls of that family (the FedRAMP page sends it; it used to be
    ignored). The counts say what was actually collected.
    """
    family = (request or {}).get("family") if isinstance(request, dict) else None
    collector = EvidenceCollector(db, org_id)
    results = await collector.collect_all_automated(family=family)
    statuses = [r.get("status") for r in results.values()]
    return {
        "status": "completed" if results else "no_rules",
        "reason": None if results else (
            "no enabled automated evidence rule" + (f" maps to family {family}" if family else "")
            + " in this organisation; create one under /audit-evidence/rules/create"
        ),
        "family": family,
        "rules_run": len(results),
        "collected": statuses.count("collected"),
        "awaiting_integration": statuses.count("awaiting_integration"),
        "no_matching_controls": statuses.count("no_matching_controls"),
        "failed": statuses.count("failed"),
        "evidence_written": sum(int(r.get("evidence_written") or 0) for r in results.values()),
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/evidence/verify", response_model=None)
async def verify_evidence_integrity(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    evidence_id: str = Query(...),
    _user: AnalystUser = None,
):
    """Re-hash an evidence file and compare it with the hash recorded at upload.

    ``integrity_valid`` is true/false when the file was re-hashed and null
    with ``status: "unverifiable"`` when no hash or no local file exists.
    """
    try:
        collector = EvidenceCollector(db, org_id)
        result = await collector.verify_evidence_integrity(
            evidence_id,
            resolve_local_path=lambda location: local_evidence_path(location, org_id),
        )
        return {
            "evidence_id": evidence_id,
            **result,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
    except HTTPException:
        raise
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Evidence not found") from e
    except Exception as e:
        logger.error(f"Error verifying evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.delete("/evidence/{evidence_id}", status_code=204)
async def delete_evidence_item(
    evidence_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AnalystUser = None,
):
    """Delete a ComplianceEvidence row.

    The frontend's "Delete" button hit this route and silently 404'd
    because it wasn't declared. Now validates ownership (org-scoped),
    soft-deletes by setting ``is_valid=False``, and writes an audit
    trail entry so an assessor can see the removal.
    """
    from src.compliance.models import ComplianceEvidence

    result = await db.execute(
        select(ComplianceEvidence).where(
            and_(
                ComplianceEvidence.id == evidence_id,
                ComplianceEvidence.organization_id == org_id,
            )
        )
    )
    evidence = result.scalar_one_or_none()
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    evidence.is_valid = False
    evidence.review_status = "rejected"
    evidence.reviewed_by = str(getattr(current_user, "id", ""))
    evidence.reviewed_at = datetime.now(timezone.utc)
    await db.flush()

    # Record the deletion in the audit trail
    try:
        audit_logger = AuditLogger(db, org_id)
        await audit_logger.log_event(
            event_type="change",
            action="evidence.soft_delete",
            actor_type="user",
            actor_id=str(getattr(current_user, "id", "")),
            resource_type="ComplianceEvidence",
            resource_id=evidence_id,
            description=f"Evidence {evidence_id} soft-deleted",
            result="success",
            risk_level="medium",
        )
    except Exception as exc:  # noqa: BLE001
        # Fail closed: the soft-delete is not committed without its audit row.
        await db.rollback()
        logger.error(f"Audit trail for evidence delete failed: {exc}")
        raise HTTPException(status_code=503, detail="Audit trail unavailable; evidence not deleted")
    await db.commit()

    return None


@router.post("/evidence/{evidence_id}/approve", status_code=200)
async def approve_evidence_item(
    evidence_id: str,
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    db: DatabaseSession = None,
):
    """Mark a ComplianceEvidence row as approved (admin only).

    Frontend "Approve" button hit this route and 404'd the same way
    the delete button did. Now sets review_status=approved, records
    the approver + timestamp, and writes an audit trail entry.
    """
    from src.compliance.models import ComplianceEvidence

    result = await db.execute(
        select(ComplianceEvidence).where(
            and_(
                ComplianceEvidence.id == evidence_id,
                ComplianceEvidence.organization_id == org_id,
            )
        )
    )
    evidence = result.scalar_one_or_none()
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # Separation of duties: the uploader cannot approve their own evidence.
    from src.compliance.separation_of_duties import ensure_not_uploader

    ensure_not_uploader(evidence, current_user)

    evidence.review_status = "approved"
    evidence.reviewed_by = str(getattr(current_user, "id", ""))
    evidence.reviewed_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(evidence)

    try:
        audit_logger = AuditLogger(db, org_id)
        await audit_logger.log_event(
            event_type="policy",
            action="evidence.approve",
            actor_type="user",
            actor_id=str(getattr(current_user, "id", "")),
            resource_type="ComplianceEvidence",
            resource_id=evidence_id,
            description=f"Evidence {evidence_id} approved",
            result="success",
            risk_level="low",
        )
    except Exception as exc:  # noqa: BLE001
        # Fail closed: the approval is not committed without its audit row.
        await db.rollback()
        logger.error(f"Audit trail for evidence approve failed: {exc}")
        raise HTTPException(status_code=503, detail="Audit trail unavailable; evidence not approved")
    await db.commit()

    return {
        "id": evidence.id,
        "status": evidence.review_status,
        "reviewed_by": evidence.reviewed_by,
        "reviewed_at": evidence.reviewed_at.isoformat() if evidence.reviewed_at else None,
    }


@router.get("/evidence/list", response_model=list[dict])
async def list_evidence_items(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    evidence_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List evidence items from the ComplianceEvidence repository.

    Returns data in the shape the frontend expects: id, title, type,
    control, source, collected, status, contentUrl.
    """
    try:
        from src.compliance.models import ComplianceEvidence, ComplianceControl

        query = select(ComplianceEvidence).where(
            ComplianceEvidence.organization_id == org_id
        )
        if evidence_type and evidence_type != "all":
            query = query.where(ComplianceEvidence.evidence_type == evidence_type)
        if status_filter and status_filter != "all":
            query = query.where(ComplianceEvidence.review_status == status_filter)
        query = query.order_by(ComplianceEvidence.collected_at.desc()).offset(skip).limit(limit)

        result = await db.execute(query)
        evidence_rows = list(result.scalars().all())

        # Resolve control_id labels in one batch lookup
        control_ids = {e.control_id_ref for e in evidence_rows if e.control_id_ref}
        control_map: dict[str, str] = {}
        if control_ids:
            ctrl_result = await db.execute(
                select(ComplianceControl).where(ComplianceControl.id.in_(control_ids))
            )
            control_map = {c.id: c.control_id for c in ctrl_result.scalars().all()}

        type_alias = {
            "configuration": "config",
            "scan_result": "scan",
            "automated_test": "scan",
            "policy": "document",
            "procedure": "document",
            "interview_notes": "document",
            "training_record": "document",
        }

        items: list[dict] = []
        for e in evidence_rows:
            items.append({
                "id": e.id,
                "title": e.title,
                "type": type_alias.get(e.evidence_type, e.evidence_type or "document"),
                "control": control_map.get(e.control_id_ref, e.control_id_ref or "—"),
                "source": e.source_system or "manual",
                "collected": e.collected_at.isoformat() if e.collected_at else None,
                "status": e.review_status or "pending",
                "contentUrl": e.file_path,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            })
        return items
    except Exception as e:
        logger.error(f"Error listing evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Evidence Package Endpoints
# ============================================================================


@router.post("/packages/create", response_model=EvidencePackageResponse)
async def create_evidence_package(
    request: EvidencePackageCreateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Create evidence package"""
    try:
        package = EvidencePackage(
            name=request.name,
            description=request.description,
            package_type=request.package_type,
            framework_id=request.framework_id,
            assessor=request.assessor,
            due_date=request.due_date,
            extra_metadata=request.metadata or {},
            organization_id=org_id,
        )
        db.add(package)
        await db.commit()
        return package
    except Exception as e:
        logger.error(f"Error creating evidence package: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/packages", response_model=list[EvidencePackageResponse])
async def list_evidence_packages(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List evidence packages"""
    try:
        query = select(EvidencePackage).where(
            EvidencePackage.organization_id == org_id
        )
        if status:
            query = query.where(EvidencePackage.status == status)
        query = query.offset(skip).limit(limit)
        packages = await db.scalars(query)
        return list(packages)
    except Exception as e:
        logger.error(f"Error listing evidence packages: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/packages/{package_id}", response_model=EvidencePackageResponse)
async def get_evidence_package(
    package_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get evidence package details"""
    try:
        query = select(EvidencePackage).where(
            (EvidencePackage.id == package_id)
            & (EvidencePackage.organization_id == org_id)
        )
        package = await db.scalar(query)
        if not package:
            raise HTTPException(status_code=404, detail="Package not found")
        return package
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting evidence package: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/packages/{package_id}/evidence", response_model=None)
async def add_evidence_to_package(
    package_id: str,
    org_id: OrganizationId,
    request: dict = Body(...),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Attach evidence items (``{"evidence_ids": [...]}``) of this organisation
    to a package. Ids outside the organisation are reported as not found."""
    evidence_ids = request.get("evidence_ids") if isinstance(request, dict) else None
    if not isinstance(evidence_ids, list) or not evidence_ids or not all(isinstance(e, str) for e in evidence_ids):
        raise HTTPException(
            status_code=422,
            detail={"error": "evidence_ids_required", "field": "evidence_ids",
                    "detail": "send a non-empty list of evidence ids"},
        )
    try:
        return await EvidenceCollector(db, org_id).add_evidence_to_package(package_id, evidence_ids[:500])
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Package not found") from e


@router.post("/packages/{package_id}/package", response_model=None)
async def package_evidence(
    package_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Seal a package (hash of its evidence items) for submission; 409 when empty."""
    try:
        collector = EvidenceCollector(db, org_id)
        result = await collector.package_evidence(package_id)
        return result
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Package not found") from e
    except ValueError as e:
        raise HTTPException(status_code=409, detail={"error": "package_empty", "detail": str(e)}) from e


@router.post("/packages/{package_id}/submit", response_model=None)
async def submit_evidence_package(
    package_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Submit evidence package to assessor"""
    try:
        # Update package status to submitted
        query = select(EvidencePackage).where(
            EvidencePackage.id == package_id,
            EvidencePackage.organization_id == org_id,
        )
        package = await db.scalar(query)
        if not package:
            raise HTTPException(status_code=404, detail="Package not found")
        if not package.evidence_items:
            raise HTTPException(
                status_code=409,
                detail={"error": "package_empty",
                        "detail": "attach evidence (POST /packages/{id}/evidence) before submitting"},
            )

        package.status = "submitted"
        package.submitted_at = datetime.now(timezone.utc)
        db.add(package)
        await db.commit()

        return {
            "package_id": package_id,
            "status": "submitted",
            "submitted_at": package.submitted_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting evidence package: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/packages/{package_id}/report", response_model=None)
async def get_evidence_report(
    package_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get evidence report for package"""
    try:
        collector = EvidenceCollector(db, org_id)
        result = await collector.generate_evidence_report(package_id)
        return result
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Package not found") from e
    except Exception as e:
        logger.error(f"Error generating evidence report: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Continuous Monitoring Endpoints
# ============================================================================


@router.post("/conmon/run-cycle", response_model=ConMonReportResponse)
async def run_conmon_cycle(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AnalystUser = None,
):
    """Run a ConMon cycle and store it (its time becomes ``lastRun``)."""
    return await _run_and_record_conmon(db, org_id, current_user)


async def _run_and_record_conmon(db: AsyncSession, org_id: str, current_user: User) -> dict:
    actor = str(getattr(current_user, "id", "") or "system")
    monitor = ContinuousMonitor(db, org_id)
    report = await monitor.run_and_persist(assessor=f"user:{actor}")
    try:
        await AuditLogger(db, org_id).log_event(
            event_type="system",
            action="conmon.run",
            actor_type="user",
            actor_id=actor,
            resource_type="ComplianceAssessment",
            resource_id=str(report.get("assessment_id")),
            description=f"ConMon cycle run: overall {report.get('overall_status')}",
            result="success",
            risk_level="low",
        )
    except Exception as exc:  # noqa: BLE001 - fail closed: no cycle without its audit row
        await db.rollback()
        logger.error("conmon_audit_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Audit trail unavailable; ConMon cycle not recorded") from exc
    await db.commit()
    return report


@router.post("/conmon/run", response_model=None)
async def run_conmon_alias(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    current_user: AnalystUser = None,
):
    """Alias for /conmon/run-cycle used by the frontend ConMon button."""
    report = await _run_and_record_conmon(db, org_id, current_user)
    return {"ok": True, "report": report}


@router.get("/conmon/report", response_model=None)
async def get_conmon_report(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """The latest stored ConMon cycle; when none was ever run, the checks are
    computed now and returned with ``persisted: false``."""
    monitor = ContinuousMonitor(db, org_id)
    latest = await monitor.latest_cycle()
    if latest and latest.get("report"):
        return {**latest["report"], "persisted": True, "assessment_id": latest["assessment_id"],
                "last_run": latest["ran_at"]}
    report = await monitor.generate_conmon_report()
    return {**report, "persisted": False, "last_run": None}


@router.get("/conmon/status", response_model=None)
async def get_conmon_status(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """ConMon status per check, computed now from stored rows.

    Returns an ARRAY of rows {id, name, active, lastRun, status,
    compliance_percentage, reason, details}. ``lastRun`` is the time of the
    last stored cycle (null when none ran; it used to be the request time);
    a check with no data is ``not_assessed`` with a null percentage.
    """
    monitor = ContinuousMonitor(db, org_id)
    cycle = await monitor.run_conmon_cycle()
    latest = await monitor.latest_cycle()
    last_run = latest["ran_at"] if latest else None

    rows: list[dict] = []
    for key, label in ContinuousMonitor.LABELS.items():
        check = cycle.get(key) or {}
        check_status = check.get("status", "not_assessed")
        rows.append({
            "id": key,
            "name": label,
            "active": check_status in ContinuousMonitor.PASSING,
            "status": check_status,
            "lastRun": last_run,
            "compliance_percentage": check.get("compliance_percentage"),
            "reason": check.get("reason"),
            "details": check,
        })
    return rows


# ============================================================================
# Audit Readiness Endpoints
# ============================================================================


@router.get("/readiness/check", response_model=AuditReadinessResponse)
async def check_audit_readiness(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework: str = Query(..., description="Framework id, short name or name"),
):
    """Audit readiness of one framework, from its control statuses."""
    checker = AuditReadinessChecker(db, org_id)
    return await checker.check_readiness(framework)


@router.get("/readiness/coverage", response_model=EvidenceCoverageResponse)
async def check_evidence_coverage(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework_id: str = Query(..., description="Framework id or short name"),
):
    """Evidence coverage per control, from the stored evidence rows.

    Read-only: it used to fire an evidence-gap automation (and POA&M
    creation) for up to 25 controls on every GET.
    """
    try:
        return await AuditReadinessChecker(db, org_id).check_evidence_coverage(framework_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Framework not found") from e


@router.get("/readiness/freshness", response_model=EvidenceFreshnessResponse)
async def check_evidence_freshness(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework_id: str = Query(..., description="Framework id or short name"),
):
    """Evidence freshness (collected within a year and unexpired)."""
    try:
        return await AuditReadinessChecker(db, org_id).check_evidence_freshness(framework_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Framework not found") from e


@router.get("/readiness/assessor-package", response_model=AssessorPackageResponse)
async def generate_assessor_package(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    framework_id: str = Query(..., description="Framework id or short name"),
):
    """Coverage + freshness summary for external assessors."""
    try:
        return await AuditReadinessChecker(db, org_id).generate_assessor_package(framework_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail="Framework not found") from e


# ============================================================================
# Automated Rules Endpoints
# ============================================================================


@router.post("/rules/create", response_model=AutomatedEvidenceRuleResponse)
async def create_evidence_rule(
    request: AutomatedRuleCreateRequest,
    org_id: OrganizationId,
    _user: AdminRoleUser,
    db: DatabaseSession = None,
):
    """Create automated evidence collection rule (configuration: admin only)."""
    try:
        rule = AutomatedEvidenceRule(
            name=request.name,
            control_ids=request.control_ids or {},
            evidence_type=request.evidence_type,
            collection_method=request.collection_method,
            collection_config=request.collection_config,
            schedule=request.schedule,
            is_enabled=request.is_enabled,
            organization_id=org_id,
        )
        db.add(rule)
        await db.commit()
        return rule
    except Exception as e:
        logger.error(f"Error creating evidence rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/rules", response_model=list[AutomatedEvidenceRuleResponse])
async def list_evidence_rules(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List automated evidence collection rules"""
    try:
        query = (
            select(AutomatedEvidenceRule)
            .where(AutomatedEvidenceRule.organization_id == org_id)
            .offset(skip)
            .limit(limit)
        )
        rules = await db.scalars(query)
        return list(rules)
    except Exception as e:
        logger.error(f"Error listing evidence rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard/stats", response_model=AuditDashboardStats)
async def get_audit_dashboard_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Audit and evidence dashboard statistics, all counted in SQL.

    Wave 4 adds the fields the page reads and could not find
    (``audit_events_last_24h``, ``total_evidence_items``,
    ``recent_audit_events``) plus ``readiness_score`` (FedRAMP Moderate
    readiness from control statuses, null when the framework has no
    controls) and the real last ConMon run.
    """
    from src.compliance.models import ComplianceEvidence

    now = datetime.now(timezone.utc)
    this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    in_org = AuditTrail.organization_id == org_id

    async def _count(stmt) -> int:
        return int((await db.execute(stmt)).scalar() or 0)

    total_audit = await _count(select(func.count(AuditTrail.id)).where(in_org))
    month_audits = await _count(select(func.count(AuditTrail.id)).where(in_org, AuditTrail.created_at >= this_month))
    last_24h = await _count(select(func.count(AuditTrail.id)).where(in_org, AuditTrail.created_at >= now - timedelta(hours=24)))
    critical = await _count(select(func.count(AuditTrail.id)).where(in_org, AuditTrail.risk_level == "critical"))
    event_types_breakdown = {
        str(k or "unknown"): int(n) for k, n in (await db.execute(
            select(AuditTrail.event_type, func.count(AuditTrail.id)).where(in_org).group_by(AuditTrail.event_type)
        )).all()
    }
    risk_distribution = {
        str(k or "unknown").lower(): int(n) for k, n in (await db.execute(
            select(AuditTrail.risk_level, func.count(AuditTrail.id)).where(in_org).group_by(AuditTrail.risk_level)
        )).all()
    }
    recent = list(await db.scalars(select(AuditTrail).where(in_org).order_by(AuditTrail.created_at.desc()).limit(10)))
    recent_audit_events = [
        {
            "id": a.id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "event_type": a.event_type,
            "action": a.action,
            "actor_id": a.actor_id,
            "resource_type": a.resource_type,
            "result": a.result,
            "risk_level": a.risk_level,
        }
        for a in recent
    ]

    pkg_counts = {
        str(k): int(n) for k, n in (await db.execute(
            select(EvidencePackage.status, func.count(EvidencePackage.id))
            .where(EvidencePackage.organization_id == org_id).group_by(EvidencePackage.status)
        )).all()
    }
    ev_in_org = ComplianceEvidence.organization_id == org_id
    total_evidence = await _count(select(func.count(ComplianceEvidence.id)).where(ev_in_org))
    approved_evidence = await _count(
        select(func.count(ComplianceEvidence.id)).where(ev_in_org, ComplianceEvidence.review_status == "approved"))

    # Share of packaged evidence items that are approved, averaged over the
    # packages that hold any (bounded to the 100 newest packages).
    pkg_scores: list[float] = []
    for items in (await db.execute(
        select(EvidencePackage.evidence_items).where(EvidencePackage.organization_id == org_id)
        .order_by(EvidencePackage.created_at.desc()).limit(100)
    )).scalars().all():
        ids = [str(i) for i in (items or {}) if i]
        if not ids:
            continue
        statuses = (await db.execute(
            select(ComplianceEvidence.review_status).where(ev_in_org, ComplianceEvidence.id.in_(ids))
        )).scalars().all()
        if statuses:
            pkg_scores.append(sum(1 for s in statuses if s == "approved") / len(statuses) * 100.0)
    avg_pkg_compliance = round(sum(pkg_scores) / len(pkg_scores), 1) if pkg_scores else 0.0

    suspicious_count = 0
    audit_logger = AuditLogger(db, org_id)
    actor_ids = (await db.execute(
        select(AuditTrail.actor_id).where(in_org, AuditTrail.created_at >= now - timedelta(days=30))
        .distinct().limit(25)
    )).scalars().all()
    for actor_id in actor_ids:
        if actor_id and await audit_logger.detect_suspicious_activity(actor_id):
            suspicious_count += 1

    readiness = await AuditReadinessChecker(db, org_id).check_readiness("fedramp_moderate")
    latest = await ContinuousMonitor(db, org_id).latest_cycle()

    return AuditDashboardStats(
        organization_id=org_id,
        total_audit_entries=total_audit,
        audit_entries_this_month=month_audits,
        audit_events_last_24h=last_24h,
        event_types_breakdown=event_types_breakdown,
        risk_distribution=risk_distribution,
        total_evidence_packages=sum(pkg_counts.values()),
        evidence_packages_in_progress=pkg_counts.get("collecting", 0),
        evidence_packages_submitted=pkg_counts.get("submitted", 0),
        avg_evidence_package_compliance=avg_pkg_compliance,
        suspicious_activities_detected=suspicious_count,
        critical_audit_events=critical,
        total_evidence_items=total_evidence,
        approved_evidence_items=approved_evidence,
        recent_audit_events=recent_audit_events,
        readiness_score=readiness["readiness_percentage"] if readiness.get("total_controls") else None,
        readiness_framework=readiness.get("framework_id"),
        last_conmon_run=latest["ran_at"] if latest else None,
        conmon_status=(latest["overall_status"] if latest else "not_run") or "not_run",
    )
