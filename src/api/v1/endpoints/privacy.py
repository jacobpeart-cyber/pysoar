"""
Privacy Engineering REST API Endpoints

Complete API for managing Data Subject Requests (DSRs), Privacy Impact Assessments (PIAs),
Consent Records, Data Processing Records (ROPA), and Privacy Incidents.
Handles GDPR, CCPA, LGPD, PIPA, PDPA, and HIPAA compliance automation.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional, Dict, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status, Query
from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from sqlalchemy import select, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.api.deps import get_current_active_user as get_current_user
from src.core.database import get_db
from src.services.automation import AutomationService
from src.schemas.privacy import (
    DataSubjectRequestCreate,
    DataSubjectRequestUpdate,
    DataSubjectRequestResponse,
    DataSubjectRequestListResponse,
    PrivacyImpactAssessmentCreate,
    PrivacyImpactAssessmentUpdate,
    PrivacyImpactAssessmentResponse,
    ConsentRecordCreate,
    ConsentRecordUpdate,
    ConsentRecordResponse,
    DataProcessingRecordCreate,
    DataProcessingRecordUpdate,
    DataProcessingRecordResponse,
    PrivacyIncidentCreate,
    PrivacyIncidentUpdate,
    PrivacyIncidentResponse,
    PrivacyDashboardStats,
    DSRDeadlineAlert,
    DSRErasureRequest,
    DSRIdentityVerification,
    RetentionViolation,
    PaginationParams,
)
from src.privacy.models import (
    DataSubjectRequest,
    PrivacyImpactAssessment,
    ConsentRecord,
    DataProcessingRecord,
    PrivacyIncident,
    DSRStatus,
    PIAStatus,
)
from src.privacy.engine import (
    DSRProcessor,
    PIAEngine,
    ConsentManager,
    DataGovernance,
    PrivacyIncidentManager,
)
from src.models.audit import AuditLog
from src.privacy import dsr as dsr_flow
from src.privacy.tasks import (
    dsr_deadline_monitor,
    consent_expiry_check,
    retention_enforcement,
    pia_review_reminder,
    cross_border_audit,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/privacy", tags=["privacy"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


async def _get_dsr_or_404(db: AsyncSession, request_id: str, org_id: str) -> DataSubjectRequest:
    """Load a DSR inside the caller's organisation or raise 404."""
    result = await db.execute(
        select(DataSubjectRequest).where(
            DataSubjectRequest.id == request_id,
            DataSubjectRequest.organization_id == org_id,
        )
    )
    dsr = result.scalar_one_or_none()
    if dsr is None:
        raise HTTPException(status_code=404, detail="DSR not found")
    return dsr


async def _get_pia_or_404(
    db: AsyncSession, assessment_id: str, org_id: str
) -> PrivacyImpactAssessment:
    """Load a PIA inside the caller's organisation or raise 404."""
    result = await db.execute(
        select(PrivacyImpactAssessment).where(
            PrivacyImpactAssessment.id == assessment_id,
            PrivacyImpactAssessment.organization_id == org_id,
        )
    )
    pia = result.scalar_one_or_none()
    if pia is None:
        raise HTTPException(status_code=404, detail="PIA not found")
    return pia


def _not_implemented(detail: str) -> HTTPException:
    """Honest 501 for workflow steps PySOAR does not actually perform."""
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "not_implemented", "detail": detail},
    )


# ============================================================================
# DATA SUBJECT REQUEST (DSR) ENDPOINTS
# ============================================================================


async def _audit(
    db: AsyncSession,
    user: Optional[User],
    org_id: str,
    action: str,
    resource_id: Optional[str],
    description: str,
    payload: Dict[str, Any],
) -> None:
    """One AuditLog row per privacy workflow action (DSR steps, erasure)."""
    db.add(AuditLog(
        user_id=str(user.id) if user is not None else None,
        organization_id=org_id,
        action=action,
        resource_type="privacy",
        resource_id=resource_id,
        description=description[:4000],
        new_value=json.dumps(payload, default=str),
        success=True,
    ))
    await db.flush()


def _conflict(detail: str, error: str = "invalid_dsr_state") -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error": error, "detail": detail})


@router.post("/dsr/requests", response_model=DataSubjectRequestResponse, status_code=201)
async def create_dsr(
    dsr: DataSubjectRequestCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Create new Data Subject Request.

    Supports GDPR Article 12-22, CCPA § 1798.100-1798.120, and other regulations.
    The deadline is computed from the regulation (GDPR 30 days, CCPA 45,
    LGPD 15, otherwise 30); ``description`` is stored as the request's
    processing notes.

    Request Types:
    - access: Right to access data (GDPR Article 15)
    - rectification: Right to correct data (GDPR Article 16)
    - erasure: Right to be forgotten (GDPR Article 17)
    - portability: Right to data portability (GDPR Article 20)
    - restriction: Right to restrict processing (GDPR Article 18)
    - objection: Right to object to processing (GDPR Article 21)
    - automated_decision: Right to human review (GDPR Article 22)
    """
    processor = DSRProcessor(db, org_id)
    request = await processor.receive_request(
        request_type=dsr.request_type.value,
        regulation=dsr.regulation.value,
        subject_name=dsr.subject_name,
        subject_email=dsr.subject_email,
        subject_identifier=dsr.subject_identifier,
        processing_notes=dsr.description,
    )
    await _audit(db, _user, org_id, "privacy.dsr_create", request.id,
                 f"DSR ({request.request_type}, {request.regulation}) received",
                 {"deadline": request.deadline, "request_type": request.request_type})
    await db.commit()
    await db.refresh(request)

    try:
        automation = AutomationService(db)
        await automation.on_privacy_dsr_created(
            dsr_id=request.id,
            subject_email=request.subject_email,
            request_type=request.request_type,
            regulation=request.regulation,
            organization_id=org_id,
        )
    except Exception as automation_exc:  # automation is best-effort; the DSR is stored
        logger.warning(f"Automation on_privacy_dsr_created failed: {automation_exc}")

    return request


@router.get("/dsr/requests", response_model=DataSubjectRequestListResponse)
async def list_dsrs(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    regulation: Optional[str] = None,
    overdue: Optional[bool] = Query(None, description="Only open DSRs past their deadline"),
):
    """
    List Data Subject Requests with pagination.

    Query Parameters:
    - status: Filter by DSR status
    - regulation: Filter by regulation (gdpr, ccpa, lgpd, etc.)
    - overdue: only open requests whose stored deadline has passed
    - page, size: Pagination

    Each item carries ``days_remaining`` / ``overdue`` computed from its
    stored deadline.
    """
    stmt = select(DataSubjectRequest).where(DataSubjectRequest.organization_id == org_id)
    if status_filter:
        stmt = stmt.where(DataSubjectRequest.status == status_filter)
    if regulation:
        stmt = stmt.where(DataSubjectRequest.regulation == regulation)
    if overdue:
        # Deadlines are stored as ISO-8601 UTC strings, which sort as text.
        stmt = stmt.where(
            DataSubjectRequest.status.in_(sorted(dsr_flow.OPEN_STATUSES)),
            DataSubjectRequest.deadline < datetime.now(timezone.utc).isoformat(),
        )

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    stmt = stmt.order_by(DataSubjectRequest.created_at.desc()).offset((page - 1) * size).limit(size)
    requests = (await db.execute(stmt)).scalars().all()
    return DataSubjectRequestListResponse(total=total, page=page, size=size, items=requests)


@router.get("/dsr/sources")
async def list_dsr_sources(
    org_id: OrganizationId,
):
    """Every data source a DSR searches, exports and erases, with what
    erasure does there (anonymise / redact / delete / retain + reason)."""
    return {
        "organization_id": org_id,
        "export_cap_per_source": dsr_flow.EXPORT_CAP,
        "erase_cap_per_source": dsr_flow.ERASE_CAP,
        "sources": [
            {
                "key": s.key,
                "label": s.label,
                "erasure": s.erasure,
                "retain_reason": s.retain_reason,
                "note": s.note,
                "fields_exported": s.fields,
            }
            for s in dsr_flow.SUBJECT_SOURCES
        ],
    }


@router.get("/dsr/deadline-alerts", response_model=List[DSRDeadlineAlert])
async def list_deadline_alerts(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Open DSRs past (BREACHED) or within 7 days of (CRITICAL) their deadline."""
    processor = DSRProcessor(db, org_id)
    return await processor.track_deadline_compliance()


@router.get("/dsr/requests/{request_id}", response_model=DataSubjectRequestResponse)
async def get_dsr(
    request_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get Data Subject Request by ID."""
    return await _get_dsr_or_404(db, request_id, org_id)


@router.patch(
    "/dsr/requests/{request_id}", response_model=DataSubjectRequestResponse
)
async def update_dsr(
    request_id: str,
    dsr_update: DataSubjectRequestUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update a DSR's status or notes.

    Status changes follow the workflow (409 otherwise): received ->
    identity_verified (only through ``verify-identity``, which records the
    attestation) -> processing -> completed / partially_complete; any open
    request can be denied (``denial_reason`` required), a denial appealed.
    """
    request = await _get_dsr_or_404(db, request_id, org_id)
    old_status = request.status
    changes: Dict[str, Any] = {}

    if dsr_update.status and dsr_update.status.value != old_status:
        new_status = dsr_update.status.value
        try:
            dsr_flow.check_transition(old_status, new_status)
        except dsr_flow.TransitionError as exc:
            raise _conflict(str(exc), "invalid_transition") from exc
        if new_status == DSRStatus.IDENTITY_VERIFIED.value:
            raise _conflict(
                "record the identity verification with POST "
                "/privacy/dsr/requests/{id}/verify-identity (method + evidence)",
                "verification_required",
            )
        if new_status == DSRStatus.DENIED.value and not (dsr_update.denial_reason or request.denial_reason):
            raise HTTPException(
                status_code=422,
                detail={"error": "denial_reason_required", "field": "denial_reason"},
            )
        if (
            new_status == DSRStatus.COMPLETED.value
            and request.request_type == "erasure"
            and request.erasure_executed_at is None
        ):
            raise _conflict(
                "an erasure request is completed by POST /privacy/dsr/requests/{id}/execute-erasure",
                "erasure_not_executed",
            )
        request.status = new_status
        if new_status in (DSRStatus.COMPLETED.value, DSRStatus.DENIED.value):
            request.completed_at = datetime.now(timezone.utc)
        elif request.completed_at is not None:
            request.completed_at = None  # reopened (appeal)
        changes["status"] = {"from": old_status, "to": new_status}

    if dsr_update.processing_notes is not None:
        request.processing_notes = dsr_update.processing_notes
        changes["processing_notes"] = True
    if dsr_update.denial_reason is not None:
        request.denial_reason = dsr_update.denial_reason
        changes["denial_reason"] = True

    if changes:
        await _audit(db, _user, org_id, "privacy.dsr_update", request.id, "DSR updated", changes)
    await db.commit()
    await db.refresh(request)
    return request


@router.post("/dsr/requests/{request_id}/verify-identity", response_model=DataSubjectRequestResponse)
async def verify_dsr_identity(
    request_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    verification: Optional[DSRIdentityVerification] = Body(None),
    verification_method: Optional[str] = Query(
        None, description="Deprecated: send {verification_method, evidence} in the body"
    ),
    _user: AnalystUser = None,
):
    """Record how the subject's identity was verified.

    PySOAR does not contact the subject itself: the analyst who verified the
    identity out of band (e-mail challenge, signed form, ID document check)
    records the method and an evidence reference; the DSR moves to
    ``identity_verified`` with who and when. Export and erasure require it.
    """
    request = await _get_dsr_or_404(db, request_id, org_id)
    if verification is None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "verification_evidence_required",
                "detail": (
                    "send {verification_method, evidence}: the method used"
                    + (f" ({verification_method!r})" if verification_method else "")
                    + " and a reference to the evidence (ticket, document id, e-mail thread)"
                ),
            },
        )
    if request.status != DSRStatus.RECEIVED.value:
        raise _conflict(
            f"identity can only be verified on a received request (status is {request.status!r})"
        )
    now = datetime.now(timezone.utc)
    request.status = DSRStatus.IDENTITY_VERIFIED.value
    request.identity_verified_at = now
    request.identity_verified_by = str(_user.id) if _user is not None else None
    request.identity_verification_method = verification.verification_method
    request.identity_verification_evidence = verification.evidence
    await _audit(db, _user, org_id, "privacy.dsr_identity_verified", request.id,
                 f"DSR subject identity verified via {verification.verification_method}",
                 {"method": verification.verification_method, "evidence": verification.evidence})
    await db.commit()
    await db.refresh(request)
    return request


@router.post("/dsr/requests/{request_id}/search-systems")
async def search_data_systems(
    request_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    systems: Optional[List[str]] = Query(
        None, description="Limit to these sources (keys from GET /privacy/dsr/sources); default all"
    ),
    _user: AnalystUser = None,
):
    """Count the subject's rows in every model that holds personal data.

    Matches the subject's e-mail (and identifier when set) in platform
    users, ITDR identities and credential exposures, alerts / incidents /
    log entries mentioning the subject, phishing targets, events and group
    membership, awareness scores, dark-web credential leaks, consent records
    and earlier DSRs. The result is stored on the request (``data_found``,
    ``data_systems_searched``, ``searched_at``).
    """
    request = await _get_dsr_or_404(db, request_id, org_id)
    try:
        result = await dsr_flow.search_subject(db, org_id, request, systems)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "unknown_source", "detail": str(exc)}) from exc
    if request.status == DSRStatus.IDENTITY_VERIFIED.value:
        request.status = DSRStatus.PROCESSING.value
    await _audit(db, _user, org_id, "privacy.dsr_search", request.id, "DSR subject search",
                 {"total_records": result["total_records"],
                  "sources": {k: v["records"] for k, v in result["sources"].items()}})
    await db.commit()
    return {"request_id": request.id, "status": request.status, **result}


@router.post("/dsr/requests/{request_id}/compile-data")
async def compile_data_package(
    request_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    format_type: str = Query("json", description="json or csv"),
    _user: AnalystUser = None,
):
    """Export the subject's rows (access / portability requests).

    Requires a verified identity. The package holds the subject's actual
    rows from every source (secrets such as password hashes, MFA secrets and
    tracking tokens are never exported; at most ``EXPORT_CAP`` rows per
    source, flagged ``truncated`` with the total when more exist). Its
    SHA-256, the record count and the time are stored on the request and in
    the audit log. ``format_type=csv`` returns one formula-safe row per
    (source, record, field).
    """
    request = await _get_dsr_or_404(db, request_id, org_id)
    fmt = (format_type or "json").lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_format", "detail": f"{format_type!r}: use json or csv"},
        )
    if request.request_type not in ("access", "portability"):
        raise _conflict(
            f"a data export answers access / portability requests, not {request.request_type!r}"
        )
    if request.status not in dsr_flow.VERIFIED_STATUSES:
        raise _conflict(
            f"the subject's identity must be verified before an export (status is {request.status!r})",
            "identity_not_verified",
        )

    package = await dsr_flow.build_export(db, org_id, request)
    body: Optional[str] = None
    if fmt == "csv":
        body = dsr_flow.package_to_csv(package)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    else:
        digest = dsr_flow.package_digest(package)
    request.exported_at = datetime.now(timezone.utc)
    request.export_sha256 = digest
    request.export_record_count = package["record_count"]
    if request.status == DSRStatus.IDENTITY_VERIFIED.value:
        request.status = DSRStatus.PROCESSING.value
    await _audit(db, _user, org_id, "privacy.dsr_export", request.id,
                 f"DSR data export ({fmt}) generated",
                 {"format": fmt, "sha256": digest, "record_count": package["record_count"],
                  "sources": {k: v["record_count"] for k, v in package["sources"].items()}})
    await db.commit()

    if body is not None:
        return Response(
            content=body,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="dsr-{request.id}.csv"',
                "X-Export-SHA256": digest,
            },
        )
    return {
        "request_id": request.id,
        "format": "json",
        "sha256": digest,
        "record_count": package["record_count"],
        "package": package,
    }


@router.post("/dsr/requests/{request_id}/execute-erasure", response_model=DataSubjectRequestResponse)
async def execute_dsr_erasure(
    request_id: str,
    org_id: OrganizationId,
    confirmation: DSRErasureRequest,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Erase the subject's data (erasure requests; admin; explicit confirm).

    Per source: platform accounts, identities, phishing targets / events
    are anonymised (identifying fields replaced, account deactivated);
    alerts, incidents and log entries keep their security content with the
    subject's e-mail / identifier redacted; credential exposures, awareness
    scores and dark-web leak rows are deleted; consent records and the DSR
    register are retained under a legal obligation and reported. One
    AuditLog row per source acted on plus a summary; the per-source log is
    stored as ``erasure_log``. When a source had more rows than one run may
    process the request is ``partially_complete`` and re-running continues.
    """
    request = await _get_dsr_or_404(db, request_id, org_id)
    if not confirmation.confirm:
        raise HTTPException(
            status_code=422,
            detail={"error": "confirmation_required", "detail": "send {\"confirm\": true}"},
        )
    if request.request_type != "erasure":
        raise _conflict(f"erasure runs only for erasure requests, not {request.request_type!r}")
    if request.status not in dsr_flow.VERIFIED_STATUSES:
        raise _conflict(
            f"the subject's identity must be verified before erasure (status is {request.status!r})",
            "identity_not_verified",
        )
    if _user is not None and (_user.email or "").strip().lower() == (request.subject_email or "").strip().lower():
        raise _conflict("an administrator cannot run erasure of their own account", "self_erasure")

    log = await dsr_flow.execute_erasure(db, org_id, request)
    for key, entry in log["sources"].items():
        if not entry["records"]:
            continue
        await _audit(db, _user, org_id, f"privacy.dsr_erasure.{entry['action']}", request.id,
                     f"DSR erasure: {entry['action']} {entry['records']} row(s) in {key}",
                     {"source": key, **entry})
    now = datetime.now(timezone.utc)
    request.erasure_executed_at = now
    request.erasure_log = json.dumps(log, default=str)
    if log["remaining"] > 0:
        request.status = DSRStatus.PARTIALLY_COMPLETE.value
        request.completed_at = None
    else:
        request.status = DSRStatus.COMPLETED.value
        request.completed_at = now
    await _audit(db, _user, org_id, "privacy.dsr_erasure", request.id,
                 f"DSR erasure executed: {log['records_processed']} processed, "
                 f"{log['records_retained']} retained, {log['remaining']} remaining",
                 {k: v for k, v in log.items() if k != "sources"})
    await db.commit()
    await db.refresh(request)
    return request


@router.post("/dsr/requests/{request_id}/deadline-alerts")
async def get_deadline_alerts(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
) -> List[DSRDeadlineAlert]:
    """Deadline alerts for the organisation's open DSRs (kept for
    compatibility; ``GET /privacy/dsr/deadline-alerts`` is the read route)."""
    processor = DSRProcessor(db, org_id)
    return await processor.track_deadline_compliance()


# ============================================================================
# PRIVACY IMPACT ASSESSMENT (PIA) ENDPOINTS
# ============================================================================


@router.post("/pia/assessments", response_model=PrivacyImpactAssessmentResponse, status_code=201)
async def create_pia(
    pia: PrivacyImpactAssessmentCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Create Privacy Impact Assessment (DPIA/PIA).

    Assessment Types:
    - dpia: GDPR Data Protection Impact Assessment (Article 35)
    - pia: General Privacy Impact Assessment
    - tia: Technology Impact Assessment
    - legitimate_interest: Legitimate Interest Assessment (Article 6(1)(f))
    """
    try:
        engine = PIAEngine(db, org_id)
        assessment = await engine.create_assessment(
            name=pia.name,
            project_name=pia.project_name,
            assessment_type=pia.assessment_type.value,
            data_types_processed=pia.data_types_processed,
            processing_purposes=pia.processing_purposes,
            legal_basis=pia.legal_basis,
            data_subjects_affected=pia.data_subjects_affected,
        )
        await db.commit()
        await db.refresh(assessment)
        return assessment

    except Exception as e:
        logger.error(f"Failed to create PIA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/pia/assessments", response_model=List[PrivacyImpactAssessmentResponse])
async def list_pias(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List Privacy Impact Assessments."""
    try:
        stmt = select(PrivacyImpactAssessment).where(
            PrivacyImpactAssessment.organization_id == org_id
        )

        if status_filter:
            stmt = stmt.where(PrivacyImpactAssessment.status == status_filter)

        stmt = stmt.offset((page - 1) * size).limit(size).order_by(
            PrivacyImpactAssessment.created_at.desc()
        )

        result = await db.execute(stmt)
        assessments = result.scalars().all()

        return assessments

    except Exception as e:
        logger.error(f"Failed to list PIAs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/pia/assessments/{assessment_id}", response_model=PrivacyImpactAssessmentResponse)
async def get_pia(
    assessment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get Privacy Impact Assessment by ID."""
    try:
        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == assessment_id,
                PrivacyImpactAssessment.organization_id == org_id,
            )
        )
        result = await db.execute(stmt)
        assessment = result.scalar_one_or_none()

        if not assessment:
            raise HTTPException(status_code=404, detail="PIA not found")

        return assessment

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get PIA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.patch("/pia/assessments/{assessment_id}", response_model=PrivacyImpactAssessmentResponse)
async def update_pia(
    assessment_id: str,
    pia_update: PrivacyImpactAssessmentUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Record assessment content (data types, purposes, legal basis, scope,
    transfers, mitigations), the assessed risk level, DPO approval or the
    supervisory-authority consultation. Every change is audited."""
    pia = await _get_pia_or_404(db, assessment_id, org_id)
    data = pia_update.model_dump(exclude_unset=True)
    for list_field in ("data_types_processed", "processing_purposes", "cross_border_transfers", "mitigations"):
        if list_field in data:
            data[list_field] = json.dumps(data[list_field]) if data[list_field] is not None else None
    for enum_field in ("status", "risk_level"):
        if data.get(enum_field) is not None:
            data[enum_field] = data[enum_field].value
    for key, value in data.items():
        if key in ("status", "risk_level", "supervisory_authority_consulted") and value is None:
            continue
        setattr(pia, key, value)
    if data:
        await _audit(db, _user, org_id, "privacy.pia_update", pia.id, f"PIA {pia.name!r} updated",
                     {"fields": sorted(data)})
    await db.commit()
    await db.refresh(pia)
    return pia


@router.post("/pia/assessments/{assessment_id}/assess-risks")
async def assess_pia_risks(
    assessment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    data_subjects_count: int = Query(..., ge=0),
    processing_scope: str = Query(...),
    _user: AnalystUser = None,
):
    """Assess risks to data subjects."""
    await _get_pia_or_404(db, assessment_id, org_id)
    try:
        engine = PIAEngine(db, org_id)
        assessment = await engine.assess_risks(
            assessment_id, data_subjects_count, processing_scope
        )

        await db.commit()
        return assessment

    except Exception as e:
        logger.error(f"Failed to assess risks: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/pia/assessments/{assessment_id}/mitigations")
async def recommend_mitigations(
    assessment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Get recommended mitigations for PIA.

    Not implemented: this used to write the same boilerplate mitigation list
    into every PIA, which then lowered its risk score.
    """
    await _get_pia_or_404(db, assessment_id, org_id)
    raise _not_implemented(
        "Assessment-specific mitigation recommendations are not implemented."
    )


@router.post("/pia/assessments/{assessment_id}/submit-dpo-review")
async def submit_pia_for_dpo_review(
    assessment_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Submit PIA for Data Protection Officer review."""
    try:
        engine = PIAEngine(db, org_id)
        success = await engine.submit_for_dpo_review(assessment_id)

        if not success:
            raise HTTPException(status_code=404, detail="PIA not found")

        await db.commit()
        return {"status": "submitted_for_review"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit for review: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# CONSENT RECORD ENDPOINTS
# ============================================================================


@router.post("/consent/records", response_model=ConsentRecordResponse, status_code=201)
async def create_consent_record(
    consent: ConsentRecordCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Record explicit consent per GDPR Article 7.

    Legal Bases:
    - consent: Explicit consent (GDPR Article 6(1)(a))
    - contract: Processing necessary for contract (Article 6(1)(b))
    - legal_obligation: Required by law (Article 6(1)(c))
    - vital_interest: Protect vital interests (Article 6(1)(d))
    - public_task: Public authority function (Article 6(1)(e))
    - legitimate_interest: Legitimate interests (Article 6(1)(f))
    """
    try:
        manager = ConsentManager(db, org_id)
        record = await manager.record_consent(
            subject_id=consent.subject_id,
            purpose=consent.purpose,
            legal_basis=consent.legal_basis.value,
            consent_mechanism=consent.consent_mechanism.value,
            evidence_location=consent.evidence_location,
        )
        await db.commit()
        return record

    except Exception as e:
        logger.error(f"Failed to create consent record: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/consent/records/{subject_id}", response_model=List[ConsentRecordResponse])
async def get_consent_records(
    subject_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get all consent records for a data subject."""
    try:
        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.organization_id == org_id,
                ConsentRecord.subject_id == subject_id,
            )
        )
        result = await db.execute(stmt)
        records = result.scalars().all()
        return records

    except Exception as e:
        logger.error(f"Failed to get consent records: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/consent/records/{record_id}/withdraw")
async def withdraw_consent(
    record_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Withdraw previously given consent (GDPR Article 7(3))."""
    try:
        manager = ConsentManager(db, org_id)
        success = await manager.withdraw_consent(record_id)

        if not success:
            raise HTTPException(status_code=404, detail="Consent record not found")

        await db.commit()
        return {"status": "withdrawn"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to withdraw consent: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# DATA PROCESSING RECORD (ROPA) ENDPOINTS
# ============================================================================


@router.post(
    "/ropa/processing-records",
    response_model=DataProcessingRecordResponse,
    status_code=201,
)
async def create_processing_record(
    record: DataProcessingRecordCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """
    Create Record of Processing Activities (ROPA) per GDPR Article 30.
    Required for all organizations processing personal data.
    """
    try:
        governance = DataGovernance(db, org_id)
        processing_record = await governance.create_processing_record(
            name=record.name,
            purpose=record.purpose,
            legal_basis=record.legal_basis,
            data_categories=record.data_categories or [],
            data_subjects=record.data_subjects,
            recipients=record.recipients,
            retention_period_days=record.retention_period_days,
            dpo_contact=record.dpo_contact,
        )
        await db.commit()
        await db.refresh(processing_record)
        return processing_record

    except Exception as e:
        logger.error(f"Failed to create processing record: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get(
    "/ropa/processing-records", response_model=List[DataProcessingRecordResponse]
)
async def list_processing_records(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List Record of Processing Activities."""
    try:
        stmt = select(DataProcessingRecord).where(
            DataProcessingRecord.organization_id == org_id
        )

        stmt = stmt.offset((page - 1) * size).limit(size).order_by(
            DataProcessingRecord.created_at.desc()
        )

        result = await db.execute(stmt)
        records = result.scalars().all()

        return records

    except Exception as e:
        logger.error(f"Failed to list processing records: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.patch("/ropa/processing-records/{record_id}", response_model=DataProcessingRecordResponse)
async def update_processing_record(
    record_id: str,
    record_update: DataProcessingRecordUpdate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Record a retention review (``last_reviewed``, ISO-8601 date or
    datetime) or change the retention period; retention-review findings
    (``/ropa/retention-violations``) are computed from these fields."""
    record = (await db.execute(
        select(DataProcessingRecord).where(
            DataProcessingRecord.id == record_id,
            DataProcessingRecord.organization_id == org_id,
        )
    )).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Processing record not found")
    data = record_update.model_dump(exclude_unset=True)
    if data.get("last_reviewed") is not None:
        try:
            reviewed = datetime.fromisoformat(str(data["last_reviewed"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "invalid_date", "field": "last_reviewed", "detail": str(exc)},
            ) from exc
        if reviewed.tzinfo is None:
            reviewed = reviewed.replace(tzinfo=timezone.utc)
        if reviewed > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise HTTPException(
                status_code=422,
                detail={"error": "review_in_future", "field": "last_reviewed"},
            )
        record.last_reviewed = reviewed.isoformat()
    if "retention_period_days" in data:
        if data["retention_period_days"] is not None and data["retention_period_days"] < 1:
            raise HTTPException(status_code=422, detail={"error": "invalid_retention_period"})
        record.retention_period_days = data["retention_period_days"]
    if data:
        await _audit(db, _user, org_id, "privacy.ropa_update", record.id,
                     f"ROPA record {record.name!r} updated", {"fields": sorted(data)})
    await db.commit()
    await db.refresh(record)
    return record


@router.post("/ropa/retention-violations", response_model=List[RetentionViolation])
async def get_retention_violations(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Check for data retention compliance violations."""
    try:
        governance = DataGovernance(db, org_id)
        violations = await governance.check_retention_compliance()
        return violations

    except Exception as e:
        logger.error(f"Failed to check retention: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/ropa/generate-ropa")
async def generate_ropa(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Generate complete ROPA document per GDPR Article 30."""
    try:
        governance = DataGovernance(db, org_id)
        ropa = await governance.generate_ropa()
        return {"document": ropa, "generated_at": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"Failed to generate ROPA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# PRIVACY INCIDENT ENDPOINTS
# ============================================================================


@router.post(
    "/incidents/report", response_model=PrivacyIncidentResponse, status_code=201
)
async def report_privacy_incident(
    incident: PrivacyIncidentCreate,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Report privacy incident (data breach, processing violation, etc.).

    Triggers GDPR Article 33 (supervisory authority) and Article 34 (data subject)
    notification workflows, as well as CCPA § 1798.82 requirements.
    """
    try:
        incident_mgr = PrivacyIncidentManager(db, org_id)
        privacy_incident = await incident_mgr.report_incident(
            title=incident.title,
            description=incident.description,
            incident_type=incident.incident_type.value,
            severity=incident.severity.value,
            data_types=incident.data_types_affected or [],
            subjects_count=incident.subjects_affected_count or 0,
            regulations=incident.regulations_implicated,
        )

        # Trigger escalation task (non-blocking — if Celery/Redis unavailable, save still works)
        try:
            from src.privacy.tasks import privacy_incident_escalation
            privacy_incident_escalation.delay(privacy_incident.id, org_id)
        except Exception:
            logger.warning("Could not dispatch escalation task — Celery/Redis may be unavailable")

        await db.commit()
        return privacy_incident

    except Exception as e:
        logger.error(f"Failed to report incident: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/incidents/reports", response_model=List[PrivacyIncidentResponse])
async def list_incidents(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List privacy incidents."""
    try:
        stmt = select(PrivacyIncident).where(
            PrivacyIncident.organization_id == org_id
        )

        if status_filter:
            stmt = stmt.where(PrivacyIncident.status == status_filter)

        stmt = stmt.offset((page - 1) * size).limit(size).order_by(
            PrivacyIncident.created_at.desc()
        )

        result = await db.execute(stmt)
        incidents = result.scalars().all()

        return incidents

    except Exception as e:
        logger.error(f"Failed to list incidents: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get(
    "/incidents/reports/{incident_id}", response_model=PrivacyIncidentResponse
)
async def get_incident(
    incident_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get privacy incident by ID."""
    try:
        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == org_id,
            )
        )
        result = await db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return incident

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get incident: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/incidents/reports/{incident_id}/notification-deadlines")
async def get_notification_deadlines(
    incident_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Get regulatory notification deadlines for incident."""
    try:
        incident_mgr = PrivacyIncidentManager(db, org_id)
        deadlines = await incident_mgr.calculate_notification_deadlines(incident_id)
        if not deadlines:
            raise HTTPException(status_code=404, detail="Incident not found")

        await db.commit()
        return deadlines

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get deadlines: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/incidents/reports/{incident_id}/mark-notified")
async def mark_incident_notified(
    incident_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Mark notifications as sent."""
    try:
        incident_mgr = PrivacyIncidentManager(db, org_id)
        success = await incident_mgr.track_notifications(incident_id)

        if not success:
            raise HTTPException(status_code=404, detail="Incident not found")

        await db.commit()
        return {"status": "notified"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark notified: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# PRIVACY DASHBOARD ENDPOINTS
# ============================================================================


@router.get("/dashboard/stats", response_model=PrivacyDashboardStats)
async def get_privacy_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get privacy module dashboard statistics."""
    try:
        # Count DSRs
        dsr_stmt = select(func.count()).select_from(DataSubjectRequest).where(
            DataSubjectRequest.organization_id == org_id
        )
        total_dsrs = (await db.execute(dsr_stmt)).scalar() or 0

        # Open = received / verified / processing / partially complete /
        # appealed; completed and denied requests are closed.
        pending_dsr_stmt = select(func.count()).select_from(DataSubjectRequest).where(
            and_(
                DataSubjectRequest.organization_id == org_id,
                DataSubjectRequest.status.in_(sorted(dsr_flow.OPEN_STATUSES)),
            )
        )
        pending_dsrs = (await db.execute(pending_dsr_stmt)).scalar() or 0

        # Deadline compliance over closed requests: closed on or before the
        # stored deadline (closed time = completed_at, else updated_at for
        # rows closed before wave 4). Bounded read of three columns.
        now_utc = datetime.now(timezone.utc)

        def _aware(value):
            if value is None:
                return None
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return None
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

        closed_rows = (await db.execute(
            select(
                DataSubjectRequest.deadline,
                DataSubjectRequest.completed_at,
                DataSubjectRequest.updated_at,
            ).where(
                DataSubjectRequest.organization_id == org_id,
                DataSubjectRequest.status.in_([DSRStatus.COMPLETED.value, DSRStatus.DENIED.value]),
            ).limit(10_000)
        )).all()
        closed_dsrs = len(closed_rows)
        on_time = 0
        for deadline_raw, completed_at, updated_at in closed_rows:
            deadline_dt = _aware(deadline_raw)
            closed_at = _aware(completed_at) or _aware(updated_at)
            if deadline_dt is None or closed_at is None or closed_at <= deadline_dt:
                on_time += 1
        dsr_compliance_rate = round(on_time / closed_dsrs * 100, 1) if closed_dsrs else None

        overdue_dsrs = (await db.execute(
            select(func.count()).select_from(DataSubjectRequest).where(
                DataSubjectRequest.organization_id == org_id,
                DataSubjectRequest.status.in_(sorted(dsr_flow.OPEN_STATUSES)),
                DataSubjectRequest.deadline < now_utc.isoformat(),
            )
        )).scalar() or 0

        # Count PIAs
        pia_stmt = select(func.count()).select_from(PrivacyImpactAssessment).where(
            PrivacyImpactAssessment.organization_id == org_id
        )
        active_pias = (await db.execute(pia_stmt)).scalar() or 0

        # Count Consents
        consent_stmt = select(func.count()).select_from(ConsentRecord).where(
            ConsentRecord.organization_id == org_id
        )
        total_consents = (await db.execute(consent_stmt)).scalar() or 0

        # Count Incidents
        incident_stmt = select(func.count()).select_from(PrivacyIncident).where(
            PrivacyIncident.organization_id == org_id
        )
        total_incidents = (await db.execute(incident_stmt)).scalar() or 0


        # PIAs requiring review
        pias_review_stmt = select(func.count()).select_from(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.organization_id == org_id,
                PrivacyImpactAssessment.status == PIAStatus.IN_REVIEW.value,
            )
        )
        pias_requiring_review = (await db.execute(pias_review_stmt)).scalar() or 0

        # Withdrawn consents
        withdrawn_stmt = select(func.count()).select_from(ConsentRecord).where(
            and_(
                ConsentRecord.organization_id == org_id,
                ConsentRecord.withdrawal_date != None,
            )
        )
        withdrawn_consents = (await db.execute(withdrawn_stmt)).scalar() or 0

        # Processing records count
        proc_stmt = select(func.count()).select_from(DataProcessingRecord).where(
            DataProcessingRecord.organization_id == org_id,
        )
        processing_records = (await db.execute(proc_stmt)).scalar() or 0

        # Pending incidents (reported or under investigation)
        pending_inc_stmt = select(func.count()).select_from(PrivacyIncident).where(
            and_(
                PrivacyIncident.organization_id == org_id,
                or_(
                    PrivacyIncident.status == "reported",
                    PrivacyIncident.status == "under_investigation",
                ),
            )
        )
        pending_incidents = (await db.execute(pending_inc_stmt)).scalar() or 0

        # Incidents created in the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        month_inc_stmt = select(func.count()).select_from(PrivacyIncident).where(
            and_(
                PrivacyIncident.organization_id == org_id,
                PrivacyIncident.created_at >= thirty_days_ago,
            )
        )
        incidents_this_month = (await db.execute(month_inc_stmt)).scalar() or 0

        # Average days from report to the last update of closed / remediated
        # incidents (no separate resolution timestamp is stored); None when
        # no incident has been closed.
        resolved_rows = (await db.execute(
            select(PrivacyIncident.created_at, PrivacyIncident.updated_at).where(
                and_(
                    PrivacyIncident.organization_id == org_id,
                    or_(
                        PrivacyIncident.status == "closed",
                        PrivacyIncident.status == "remediated",
                    ),
                )
            ).limit(10_000)
        )).all()
        spans = [
            (_aware(u) - _aware(c)).total_seconds() / 86400.0
            for c, u in resolved_rows
            if c is not None and u is not None
        ]
        avg_incident_resolution_days = round(sum(spans) / len(spans), 1) if spans else None

        stats = PrivacyDashboardStats(
            total_dsrs=total_dsrs,
            pending_dsrs=pending_dsrs,
            dsr_compliance_rate=dsr_compliance_rate,
            closed_dsrs=closed_dsrs,
            overdue_dsrs=overdue_dsrs,
            active_pias=active_pias,
            pias_requiring_review=pias_requiring_review,
            total_consents=total_consents,
            withdrawn_consents=withdrawn_consents,
            processing_records=processing_records,
            pending_incidents=pending_incidents,
            incidents_this_month=incidents_this_month,
            avg_incident_resolution_days=avg_incident_resolution_days,
        )

        return stats

    except Exception as e:
        logger.error(f"Failed to get stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# MONITORING & ENFORCEMENT ENDPOINTS
# ============================================================================


@router.post("/monitoring/trigger-dsr-deadline-check")
async def trigger_dsr_deadline_check(
    org_id: OrganizationId,
    _user: AnalystUser = None,
):
    """Manually trigger DSR deadline monitoring task."""
    try:
        dsr_deadline_monitor.delay(org_id)
        return {"status": "monitoring_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger monitoring: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-retention-check")
async def trigger_retention_check(
    org_id: OrganizationId,
    _user: AnalystUser = None,
):
    """Manually trigger retention enforcement task."""
    try:
        retention_enforcement.delay(org_id)
        return {"status": "retention_check_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger retention check: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-consent-expiry-check")
async def trigger_consent_check(
    org_id: OrganizationId,
    _user: AnalystUser = None,
):
    """Manually trigger consent expiry check task."""
    try:
        consent_expiry_check.delay(org_id)
        return {"status": "consent_check_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger consent check: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-pia-review-reminder")
async def trigger_pia_reminder(
    org_id: OrganizationId,
    _user: AnalystUser = None,
):
    """Manually trigger PIA review reminder task."""
    try:
        pia_review_reminder.delay(org_id)
        return {"status": "pia_reminder_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger PIA reminder: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )
