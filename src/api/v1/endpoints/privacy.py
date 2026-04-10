"""
Privacy Engineering REST API Endpoints

Complete API for managing Data Subject Requests (DSRs), Privacy Impact Assessments (PIAs),
Consent Records, Data Processing Records (ROPA), and Privacy Incidents.
Handles GDPR, CCPA, LGPD, PIPA, PDPA, and HIPAA compliance automation.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query
from src.api.deps import CurrentUser, DatabaseSession
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
from src.privacy.tasks import (
    dsr_deadline_monitor,
    consent_expiry_check,
    retention_enforcement,
    pia_review_reminder,
    cross_border_audit,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/privacy", tags=["privacy"])


# ============================================================================
# DATA SUBJECT REQUEST (DSR) ENDPOINTS
# ============================================================================


@router.post("/dsr/requests", response_model=DataSubjectRequestResponse, status_code=201)
async def create_dsr(
    dsr: DataSubjectRequestCreate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Create new Data Subject Request.

    Supports GDPR Article 12-22, CCPA § 1798.100-1798.120, and other regulations.
    Automatically calculates compliance deadline.

    Request Types:
    - access: Right to access data (GDPR Article 15)
    - rectification: Right to correct data (GDPR Article 16)
    - erasure: Right to be forgotten (GDPR Article 17)
    - portability: Right to data portability (GDPR Article 20)
    - restriction: Right to restrict processing (GDPR Article 18)
    - objection: Right to object to processing (GDPR Article 21)
    - automated_decision: Right to human review (GDPR Article 22)
    """
    try:
        processor = DSRProcessor(db, getattr(current_user, "organization_id", None))
        request = await processor.receive_request(
            request_type=dsr.request_type.value,
            regulation=dsr.regulation.value,
            subject_name=dsr.subject_name,
            subject_email=dsr.subject_email,
            subject_identifier=dsr.subject_identifier,
        )
        await db.commit()

        try:
            org_id = getattr(current_user, "organization_id", None)
            automation = AutomationService(db)
            await automation.on_privacy_dsr_created(
                dsr_id=request.id,
                subject_email=request.subject_email,
                request_type=request.request_type,
                regulation=request.regulation,
                organization_id=org_id,
            )
        except Exception as automation_exc:
            logger.warning(f"Automation on_privacy_dsr_created failed: {automation_exc}")

        return request

    except Exception as e:
        logger.error(f"Failed to create DSR: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/dsr/requests", response_model=DataSubjectRequestListResponse)
async def list_dsrs(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    regulation: Optional[str] = None,
):
    """
    List Data Subject Requests with pagination.

    Query Parameters:
    - status: Filter by DSR status
    - regulation: Filter by regulation (gdpr, ccpa, lgpd, etc.)
    - page, size: Pagination
    """
    try:
        stmt = select(DataSubjectRequest).where(
            DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None)
        )

        if status:
            stmt = stmt.where(DataSubjectRequest.status == status)

        if regulation:
            stmt = stmt.where(DataSubjectRequest.regulation == regulation)

        # Count total
        count_stmt = select(func.count()).select_from(DataSubjectRequest).where(
            DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None)
        )
        count_result = await db.execute(count_stmt)
        total = count_result.scalar()

        # Paginate
        stmt = stmt.offset((page - 1) * size).limit(size).order_by(
            DataSubjectRequest.created_at.desc()
        )

        result = await db.execute(stmt)
        requests = result.scalars().all()

        return DataSubjectRequestListResponse(
            total=total, page=page, size=size, items=requests
        )

    except Exception as e:
        logger.error(f"Failed to list DSRs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/dsr/requests/{request_id}", response_model=DataSubjectRequestResponse)
async def get_dsr(
    request_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get Data Subject Request by ID."""
    try:
        stmt = select(DataSubjectRequest).where(
            and_(
                DataSubjectRequest.id == request_id,
                DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None),
            )
        )
        result = await db.execute(stmt)
        request = result.scalar_one_or_none()

        if not request:
            raise HTTPException(status_code=404, detail="DSR not found")

        return request

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get DSR: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.patch(
    "/dsr/requests/{request_id}", response_model=DataSubjectRequestResponse
)
async def update_dsr(
    request_id: str,
    dsr_update: DataSubjectRequestUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update Data Subject Request status or notes."""
    try:
        stmt = select(DataSubjectRequest).where(
            and_(
                DataSubjectRequest.id == request_id,
                DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None),
            )
        )
        result = await db.execute(stmt)
        request = result.scalar_one_or_none()

        if not request:
            raise HTTPException(status_code=404, detail="DSR not found")

        if dsr_update.status:
            request.status = dsr_update.status.value

        if dsr_update.processing_notes is not None:
            request.processing_notes = dsr_update.processing_notes

        if dsr_update.denial_reason is not None:
            request.denial_reason = dsr_update.denial_reason

        await db.commit()
        return request

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update DSR: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/dsr/requests/{request_id}/verify-identity")
async def verify_dsr_identity(
    request_id: str,
    db: DatabaseSession = None,
    verification_method: str = Query(..., description="email, phone, document"),
    current_user: CurrentUser = None,
):
    """Verify Data Subject identity."""
    try:
        processor = DSRProcessor(db, getattr(current_user, "organization_id", None))
        success = await processor.verify_identity(request_id, verification_method)

        if not success:
            raise HTTPException(status_code=404, detail="DSR not found")

        await db.commit()
        return {"status": "verified", "method": verification_method}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify identity: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/dsr/requests/{request_id}/search-systems")
async def search_data_systems(
    request_id: str,
    db: DatabaseSession = None,
    systems: List[str] = Query(...),
    current_user: CurrentUser = None,
):
    """Search data systems for subject data."""
    try:
        processor = DSRProcessor(db, getattr(current_user, "organization_id", None))
        results = await processor.search_data_systems(request_id, systems)

        await db.commit()
        return results

    except Exception as e:
        logger.error(f"Failed to search systems: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/dsr/requests/{request_id}/compile-data")
async def compile_data_package(
    request_id: str,
    db: DatabaseSession = None,
    format_type: str = Query("json", description="json, csv, xml"),
    current_user: CurrentUser = None,
):
    """Compile data package for portability/access requests."""
    try:
        processor = DSRProcessor(db, getattr(current_user, "organization_id", None))
        package = await processor.compile_data_package(request_id, format_type)

        await db.commit()
        return package

    except Exception as e:
        logger.error(f"Failed to compile data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/dsr/requests/{request_id}/deadline-alerts")
async def get_deadline_alerts(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
) -> List[DSRDeadlineAlert]:
    """Get DSR deadline compliance alerts."""
    try:
        processor = DSRProcessor(db, getattr(current_user, "organization_id", None))
        alerts = await processor.track_deadline_compliance()
        return alerts

    except Exception as e:
        logger.error(f"Failed to get deadline alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


# ============================================================================
# PRIVACY IMPACT ASSESSMENT (PIA) ENDPOINTS
# ============================================================================


@router.post("/pia/assessments", response_model=PrivacyImpactAssessmentResponse, status_code=201)
async def create_pia(
    pia: PrivacyImpactAssessmentCreate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        engine = PIAEngine(db, getattr(current_user, "organization_id", None))
        assessment = await engine.create_assessment(
            name=pia.name,
            project_name=pia.project_name,
            assessment_type=pia.assessment_type.value,
        )
        await db.commit()
        return assessment

    except Exception as e:
        logger.error(f"Failed to create PIA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/pia/assessments", response_model=List[PrivacyImpactAssessmentResponse])
async def list_pias(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List Privacy Impact Assessments."""
    try:
        stmt = select(PrivacyImpactAssessment).where(
            PrivacyImpactAssessment.organization_id == getattr(current_user, "organization_id", None)
        )

        if status:
            stmt = stmt.where(PrivacyImpactAssessment.status == status)

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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get Privacy Impact Assessment by ID."""
    try:
        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == assessment_id,
                PrivacyImpactAssessment.organization_id == getattr(current_user, "organization_id", None),
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


@router.post("/pia/assessments/{assessment_id}/assess-risks")
async def assess_pia_risks(
    assessment_id: str,
    db: DatabaseSession = None,
    data_subjects_count: int = Query(..., ge=0),
    processing_scope: str = Query(...),
    current_user: CurrentUser = None,
):
    """Assess risks to data subjects."""
    try:
        engine = PIAEngine(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get recommended mitigations for PIA."""
    try:
        engine = PIAEngine(db, getattr(current_user, "organization_id", None))
        mitigations = await engine.recommend_mitigations(assessment_id)

        await db.commit()
        return {"mitigations": mitigations}

    except Exception as e:
        logger.error(f"Failed to get mitigations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/pia/assessments/{assessment_id}/submit-dpo-review")
async def submit_pia_for_dpo_review(
    assessment_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Submit PIA for Data Protection Officer review."""
    try:
        engine = PIAEngine(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
        manager = ConsentManager(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get all consent records for a data subject."""
    try:
        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.organization_id == getattr(current_user, "organization_id", None),
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Withdraw previously given consent (GDPR Article 7(3))."""
    try:
        manager = ConsentManager(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Create Record of Processing Activities (ROPA) per GDPR Article 30.
    Required for all organizations processing personal data.
    """
    try:
        governance = DataGovernance(db, getattr(current_user, "organization_id", None))
        processing_record = await governance.create_processing_record(
            name=record.name,
            purpose=record.purpose,
            legal_basis=record.legal_basis,
            data_categories=record.data_categories or [],
        )
        await db.commit()
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List Record of Processing Activities."""
    try:
        stmt = select(DataProcessingRecord).where(
            DataProcessingRecord.organization_id == getattr(current_user, "organization_id", None)
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


@router.post("/ropa/retention-violations", response_model=List[RetentionViolation])
async def get_retention_violations(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Check for data retention compliance violations."""
    try:
        governance = DataGovernance(db, getattr(current_user, "organization_id", None))
        violations = await governance.check_retention_compliance()
        return violations

    except Exception as e:
        logger.error(f"Failed to check retention: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.get("/ropa/generate-ropa")
async def generate_ropa(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Generate complete ROPA document per GDPR Article 30."""
    try:
        governance = DataGovernance(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Report privacy incident (data breach, processing violation, etc.).

    Triggers GDPR Article 33 (supervisory authority) and Article 34 (data subject)
    notification workflows, as well as CCPA § 1798.82 requirements.
    """
    try:
        incident_mgr = PrivacyIncidentManager(db, getattr(current_user, "organization_id", None))
        privacy_incident = await incident_mgr.report_incident(
            title=incident.title,
            description=incident.description,
            incident_type=incident.incident_type.value,
            severity=incident.severity.value,
            data_types=incident.data_types_affected or [],
            subjects_count=incident.subjects_affected_count or 0,
        )

        # Trigger escalation task (non-blocking — if Celery/Redis unavailable, save still works)
        try:
            from src.privacy.tasks import privacy_incident_escalation
            privacy_incident_escalation.delay(privacy_incident.id, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List privacy incidents."""
    try:
        stmt = select(PrivacyIncident).where(
            PrivacyIncident.organization_id == getattr(current_user, "organization_id", None)
        )

        if status:
            stmt = stmt.where(PrivacyIncident.status == status)

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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get privacy incident by ID."""
    try:
        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == getattr(current_user, "organization_id", None),
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get regulatory notification deadlines for incident."""
    try:
        incident_mgr = PrivacyIncidentManager(db, getattr(current_user, "organization_id", None))
        deadlines = await incident_mgr.calculate_notification_deadlines(incident_id)

        await db.commit()
        return deadlines

    except Exception as e:
        logger.error(f"Failed to get deadlines: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/incidents/reports/{incident_id}/mark-notified")
async def mark_incident_notified(
    incident_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Mark notifications as sent."""
    try:
        incident_mgr = PrivacyIncidentManager(db, getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get privacy module dashboard statistics."""
    try:
        # Count DSRs
        dsr_stmt = select(func.count()).select_from(DataSubjectRequest).where(
            DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None)
        )
        total_dsrs = (await db.execute(dsr_stmt)).scalar() or 0

        pending_dsr_stmt = select(func.count()).select_from(DataSubjectRequest).where(
            and_(
                DataSubjectRequest.organization_id == getattr(current_user, "organization_id", None),
                DataSubjectRequest.status != DSRStatus.COMPLETED.value,
            )
        )
        pending_dsrs = (await db.execute(pending_dsr_stmt)).scalar() or 0

        # Count PIAs
        pia_stmt = select(func.count()).select_from(PrivacyImpactAssessment).where(
            PrivacyImpactAssessment.organization_id == getattr(current_user, "organization_id", None)
        )
        active_pias = (await db.execute(pia_stmt)).scalar() or 0

        # Count Consents
        consent_stmt = select(func.count()).select_from(ConsentRecord).where(
            ConsentRecord.organization_id == getattr(current_user, "organization_id", None)
        )
        total_consents = (await db.execute(consent_stmt)).scalar() or 0

        # Count Incidents
        incident_stmt = select(func.count()).select_from(PrivacyIncident).where(
            PrivacyIncident.organization_id == getattr(current_user, "organization_id", None)
        )
        total_incidents = (await db.execute(incident_stmt)).scalar() or 0

        org_id = getattr(current_user, "organization_id", None)

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

        # Average incident resolution days (from created_at to updated_at for closed/remediated)
        resolution_stmt = select(
            func.avg(
                func.julianday(PrivacyIncident.updated_at) - func.julianday(PrivacyIncident.created_at)
            )
        ).where(
            and_(
                PrivacyIncident.organization_id == org_id,
                or_(
                    PrivacyIncident.status == "closed",
                    PrivacyIncident.status == "remediated",
                ),
            )
        )
        try:
            avg_resolution = (await db.execute(resolution_stmt)).scalar()
            avg_incident_resolution_days = round(float(avg_resolution), 1) if avg_resolution else 0.0
        except Exception:
            # julianday may not be available on all DB backends; fall back to 0
            avg_incident_resolution_days = 0.0

        stats = PrivacyDashboardStats(
            total_dsrs=total_dsrs,
            pending_dsrs=pending_dsrs,
            dsr_compliance_rate=((total_dsrs - pending_dsrs) / total_dsrs * 100)
            if total_dsrs > 0
            else 0,
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
    current_user: CurrentUser = None,
):
    """Manually trigger DSR deadline monitoring task."""
    try:
        dsr_deadline_monitor.delay(getattr(current_user, "organization_id", None))
        return {"status": "monitoring_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger monitoring: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-retention-check")
async def trigger_retention_check(
    current_user: CurrentUser = None,
):
    """Manually trigger retention enforcement task."""
    try:
        retention_enforcement.delay(getattr(current_user, "organization_id", None))
        return {"status": "retention_check_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger retention check: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-consent-expiry-check")
async def trigger_consent_check(
    current_user: CurrentUser = None,
):
    """Manually trigger consent expiry check task."""
    try:
        consent_expiry_check.delay(getattr(current_user, "organization_id", None))
        return {"status": "consent_check_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger consent check: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )


@router.post("/monitoring/trigger-pia-review-reminder")
async def trigger_pia_reminder(
    current_user: CurrentUser = None,
):
    """Manually trigger PIA review reminder task."""
    try:
        pia_review_reminder.delay(getattr(current_user, "organization_id", None))
        return {"status": "pia_reminder_triggered"}

    except Exception as e:
        logger.error(f"Failed to trigger PIA reminder: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Operation failed. Please try again or contact support."
        )
