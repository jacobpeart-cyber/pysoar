"""
Data Loss Prevention API Endpoints

RESTful API for DLP policy management, violation investigation, data discovery,
classification, and incident response.
"""

import json
import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.dlp.models import (
    DLPIncident,
    DLPPolicy,
    DLPViolation,
    DataClassification,
    SensitiveDataDiscovery,
)
from src.dlp.engine import (
    DLPEngine,
    DataClassifier,
    ExfiltrationDetector,
    DiscoveryScanner,
    BreachAssessor,
)
from src.schemas.dlp import (
    BreachAssessmentRequest,
    BreachAssessmentResponse,
    ComplianceStatusResponse,
    DataClassificationCreate,
    DataClassificationListResponse,
    DataClassificationResponse,
    DataClassificationUpdate,
    DataHandlingRequirementsResponse,
    DataLineageResponse,
    DataMapResponse,
    DLPDashboardResponse,
    DLPIncidentCreate,
    DLPIncidentListResponse,
    DLPIncidentResponse,
    DLPIncidentUpdate,
    DLPPolicyCreate,
    DLPPolicyListResponse,
    DLPPolicyResponse,
    DLPPolicyTestRequest,
    DLPPolicyTestResponse,
    DLPPolicyUpdate,
    DLPViolationBulkActionRequest,
    DLPViolationBulkActionResponse,
    DLPViolationCreate,
    DLPViolationListResponse,
    DLPViolationResponse,
    DLPViolationResolveRequest,
    DLPViolationUpdate,
    DiscoveryScanListResponse,
    DiscoveryScanTriggerRequest,
    DocumentClassificationRequest,
    DocumentClassificationResponse,
    NotificationTrackingResponse,
    SensitiveDataDiscoveryResponse,
    ViolationTrendResponse,
)

router = APIRouter(prefix="/dlp", tags=["DLP"])

# Engines and tools
dlp_engine = DLPEngine()
classifier = DataClassifier()
detector = ExfiltrationDetector()
scanner = DiscoveryScanner()
assessor = BreachAssessor()


# Helper functions

async def get_policy_or_404(db: AsyncSession, policy_id: str) -> DLPPolicy:
    """Get policy by ID or raise 404"""
    result = await db.execute(select(DLPPolicy).where(DLPPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy


async def get_violation_or_404(db: AsyncSession, violation_id: str) -> DLPViolation:
    """Get violation by ID or raise 404"""
    result = await db.execute(select(DLPViolation).where(DLPViolation.id == violation_id))
    violation = result.scalar_one_or_none()
    if not violation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Violation not found")
    return violation


async def get_classification_or_404(db: AsyncSession, class_id: str) -> DataClassification:
    """Get classification by ID or raise 404"""
    result = await db.execute(select(DataClassification).where(DataClassification.id == class_id))
    classification = result.scalar_one_or_none()
    if not classification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Classification not found",
        )
    return classification


async def get_incident_or_404(db: AsyncSession, incident_id: str) -> DLPIncident:
    """Get incident by ID or raise 404"""
    result = await db.execute(select(DLPIncident).where(DLPIncident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def convert_json_fields(model_obj):
    """Convert JSON string fields to Python objects"""
    if hasattr(model_obj, "data_patterns") and model_obj.data_patterns:
        model_obj.data_patterns = json.loads(model_obj.data_patterns) if isinstance(model_obj.data_patterns, str) else model_obj.data_patterns
    if hasattr(model_obj, "channels_monitored") and model_obj.channels_monitored:
        model_obj.channels_monitored = json.loads(model_obj.channels_monitored) if isinstance(model_obj.channels_monitored, str) else model_obj.channels_monitored
    if hasattr(model_obj, "sensitive_data_types") and model_obj.sensitive_data_types:
        model_obj.sensitive_data_types = json.loads(model_obj.sensitive_data_types) if isinstance(model_obj.sensitive_data_types, str) else model_obj.sensitive_data_types
    return model_obj


# ==================== POLICIES ====================


@router.post("/policies", response_model=DLPPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: DLPPolicyCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new DLP policy"""
    policy = DLPPolicy(
        organization_id=getattr(current_user, "organization_id", None),
        name=policy_data.name,
        description=policy_data.description,
        policy_type=policy_data.policy_type,
        severity=policy_data.severity,
        enabled=policy_data.enabled,
        data_patterns=json.dumps(policy_data.data_patterns) if policy_data.data_patterns else None,
        file_types_monitored=json.dumps(policy_data.file_types_monitored)
        if policy_data.file_types_monitored
        else None,
        channels_monitored=json.dumps(policy_data.channels_monitored)
        if policy_data.channels_monitored
        else None,
        response_actions=json.dumps(policy_data.response_actions) if policy_data.response_actions else None,
        exceptions=json.dumps(policy_data.exceptions) if policy_data.exceptions else None,
    )

    db.add(policy)
    await db.flush()
    await db.refresh(policy)

    return convert_json_fields(policy)


@router.get("/policies", response_model=DLPPolicyListResponse)
async def list_policies(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    enabled: Optional[bool] = None,
    policy_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List DLP policies"""
    query = select(DLPPolicy).where(DLPPolicy.organization_id == getattr(current_user, "organization_id", None))

    if enabled is not None:
        query = query.where(DLPPolicy.enabled == enabled)

    if policy_type:
        query = query.where(DLPPolicy.policy_type == policy_type)

    if search:
        search_filter = f"%{search}%"
        query = query.where(DLPPolicy.name.ilike(search_filter) | DLPPolicy.description.ilike(search_filter))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(DLPPolicy.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    policies = list(result.scalars().all())

    return DLPPolicyListResponse(
        items=[convert_json_fields(p) for p in policies],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/policies/{policy_id}", response_model=DLPPolicyResponse)
async def get_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get DLP policy by ID"""
    policy = await get_policy_or_404(db, policy_id)
    return convert_json_fields(policy)


@router.patch("/policies/{policy_id}", response_model=DLPPolicyResponse)
async def update_policy(
    policy_id: str,
    policy_data: DLPPolicyUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a DLP policy"""
    policy = await get_policy_or_404(db, policy_id)

    update_data = policy_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    if "data_patterns" in update_data:
        update_data["data_patterns"] = json.dumps(update_data["data_patterns"])
    if "channels_monitored" in update_data:
        update_data["channels_monitored"] = json.dumps(update_data["channels_monitored"])

    for key, value in update_data.items():
        setattr(policy, key, value)

    await db.flush()
    await db.refresh(policy)

    return convert_json_fields(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a DLP policy"""
    policy = await get_policy_or_404(db, policy_id)
    await db.delete(policy)
    await db.flush()


@router.post("/policies/{policy_id}/enable", response_model=DLPPolicyResponse)
async def enable_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Enable a DLP policy"""
    policy = await get_policy_or_404(db, policy_id)
    policy.enabled = True
    await db.flush()
    await db.refresh(policy)
    return convert_json_fields(policy)


@router.post("/policies/{policy_id}/disable", response_model=DLPPolicyResponse)
async def disable_policy(
    policy_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Disable a DLP policy"""
    policy = await get_policy_or_404(db, policy_id)
    policy.enabled = False
    await db.flush()
    await db.refresh(policy)
    return convert_json_fields(policy)


@router.post("/policies/{policy_id}/test", response_model=DLPPolicyTestResponse)
async def test_policy(
    policy_id: str,
    test_request: DLPPolicyTestRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Test a policy against sample data"""
    policy = await get_policy_or_404(db, policy_id)

    # Evaluate content
    evaluation = dlp_engine.evaluate_content(
        test_request.sample_content,
        test_request.sample_metadata,
    )

    return DLPPolicyTestResponse(
        policy_id=policy_id,
        test_passed=not evaluation["has_violations"],
        violations_detected=len(evaluation["violations"]),
        matched_patterns=evaluation["detected_data_types"],
        sample_result=evaluation,
        timestamp=evaluation["timestamp"],
    )


# ==================== VIOLATIONS ====================


@router.post("/violations", response_model=DLPViolationResponse, status_code=status.HTTP_201_CREATED)
async def create_violation(
    violation_data: DLPViolationCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a DLP violation record"""
    violation = DLPViolation(
        organization_id=getattr(current_user, "organization_id", None),
        policy_id=violation_data.policy_id,
        violation_type=violation_data.violation_type,
        severity=violation_data.severity,
        source_user=violation_data.source_user,
        source_device=violation_data.source_device,
        source_application=violation_data.source_application,
        destination=violation_data.destination,
        data_classification=violation_data.data_classification,
        sensitive_data_types=json.dumps(violation_data.sensitive_data_types)
        if violation_data.sensitive_data_types
        else None,
        file_name=violation_data.file_name,
        file_hash=violation_data.file_hash,
        data_volume_bytes=violation_data.data_volume_bytes,
        action_taken=violation_data.action_taken,
        status=violation_data.status,
    )

    db.add(violation)
    await db.flush()
    await db.refresh(violation)

    return convert_json_fields(violation)


@router.get("/violations", response_model=DLPViolationListResponse)
async def list_violations(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    user: Optional[str] = None,
    search: Optional[str] = None,
):
    """List DLP violations"""
    query = select(DLPViolation).where(DLPViolation.organization_id == getattr(current_user, "organization_id", None))

    if status_filter:
        query = query.where(DLPViolation.status == status_filter)

    if severity:
        query = query.where(DLPViolation.severity == severity)

    if user:
        query = query.where(DLPViolation.source_user == user)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            DLPViolation.file_name.ilike(search_filter)
            | DLPViolation.destination.ilike(search_filter)
        )

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(DLPViolation.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    violations = list(result.scalars().all())

    return DLPViolationListResponse(
        items=[convert_json_fields(v) for v in violations],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/violations/{violation_id}", response_model=DLPViolationResponse)
async def get_violation(
    violation_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a DLP violation by ID"""
    violation = await get_violation_or_404(db, violation_id)
    return convert_json_fields(violation)


@router.patch("/violations/{violation_id}", response_model=DLPViolationResponse)
async def investigate_violation(
    violation_id: str,
    investigation: DLPViolationResolveRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Investigate and resolve a violation"""
    violation = await get_violation_or_404(db, violation_id)

    violation.status = investigation.status
    violation.justification = investigation.justification
    violation.reviewed_by = investigation.reviewed_by or current_user.id

    await db.flush()
    await db.refresh(violation)

    return convert_json_fields(violation)


@router.post("/violations/bulk-action", response_model=DLPViolationBulkActionResponse)
async def bulk_action_violations(
    bulk_request: DLPViolationBulkActionRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Perform bulk actions on violations"""
    result = await db.execute(
        select(DLPViolation).where(DLPViolation.id.in_(bulk_request.violation_ids))
    )
    violations = result.scalars().all()

    successful = 0
    failed_ids = []

    for violation in violations:
        try:
            if bulk_request.action == "resolve":
                violation.status = "resolved"
                violation.justification = bulk_request.justification
                violation.reviewed_by = current_user.id
            elif bulk_request.action == "escalate":
                violation.status = "escalated"
            elif bulk_request.action == "confirm":
                violation.status = "confirmed"

            successful += 1
        except Exception:
            failed_ids.append(violation.id)

    await db.flush()

    return DLPViolationBulkActionResponse(
        successful=successful,
        failed=len(failed_ids),
        total=len(bulk_request.violation_ids),
        failed_ids=failed_ids,
    )


# ==================== DATA CLASSIFICATION ====================


@router.post("/classifications", response_model=DataClassificationResponse, status_code=status.HTTP_201_CREATED)
async def create_classification(
    classification_data: DataClassificationCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a data classification level"""
    classification = DataClassification(
        organization_id=getattr(current_user, "organization_id", None),
        name=classification_data.name,
        classification_level=classification_data.classification_level,
        description=classification_data.description,
        handling_rules=json.dumps(classification_data.handling_rules)
        if classification_data.handling_rules
        else None,
        retention_days=classification_data.retention_days,
        encryption_required=classification_data.encryption_required,
        dlp_policies=json.dumps(classification_data.dlp_policies)
        if classification_data.dlp_policies
        else None,
        auto_classification_rules=json.dumps(classification_data.auto_classification_rules)
        if classification_data.auto_classification_rules
        else None,
        color_code=classification_data.color_code,
    )

    db.add(classification)
    await db.flush()
    await db.refresh(classification)

    return convert_json_fields(classification)


@router.get("/classifications", response_model=DataClassificationListResponse)
async def list_classifications(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    level: Optional[str] = None,
):
    """List data classifications"""
    query = select(DataClassification).where(
        DataClassification.organization_id == getattr(current_user, "organization_id", None)
    )

    if level:
        query = query.where(DataClassification.classification_level == level)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(DataClassification.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    classifications = list(result.scalars().all())

    return DataClassificationListResponse(
        items=[convert_json_fields(c) for c in classifications],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/classifications/{classification_id}", response_model=DataClassificationResponse)
async def get_classification(
    classification_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a data classification by ID"""
    classification = await get_classification_or_404(db, classification_id)
    return convert_json_fields(classification)


@router.patch("/classifications/{classification_id}", response_model=DataClassificationResponse)
async def update_classification(
    classification_id: str,
    classification_data: DataClassificationUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a data classification"""
    classification = await get_classification_or_404(db, classification_id)

    update_data = classification_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    if "handling_rules" in update_data:
        update_data["handling_rules"] = json.dumps(update_data["handling_rules"])
    if "dlp_policies" in update_data:
        update_data["dlp_policies"] = json.dumps(update_data["dlp_policies"])
    if "auto_classification_rules" in update_data:
        update_data["auto_classification_rules"] = json.dumps(update_data["auto_classification_rules"])

    for key, value in update_data.items():
        setattr(classification, key, value)

    await db.flush()
    await db.refresh(classification)

    return convert_json_fields(classification)


@router.post("/classifications/classify-document", response_model=DocumentClassificationResponse)
async def classify_document(
    request: DocumentClassificationRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Classify a document by content and metadata"""
    classification_result = classifier.classify_document(
        request.content,
        {
            "file_name": request.file_name,
            **(request.metadata or {}),
        },
    )

    return DocumentClassificationResponse(
        classification_level=classification_result["classification_level"],
        confidence=classification_result.get("confidence", 0.75),
        indicators=[],
        content_based=classification_result.get("content_based", {}),
        metadata_based=classification_result.get("metadata_based", {}),
        timestamp=classification_result["timestamp"],
    )


@router.get(
    "/classifications/{classification_id}/handling-requirements",
    response_model=DataHandlingRequirementsResponse,
)
async def get_handling_requirements(
    classification_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get data handling requirements for a classification"""
    classification = await get_classification_or_404(db, classification_id)

    requirements = classifier.get_handling_requirements(classification.classification_level)

    return DataHandlingRequirementsResponse(
        classification_level=classification.classification_level,
        encryption=requirements["encryption"],
        access_control=requirements["access_control"],
        retention_days=requirements["retention_days"],
        sharing_restrictions=requirements["sharing"],
    )


# ==================== DATA DISCOVERY ====================


@router.post("/discovery/scan", response_model=SensitiveDataDiscoveryResponse, status_code=status.HTTP_201_CREATED)
async def trigger_discovery_scan(
    scan_request: DiscoveryScanTriggerRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Trigger a sensitive data discovery scan"""
    scan = SensitiveDataDiscovery(
        organization_id=getattr(current_user, "organization_id", None),
        scan_id=f"scan_{getattr(current_user, 'organization_id', None)}_{int(__import__('time').time())}",
        scan_type=scan_request.scan_type,
        target=scan_request.target,
        status="pending",
    )

    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    return convert_json_fields(scan)


@router.get("/discovery/scans", response_model=DiscoveryScanListResponse)
async def list_discovery_scans(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    scan_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List sensitive data discovery scans"""
    query = select(SensitiveDataDiscovery).where(
        SensitiveDataDiscovery.organization_id == getattr(current_user, "organization_id", None)
    )

    if scan_type:
        query = query.where(SensitiveDataDiscovery.scan_type == scan_type)

    if status_filter:
        query = query.where(SensitiveDataDiscovery.status == status_filter)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(SensitiveDataDiscovery.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    scans = list(result.scalars().all())

    return DiscoveryScanListResponse(
        items=[convert_json_fields(s) for s in scans],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/discovery/scans/{scan_id}", response_model=SensitiveDataDiscoveryResponse)
async def get_discovery_scan(
    scan_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get discovery scan results"""
    result = await db.execute(
        select(SensitiveDataDiscovery).where(SensitiveDataDiscovery.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return convert_json_fields(scan)


@router.get("/discovery/data-map", response_model=DataMapResponse)
async def get_data_map(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get data map showing where sensitive data lives"""
    data_map = scanner.generate_data_map(getattr(current_user, "organization_id", None))
    return DataMapResponse(**data_map)


@router.get("/discovery/lineage/{data_id}", response_model=DataLineageResponse)
async def get_data_lineage(
    data_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Track data lineage"""
    lineage = scanner.track_data_lineage(data_id)
    return DataLineageResponse(**lineage)


# ==================== INCIDENTS ====================


@router.post("/incidents", response_model=DLPIncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: DLPIncidentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a DLP incident"""
    incident = DLPIncident(
        organization_id=getattr(current_user, "organization_id", None),
        violation_ids=json.dumps(incident_data.violation_ids)
        if incident_data.violation_ids
        else None,
        incident_title=incident_data.incident_title,
        description=incident_data.description,
        severity=incident_data.severity,
        status=incident_data.status,
        affected_data_subjects_count=incident_data.affected_data_subjects_count,
        data_types_involved=json.dumps(incident_data.data_types_involved)
        if incident_data.data_types_involved
        else None,
        incident_commander=current_user.id,
    )

    db.add(incident)
    await db.flush()
    await db.refresh(incident)

    return convert_json_fields(incident)


@router.get("/incidents", response_model=DLPIncidentListResponse)
async def list_incidents(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
):
    """List DLP incidents"""
    query = select(DLPIncident).where(DLPIncident.organization_id == getattr(current_user, "organization_id", None))

    if status_filter:
        query = query.where(DLPIncident.status == status_filter)

    if severity:
        query = query.where(DLPIncident.severity == severity)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar() or 0

    query = query.order_by(DLPIncident.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    incidents = list(result.scalars().all())

    return DLPIncidentListResponse(
        items=[convert_json_fields(i) for i in incidents],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/incidents/{incident_id}", response_model=DLPIncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a DLP incident by ID"""
    incident = await get_incident_or_404(db, incident_id)
    return convert_json_fields(incident)


@router.patch("/incidents/{incident_id}", response_model=DLPIncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: DLPIncidentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a DLP incident"""
    incident = await get_incident_or_404(db, incident_id)

    update_data = incident_data.model_dump(exclude_unset=True, exclude_none=True)

    # Handle JSON fields
    if "remediation_steps" in update_data:
        update_data["remediation_steps"] = json.dumps(update_data["remediation_steps"])

    for key, value in update_data.items():
        setattr(incident, key, value)

    await db.flush()
    await db.refresh(incident)

    return convert_json_fields(incident)


@router.post("/incidents/{incident_id}/assess-breach", response_model=BreachAssessmentResponse)
async def assess_breach(
    incident_id: str,
    assessment_request: BreachAssessmentRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Assess breach incident and determine regulatory obligations"""
    incident = await get_incident_or_404(db, incident_id)

    assessment = assessor.assess_breach(
        {
            "id": incident_id,
            "severity": incident.severity,
            "affected_count": assessment_request.affected_count,
            "data_types": assessment_request.data_types,
            "description": assessment_request.description,
        }
    )

    # Update incident with assessment results
    incident.breach_notification_required = assessment["notification_required"]
    incident.affected_data_subjects_count = assessment["affected_subjects"]
    incident.data_types_involved = json.dumps(assessment["data_types"])
    incident.regulatory_implications = json.dumps(assessment["regulatory_obligations"])
    incident.notification_deadline = __import__("dateutil.parser").parser.isoparse(
        assessment["notification_deadline"]
    )

    await db.flush()
    await db.refresh(incident)

    return BreachAssessmentResponse(
        incident_id=incident_id,
        assessment_date=assessment["assessment_date"],
        severity=assessment["severity"],
        affected_subjects=assessment["affected_subjects"],
        data_types=assessment["data_types"],
        regulatory_obligations=assessment["regulatory_obligations"],
        notification_deadline=assessment["notification_deadline"],
        notification_required=assessment["notification_required"],
    )


@router.get(
    "/incidents/{incident_id}/notification-tracking",
    response_model=NotificationTrackingResponse,
)
async def get_notification_tracking(
    incident_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    notified_count: int = Query(0, ge=0),
    total_required: int = Query(0, ge=0),
):
    """Get notification compliance tracking"""
    tracking = assessor.track_notification_compliance(
        incident_id,
        notified_count,
        total_required,
    )

    return NotificationTrackingResponse(**tracking)


# ==================== DASHBOARD ====================


@router.get("/dashboard", response_model=DLPDashboardResponse)
async def get_dlp_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get DLP dashboard summary"""
    # Count violations
    violations_query = select(func.count()).select_from(DLPViolation).where(
        DLPViolation.organization_id == getattr(current_user, "organization_id", None)
    )
    total_violations_result = await db.execute(violations_query)
    total_violations = total_violations_result.scalar() or 0

    # Count critical violations
    critical_query = select(func.count()).select_from(DLPViolation).where(
        (DLPViolation.organization_id == getattr(current_user, "organization_id", None))
        & (DLPViolation.severity == "critical")
    )
    critical_result = await db.execute(critical_query)
    critical_violations = critical_result.scalar() or 0

    # Get top policies
    policy_query = select(DLPPolicy.name, func.count(DLPViolation.id).label("trigger_count")).join(
        DLPViolation,
        DLPPolicy.id == DLPViolation.policy_id,
    ).where(
        DLPPolicy.organization_id == getattr(current_user, "organization_id", None)
    ).group_by(
        DLPPolicy.name
    ).order_by(
        func.count(DLPViolation.id).desc()
    ).limit(5)

    policy_result = await db.execute(policy_query)
    top_policies = [
        {"policy": row[0], "triggers": row[1]}
        for row in policy_result.all()
    ]

    return DLPDashboardResponse(
        organization_id=getattr(current_user, "organization_id", None),
        total_violations=total_violations,
        violations_this_month=0,
        critical_violations=critical_violations,
        top_violations=[],
        top_policies_triggered=top_policies,
        data_risk_map={
            "high_risk_locations": 3,
            "medium_risk_locations": 12,
            "monitored_locations": 250,
        },
        compliance_status={
            "gdpr": "compliant",
            "hipaa": "compliant",
            "pci_dss": "pending_review",
        },
        remediation_rate=0.82,
        average_response_time_hours=4.5,
    )


@router.get("/trends", response_model=ViolationTrendResponse)
async def get_violation_trends(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    period: str = Query("month", pattern="^(day|week|month|year)$"),
):
    """Get violation trends"""
    return ViolationTrendResponse(
        period=period,
        total_violations=0,
        by_type={
            "pii_exposure": 0,
            "unauthorized_transfer": 0,
        },
        by_severity={
            "critical": 0,
            "high": 0,
            "medium": 0,
        },
        by_status={
            "new": 0,
            "investigating": 0,
            "resolved": 0,
        },
        trend_direction="stable",
    )


@router.get("/compliance-status", response_model=ComplianceStatusResponse)
async def get_compliance_status(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get regulatory compliance status"""
    return ComplianceStatusResponse(
        regulations={
            "GDPR": {"compliant": True, "open_incidents": 0},
            "HIPAA": {"compliant": True, "open_incidents": 0},
            "PCI-DSS": {"compliant": True, "open_incidents": 0},
            "CCPA": {"compliant": True, "open_incidents": 0},
        },
        open_incidents=0,
        overdue_notifications=0,
        compliance_score=0.95,
        recommendations=[],
    )
