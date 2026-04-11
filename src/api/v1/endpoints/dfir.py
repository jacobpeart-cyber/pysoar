"""DFIR API endpoints for forensic case management, evidence handling, and timeline reconstruction"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
from src.core.utils import safe_json_loads
from src.models.user import User
from src.dfir.models import (
    ForensicCase,
    ForensicEvidence,
    ForensicTimeline,
    ForensicArtifact,
    LegalHold,
    CaseStatus,
)
from src.dfir.engine import (
    ForensicEngine,
    EvidenceManager,
    TimelineReconstructor,
    ArtifactAnalyzer,
    LegalHoldManager,
)
from src.schemas.dfir import (
    ForensicCaseCreate,
    ForensicCaseUpdate,
    ForensicCaseResponse,
    ForensicCaseListResponse,
    ForensicEvidenceCreate,
    ForensicEvidenceUpdate,
    ForensicEvidenceResponse,
    ForensicEvidenceListResponse,
    ForensicTimelineCreate,
    ForensicTimelineUpdate,
    ForensicTimelineResponse,
    ForensicTimelineListResponse,
    ForensicArtifactCreate,
    ForensicArtifactUpdate,
    ForensicArtifactResponse,
    ForensicArtifactListResponse,
    LegalHoldCreate,
    LegalHoldUpdate,
    LegalHoldResponse,
    LegalHoldListResponse,
    EvidenceVerifyRequest,
    ChainOfCustodyUpdateRequest,
    ArtifactAnalysisRequest,
    ArtifactAnalysisResponse,
    IOCExtractionResponse,
    CaseReportResponse,
    TimelineExportResponse,
    ChainOfCustodyReportResponse,
    CaseMetrics,
    DFIRDashboardResponse,
)

router = APIRouter(prefix="/dfir", tags=["DFIR"])


# ============================================================================
# Helper Functions
# ============================================================================


async def get_case_or_404(db: AsyncSession, case_id: str) -> ForensicCase:
    """Get forensic case by ID or raise 404"""
    result = await db.execute(
        select(ForensicCase)
        .options(
            selectinload(ForensicCase.evidence),
            selectinload(ForensicCase.timeline_events),
            selectinload(ForensicCase.artifacts),
            selectinload(ForensicCase.legal_holds),
        )
        .where(ForensicCase.id == case_id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic case not found",
        )
    return case


async def get_evidence_or_404(db: AsyncSession, evidence_id: str) -> ForensicEvidence:
    """Get forensic evidence by ID or raise 404"""
    result = await db.execute(
        select(ForensicEvidence)
        .options(selectinload(ForensicEvidence.case))
        .where(ForensicEvidence.id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )
    return evidence


# ============================================================================
# Forensic Case Endpoints - CRUD Operations
# ============================================================================


@router.get("/cases", response_model=ForensicCaseListResponse)
async def list_cases(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    case_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List forensic cases with filtering and pagination"""
    query = select(ForensicCase).options(
        selectinload(ForensicCase.lead_investigator),
        selectinload(ForensicCase.evidence),
    )

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(ForensicCase.organization_id == org_id)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (ForensicCase.case_number.ilike(search_filter))
            | (ForensicCase.title.ilike(search_filter))
            | (ForensicCase.description.ilike(search_filter))
        )

    if case_type:
        query = query.where(ForensicCase.case_type == case_type)

    if status_filter:
        query = query.where(ForensicCase.status == status_filter)

    if severity:
        query = query.where(ForensicCase.severity == severity)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicCase.id).where(query.whereclause) if query.whereclause is not None else select(ForensicCase.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply sorting
    sort_column = getattr(ForensicCase, sort_by, ForensicCase.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    cases = list(result.scalars().all())

    items = [ForensicCaseResponse.model_validate(case) for case in cases]

    return ForensicCaseListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/cases/{case_id}", response_model=ForensicCaseResponse)
async def get_case(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific forensic case"""
    case = await get_case_or_404(db, case_id)
    return ForensicCaseResponse.model_validate(case)


@router.post("/cases", response_model=ForensicCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    case_data: ForensicCaseCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new forensic case"""
    # Check for duplicate case number
    result = await db.execute(
        select(ForensicCase).where(ForensicCase.case_number == case_data.case_number)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case number {case_data.case_number} already exists",
        )

    case = ForensicCase(
        case_number=case_data.case_number,
        title=case_data.title,
        description=case_data.description,
        case_type=case_data.case_type,
        severity=case_data.severity,
        lead_investigator_id=case_data.lead_investigator_id,
        assigned_team=json.dumps(case_data.assigned_team) if case_data.assigned_team else None,
        created_by=case_data.created_by,
        organization_id=getattr(current_user, "organization_id", None),
        status=CaseStatus.OPEN.value,
    )

    db.add(case)
    await db.flush()
    await db.refresh(case)

    return ForensicCaseResponse.model_validate(case)


@router.put("/cases/{case_id}", response_model=ForensicCaseResponse)
async def update_case(
    case_id: str,
    case_data: ForensicCaseUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a forensic case"""
    case = await get_case_or_404(db, case_id)

    update_data = case_data.model_dump(exclude_unset=True)

    # Handle JSON fields
    if "assigned_team" in update_data and update_data["assigned_team"] is not None:
        update_data["assigned_team"] = json.dumps(update_data["assigned_team"])

    for field, value in update_data.items():
        setattr(case, field, value)

    case.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(case)

    return ForensicCaseResponse.model_validate(case)


@router.post("/cases/{case_id}/close", response_model=ForensicCaseResponse)
async def close_case(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    conclusion: Optional[str] = None,
):
    """Close a forensic case"""
    case = await get_case_or_404(db, case_id)

    case.status = CaseStatus.CLOSED.value
    case.updated_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(case)

    return ForensicCaseResponse.model_validate(case)


# ============================================================================
# Evidence Management Endpoints
# ============================================================================


@router.get("/cases/{case_id}/evidence", response_model=ForensicEvidenceListResponse)
async def list_evidence(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    evidence_type: Optional[str] = None,
    is_verified: Optional[bool] = None,
):
    """List evidence for a forensic case"""
    # Verify case exists
    await get_case_or_404(db, case_id)

    query = select(ForensicEvidence).where(ForensicEvidence.case_id == case_id)

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(ForensicEvidence.organization_id == org_id)

    if evidence_type:
        query = query.where(ForensicEvidence.evidence_type == evidence_type)

    if is_verified is not None:
        query = query.where(ForensicEvidence.is_verified == is_verified)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicEvidence.id).where(query.whereclause) if query.whereclause is not None else select(ForensicEvidence.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(ForensicEvidence.created_at.desc()).offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    evidence_list = list(result.scalars().all())

    items = [ForensicEvidenceResponse.model_validate(e) for e in evidence_list]

    return ForensicEvidenceListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/evidence/{evidence_id}", response_model=ForensicEvidenceResponse)
async def get_evidence(
    evidence_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a specific evidence item"""
    evidence = await get_evidence_or_404(db, evidence_id)
    return ForensicEvidenceResponse.model_validate(evidence)


@router.post("/evidence", response_model=ForensicEvidenceResponse, status_code=status.HTTP_201_CREATED)
async def collect_evidence(
    evidence_data: ForensicEvidenceCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Collect and register forensic evidence"""
    # Verify case exists
    await get_case_or_404(db, evidence_data.case_id)

    evidence = ForensicEvidence(
        case_id=evidence_data.case_id,
        evidence_type=evidence_data.evidence_type,
        source_device=evidence_data.source_device,
        source_ip=evidence_data.source_ip,
        acquisition_method=evidence_data.acquisition_method,
        original_hash_md5=evidence_data.original_hash_md5,
        original_hash_sha256=evidence_data.original_hash_sha256,
        storage_location=evidence_data.storage_location,
        file_size_bytes=evidence_data.file_size_bytes,
        handling_notes=evidence_data.handling_notes,
        organization_id=getattr(current_user, "organization_id", None),
        chain_of_custody_log={
            "entries": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": getattr(current_user, "full_name", None) or current_user.email,
                    "action": "collected",
                    "hash": evidence_data.original_hash_sha256,
                }
            ]
        },
    )

    db.add(evidence)
    await db.flush()
    await db.refresh(evidence)

    return ForensicEvidenceResponse.model_validate(evidence)


@router.post("/evidence/{evidence_id}/verify", response_model=ForensicEvidenceResponse)
async def verify_evidence_integrity(
    evidence_id: str,
    verify_data: EvidenceVerifyRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Verify evidence integrity through hash comparison"""
    evidence = await get_evidence_or_404(db, evidence_id)

    # Verify hash
    is_valid = True
    if verify_data.original_hash:
        is_valid = verify_data.evidence_hash.lower() == verify_data.original_hash.lower()

    evidence.is_verified = is_valid
    evidence.verified_by = getattr(current_user, "full_name", None) or current_user.email
    evidence.verification_date = datetime.now(timezone.utc).isoformat()

    if verify_data.hash_algorithm == "sha256":
        evidence.original_hash_sha256 = verify_data.evidence_hash
    elif verify_data.hash_algorithm == "md5":
        evidence.original_hash_md5 = verify_data.evidence_hash

    await db.flush()
    await db.refresh(evidence)

    return ForensicEvidenceResponse.model_validate(evidence)


@router.post("/evidence/{evidence_id}/chain-of-custody", response_model=ForensicEvidenceResponse)
async def update_chain_of_custody(
    evidence_id: str,
    coc_data: ChainOfCustodyUpdateRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update chain of custody log"""
    evidence = await get_evidence_or_404(db, evidence_id)

    # Parse existing log
    coc_log = evidence.chain_of_custody_log or {"entries": []}
    if isinstance(coc_log, str):
        coc_log = safe_json_loads(coc_log, {})

    if "entries" not in coc_log:
        coc_log["entries"] = []

    # Add new entry
    coc_log["entries"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": coc_data.actor,
            "action": coc_data.action,
            "hash": coc_data.evidence_hash,
            "details": coc_data.details,
        }
    )

    evidence.chain_of_custody_log = coc_log
    await db.flush()
    await db.refresh(evidence)

    return ForensicEvidenceResponse.model_validate(evidence)


# ============================================================================
# Timeline Endpoints
# ============================================================================


@router.get("/cases/{case_id}/timeline", response_model=ForensicTimelineListResponse)
async def get_timeline(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    is_pivotal: Optional[bool] = None,
):
    """Get case timeline"""
    await get_case_or_404(db, case_id)

    query = select(ForensicTimeline).where(ForensicTimeline.case_id == case_id)

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(ForensicTimeline.organization_id == org_id)

    if event_type:
        query = query.where(ForensicTimeline.event_type == event_type)

    if is_pivotal is not None:
        query = query.where(ForensicTimeline.is_pivotal == is_pivotal)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicTimeline.id).where(query.whereclause) if query.whereclause is not None else select(ForensicTimeline.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply sorting by timestamp
    query = query.order_by(ForensicTimeline.event_timestamp.asc()).offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    events = list(result.scalars().all())

    items = [ForensicTimelineResponse.model_validate(e) for e in events]

    return ForensicTimelineListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/cases/{case_id}/timeline/events", response_model=ForensicTimelineResponse, status_code=status.HTTP_201_CREATED)
async def add_timeline_event(
    case_id: str,
    event_data: ForensicTimelineCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Add event to case timeline"""
    await get_case_or_404(db, case_id)

    event = ForensicTimeline(
        case_id=case_id,
        event_timestamp=event_data.event_timestamp,
        event_type=event_data.event_type,
        source=event_data.source,
        source_evidence_id=event_data.source_evidence_id,
        description=event_data.description,
        artifact_data=event_data.artifact_data or {},
        mitre_technique_id=event_data.mitre_technique_id,
        severity_score=event_data.severity_score,
        is_pivotal=event_data.is_pivotal,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(event)
    await db.flush()
    await db.refresh(event)

    return ForensicTimelineResponse.model_validate(event)


@router.post("/cases/{case_id}/timeline/export", response_model=TimelineExportResponse)
async def export_timeline(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Export case timeline"""
    case = await get_case_or_404(db, case_id)

    result = await db.execute(
        select(ForensicTimeline)
        .where(ForensicTimeline.case_id == case_id)
        .order_by(ForensicTimeline.event_timestamp.asc())
    )
    events = list(result.scalars().all())

    return TimelineExportResponse(
        case_id=case_id,
        generated_at=datetime.now(timezone.utc),
        event_count=len(events),
        events=[ForensicTimelineResponse.model_validate(e) for e in events],
    )


# ============================================================================
# Artifact Analysis Endpoints
# ============================================================================


@router.get("/cases/{case_id}/artifacts", response_model=ForensicArtifactListResponse)
async def list_artifacts(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    artifact_type: Optional[str] = None,
    min_risk_score: float = Query(0.0, ge=0.0, le=10.0),
):
    """List artifacts for a case"""
    await get_case_or_404(db, case_id)

    query = select(ForensicArtifact).where(ForensicArtifact.case_id == case_id)

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(ForensicArtifact.organization_id == org_id)

    if artifact_type:
        query = query.where(ForensicArtifact.artifact_type == artifact_type)

    if min_risk_score > 0:
        query = query.where(ForensicArtifact.risk_score >= min_risk_score)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicArtifact.id).where(query.whereclause) if query.whereclause is not None else select(ForensicArtifact.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply sorting by risk score descending
    query = query.order_by(ForensicArtifact.risk_score.desc()).offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    artifacts = list(result.scalars().all())

    items = [ForensicArtifactResponse.model_validate(a) for a in artifacts]

    return ForensicArtifactListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/cases/{case_id}/artifacts", response_model=ForensicArtifactResponse, status_code=status.HTTP_201_CREATED)
async def create_artifact(
    case_id: str,
    artifact_data: ForensicArtifactCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create forensic artifact"""
    await get_case_or_404(db, case_id)
    await get_evidence_or_404(db, artifact_data.evidence_id)

    artifact = ForensicArtifact(
        case_id=case_id,
        evidence_id=artifact_data.evidence_id,
        artifact_type=artifact_data.artifact_type,
        artifact_data=artifact_data.artifact_data or {},
        analysis_notes=artifact_data.analysis_notes,
        ioc_extracted=artifact_data.ioc_extracted or {},
        mitre_mapping=artifact_data.mitre_mapping,
        risk_score=artifact_data.risk_score,
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(artifact)
    await db.flush()
    await db.refresh(artifact)

    return ForensicArtifactResponse.model_validate(artifact)


@router.post("/artifacts/analyze", response_model=ArtifactAnalysisResponse)
async def analyze_artifact(
    analysis_data: ArtifactAnalysisRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Analyze a forensic artifact"""
    analyzer = ArtifactAnalyzer()

    # Perform analysis
    if analysis_data.artifact_type.startswith("disk_"):
        analysis = analyzer.analyze_disk_artifacts(analysis_data.artifact_type, analysis_data.artifact_data)
    elif analysis_data.artifact_type.startswith("memory_"):
        analysis = analyzer.analyze_memory_artifacts(analysis_data.artifact_type, analysis_data.artifact_data)
    elif analysis_data.artifact_type.startswith("network_"):
        analysis = analyzer.analyze_network_artifacts(analysis_data.artifact_type, analysis_data.artifact_data)
    else:
        analysis = {"status": "error", "message": f"Unknown artifact type: {analysis_data.artifact_type}"}

    if analysis["status"] != "success":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=analysis.get("message"))

    # Extract IOCs
    ioc_result = analyzer.extract_iocs(analysis_data.artifact_data, analysis_data.artifact_type)

    # Map to MITRE
    mitre_result = analyzer.map_to_mitre(analysis_data.artifact_type, analysis_data.artifact_data)

    return ArtifactAnalysisResponse(
        status="success",
        artifact_type=analysis_data.artifact_type,
        analysis=analysis.get("analysis", {}),
        iocs_extracted=ioc_result.get("total_extracted", 0),
        mitre_mapping=mitre_result.get("mapping", {}),
    )


@router.post("/cases/{case_id}/artifacts/extract-iocs", response_model=IOCExtractionResponse)
async def extract_case_iocs(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Extract all IOCs from case artifacts"""
    await get_case_or_404(db, case_id)

    result = await db.execute(
        select(ForensicArtifact).where(ForensicArtifact.case_id == case_id)
    )
    artifacts = list(result.scalars().all())

    analyzer = ArtifactAnalyzer()
    aggregated_iocs = {
        "ipv4_addresses": set(),
        "ipv6_addresses": set(),
        "domains": set(),
        "file_hashes": set(),
        "email_addresses": set(),
        "urls": set(),
    }

    for artifact in artifacts:
        ioc_result = analyzer.extract_iocs(artifact.artifact_data or {}, artifact.artifact_type)
        if ioc_result["status"] == "success":
            iocs = ioc_result.get("iocs", {})
            for ioc_type, values in iocs.items():
                aggregated_iocs[ioc_type].update(values)

    # Convert sets to lists
    final_iocs = {k: list(v) for k, v in aggregated_iocs.items()}
    total = sum(len(v) for v in final_iocs.values())

    from src.schemas.dfir import IOCData

    return IOCExtractionResponse(
        status="success",
        iocs=IOCData(**final_iocs),
        total_extracted=total,
    )


# ============================================================================
# Legal Hold Endpoints
# ============================================================================


@router.get("/cases/{case_id}/legal-holds", response_model=LegalHoldListResponse)
async def list_legal_holds(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List legal holds for a case"""
    await get_case_or_404(db, case_id)

    query = select(LegalHold).where(LegalHold.case_id == case_id)

    # Filter by organization
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        query = query.where(LegalHold.organization_id == org_id)

    count_query = select(func.count()).select_from(
        select(LegalHold.id).where(query.whereclause) if query.whereclause is not None else select(LegalHold.id)
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    query = query.order_by(LegalHold.created_at.desc()).offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    holds = list(result.scalars().all())

    items = [LegalHoldResponse.model_validate(h) for h in holds]

    return LegalHoldListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/cases/{case_id}/legal-holds", response_model=LegalHoldResponse, status_code=status.HTTP_201_CREATED)
async def create_legal_hold(
    case_id: str,
    hold_data: LegalHoldCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a legal hold"""
    case = await get_case_or_404(db, case_id)

    hold = LegalHold(
        case_id=case_id,
        hold_type=hold_data.hold_type,
        custodians=hold_data.custodians,
        data_sources=hold_data.data_sources,
        issued_by=hold_data.issued_by,
        issued_date=hold_data.issued_date or datetime.now(timezone.utc).isoformat(),
        expiry_date=hold_data.expiry_date,
        status="active",
        organization_id=getattr(current_user, "organization_id", None),
    )

    db.add(hold)
    case.legal_hold_active = True
    await db.flush()
    await db.refresh(hold)

    return LegalHoldResponse.model_validate(hold)


@router.put("/legal-holds/{hold_id}", response_model=LegalHoldResponse)
async def update_legal_hold(
    hold_id: str,
    hold_data: LegalHoldUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update legal hold"""
    result = await db.execute(select(LegalHold).where(LegalHold.id == hold_id))
    hold = result.scalar_one_or_none()

    if not hold:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Legal hold not found")

    update_data = hold_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(hold, field, value)

    hold.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(hold)

    return LegalHoldResponse.model_validate(hold)


# ============================================================================
# Report Endpoints
# ============================================================================


@router.get("/cases/{case_id}/report", response_model=CaseReportResponse)
async def generate_case_report(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Generate comprehensive case report"""
    case = await get_case_or_404(db, case_id)

    # Get counts
    evidence_count = len(case.evidence or [])
    artifact_count = len(case.artifacts or [])
    timeline_count = len(case.timeline_events or [])
    legal_holds = len(case.legal_holds or [])

    return CaseReportResponse(
        case_id=case_id,
        generated_at=datetime.now(timezone.utc),
        sections=["timeline_reconstruction", "artifact_analysis", "findings_and_conclusions"],
        evidence_count=evidence_count,
        artifact_count=artifact_count,
        timeline_events=timeline_count,
        legal_holds_active=legal_holds,
    )


@router.get("/evidence/{evidence_id}/chain-of-custody", response_model=ChainOfCustodyReportResponse)
async def get_chain_of_custody_report(
    evidence_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get chain of custody report"""
    evidence = await get_evidence_or_404(db, evidence_id)

    coc_log = evidence.chain_of_custody_log or {}
    if isinstance(coc_log, str):
        coc_log = safe_json_loads(coc_log, {})

    entries = []
    if "entries" in coc_log:
        from src.schemas.dfir import ChainOfCustodyEntry

        entries = [ChainOfCustodyEntry(**e) for e in coc_log["entries"]]

    return ChainOfCustodyReportResponse(
        evidence_id=evidence_id,
        generated_at=datetime.now(timezone.utc),
        log_entries=entries,
        is_court_admissible=evidence.is_verified,
    )


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard/metrics", response_model=DFIRDashboardResponse)
async def get_dfir_dashboard(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get DFIR dashboard metrics"""
    org_id = getattr(current_user, "organization_id", None)

    # Count cases by status
    cases_query = select(func.count()).select_from(ForensicCase)
    if org_id:
        cases_query = cases_query.where(ForensicCase.organization_id == org_id)
    all_cases = await db.execute(cases_query)
    total_cases = all_cases.scalar() or 0

    active_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.status.in_([CaseStatus.OPEN.value, CaseStatus.IN_PROGRESS.value])
    )
    if org_id:
        active_query = active_query.where(ForensicCase.organization_id == org_id)
    active_cases = await db.execute(active_query)
    active_count = active_cases.scalar() or 0

    analysis_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.status == CaseStatus.ANALYSIS.value
    )
    if org_id:
        analysis_query = analysis_query.where(ForensicCase.organization_id == org_id)
    analysis_cases = await db.execute(analysis_query)
    analysis_count = analysis_cases.scalar() or 0

    # Count evidence
    evidence_query = select(func.count()).select_from(ForensicEvidence)
    if org_id:
        evidence_query = evidence_query.where(ForensicEvidence.organization_id == org_id)
    total_evidence = await db.execute(evidence_query)
    evidence_count = total_evidence.scalar() or 0

    # Count artifacts
    artifacts_query = select(func.count()).select_from(ForensicArtifact)
    if org_id:
        artifacts_query = artifacts_query.where(ForensicArtifact.organization_id == org_id)
    total_artifacts = await db.execute(artifacts_query)
    artifacts_count = total_artifacts.scalar() or 0

    # Count legal holds
    holds_query = select(func.count()).select_from(LegalHold).where(LegalHold.status == "active")
    if org_id:
        holds_query = holds_query.where(LegalHold.organization_id == org_id)
    active_holds = await db.execute(holds_query)
    holds_count = active_holds.scalar() or 0

    holds_cases_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.legal_hold_active == True
    )
    if org_id:
        holds_cases_query = holds_cases_query.where(ForensicCase.organization_id == org_id)
    cases_with_holds = await db.execute(holds_cases_query)
    holds_cases = cases_with_holds.scalar() or 0

    return DFIRDashboardResponse(
        total_cases=total_cases,
        active_cases=active_count,
        cases_in_analysis=analysis_count,
        total_evidence_items=evidence_count,
        total_artifacts=artifacts_count,
        legal_holds_active=holds_count,
        cases_with_legal_holds=holds_cases,
    )


@router.get("/cases/{case_id}/metrics", response_model=CaseMetrics)
async def get_case_metrics(
    case_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get metrics for a specific case"""
    case = await get_case_or_404(db, case_id)

    evidence_count = len(case.evidence or [])
    artifact_count = len(case.artifacts or [])
    timeline_count = len(case.timeline_events or [])
    legal_holds = len(case.legal_holds or [])

    # Count high-risk artifacts
    high_risk = len([a for a in (case.artifacts or []) if a.risk_score >= 7.0])

    # Count pivotal events
    pivotal = len([e for e in (case.timeline_events or []) if e.is_pivotal])

    return CaseMetrics(
        case_id=case_id,
        evidence_count=evidence_count,
        artifact_count=artifact_count,
        timeline_events=timeline_count,
        legal_holds_active=legal_holds,
        high_risk_artifacts=high_risk,
        pivotal_events=pivotal,
    )
