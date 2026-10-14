"""DFIR schemas for API request/response validation"""

from datetime import datetime
from typing import Any, Optional, Union

from pydantic import BaseModel, Field, computed_field

from src.schemas.base import DBModel

# ============================================================================
# Forensic Case Schemas
# ============================================================================


class ForensicCaseBase(BaseModel):
    """Base forensic case schema"""

    case_number: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    case_type: str = ""
    severity: str = "medium"


class ForensicCaseCreate(ForensicCaseBase):
    """Schema for creating a forensic case"""

    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[list[str]] = None
    created_by: Optional[str] = None


class ForensicCaseUpdate(BaseModel):
    """Schema for updating a forensic case"""

    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[list[str]] = None
    legal_hold_active: Optional[bool] = None
    classification_level: Optional[str] = None
    court_admissible: Optional[bool] = None


class ForensicCaseResponse(ForensicCaseBase, DBModel):
    """Schema for forensic case response"""

    id: str = ""
    status: str = ""
    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[list[str]] = None
    legal_hold_active: bool = False
    chain_of_custody_hash: Optional[str] = None
    classification_level: Optional[str] = None
    court_admissible: bool = False
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Wave 3: number of evidence rows on the case (set by the list/get routes).
    evidence_count: int = 0

    class Config:
        from_attributes = True


class ForensicCaseListResponse(BaseModel):
    """Schema for paginated forensic case list"""

    items: list[ForensicCaseResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# Forensic Evidence Schemas
# ============================================================================


class ChainOfCustodyEntry(BaseModel):
    """Chain of custody log entry"""

    timestamp: str = ""
    actor: str = ""
    action: str = ""
    hash: Optional[str] = None
    details: Optional[str] = None


class ForensicEvidenceBase(BaseModel):
    """Base forensic evidence schema"""

    evidence_type: str = ""
    source_device: str = Field(..., min_length=1)
    source_ip: Optional[str] = None
    acquisition_method: str = ""
    storage_location: str = ""


class ForensicEvidenceCreate(ForensicEvidenceBase):
    """Schema for collecting forensic evidence"""

    case_id: str = ""
    original_hash_md5: Optional[str] = None
    original_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    handling_notes: Optional[str] = None


class ForensicEvidenceUpdate(BaseModel):
    """Schema for updating forensic evidence"""

    evidence_type: Optional[str] = None
    source_device: Optional[str] = None
    source_ip: Optional[str] = None
    acquisition_method: Optional[str] = None
    storage_location: Optional[str] = None
    is_verified: Optional[bool] = None
    verified_by: Optional[str] = None
    handling_notes: Optional[str] = None


class ForensicEvidenceResponse(ForensicEvidenceBase, DBModel):
    """Schema for forensic evidence response"""

    id: str = ""
    case_id: str = ""
    original_hash_md5: Optional[str] = None
    original_hash_sha256: Optional[str] = None
    # Writers store {"entries": [...]} (see dfir.py create/upload/download/verify);
    # typing this as a bare list made every evidence create, list and upload
    # fail response validation with a 500. Accept the stored shape, and the
    # older list shape for rows written before the entries wrapper existed.
    chain_of_custody_log: Union[dict[str, Any], list[ChainOfCustodyEntry]] = Field(default_factory=dict)
    file_size_bytes: Optional[int] = None
    is_verified: bool = False
    verified_by: Optional[str] = None
    verification_date: Optional[str] = None
    handling_notes: Optional[str] = None
    # Wave 3: endpoint-agent collection. NULL for uploads / registered objects;
    # otherwise awaiting_approval | pending | collected | collected_on_host | failed.
    collection_status: Optional[str] = None
    collection_command_id: Optional[str] = None
    collection_agent_id: Optional[str] = None
    collection_error: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def storage_kind(self) -> str:
        """``local`` (bytes held by PySOAR), ``remote`` (https/s3 object) or ``none``."""
        if not self.storage_location:
            return "none"
        return "remote" if "://" in self.storage_location else "local"

    class Config:
        from_attributes = True


class EvidenceVerification(BaseModel):
    """Outcome of one integrity verification (POST /dfir/evidence/{id}/verify)."""

    algorithm: str = "sha256"
    reference: str = ""  # "file" (stored bytes re-hashed) or "stored_hash" (no local file)
    computed_hash: Optional[str] = None
    stored_hash: Optional[str] = None
    file_matches_stored_hash: Optional[bool] = None
    claimed_hash_matches: Optional[bool] = None
    is_valid: bool = False


class EvidenceVerifyResponse(ForensicEvidenceResponse):
    """Evidence row plus the verification just performed."""

    verification: Optional[EvidenceVerification] = None


class EvidenceCollectRequest(BaseModel):
    """Collect evidence from a host through its endpoint agent."""

    hostname: str = Field(..., min_length=1, max_length=255)
    collection_type: str = Field(..., description="process_list, network_connections, file, memory_dump")
    path: Optional[str] = Field(None, description="file collections: absolute path on the host")
    max_bytes: Optional[int] = Field(None, ge=1, description="file collections: refuse larger files")
    pid: Optional[int] = Field(None, ge=1, description="memory dumps: process id")
    notes: Optional[str] = None


class EvidenceCollectResponse(BaseModel):
    """``awaiting_agent`` (nothing created), ``awaiting_approval`` or ``pending``."""

    status: str = ""
    detail: str = ""
    evidence: Optional[ForensicEvidenceResponse] = None
    command_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_hostname: Optional[str] = None


class ForensicEvidenceListResponse(BaseModel):
    """Schema for paginated evidence list"""

    items: list[ForensicEvidenceResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class EvidenceVerifyRequest(BaseModel):
    """Request to verify evidence integrity.

    ``evidence_hash`` is optional: without it the stored file is re-hashed and
    compared with the hash recorded at collection.
    """

    evidence_hash: str = ""
    hash_algorithm: str = "sha256"
    original_hash: Optional[str] = None


class ChainOfCustodyUpdateRequest(BaseModel):
    """Request to update chain of custody"""

    actor: str = ""
    action: str = ""
    evidence_hash: Optional[str] = None
    details: Optional[str] = None


# ============================================================================
# Forensic Timeline Schemas
# ============================================================================


class ArtifactData(BaseModel):
    """Artifact data container"""

    class Config:
        extra = "forbid"


class ForensicTimelineBase(BaseModel):
    """Base forensic timeline schema"""

    event_type: str = Field(..., min_length=1)
    source: str = Field(..., min_length=1)
    description: Optional[str] = None
    severity_score: float = Field(default=0.0, ge=0.0, le=10.0)
    mitre_technique_id: Optional[str] = None
    is_pivotal: bool = False


class ForensicTimelineCreate(ForensicTimelineBase):
    """Schema for creating timeline events"""

    case_id: str = ""
    event_timestamp: str = ""
    source_evidence_id: Optional[str] = None
    artifact_data: Optional[dict[str, Any]] = Field(default_factory=dict)


class ForensicTimelineUpdate(BaseModel):
    """Schema for updating timeline events"""

    event_type: Optional[str] = None
    source: Optional[str] = None
    description: Optional[str] = None
    severity_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    mitre_technique_id: Optional[str] = None
    is_pivotal: Optional[bool] = None
    artifact_data: Optional[dict[str, Any]] = None


class ForensicTimelineResponse(ForensicTimelineBase, DBModel):
    """Schema for forensic timeline response"""

    id: str = ""
    case_id: str = ""
    event_timestamp: str = ""
    source_evidence_id: Optional[str] = None
    artifact_data: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ForensicTimelineListResponse(BaseModel):
    """Schema for paginated timeline list"""

    items: list[ForensicTimelineResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


# ============================================================================
# Forensic Artifact Schemas
# ============================================================================


class IOCData(BaseModel):
    """IOC container"""

    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class ForensicArtifactBase(BaseModel):
    """Base forensic artifact schema"""

    artifact_type: str = Field(..., min_length=1)
    artifact_data: dict[str, Any] = Field(default_factory=dict)
    analysis_notes: Optional[str] = None
    mitre_mapping: Optional[str] = None
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)


class ForensicArtifactCreate(ForensicArtifactBase):
    """Schema for creating forensic artifacts"""

    case_id: str = ""
    evidence_id: str = ""
    ioc_extracted: Optional[dict[str, Any]] = Field(default_factory=dict)


class ForensicArtifactUpdate(BaseModel):
    """Schema for updating forensic artifacts"""

    artifact_type: Optional[str] = None
    artifact_data: Optional[dict[str, Any]] = None
    analysis_notes: Optional[str] = None
    ioc_extracted: Optional[dict[str, Any]] = None
    mitre_mapping: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0)


class ForensicArtifactResponse(ForensicArtifactBase, DBModel):
    """Schema for forensic artifact response"""

    id: str = ""
    case_id: str = ""
    evidence_id: str = ""
    ioc_extracted: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ioc_count(self) -> int:
        """Indicators persisted on this artifact by the last IOC extraction."""
        return sum(len(v) for v in (self.ioc_extracted or {}).values() if isinstance(v, list))

    class Config:
        from_attributes = True


class ForensicArtifactListResponse(BaseModel):
    """Schema for paginated artifact list"""

    items: list[ForensicArtifactResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class ArtifactAnalysisRequest(BaseModel):
    """Request to analyze artifact"""

    artifact_type: str = ""
    artifact_data: dict[str, Any]


class ArtifactAnalysisResponse(BaseModel):
    """Response from artifact analysis"""

    status: str = ""
    artifact_type: str = ""
    analysis: dict[str, Any]
    iocs_extracted: int = 0
    mitre_mapping: dict[str, Any] = Field(default_factory=dict)


class IOCExtractionResponse(BaseModel):
    """Response from IOC extraction over the case's stored artifacts and evidence bytes"""

    status: str = ""
    iocs: IOCData
    total_extracted: int = 0
    # Wave 3 (the UI read these names; total_extracted is kept).
    iocs_extracted: int = 0
    artifacts_scanned: int = 0
    evidence_files_scanned: int = 0
    evidence_files_truncated: int = 0
    evidence_skipped: list[dict[str, str]] = Field(default_factory=list)
    scan_artifacts_written: int = 0


# ============================================================================
# Legal Hold Schemas
# ============================================================================


class LegalHoldBase(BaseModel):
    """Base legal hold schema"""

    hold_type: str = ""
    custodians: list[str]
    data_sources: list[str] = Field(default_factory=list)
    issued_by: str = ""
    issued_date: Optional[str] = None
    expiry_date: Optional[str] = None


class LegalHoldCreate(LegalHoldBase):
    """Schema for creating legal holds"""

    case_id: str = ""


class LegalHoldUpdate(BaseModel):
    """Schema for updating legal holds"""

    hold_type: Optional[str] = None
    custodians: Optional[list[str]] = None
    data_sources: Optional[list[str]] = None
    status: Optional[str] = None
    expiry_date: Optional[str] = None


class LegalHoldResponse(LegalHoldBase, DBModel):
    """Schema for legal hold response"""

    id: str = ""
    case_id: str = ""
    acknowledgments: dict[str, Any] = Field(default_factory=dict)
    status: str = "active"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class LegalHoldListResponse(BaseModel):
    """Schema for paginated legal hold list"""

    items: list[LegalHoldResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0


class LegalHoldExtendRequest(BaseModel):
    """Request to extend legal hold"""

    new_expiry_date: str = ""
    reason: str = ""


class LegalHoldReleaseRequest(BaseModel):
    """Request to release legal hold"""

    reason: str = ""


class CustodianAcknowledgment(BaseModel):
    """Custodian acknowledgment tracking"""

    custodian: str = ""
    acknowledged: bool = False
    timestamp: Optional[str] = None


# ============================================================================
# Report Schemas
# ============================================================================


class TimelineVisualizationData(BaseModel):
    """Data for timeline visualization"""

    timestamp: str = ""
    event_type: str = ""
    severity: float = 0.0
    is_pivotal: bool = False


class CaseReportResponse(BaseModel):
    """Case report response"""

    case_id: str = ""
    generated_at: Optional[datetime] = None
    sections: list[str]
    evidence_count: int = 0
    artifact_count: int = 0
    timeline_events: int = 0
    legal_holds_active: int = 0
    investigation_duration_days: int = 0


class TimelineReconstructResponse(BaseModel):
    """Timeline rows derived from custody logs and stored artifacts."""

    case_id: str = ""
    created: int = 0
    already_present: int = 0
    from_custody: int = 0
    from_artifacts: int = 0
    truncated: bool = False


class TimelineExportResponse(BaseModel):
    """Timeline export response"""

    case_id: str = ""
    generated_at: Optional[datetime] = None
    event_count: int = 0
    events: list[ForensicTimelineResponse] = Field(default_factory=list)


class ChainOfCustodyReportResponse(BaseModel):
    """Chain of custody report"""

    evidence_id: str = ""
    generated_at: Optional[datetime] = None
    log_entries: list[ChainOfCustodyEntry] = Field(default_factory=list)
    is_court_admissible: bool = True


# ============================================================================
# Dashboard/Metrics Schemas
# ============================================================================


class CaseMetrics(BaseModel):
    """Case metrics and statistics"""

    case_id: str = ""
    evidence_count: int = 0
    artifact_count: int = 0
    timeline_events: int = 0
    legal_holds_active: int = 0
    investigation_duration_days: int = 0
    high_risk_artifacts: int = 0
    pivotal_events: int = 0


class DFIRDashboardResponse(BaseModel):
    """DFIR dashboard overview"""

    total_cases: int = 0
    active_cases: int = 0
    cases_in_analysis: int = 0
    total_evidence_items: int = 0
    total_artifacts: int = 0
    legal_holds_active: int = 0
    critical_cases: int = 0
    high_cases: int = 0
    cases_with_legal_holds: int = 0
    # Wave 3: agent collections not yet resolved (pending / awaiting_approval).
    collections_pending: int = 0
