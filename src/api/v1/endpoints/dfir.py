"""DFIR API endpoints for forensic case management, evidence handling, and timeline reconstruction"""

import hashlib
import json
import math
import os
import re
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.core.csvsafe import csv_safe
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.dfir.storage import EvidencePathRefusedError, relative_location, resolve_tenant_evidence_path
from src.models.user import User, UserRole

logger = get_logger(__name__)

# Case, evidence, timeline, artifact and legal-hold writes need analyst or
# admin; releasing a legal hold needs admin. Viewers are read-only.
_ANALYST_ROLES = [UserRole.ADMIN, UserRole.ANALYST]


def _session_actor(user: User) -> str:
    """Chain-of-custody actor: always the authenticated session user."""
    return getattr(user, "full_name", None) or user.email


def _require_admin_to_release(user: User, what: str) -> None:
    if user.is_superuser or user.role == UserRole.ADMIN.value:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "admin_required", "detail": f"{what} requires the admin role"},
    )


def _not_implemented(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "not_implemented", "detail": detail},
    )

# Evidence locations a client may register directly. Local filesystem paths are
# assigned only by the upload endpoint, which writes under DFIR_UPLOAD_ROOT:
# accepting them from a request body let any user register "/opt/pysoar/.env"
# as evidence and download it (fixed 2026-10-08).
_REMOTE_EVIDENCE_SCHEMES = ("https://", "s3://")


def _validate_client_storage_location(location: Optional[str]) -> str:
    if location is None or location == "":
        return ""  # column is NOT NULL; "" means "no object registered yet"
    if location.startswith(_REMOTE_EVIDENCE_SCHEMES):
        return location
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "invalid_storage_location",
            "detail": (
                "storage_location must be an https:// or s3:// object URL; local files "
                "are registered through POST /dfir/cases/{case_id}/evidence/upload"
            ),
        },
    )


def _local_evidence_path(location: str, org_id: Optional[str] = None) -> str:
    """Resolve a stored local evidence location, confined to the tenant's subtree.

    Every route passes the caller's ``org_id``: the path must resolve inside
    ``DFIR_UPLOAD_ROOT/<org_id>`` (403 ``evidence_path_outside_tenant_root``
    otherwise, e.g. a legacy row pointing into another tenant's directory) and
    always inside the root (403 ``evidence_path_outside_storage_root``).
    Relative locations (what new rows store) are taken relative to the root.
    """
    try:
        return resolve_tenant_evidence_path(DFIR_UPLOAD_ROOT, location, org_id)
    except EvidencePathRefusedError as exc:
        logger.warning("dfir_evidence_path_refused", reason=exc.reason, organization_id=org_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": exc.reason, "detail": exc.detail},
        ) from None


def _hash_file(path: str, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
from src.dfir.analysis import reconstruct_timeline, scan_case_iocs
from src.dfir.collection import (
    PENDING_STATES,
    CollectionRequestError,
    build_payload,
    reconcile_evidence,
    request_collection,
)
from src.dfir.models import (
    CaseStatus,
    ForensicArtifact,
    ForensicCase,
    ForensicEvidence,
    ForensicTimeline,
    LegalHold,
)
from src.schemas.dfir import (
    ArtifactAnalysisRequest,
    ArtifactAnalysisResponse,
    CaseMetrics,
    CaseReportResponse,
    ChainOfCustodyReportResponse,
    ChainOfCustodyUpdateRequest,
    DFIRDashboardResponse,
    EvidenceCollectRequest,
    EvidenceCollectResponse,
    EvidenceVerification,
    EvidenceVerifyRequest,
    EvidenceVerifyResponse,
    ForensicArtifactCreate,
    ForensicArtifactListResponse,
    ForensicArtifactResponse,
    ForensicCaseCreate,
    ForensicCaseListResponse,
    ForensicCaseResponse,
    ForensicCaseUpdate,
    ForensicEvidenceCreate,
    ForensicEvidenceListResponse,
    ForensicEvidenceResponse,
    ForensicTimelineCreate,
    ForensicTimelineListResponse,
    ForensicTimelineResponse,
    IOCExtractionResponse,
    LegalHoldCreate,
    LegalHoldListResponse,
    LegalHoldResponse,
    LegalHoldUpdate,
    TimelineExportResponse,
    TimelineReconstructResponse,
)

router = APIRouter(prefix="/dfir", tags=["DFIR"])


# ============================================================================
# Helper Functions
# ============================================================================


async def get_case_or_404(db: AsyncSession, case_id: str, org_id: str) -> ForensicCase:
    """Get forensic case by ID or raise 404"""
    stmt = (
        select(ForensicCase)
        .options(
            selectinload(ForensicCase.evidence),
            selectinload(ForensicCase.timeline_events),
            selectinload(ForensicCase.artifacts),
            selectinload(ForensicCase.legal_holds),
        )
        .where(ForensicCase.id == case_id)
    )
    stmt = stmt.where(ForensicCase.organization_id == org_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic case not found",
        )
    return case


async def get_evidence_or_404(db: AsyncSession, evidence_id: str, org_id: str) -> ForensicEvidence:
    """Get forensic evidence by ID or raise 404"""
    stmt = (
        select(ForensicEvidence)
        .options(selectinload(ForensicEvidence.case))
        .where(ForensicEvidence.id == evidence_id)
    )
    stmt = stmt.where(ForensicEvidence.organization_id == org_id)
    result = await db.execute(stmt)
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )
    return evidence


def _case_response(case: ForensicCase) -> ForensicCaseResponse:
    """Case response with ``evidence_count`` from the loaded evidence rows."""
    out = ForensicCaseResponse.model_validate(case)
    out.evidence_count = len(case.evidence or [])
    return out


async def _reconcile_pending(db: AsyncSession, rows: list[ForensicEvidence]) -> None:
    """Bring agent-collected rows up to date with their command results."""
    for row in rows:
        if row.collection_status in PENDING_STATES and row.collection_command_id:
            await reconcile_evidence(db, row, root=DFIR_UPLOAD_ROOT)


# ============================================================================
# Forensic Case Endpoints - CRUD Operations
# ============================================================================


@router.get("/cases", response_model=ForensicCaseListResponse)
async def list_cases(
    org_id: OrganizationId = None,
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
    query = query.where(ForensicCase.organization_id == org_id)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (ForensicCase.case_number.ilike(search_filter))
            | (ForensicCase.title.ilike(search_filter))
            | (ForensicCase.description.ilike(search_filter)),
        )

    if case_type:
        query = query.where(ForensicCase.case_type == case_type)

    if status_filter:
        query = query.where(ForensicCase.status == status_filter)

    if severity:
        query = query.where(ForensicCase.severity == severity)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicCase.id).where(query.whereclause) if query.whereclause is not None else select(ForensicCase.id),
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

    items = [_case_response(case) for case in cases]

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get a specific forensic case"""
    case = await get_case_or_404(db, case_id, org_id)
    return _case_response(case)


@router.post("/cases", response_model=ForensicCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    case_data: ForensicCaseCreate,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a new forensic case"""
    # forensic_cases.case_number is unique across the whole table, so a number
    # held by any tenant cannot be reused. The 409 is identical whichever
    # tenant holds it and nothing about the other row is read or returned.
    in_use_conflict = HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Case number {case_data.case_number} is already in use; choose another",
    )
    result = await db.execute(
        select(ForensicCase.id).where(ForensicCase.case_number == case_data.case_number).limit(1),
    )
    if result.scalar_one_or_none() is not None:
        raise in_use_conflict

    if case_data.lead_investigator_id:
        lead = await db.execute(
            select(User.id).where(
                User.id == case_data.lead_investigator_id,
                User.organization_id == org_id,
            ),
        )
        if lead.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_lead_investigator", "detail": "lead investigator is not a user in this organisation"},
            )

    case = ForensicCase(
        case_number=case_data.case_number,
        title=case_data.title,
        description=case_data.description,
        case_type=case_data.case_type,
        severity=case_data.severity,
        lead_investigator_id=case_data.lead_investigator_id,
        assigned_team=json.dumps(case_data.assigned_team) if case_data.assigned_team else None,
        created_by=str(current_user.id),
        organization_id=org_id,
        status=CaseStatus.OPEN.value,
    )

    db.add(case)
    try:
        await db.flush()
    except IntegrityError:
        # Lost a race for the same globally-unique case number.
        raise in_use_conflict from None
    await db.refresh(case)

    return ForensicCaseResponse.model_validate(case)


@router.put("/cases/{case_id}", response_model=ForensicCaseResponse)
async def update_case(
    case_id: str,
    case_data: ForensicCaseUpdate,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update a forensic case"""
    case = await get_case_or_404(db, case_id, org_id)

    update_data = case_data.model_dump(exclude_unset=True)

    if update_data.get("legal_hold_active") is False and case.legal_hold_active:
        _require_admin_to_release(current_user, "clearing a case's legal hold")
    if update_data.get("lead_investigator_id"):
        lead = await db.execute(
            select(User.id).where(
                User.id == update_data["lead_investigator_id"],
                User.organization_id == org_id,
            ),
        )
        if lead.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_lead_investigator", "detail": "lead investigator is not a user in this organisation"},
            )

    # Handle JSON fields
    if "assigned_team" in update_data and update_data["assigned_team"] is not None:
        update_data["assigned_team"] = json.dumps(update_data["assigned_team"])

    for field, value in update_data.items():
        setattr(case, field, value)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    evidence_type: Optional[str] = None,
    is_verified: Optional[bool] = None,
):
    """List evidence for a forensic case"""
    # Filter by organization

    # Verify case exists
    await get_case_or_404(db, case_id, org_id)

    query = select(ForensicEvidence).where(ForensicEvidence.case_id == case_id)

    query = query.where(ForensicEvidence.organization_id == org_id)

    if evidence_type:
        query = query.where(ForensicEvidence.evidence_type == evidence_type)

    if is_verified is not None:
        query = query.where(ForensicEvidence.is_verified == is_verified)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicEvidence.id).where(query.whereclause) if query.whereclause is not None else select(ForensicEvidence.id),
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.order_by(ForensicEvidence.created_at.desc()).offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    evidence_list = list(result.scalars().all())
    await _reconcile_pending(db, evidence_list)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get a specific evidence item"""
    evidence = await get_evidence_or_404(db, evidence_id, org_id)
    await _reconcile_pending(db, [evidence])
    return ForensicEvidenceResponse.model_validate(evidence)


@router.get("/evidence/{evidence_id}/download")
async def download_evidence(
    evidence_id: str,
    current_user: CurrentUser = None,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Download forensic evidence, appending a chain-of-custody entry.

    The path is checked before the custody entry is written, so a refused
    read leaves no "accessed" record.

    Supports local filesystem ``storage_location`` paths (streams the file)
    and HTTP(S) URLs (returns a 307 redirect to the signed URL). Every
    download is appended to ``chain_of_custody_log`` as an immutable record
    for NIST SP 800-86 compliance — who accessed what, when, and the SHA-256
    at access time.
    """
    import os

    from fastapi.responses import FileResponse, RedirectResponse

    evidence = await get_evidence_or_404(db, evidence_id, org_id)

    if not evidence.storage_location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No storage_location set for this evidence item",
        )

    loc = evidence.storage_location
    if "://" not in loc:
        _local_evidence_path(loc, org_id)

    # Append chain-of-custody entry for this access
    chain = dict(evidence.chain_of_custody_log or {})
    entries = list(chain.get("entries", []))
    entries.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": _session_actor(current_user),
        "action": "accessed_download",
        "hash": evidence.original_hash_sha256,
    })
    chain["entries"] = entries
    evidence.chain_of_custody_log = chain
    await db.flush()

    # Remote object URL: redirect, but only to the schemes a client may register.
    if loc.startswith(_REMOTE_EVIDENCE_SCHEMES):
        return RedirectResponse(url=loc)
    if "://" in loc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_storage_location", "detail": "only https:// and s3:// evidence URLs are served"},
        )

    # Local path: must resolve inside this tenant's evidence directory (403 otherwise).
    path = _local_evidence_path(loc, org_id)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file missing at storage_location",
        )
    filename = os.path.basename(path) or f"evidence-{evidence_id}"
    return FileResponse(
        path=path,
        media_type="application/octet-stream",
        filename=filename,
    )


@router.post("/evidence", response_model=ForensicEvidenceResponse, status_code=status.HTTP_201_CREATED)
async def collect_evidence(
    evidence_data: ForensicEvidenceCreate,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Collect and register forensic evidence"""
    # Verify case exists
    await get_case_or_404(db, evidence_data.case_id, org_id)

    evidence = ForensicEvidence(
        case_id=evidence_data.case_id,
        evidence_type=evidence_data.evidence_type,
        source_device=evidence_data.source_device,
        source_ip=evidence_data.source_ip,
        acquisition_method=evidence_data.acquisition_method,
        original_hash_md5=evidence_data.original_hash_md5,
        original_hash_sha256=evidence_data.original_hash_sha256,
        storage_location=_validate_client_storage_location(evidence_data.storage_location),
        file_size_bytes=evidence_data.file_size_bytes,
        handling_notes=evidence_data.handling_notes,
        organization_id=org_id,
        chain_of_custody_log={
            "entries": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": _session_actor(current_user),
                    "action": "collected",
                    "hash": evidence_data.original_hash_sha256,
                },
            ],
        },
    )

    db.add(evidence)
    await db.flush()
    await db.refresh(evidence)

    return ForensicEvidenceResponse.model_validate(evidence)


DFIR_UPLOAD_ROOT = os.environ.get("DFIR_UPLOAD_ROOT", "/app/uploads/dfir")

# Filenames with any of these fragments or separators are rejected
_FILENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_filename(filename: str) -> str:
    """Return a safe basename for on-disk storage.

    - Strips any directory component (defends against path traversal).
    - Collapses unsafe characters to underscores.
    - Caps length at 200 chars so the final path stays within OS limits.
    """
    base = os.path.basename(filename or "").strip() or "evidence.bin"
    base = _FILENAME_SANITIZE_RE.sub("_", base).strip("._") or "evidence.bin"
    return base[:200]


@router.post(
    "/cases/{case_id}/evidence/upload",
    response_model=ForensicEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence_file(
    case_id: str,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    evidence_type: str = Form("file"),
    description: Optional[str] = Form(None),
    source_device: Optional[str] = Form(None),
    source_ip: Optional[str] = Form(None),
    acquisition_method: str = Form("manual_upload"),
    collector: Optional[str] = Form(None),
    handling_notes: Optional[str] = Form(None),
):
    """Stream-upload forensic evidence file, hash it, and register a ForensicEvidence row.

    - Streams the multipart body into ``/app/uploads/dfir/<org>/<case>/<uuid>_<name>``.
    - Computes SHA-256, MD5 and SHA-512 over the bytes while writing (no double pass).
    - Captures the collector + timestamp as the first chain-of-custody entry.
    - Transactional: if the DB insert fails the on-disk file is deleted so we
      never leave an orphan.
    """
    await get_case_or_404(db, case_id, org_id)

    # Determine final storage path
    target_dir = os.path.join(DFIR_UPLOAD_ROOT, str(org_id), str(case_id))
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to create evidence storage directory: {exc}",
        )

    sanitized = _sanitize_filename(file.filename or "evidence.bin")
    unique_prefix = uuid_mod.uuid4().hex
    final_path = os.path.join(target_dir, f"{unique_prefix}_{sanitized}")

    # Stream the file to disk while hashing
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    sha512 = hashlib.sha512()
    total_bytes = 0
    CHUNK = 1024 * 1024  # 1 MiB

    try:
        with open(final_path, "wb") as out_fh:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                sha512.update(chunk)
                out_fh.write(chunk)
                total_bytes += len(chunk)
    except Exception as exc:
        # Any IO failure during streaming — remove whatever we wrote
        try:
            if os.path.exists(final_path):
                os.remove(final_path)
        except OSError:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write evidence file: {exc}",
        )
    finally:
        await file.close()

    if total_bytes == 0:
        # Refuse to register an empty upload
        try:
            os.remove(final_path)
        except OSError:
            pass
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    sha256_hex = sha256.hexdigest()
    md5_hex = md5.hexdigest()
    sha512_hex = sha512.hexdigest()

    # Build chain-of-custody entry. The actor is the session user; a
    # client-supplied ``collector`` is kept only as a reported note.
    actor = _session_actor(current_user)
    now_iso = datetime.now(timezone.utc).isoformat()
    handling_suffix = []
    if title:
        handling_suffix.append(f"title={title}")
    if description:
        handling_suffix.append(f"description={description}")
    merged_notes = handling_notes or ""
    if handling_suffix:
        merged_notes = (merged_notes + "\n" if merged_notes else "") + " | ".join(handling_suffix)

    evidence = ForensicEvidence(
        case_id=case_id,
        evidence_type=evidence_type,
        source_device=source_device or sanitized,
        source_ip=source_ip,
        acquisition_method=acquisition_method,
        original_hash_sha256=sha256_hex,
        original_hash_md5=md5_hex,
        # Relative to DFIR_UPLOAD_ROOT (<org>/<case>/<file>); always server-chosen.
        storage_location=relative_location(DFIR_UPLOAD_ROOT, final_path),
        file_size_bytes=total_bytes,
        handling_notes=merged_notes or None,
        organization_id=org_id,
        chain_of_custody_log={
            "entries": [
                {
                    "timestamp": now_iso,
                    "actor": actor,
                    "action": "collected",
                    "hash": sha256_hex,
                    "hash_md5": md5_hex,
                    "hash_sha512": sha512_hex,
                    "size_bytes": total_bytes,
                    "original_filename": file.filename or sanitized,
                    "details": description,
                    **({"reported_collector": collector} if collector else {}),
                },
            ],
            "sha512": sha512_hex,
        },
    )

    # Transactional insert — if DB fails, delete the file
    try:
        db.add(evidence)
        await db.flush()
        await db.refresh(evidence)
    except Exception as exc:
        try:
            if os.path.exists(final_path):
                os.remove(final_path)
        except OSError:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register evidence record: {exc}",
        )

    return ForensicEvidenceResponse.model_validate(evidence)


@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceVerifyResponse)
async def verify_evidence_integrity(
    evidence_id: str,
    verify_data: EvidenceVerifyRequest,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Verify evidence integrity by re-hashing the stored bytes.

    The stored file (inside this tenant's evidence directory) is re-hashed
    and compared with the hash recorded at collection; an optional
    ``evidence_hash`` from the client is compared with the same reference.
    The recorded hashes are never overwritten. Remote objects (https / s3)
    have no local bytes, so only a client hash can be checked against the
    recorded one. A local file that has gone missing fails verification.
    """
    evidence = await get_evidence_or_404(db, evidence_id, org_id)

    algorithm = (verify_data.hash_algorithm or "sha256").lower()
    if algorithm not in ("sha256", "md5"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "unsupported_hash_algorithm", "detail": "hash_algorithm must be sha256 or md5"},
        )
    claimed = (verify_data.evidence_hash or "").strip().lower() or None

    computed: Optional[str] = None
    file_missing = False
    loc = evidence.storage_location or ""
    if loc and "://" not in loc:
        path = _local_evidence_path(loc, org_id)
        if os.path.isfile(path):
            computed = _hash_file(path, algorithm)
        else:
            file_missing = True
    stored_raw = evidence.original_hash_sha256 if algorithm == "sha256" else evidence.original_hash_md5
    stored = stored_raw.strip().lower() if stored_raw else None
    reference = computed or stored
    if reference is None and not file_missing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "no_reference_hash",
                "detail": f"no stored {algorithm} hash and no local file to compute one from",
            },
        )
    if computed is None and claimed is None and not file_missing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "nothing_to_compare",
                "detail": "the evidence bytes are not held by PySOAR; supply evidence_hash to compare with the recorded hash",
            },
        )

    file_matches = (computed == stored) if (computed and stored) else None
    claim_matches = (claimed == reference) if (claimed and reference) else None
    is_valid = (
        not file_missing
        and file_matches is not False
        and claim_matches is not False
        and (file_matches is True or claim_matches is True)
    )
    verification = EvidenceVerification(
        algorithm=algorithm,
        reference="file" if computed else "stored_hash",
        computed_hash=computed,
        stored_hash=stored,
        file_matches_stored_hash=file_matches,
        claimed_hash_matches=claim_matches,
        is_valid=is_valid,
    )

    evidence.is_verified = is_valid
    evidence.verified_by = _session_actor(current_user)
    evidence.verification_date = datetime.now(timezone.utc).isoformat()

    chain = dict(evidence.chain_of_custody_log or {})
    entries = list(chain.get("entries", []))
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": evidence.verified_by,
        "action": "verified" if is_valid else "verification_failed",
        "algorithm": algorithm,
        "reference": verification.reference,
        "hash": computed,
        "stored_hash_matches": file_matches,
        "claimed_hash_matches": claim_matches,
    }
    if file_missing:
        entry["details"] = "stored evidence file is missing"
    entries.append(entry)
    chain["entries"] = entries
    evidence.chain_of_custody_log = chain

    await db.flush()
    await db.refresh(evidence)

    out = EvidenceVerifyResponse.model_validate(evidence)
    out.verification = verification
    return out


@router.post(
    "/cases/{case_id}/evidence/collect",
    response_model=EvidenceCollectResponse,
    status_code=status.HTTP_200_OK,
)
async def collect_evidence_from_agent(
    case_id: str,
    body: EvidenceCollectRequest,
    response: Response,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Collect evidence from a host through its endpoint agent.

    Issues a ``collect_process_list`` / ``collect_network_connections`` /
    ``collect_file`` / ``collect_memory_dump`` command (memory dumps wait for
    a second approver). Returns 202 with the new evidence row
    (``collection_status`` pending / awaiting_approval); the row moves to
    collected / collected_on_host / failed from the command result. With no
    enrolled agent able to run the command, returns 200 ``awaiting_agent``
    and creates nothing.
    """
    from src.agents.service import AgentServiceError

    await get_case_or_404(db, case_id, org_id)
    try:
        payload = build_payload(body.collection_type, body.path, body.max_bytes, body.pid)
    except CollectionRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_collection_request", "detail": str(exc)},
        ) from None
    try:
        outcome = await request_collection(
            db,
            org_id=org_id,
            case_id=case_id,
            hostname=body.hostname.strip(),
            collection_type=body.collection_type,
            payload=payload,
            actor_user_id=str(current_user.id),
            actor_name=_session_actor(current_user),
            notes=body.notes,
        )
    except AgentServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "agent_refused", "detail": str(exc)},
        ) from None

    if outcome.evidence is not None:
        response.status_code = status.HTTP_202_ACCEPTED
    return EvidenceCollectResponse(
        status=outcome.status,
        detail=outcome.detail,
        evidence=ForensicEvidenceResponse.model_validate(outcome.evidence) if outcome.evidence is not None else None,
        command_id=outcome.command_id,
        agent_id=outcome.agent_id,
        agent_hostname=outcome.agent_hostname,
    )


@router.post("/evidence/{evidence_id}/chain-of-custody", response_model=ForensicEvidenceResponse)
async def update_chain_of_custody(
    evidence_id: str,
    coc_data: ChainOfCustodyUpdateRequest,
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update chain of custody log"""
    evidence = await get_evidence_or_404(db, evidence_id, org_id)

    # Parse existing log
    coc_log = evidence.chain_of_custody_log or {"entries": []}
    if isinstance(coc_log, str):
        coc_log = safe_json_loads(coc_log, {})

    # Copy before appending: mutating the loaded JSON in place is not seen
    # by SQLAlchemy change tracking, so the entry could be silently dropped.
    coc_log = dict(coc_log)
    coc_log["entries"] = list(coc_log.get("entries", []))

    # Add new entry
    coc_log["entries"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            # Bound to the session user: a body ``actor`` is ignored so the
            # chain of custody cannot be forged.
            "actor": _session_actor(current_user),
            "action": coc_data.action,
            "hash": coc_data.evidence_hash,
            "details": coc_data.details,
        },
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    is_pivotal: Optional[bool] = None,
):
    """Get case timeline"""
    # Filter by organization

    await get_case_or_404(db, case_id, org_id)

    query = select(ForensicTimeline).where(ForensicTimeline.case_id == case_id)

    query = query.where(ForensicTimeline.organization_id == org_id)

    if event_type:
        query = query.where(ForensicTimeline.event_type == event_type)

    if is_pivotal is not None:
        query = query.where(ForensicTimeline.is_pivotal == is_pivotal)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicTimeline.id).where(query.whereclause) if query.whereclause is not None else select(ForensicTimeline.id),
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
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Add event to case timeline"""
    await get_case_or_404(db, case_id, org_id)

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
        organization_id=org_id,
    )

    db.add(event)
    await db.flush()
    await db.refresh(event)

    return ForensicTimelineResponse.model_validate(event)


@router.post(
    "/cases/{case_id}/timeline/reconstruct",
    response_model=TimelineReconstructResponse,
)
async def reconstruct_case_timeline(
    case_id: str,
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Derive timeline events from the case's stored material.

    One event per chain-of-custody entry of every evidence item and one per
    timestamp field found in stored artifacts (top level and record lists).
    Re-running adds only what is new (rows carry ``artifact_data.derived_from``).
    """
    await get_case_or_404(db, case_id, org_id)
    out = await reconstruct_timeline(db, case_id=case_id, org_id=org_id)
    return TimelineReconstructResponse(
        case_id=case_id,
        created=out.created,
        already_present=out.already_present,
        from_custody=out.from_custody,
        from_artifacts=out.from_artifacts,
        truncated=out.truncated,
    )


_TIMELINE_CSV_COLUMNS = (
    "event_timestamp", "event_type", "source", "source_evidence_id", "description",
    "mitre_technique_id", "severity_score", "is_pivotal", "id",
)


@router.post("/cases/{case_id}/timeline/export", response_model=TimelineExportResponse)
async def export_timeline(
    case_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    export_format: str = Query("json", alias="format", pattern="^(json|csv)$"),
):
    """Export the case timeline stored for this case (``format=json`` or ``csv``)."""
    await get_case_or_404(db, case_id, org_id)

    timeline_stmt = (
        select(ForensicTimeline)
        .where(ForensicTimeline.case_id == case_id)
        .order_by(ForensicTimeline.event_timestamp.asc())
    )
    timeline_stmt = timeline_stmt.where(ForensicTimeline.organization_id == org_id)
    result = await db.execute(timeline_stmt)
    events = list(result.scalars().all())

    if export_format == "csv":
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_TIMELINE_CSV_COLUMNS)
        for e in events:
            writer.writerow([csv_safe(getattr(e, col)) for col in _TIMELINE_CSV_COLUMNS])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="timeline-{case_id}.csv"'},
        )

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    artifact_type: Optional[str] = None,
    min_risk_score: float = Query(0.0, ge=0.0, le=10.0),
):
    """List artifacts for a case"""
    # Filter by organization

    await get_case_or_404(db, case_id, org_id)

    query = select(ForensicArtifact).where(ForensicArtifact.case_id == case_id)

    query = query.where(ForensicArtifact.organization_id == org_id)

    if artifact_type:
        query = query.where(ForensicArtifact.artifact_type == artifact_type)

    if min_risk_score > 0:
        query = query.where(ForensicArtifact.risk_score >= min_risk_score)

    # Get total count
    count_query = select(func.count()).select_from(
        select(ForensicArtifact.id).where(query.whereclause) if query.whereclause is not None else select(ForensicArtifact.id),
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
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create forensic artifact"""
    await get_case_or_404(db, case_id, org_id)
    await get_evidence_or_404(db, artifact_data.evidence_id, org_id)

    artifact = ForensicArtifact(
        case_id=case_id,
        evidence_id=artifact_data.evidence_id,
        artifact_type=artifact_data.artifact_type,
        artifact_data=artifact_data.artifact_data or {},
        analysis_notes=artifact_data.analysis_notes,
        ioc_extracted=artifact_data.ioc_extracted or {},
        mitre_mapping=artifact_data.mitre_mapping,
        risk_score=artifact_data.risk_score,
        organization_id=org_id,
    )

    db.add(artifact)
    await db.flush()
    await db.refresh(artifact)

    return ForensicArtifactResponse.model_validate(artifact)


@router.post("/artifacts/analyze", response_model=ArtifactAnalysisResponse)
async def analyze_artifact(
    _analysis_data: ArtifactAnalysisRequest,
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    _org_id: OrganizationId = None,
    _db: DatabaseSession = None,
):
    """Analyze a forensic artifact.

    Not implemented: the route dispatched on a ``disk_``/``memory_``/``network_``
    prefix while the analyzers match unprefixed names, so every call returned
    "success" with nothing parsed, and nothing was persisted.
    """
    raise _not_implemented(
        "artifact analysis is not implemented: no artifact parser runs behind this route, "
        "so it no longer reports success",
    )


@router.post("/cases/{case_id}/artifacts/extract-iocs", response_model=IOCExtractionResponse)
async def extract_case_iocs(
    case_id: str,
    _current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Extract IOCs from the case's stored artifacts and stored evidence bytes.

    Artifacts: every string in ``artifact_data``; results persisted to
    ``ioc_extracted``. Evidence: the printable strings of the first 8 MiB of
    each file held in this tenant's evidence directory; results persisted as
    one ``evidence_ioc_scan`` artifact per file. Evidence without local bytes
    (remote objects, pending collections) is listed in ``evidence_skipped``.
    """
    await get_case_or_404(db, case_id, org_id)
    scan = await scan_case_iocs(db, case_id=case_id, org_id=org_id, root=DFIR_UPLOAD_ROOT)

    from src.schemas.dfir import IOCData

    return IOCExtractionResponse(
        status="success",
        iocs=IOCData(**scan.iocs),
        total_extracted=scan.total,
        iocs_extracted=scan.total,
        artifacts_scanned=scan.artifacts_scanned,
        evidence_files_scanned=scan.evidence_files_scanned,
        evidence_files_truncated=scan.evidence_files_truncated,
        evidence_skipped=scan.evidence_skipped,
        scan_artifacts_written=scan.scan_artifacts_written,
    )


# ============================================================================
# Legal Hold Endpoints
# ============================================================================


@router.get("/cases/{case_id}/legal-holds", response_model=LegalHoldListResponse)
async def list_legal_holds(
    case_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    """List legal holds for a case"""
    # Filter by organization

    await get_case_or_404(db, case_id, org_id)

    query = select(LegalHold).where(LegalHold.case_id == case_id)

    query = query.where(LegalHold.organization_id == org_id)

    count_query = select(func.count()).select_from(
        select(LegalHold.id).where(query.whereclause) if query.whereclause is not None else select(LegalHold.id),
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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Create a legal hold"""
    case = await get_case_or_404(db, case_id, org_id)

    hold = LegalHold(
        case_id=case_id,
        hold_type=hold_data.hold_type,
        custodians=hold_data.custodians,
        data_sources=hold_data.data_sources,
        issued_by=_session_actor(current_user),
        issued_date=hold_data.issued_date or datetime.now(timezone.utc).isoformat(),
        expiry_date=hold_data.expiry_date,
        status="active",
        organization_id=org_id,
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
    current_user: User = Depends(require_role(_ANALYST_ROLES)),
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Update legal hold"""
    hold_stmt = select(LegalHold).where(LegalHold.id == hold_id)
    hold_stmt = hold_stmt.where(LegalHold.organization_id == org_id)
    result = await db.execute(hold_stmt)
    hold = result.scalar_one_or_none()

    if not hold:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Legal hold not found")

    update_data = hold_data.model_dump(exclude_unset=True)
    new_status = update_data.get("status")
    if new_status is not None and new_status != "active" and hold.status == "active":
        _require_admin_to_release(current_user, "releasing a legal hold")
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Generate comprehensive case report.

    Not implemented: the route returned four counts and a hard-coded list of
    section names with no report content. Per-case counts are available from
    GET /dfir/cases/{case_id}/metrics.
    """
    await get_case_or_404(db, case_id, org_id)
    raise _not_implemented(
        "case report generation is not implemented: no report content is produced; "
        "per-case counts are at GET /dfir/cases/{case_id}/metrics",
    )


@router.get("/evidence/{evidence_id}/chain-of-custody", response_model=ChainOfCustodyReportResponse)
async def get_chain_of_custody_report(
    evidence_id: str,
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get chain of custody report"""
    evidence = await get_evidence_or_404(db, evidence_id, org_id)

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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get DFIR dashboard metrics"""

    # Count cases by status
    cases_query = select(func.count()).select_from(ForensicCase)
    cases_query = cases_query.where(ForensicCase.organization_id == org_id)
    all_cases = await db.execute(cases_query)
    total_cases = all_cases.scalar() or 0

    active_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.status.in_([CaseStatus.OPEN.value, CaseStatus.IN_PROGRESS.value]),
    )
    active_query = active_query.where(ForensicCase.organization_id == org_id)
    active_cases = await db.execute(active_query)
    active_count = active_cases.scalar() or 0

    analysis_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.status == CaseStatus.ANALYSIS.value,
    )
    analysis_query = analysis_query.where(ForensicCase.organization_id == org_id)
    analysis_cases = await db.execute(analysis_query)
    analysis_count = analysis_cases.scalar() or 0

    # Count evidence
    evidence_query = select(func.count()).select_from(ForensicEvidence)
    evidence_query = evidence_query.where(ForensicEvidence.organization_id == org_id)
    total_evidence = await db.execute(evidence_query)
    evidence_count = total_evidence.scalar() or 0

    # Count artifacts
    artifacts_query = select(func.count()).select_from(ForensicArtifact)
    artifacts_query = artifacts_query.where(ForensicArtifact.organization_id == org_id)
    total_artifacts = await db.execute(artifacts_query)
    artifacts_count = total_artifacts.scalar() or 0

    # Count legal holds
    holds_query = select(func.count()).select_from(LegalHold).where(LegalHold.status == "active")
    holds_query = holds_query.where(LegalHold.organization_id == org_id)
    active_holds = await db.execute(holds_query)
    holds_count = active_holds.scalar() or 0

    holds_cases_query = select(func.count()).select_from(ForensicCase).where(
        ForensicCase.legal_hold_active == True,
    )
    holds_cases_query = holds_cases_query.where(ForensicCase.organization_id == org_id)
    cases_with_holds = await db.execute(holds_cases_query)
    holds_cases = cases_with_holds.scalar() or 0

    async def _count(stmt) -> int:
        return (await db.execute(stmt)).scalar() or 0

    critical_count = await _count(
        select(func.count()).select_from(ForensicCase).where(
            ForensicCase.organization_id == org_id, ForensicCase.severity == "critical",
        ),
    )
    high_count = await _count(
        select(func.count()).select_from(ForensicCase).where(
            ForensicCase.organization_id == org_id, ForensicCase.severity == "high",
        ),
    )
    collections_pending = await _count(
        select(func.count()).select_from(ForensicEvidence).where(
            ForensicEvidence.organization_id == org_id,
            ForensicEvidence.collection_status.in_(PENDING_STATES),
        ),
    )

    return DFIRDashboardResponse(
        critical_cases=critical_count,
        high_cases=high_count,
        collections_pending=collections_pending,
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
    org_id: OrganizationId = None,
    db: DatabaseSession = None,
):
    """Get metrics for a specific case"""
    case = await get_case_or_404(db, case_id, org_id)

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
