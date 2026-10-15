"""
STIG/SCAP REST API Endpoints

REST endpoints for STIG benchmark scanning, rule management, remediation,
SCAP operations, and compliance dashboard.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Annotated, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Body, UploadFile, File, Path as FPath
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user, OrganizationId, require_role
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.core.database import get_db
from src.core.logging import get_logger
from src.stig.engine import (
    BenchmarkOwnershipConflict,
    SCAPEngine,
    STIGLibrary,
    STIGNotFoundError,
    STIGRemediator,
    STIGScanner,
)
from src.stig.agent_scan import reconcile_stig_scan, request_stig_scan
from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult, SCAPProfile
from src.schemas.stig import (
    STIGBenchmarkResponse,
    STIGRuleResponse,
    STIGScanResultResponse,
    SCAPProfileResponse,
    ScanRequest,
    ScanFleetRequest,
    RemediationRequest,
    ScanComparisonRequest,
    SCAPImportRequest,
    OVALValidationRequest,
    ARFReportRequest,
    ScanComparisonResponse,
    RemediationScriptResponse,
    RemediationResponse,
    STIGDashboardStats,
    RuleSearchResponse,
    BenchmarkListResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/stig", tags=["stig"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _benchmark_conflict(exc: BenchmarkOwnershipConflict) -> HTTPException:
    """409 for an XCCDF benchmark id another organisation already holds."""
    return HTTPException(
        status_code=409,
        detail={
            "error": "benchmark_id_conflict",
            "detail": (
                f"{exc}. Benchmark ids are unique platform-wide until the schema "
                "allows one row per organisation; this import was not applied."
            ),
        },
    )


# ============================================================================
# Benchmark Endpoints
# ============================================================================


@router.get("/benchmarks", response_model=list[BenchmarkListResponse])
async def list_benchmarks(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    platform: Optional[str] = Query(None, description="Substring of the benchmark platform"),
):
    """List STIG benchmarks for organization"""
    try:
        stmt = select(STIGBenchmark).where(STIGBenchmark.organization_id == org_id)
        if platform:
            stmt = stmt.where(STIGBenchmark.platform.ilike(f"%{platform}%"))
        stmt = stmt.offset(skip).limit(limit)
        benchmarks = await db.scalars(stmt)
        return benchmarks
    except Exception as e:
        logger.error(f"Error listing benchmarks: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/benchmarks/{benchmark_id}", response_model=STIGBenchmarkResponse)
async def get_benchmark(
    benchmark_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get STIG benchmark details (by row id or XCCDF benchmark id)."""
    try:
        from sqlalchemy import or_
        stmt = select(STIGBenchmark).where(
            or_(
                STIGBenchmark.id == benchmark_id,
                STIGBenchmark.benchmark_id == benchmark_id,
            ),
            STIGBenchmark.organization_id == org_id,
        )
        benchmark = await db.scalar(stmt)
        if not benchmark:
            raise HTTPException(status_code=404, detail="Benchmark not found")
        return benchmark
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting benchmark: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/benchmarks/{benchmark_id}/rules", response_model=list[STIGRuleResponse])
async def list_benchmark_rules(
    benchmark_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List rules for a STIG benchmark.

    `benchmark_id` accepts EITHER the row UUID (which /scap/upload
    returns to the client) or the XCCDF-declared benchmark_id string
    (what the document itself asserts). Ambiguity here used to 404
    every lookup the UI made after an upload — the widget holds the
    UUID, the matcher required the string.
    """
    try:
        from sqlalchemy import or_
        stmt = select(STIGBenchmark).where(
            or_(
                STIGBenchmark.id == benchmark_id,
                STIGBenchmark.benchmark_id == benchmark_id,
            )
            & (STIGBenchmark.organization_id == org_id)
        )
        benchmark = await db.scalar(stmt)
        if not benchmark:
            raise HTTPException(status_code=404, detail="Benchmark not found")

        query = select(STIGRule).where(
            (STIGRule.benchmark_id_ref == benchmark.id)
            & (STIGRule.organization_id == org_id)
        )

        if severity:
            query = query.where(STIGRule.severity == severity)

        query = query.offset(skip).limit(limit)
        rules = await db.scalars(query)
        return rules
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/rules/search", response_model=list[RuleSearchResponse])
async def search_rules(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    q: str = Query(..., min_length=1),
):
    """Search STIG rules by keyword, ID, or content"""
    try:
        library = STIGLibrary(db)
        results = await library.search_rules(q, org_id)
        return results
    except Exception as e:
        logger.error(f"Error searching rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/rules/{rule_id}", response_model=STIGRuleResponse)
async def get_rule(
    rule_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get STIG rule details"""
    try:
        stmt = select(STIGRule).where(
            (STIGRule.rule_id == rule_id)
            & (STIGRule.organization_id == org_id)
        )
        rule = await db.scalar(stmt)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        return rule
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Scan Endpoints
# ============================================================================


def _dispatch_view(dispatch) -> dict:
    scan = dispatch.scan
    return {
        "scan_id": scan.id,
        "host": scan.target_host,
        "benchmark": scan.benchmark_id_ref,
        "status": dispatch.status,
        "status_reason": scan.status_reason,
        "agent_id": scan.agent_id,
        "command_id": scan.command_id,
        "checks_executed": 0,
        "total_checks": scan.total_checks,
        "compliance_percentage": None,
        "note": dispatch.detail,
    }


async def _launch_one(db: AsyncSession, org_id: str, user: User, host: str, benchmark_id: str,
                      scan_type: str, target_ip: Optional[str] = None) -> dict:
    """``manual`` registers a scan that waits for an uploaded ARF; every other
    type runs through the host's endpoint agent (``stig_scan``) or is stored
    as ``not_run`` with the reason."""
    if scan_type == "manual":
        return await STIGScanner(db).scan_host(
            host=host, benchmark_id=benchmark_id, org_id=org_id, scan_type="manual", target_ip=target_ip,
        )
    dispatch = await request_stig_scan(
        db, org_id=org_id, host=host, benchmark_id=benchmark_id,
        requested_by=str(user.id), target_ip=target_ip,
    )
    db.add(AuditLog(
        user_id=str(user.id),
        organization_id=org_id,
        action="stig_scan_launch",
        resource_type="stig_scan",
        resource_id=dispatch.scan.id,
        description=f"STIG scan of {host}: {dispatch.status}"[:4000],
        new_value=json.dumps({"host": host, "benchmark": benchmark_id, "status": dispatch.status,
                              "reason": dispatch.scan.status_reason, "command_id": dispatch.scan.command_id}),
        success=dispatch.status != "not_run",
        error_message=dispatch.scan.status_reason,
    ))
    await db.commit()
    return _dispatch_view(dispatch)


@router.post("/scans/launch", response_model=None, status_code=202)
async def launch_scan(
    request: ScanRequest,
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    db: DatabaseSession = None,
):
    """Run a STIG benchmark against a host (admin only: it targets a live host).

    The scan is queued as a ``stig_scan`` command on the host's endpoint
    agent (status ``dispatched`` / ``awaiting_approval``; results are parsed
    from the agent's ARF output) or stored as ``not_run`` with
    ``status_reason`` when no agent with the capability covers the host.
    ``scan_type: manual`` registers a ``pending_results`` scan for an ARF
    upload instead. No scan is scored without results.
    """
    try:
        return await _launch_one(
            db, org_id, current_user, request.host, request.benchmark_id,
            request.scan_type.value if hasattr(request.scan_type, "value") else str(request.scan_type),
            request.target_ip,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/scans/fleet", response_model=list[dict], status_code=202)
async def launch_fleet_scan(
    request: ScanFleetRequest,
    org_id: OrganizationId,
    current_user: AdminRoleUser,
    db: DatabaseSession = None,
):
    """Run a STIG benchmark on several hosts (admin only; each host as in /scans/launch)."""
    scan_type = request.scan_type.value if hasattr(request.scan_type, "value") else str(request.scan_type)
    results = []
    try:
        for host in request.hosts[:200]:
            results.append(await _launch_one(db, org_id, current_user, host, request.benchmark_id, scan_type))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return results


@router.get("/scans", response_model=list[STIGScanResultResponse])
async def list_scans(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    benchmark_id: Optional[str] = None,
    target_host: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List STIG scan results"""
    try:
        query = select(STIGScanResult).where(
            STIGScanResult.organization_id == org_id
        )

        if benchmark_id:
            stmt = select(STIGBenchmark.id).where(
                STIGBenchmark.benchmark_id == benchmark_id,
                STIGBenchmark.organization_id == org_id,
            )
            bid = await db.scalar(stmt)
            if bid:
                query = query.where(STIGScanResult.benchmark_id_ref == bid)

        if target_host:
            query = query.where(STIGScanResult.target_host.ilike(f"%{target_host}%"))

        if status:
            query = query.where(STIGScanResult.status == status)

        query = query.offset(skip).limit(limit)
        scans = await db.scalars(query)
        return scans
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/scans/{scan_id}", response_model=STIGScanResultResponse)
async def get_scan(
    scan_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get STIG scan result details"""
    try:
        stmt = select(STIGScanResult).where(
            (STIGScanResult.id == scan_id)
            & (STIGScanResult.organization_id == org_id)
        )
        scan = await db.scalar(stmt)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        # Apply the agent's result if it has arrived (the beat task does the
        # same for scans nobody opens).
        if await reconcile_stig_scan(db, scan):
            await db.commit()
            await db.refresh(scan)
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scans/compare", response_model=ScanComparisonResponse)
async def compare_scans(
    request: ScanComparisonRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Compare two STIG scan baselines (read-only computation: viewers allowed)."""
    try:
        scanner = STIGScanner(db)
        return await scanner.get_scan_comparison(request.scan_id_1, request.scan_id_2, org_id)
    except STIGNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error comparing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Remediation Endpoints
# ============================================================================


@router.post("/remediate/auto", response_model=RemediationResponse)
async def auto_remediate(
    request: RemediationRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Auto-remediate STIG findings"""
    try:
        remediator = STIGRemediator(db)
        return await remediator.auto_remediate(
            scan_result_id=request.scan_result_id,
            org_id=org_id,
            categories=request.categories,
        )
    except STIGNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error remediating findings: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/remediate/script", response_model=RemediationScriptResponse)
async def generate_remediation_script(
    org_id: OrganizationId,
    request: dict = Body(...),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Generate remediation script for findings"""
    try:
        remediator = STIGRemediator(db)
        script = await remediator.generate_remediation_script(
            findings=request.get("findings", {}),
            platform=request.get("platform", "linux"),
            org_id=org_id,
        )
        return RemediationScriptResponse(
            platform=request.get("platform", "linux"),
            script=script,
            total_findings=len(request.get("findings", {})),
            generated_at=datetime.utcnow(),
        )
    except Exception as e:
        logger.error(f"Error generating script: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# SCAP Endpoints
# ============================================================================


# Where uploaded XCCDF files are persisted on disk. A bind mount in
# production, a tmp dir in tests. Kept outside /tmp so the file survives
# container restarts; the SCAPProfile row stores the absolute path so
# later re-scans can hash-verify content integrity. It is also the only
# directory POST /stig/scap/import will read from.
STIG_CONTENT_DIR = os.environ.get("PYSOAR_STIG_CONTENT_DIR", "/app/data/stig/xccdf")


def _stig_content_path(content_path: Optional[str]) -> str:
    """Resolve a client-supplied content path; 403 unless it is a file
    inside STIG_CONTENT_DIR.

    Before 2026-10-08 /scap/import parsed any server-side path the caller
    named (e.g. /opt/pysoar/.env), leaking file existence and parse errors.
    """
    root = os.path.realpath(STIG_CONTENT_DIR)
    real = os.path.realpath(content_path or "")
    if not content_path or not real.startswith(root + os.sep):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "content_path_outside_stig_root",
                "detail": "content_path must name a file previously uploaded through POST /stig/scap/upload",
            },
        )
    return real


@router.post("/scap/import", response_model=SCAPProfileResponse)
async def import_scap_content(
    request: SCAPImportRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Import SCAP content (XCCDF, OVAL) from a file already under the STIG
    content directory (see POST /stig/scap/upload)."""
    xccdf_path = _stig_content_path(request.content_path)
    try:
        engine = SCAPEngine(db)
        result = await engine.import_scap_content(
            xccdf_path=xccdf_path,
            org_id=org_id,
        )
        return result
    except BenchmarkOwnershipConflict as e:
        raise _benchmark_conflict(e) from e
    except Exception as e:
        logger.error(f"Error importing SCAP content: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scap/upload")
async def upload_scap_content(
    org_id: OrganizationId,
    file: UploadFile = File(..., description="XCCDF XML file (DISA STIG content)"),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Upload an XCCDF STIG file and import it.

    Accepts multipart form data. Content is written to the persistent
    STIG content directory, SHA-256 hashed, parsed, and every <Rule>
    element is stored as an STIGRule row.
    """
    if not file.filename or not file.filename.lower().endswith((".xml", ".xccdf", ".xccdf.xml")):
        raise HTTPException(status_code=400, detail="File must have .xml, .xccdf, or .xccdf.xml extension")

    Path(STIG_CONTENT_DIR).mkdir(parents=True, exist_ok=True)
    # Use a UUID prefix to avoid filename collisions between orgs uploading
    # the same DISA content package.
    from uuid import uuid4 as _uuid4
    safe_name = file.filename.replace("..", "_").replace("/", "_").replace("\\", "_")
    dest = Path(STIG_CONTENT_DIR) / f"{_uuid4().hex[:12]}_{safe_name}"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    dest.write_bytes(content)

    engine = SCAPEngine(db)
    try:
        result = await engine.import_scap_content(xccdf_path=str(dest), org_id=org_id)
    except BenchmarkOwnershipConflict as e:
        raise _benchmark_conflict(e) from e
    except Exception as e:
        logger.error("SCAP upload import failed", error=str(e))
        # Leave the uploaded file on disk for forensics even when import fails.
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)[:200]}")
    if result.get("status", "").startswith("error"):
        raise HTTPException(status_code=400, detail=result.get("parse_error") or "Import error")
    return result


@router.post("/scans/{scan_id}/arf")
async def ingest_arf_result(
    org_id: OrganizationId,
    scan_id: str = FPath(..., description="STIGScanResult UUID"),
    file: UploadFile = File(..., description="oscap-generated ARF XML"),
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Ingest an oscap ARF (Asset Reporting Format) report into an existing
    scan record. Parses <rule-result> elements and updates findings +
    compliance percentage. Endpoint agents call this after running
    `oscap xccdf eval --results-arf ...`.
    """
    arf_bytes = await file.read()
    if not arf_bytes:
        raise HTTPException(status_code=400, detail="ARF file is empty")

    scanner = STIGScanner(db)
    try:
        result = await scanner.ingest_arf_result(scan_id=scan_id, arf_xml=arf_bytes, org_id=org_id)
    except STIGNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("error") or "ARF ingestion failed")
    return result


@router.post("/scap/scan", response_model=None)
async def run_scap_scan(
    org_id: OrganizationId,
    _user: AdminRoleUser,
    request: dict = Body(...),
    db: DatabaseSession = None,
):
    """SCAP profile evaluation (admin only: names a live target).

    Nothing is executed against the target; the result's status is
    ``not_executed`` and its counts come from imported rule defaults.
    """
    try:
        engine = SCAPEngine(db)
        return await engine.run_scap_scan(
            profile_id=request.get("profile_id"),
            target=request.get("target"),
            org_id=org_id,
        )
    except STIGNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error running SCAP scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scap/validate-oval", response_model=None)
async def validate_oval(
    request: OVALValidationRequest,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Validate OVAL (Open Vulnerability and Assessment Language) definitions"""
    try:
        engine = SCAPEngine(db)
        result = await engine.validate_oval_definitions(request.content)
        return result
    except Exception as e:
        logger.error(f"Error validating OVAL: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scap/arf-report", response_model=None)
async def generate_arf_report(
    request: ARFReportRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Generate Assessment Results Format (ARF) report (read-only: viewers allowed)."""
    try:
        engine = SCAPEngine(db)
        return await engine.generate_arf_report(request.scan_id, org_id)
    except STIGNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error generating ARF report: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/scap/profiles", response_model=list[SCAPProfileResponse])
async def list_scap_profiles(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List SCAP profiles"""
    try:
        query = (
            select(SCAPProfile)
            .where(SCAPProfile.organization_id == org_id)
            .offset(skip)
            .limit(limit)
        )
        profiles = await db.scalars(query)
        return profiles
    except Exception as e:
        logger.error(f"Error listing SCAP profiles: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Dashboard Endpoints
# ============================================================================


@router.get("/dashboard/stats", response_model=STIGDashboardStats)
async def get_stig_stats(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get STIG compliance dashboard statistics.

    Returns real benchmark and scan aggregates plus the three fields
    the frontend actually renders on the dashboard tab
    (``compliance_by_benchmark``, ``findings_by_severity``,
    ``recent_scans``). These three were silently missing from the
    schema historically, so the UI always showed zeros even when real
    scans existed.
    """

    try:
        # Count benchmarks
        bench_query = select(STIGBenchmark).where(
            STIGBenchmark.organization_id == org_id
        )
        benchmarks = list(await db.scalars(bench_query))
        benchmarks_by_id = {b.id: b for b in benchmarks}
        total_benchmarks = len(benchmarks)

        # Count scans
        scan_query = (
            select(STIGScanResult)
            .where(STIGScanResult.organization_id == org_id)
            .order_by(desc(STIGScanResult.created_at))
        )
        scan_list = list(await db.scalars(scan_query))
        total_scans = len(scan_list)

        # Average only scans with real results: pending_results / failed
        # scans executed no checks and carry no compliance score.
        scored = [s for s in scan_list if s.status == "completed"]
        avg_compliance = (
            sum(s.compliance_percentage or 0.0 for s in scored) / len(scored)
            if scored
            else 0.0
        )
        # STIG CAT I = High, CAT II = Medium, CAT III = Low
        critical_findings = sum(s.cat1_open for s in scan_list)
        high_findings = sum(s.cat2_open for s in scan_list)
        medium_findings = sum(s.cat3_open for s in scan_list)

        # default=None: scans that never completed (not_run / dispatched) have
        # no completed_at, and max() of nothing used to 500 the dashboard.
        last_scan_date = max((s.completed_at for s in scan_list if s.completed_at), default=None)

        # --- compliance_by_benchmark (real aggregate) ---
        compliance_by_benchmark: list[dict] = []
        benchmark_scan_buckets: dict[str, list[float]] = {}
        for s in scored:
            if s.benchmark_id_ref:
                benchmark_scan_buckets.setdefault(s.benchmark_id_ref, []).append(
                    float(s.compliance_percentage or 0)
                )
        for bench_id, pcts in benchmark_scan_buckets.items():
            bench = benchmarks_by_id.get(bench_id)
            if bench is None or not pcts:
                continue
            compliance_by_benchmark.append({
                "name": bench.title or bench.benchmark_id,
                "percentage": round(sum(pcts) / len(pcts), 1),
            })

        # --- findings_by_severity (matches frontend bar chart) ---
        findings_by_severity = {
            "CAT I": critical_findings,
            "CAT II": high_findings,
            "CAT III": medium_findings,
        }

        # --- recent_scans (last 5 completed, serialized for table) ---
        recent_scans = [
            {
                "id": s.id,
                "host": s.target_host,
                "benchmark": (
                    benchmarks_by_id.get(s.benchmark_id_ref).title
                    if s.benchmark_id_ref and benchmarks_by_id.get(s.benchmark_id_ref)
                    else "unknown"
                ),
                "status": s.status,
                "status_reason": s.status_reason,
                "compliance": float(s.compliance_percentage or 0) if s.status == "completed" else None,
                "findings": {
                    "open": s.open_findings or 0,
                    "naf": s.not_a_finding or 0,
                    "na": s.not_applicable or 0,
                    "nr": s.not_reviewed or 0,
                },
                "date": s.completed_at.isoformat() if s.completed_at else (s.created_at.isoformat() if s.created_at else None),
            }
            for s in scan_list[:5]
        ]

        # --- real compliance_trend (improving/declining/stable) ---
        compliance_trend = "stable"
        if total_scans >= 2:
            # Compare the most recent 5 scans' average to the prior 5.
            recent_window = scan_list[:5]
            prior_window = scan_list[5:10] if total_scans >= 6 else []
            if prior_window:
                recent_avg = sum(s.compliance_percentage or 0 for s in recent_window) / len(recent_window)
                prior_avg = sum(s.compliance_percentage or 0 for s in prior_window) / len(prior_window)
                delta = recent_avg - prior_avg
                if delta >= 2.0:
                    compliance_trend = "improving"
                elif delta <= -2.0:
                    compliance_trend = "declining"

        return STIGDashboardStats(
            organization_id=org_id,
            total_benchmarks=total_benchmarks,
            total_scans=total_scans,
            average_compliance=round(avg_compliance, 1),
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=0,
            last_scan_date=last_scan_date,
            scans_this_month=len(
                [
                    s for s in scan_list
                    if s.created_at
                    and (s.created_at.year, s.created_at.month)
                    == (datetime.utcnow().year, datetime.utcnow().month)
                ]
            ),
            compliance_trend=compliance_trend,
            compliance_by_benchmark=compliance_by_benchmark,
            findings_by_severity=findings_by_severity,
            recent_scans=recent_scans,
            scans_not_run=sum(1 for s in scan_list if s.status in ("not_run", "no_agent", "failed")),
            scans_pending=sum(1 for s in scan_list if s.status in ("dispatched", "awaiting_approval", "pending_results")),
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")
