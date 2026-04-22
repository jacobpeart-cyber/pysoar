"""
STIG/SCAP REST API Endpoints

REST endpoints for STIG benchmark scanning, rule management, remediation,
SCAP operations, and compliance dashboard.
"""

import os
import tempfile
from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Body, UploadFile, File, Path as FPath
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
from src.stig.engine import STIGScanner, STIGRemediator, STIGLibrary, SCAPEngine
from src.stig.models import STIGBenchmark, STIGRule, STIGScanResult, SCAPProfile
from src.services.automation import AutomationService
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


# ============================================================================
# Benchmark Endpoints
# ============================================================================


@router.get("/benchmarks", response_model=list[BenchmarkListResponse])
async def list_benchmarks(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List STIG benchmarks for organization"""
    try:
        stmt = (
            select(STIGBenchmark)
            .where(STIGBenchmark.organization_id == getattr(current_user, "organization_id", None))
            .offset(skip)
            .limit(limit)
        )
        benchmarks = await db.scalars(stmt)
        return benchmarks
    except Exception as e:
        logger.error(f"Error listing benchmarks: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/benchmarks/{benchmark_id}", response_model=STIGBenchmarkResponse)
async def get_benchmark(
    benchmark_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get STIG benchmark details"""
    try:
        stmt = select(STIGBenchmark).where(
            (STIGBenchmark.benchmark_id == benchmark_id)
            & (STIGBenchmark.organization_id == getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List rules for STIG benchmark"""
    try:
        stmt = select(STIGBenchmark).where(
            (STIGBenchmark.benchmark_id == benchmark_id)
            & (STIGBenchmark.organization_id == getattr(current_user, "organization_id", None))
        )
        benchmark = await db.scalar(stmt)
        if not benchmark:
            raise HTTPException(status_code=404, detail="Benchmark not found")

        query = select(STIGRule).where(
            (STIGRule.benchmark_id_ref == benchmark.id)
            & (STIGRule.organization_id == getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    q: str = Query(..., min_length=1),
    current_user: CurrentUser = None,
):
    """Search STIG rules by keyword, ID, or content"""
    try:
        library = STIGLibrary(db)
        results = await library.search_rules(q, getattr(current_user, "organization_id", None))
        return results
    except Exception as e:
        logger.error(f"Error searching rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/rules/{rule_id}", response_model=STIGRuleResponse)
async def get_rule(
    rule_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get STIG rule details"""
    try:
        stmt = select(STIGRule).where(
            (STIGRule.rule_id == rule_id)
            & (STIGRule.organization_id == getattr(current_user, "organization_id", None))
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


@router.post("/scans/launch", response_model=None)
async def launch_scan(
    request: ScanRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Launch STIG benchmark scan against target host"""
    try:
        scanner = STIGScanner(db)
        result = await scanner.scan_host(
            host=request.host,
            benchmark_id=request.benchmark_id,
            scan_type=request.scan_type,
            target_ip=request.target_ip,
        )

        try:
            org_id = getattr(current_user, "organization_id", None)
            failed_count = 0
            if isinstance(result, dict):
                failed_count = result.get("failed", 0) or result.get("failures", 0) or 0
            if failed_count:
                automation = AutomationService(db)
                await automation.on_stig_finding(
                    benchmark=request.benchmark_id,
                    finding_title=f"STIG scan failures on {request.host}",
                    severity="high",
                    organization_id=org_id,
                )
        except Exception as automation_exc:
            logger.warning(f"Automation on_stig_finding failed: {automation_exc}")

        return result
    except Exception as e:
        logger.error(f"Error launching scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scans/fleet", response_model=list[dict])
async def launch_fleet_scan(
    request: ScanFleetRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Launch STIG scans against multiple hosts"""
    try:
        scanner = STIGScanner(db)
        results = await scanner.scan_fleet(
            hosts=request.hosts,
            benchmark_id=request.benchmark_id,
            scan_type=request.scan_type,
        )
        return results
    except Exception as e:
        logger.error(f"Error launching fleet scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/scans", response_model=list[STIGScanResultResponse])
async def list_scans(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    benchmark_id: Optional[str] = None,
    target_host: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List STIG scan results"""
    try:
        query = select(STIGScanResult).where(
            STIGScanResult.organization_id == getattr(current_user, "organization_id", None)
        )

        if benchmark_id:
            stmt = select(STIGBenchmark.id).where(
                STIGBenchmark.benchmark_id == benchmark_id
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get STIG scan result details"""
    try:
        stmt = select(STIGScanResult).where(
            (STIGScanResult.id == scan_id)
            & (STIGScanResult.organization_id == getattr(current_user, "organization_id", None))
        )
        scan = await db.scalar(stmt)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scans/compare", response_model=ScanComparisonResponse)
async def compare_scans(
    request: ScanComparisonRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Compare two STIG scan baselines"""
    try:
        scanner = STIGScanner(db)
        result = await scanner.get_scan_comparison(request.scan_id_1, request.scan_id_2)
        return result
    except Exception as e:
        logger.error(f"Error comparing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Remediation Endpoints
# ============================================================================


@router.post("/remediate/auto", response_model=RemediationResponse)
async def auto_remediate(
    request: RemediationRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Auto-remediate STIG findings"""
    try:
        remediator = STIGRemediator(db)
        result = await remediator.auto_remediate(
            scan_result_id=request.scan_result_id,
            categories=request.categories,
        )
        return result
    except Exception as e:
        logger.error(f"Error remediating findings: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/remediate/script", response_model=RemediationScriptResponse)
async def generate_remediation_script(
    request: dict = Body(...),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Generate remediation script for findings"""
    try:
        remediator = STIGRemediator(db)
        script = await remediator.generate_remediation_script(
            findings=request.get("findings", {}),
            platform=request.get("platform", "linux"),
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


@router.post("/scap/import", response_model=SCAPProfileResponse)
async def import_scap_content(
    request: SCAPImportRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Import SCAP content (XCCDF, OVAL) by server-side path."""
    try:
        engine = SCAPEngine(db)
        result = await engine.import_scap_content(
            xccdf_path=request.content_path,
            org_id=getattr(current_user, "organization_id", None),
        )
        return result
    except Exception as e:
        logger.error(f"Error importing SCAP content: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# Where uploaded XCCDF files are persisted on disk. A bind mount in
# production, a tmp dir in tests. Kept outside /tmp so the file survives
# container restarts; the SCAPProfile row stores the absolute path so
# later re-scans can hash-verify content integrity.
STIG_CONTENT_DIR = os.environ.get("PYSOAR_STIG_CONTENT_DIR", "/app/data/stig/xccdf")


@router.post("/scap/upload", response_model=SCAPProfileResponse)
async def upload_scap_content(
    file: UploadFile = File(..., description="XCCDF XML file (DISA STIG content)"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Upload an XCCDF STIG file and import it.

    Accepts multipart form data. Content is written to the persistent
    STIG content directory, SHA-256 hashed, parsed, and every <Rule>
    element is stored as an STIGRule row.
    """
    if not file.filename or not file.filename.lower().endswith((".xml", ".xccdf", ".xccdf.xml")):
        raise HTTPException(status_code=400, detail="File must have .xml, .xccdf, or .xccdf.xml extension")

    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

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
    except Exception as e:
        logger.error("SCAP upload import failed", error=str(e))
        # Leave the uploaded file on disk for forensics even when import fails.
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)[:200]}")
    if result.get("status", "").startswith("error"):
        raise HTTPException(status_code=400, detail=result.get("parse_error") or "Import error")
    return result


@router.post("/scans/{scan_id}/arf")
async def ingest_arf_result(
    scan_id: str = FPath(..., description="STIGScanResult UUID"),
    file: UploadFile = File(..., description="oscap-generated ARF XML"),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
    result = await scanner.ingest_arf_result(scan_id=scan_id, arf_xml=arf_bytes)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("error") or "ARF ingestion failed")
    return result


@router.post("/scap/scan", response_model=None)
async def run_scap_scan(
    request: dict = Body(...),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Run SCAP scan using profile"""
    try:
        engine = SCAPEngine(db)
        result = await engine.run_scap_scan(
            profile_id=request.get("profile_id"),
            target=request.get("target"),
        )
        return result
    except Exception as e:
        logger.error(f"Error running SCAP scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/scap/validate-oval", response_model=None)
async def validate_oval(
    request: OVALValidationRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Generate Assessment Results Format (ARF) report"""
    try:
        engine = SCAPEngine(db)
        result = await engine.generate_arf_report(request.scan_id)
        return result
    except Exception as e:
        logger.error(f"Error generating ARF report: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/scap/profiles", response_model=list[SCAPProfileResponse])
async def list_scap_profiles(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List SCAP profiles"""
    try:
        query = (
            select(SCAPProfile)
            .where(SCAPProfile.organization_id == getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get STIG compliance dashboard statistics.

    Returns real benchmark and scan aggregates plus the three fields
    the frontend actually renders on the dashboard tab
    (``compliance_by_benchmark``, ``findings_by_severity``,
    ``recent_scans``). These three were silently missing from the
    schema historically, so the UI always showed zeros even when real
    scans existed.
    """
    org_id = getattr(current_user, "organization_id", None)

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

        # Calculate averages and totals
        avg_compliance = (
            sum(s.compliance_percentage for s in scan_list) / total_scans
            if total_scans > 0
            else 0.0
        )
        # STIG CAT I = High, CAT II = Medium, CAT III = Low
        critical_findings = sum(s.cat1_open for s in scan_list)
        high_findings = sum(s.cat2_open for s in scan_list)
        medium_findings = sum(s.cat3_open for s in scan_list)

        last_scan_date = (
            max(s.completed_at for s in scan_list if s.completed_at)
            if scan_list
            else None
        )

        # --- compliance_by_benchmark (real aggregate) ---
        compliance_by_benchmark: list[dict] = []
        benchmark_scan_buckets: dict[str, list[float]] = {}
        for s in scan_list:
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
                "compliance": float(s.compliance_percentage or 0),
                "findings": {
                    "open": (s.cat1_open or 0) + (s.cat2_open or 0) + (s.cat3_open or 0),
                    "naf": 0,
                    "na": 0,
                    "nr": 0,
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
            organization_id=org_id or "",
            total_benchmarks=total_benchmarks,
            total_scans=total_scans,
            average_compliance=round(avg_compliance, 1),
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=0,
            last_scan_date=last_scan_date,
            scans_this_month=len(
                [s for s in scan_list if s.created_at and s.created_at.month == datetime.utcnow().month]
            ),
            compliance_trend=compliance_trend,
            compliance_by_benchmark=compliance_by_benchmark,
            findings_by_severity=findings_by_severity,
            recent_scans=recent_scans,
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")
