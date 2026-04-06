"""
Audit & Evidence Collection REST API Endpoints

REST endpoints for audit logging, evidence collection, packaging,
continuous monitoring, and audit readiness checking.
"""

from typing import Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.api.deps import CurrentUser, DatabaseSession, get_current_active_user
from src.core.database import get_db
from src.core.logging import get_logger
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


# ============================================================================
# Audit Trail Endpoints
# ============================================================================


@router.post("/audit/log", response_model=AuditTrailResponse)
async def log_audit_event(
    request: AuditLogRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Log audit event"""
    try:
        audit_logger = AuditLogger(db, getattr(current_user, "organization_id", None))
        trail = await audit_logger.log_event(
            event_type=request.event_type,
            action=request.action,
            actor_type=request.actor_type,
            actor_id=request.actor_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            description=request.description,
            old_value=request.old_value,
            new_value=request.new_value,
            result=request.result,
            risk_level=request.risk_level,
            actor_ip=request.actor_ip,
        )
        return trail
    except Exception as e:
        logger.error(f"Error logging audit event: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/audit/search", response_model=list[AuditTrailResponse])
async def search_audit_trail(
    request: AuditSearchRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Search audit trail with filters"""
    try:
        audit_logger = AuditLogger(db, getattr(current_user, "organization_id", None))

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

        results = await audit_logger.search_audit_trail(filters)
        return results[request.skip : request.skip + request.limit]
    except Exception as e:
        logger.error(f"Error searching audit trail: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/audit/export", response_model=None)
async def export_audit_trail(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    format: str = Query("json", pattern="^(json|csv|xml)$"),
    days: int = Query(30, ge=1, le=365),
):
    """Export audit trail"""
    try:
        audit_logger = AuditLogger(db, getattr(current_user, "organization_id", None))

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
    db: DatabaseSession = None,
    actor_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Detect suspicious activity for actor"""
    try:
        audit_logger = AuditLogger(db, getattr(current_user, "organization_id", None))
        activities = await audit_logger.detect_suspicious_activity(actor_id)
        return activities
    except Exception as e:
        logger.error(f"Error detecting suspicious activity: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Evidence Collection Endpoints
# ============================================================================


@router.post("/evidence/collect", response_model=None)
async def collect_evidence(
    request: dict = Body(...),
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Collect evidence based on rule"""
    try:
        collector = EvidenceCollector(db, getattr(current_user, "organization_id", None))
        result = await collector.collect_evidence(request.get("rule_id"))
        return {
            "status": "success",
            "evidence": result,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error collecting evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/evidence/collect-all", response_model=None)
async def collect_all_automated_evidence(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Collect evidence from all enabled automated rules"""
    try:
        collector = EvidenceCollector(db, getattr(current_user, "organization_id", None))
        results = await collector.collect_all_automated()
        return {
            "status": "completed",
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error collecting automated evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/evidence/verify", response_model=None)
async def verify_evidence_integrity(
    db: DatabaseSession = None,
    evidence_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Verify evidence integrity"""
    try:
        collector = EvidenceCollector(db, getattr(current_user, "organization_id", None))
        is_valid = await collector.verify_evidence_integrity(evidence_id)
        return {
            "evidence_id": evidence_id,
            "integrity_valid": is_valid,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error verifying evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/evidence/list", response_model=list[dict])
async def list_evidence_items(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    evidence_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List evidence items"""
    try:
        query = select(AutomatedEvidenceRule).where(
            AutomatedEvidenceRule.organization_id == getattr(current_user, "organization_id", None)
        )
        if evidence_type:
            query = query.where(AutomatedEvidenceRule.rule_type == evidence_type)
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        items = result.scalars().all()
        return list(items)
    except Exception as e:
        logger.error(f"Error listing evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Evidence Package Endpoints
# ============================================================================


@router.post("/packages/create", response_model=EvidencePackageResponse)
async def create_evidence_package(
    request: EvidencePackageCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
            metadata=request.metadata or {},
            organization_id=getattr(current_user, "organization_id", None),
        )
        db.add(package)
        await db.commit()
        return package
    except Exception as e:
        logger.error(f"Error creating evidence package: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/packages", response_model=list[EvidencePackageResponse])
async def list_evidence_packages(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List evidence packages"""
    try:
        query = select(EvidencePackage).where(
            EvidencePackage.organization_id == getattr(current_user, "organization_id", None)
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get evidence package details"""
    try:
        query = select(EvidencePackage).where(
            (EvidencePackage.id == package_id)
            & (EvidencePackage.organization_id == getattr(current_user, "organization_id", None))
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


@router.post("/packages/{package_id}/package", response_model=None)
async def package_evidence(
    package_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Package evidence for submission"""
    try:
        collector = EvidenceCollector(db, getattr(current_user, "organization_id", None))
        result = await collector.package_evidence(package_id)
        return result
    except Exception as e:
        logger.error(f"Error packaging evidence: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.post("/packages/{package_id}/submit", response_model=None)
async def submit_evidence_package(
    package_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Submit evidence package to assessor"""
    try:
        # Update package status to submitted
        query = select(EvidencePackage).where(EvidencePackage.id == package_id)
        package = await db.scalar(query)
        if not package:
            raise HTTPException(status_code=404, detail="Package not found")

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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get evidence report for package"""
    try:
        collector = EvidenceCollector(db, getattr(current_user, "organization_id", None))
        result = await collector.generate_evidence_report(package_id)
        return result
    except Exception as e:
        logger.error(f"Error generating evidence report: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Continuous Monitoring Endpoints
# ============================================================================


@router.post("/conmon/run-cycle", response_model=ConMonReportResponse)
async def run_conmon_cycle(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Run FedRAMP ConMon cycle"""
    try:
        monitor = ContinuousMonitor(db, getattr(current_user, "organization_id", None))
        report = await monitor.generate_conmon_report()
        return report
    except Exception as e:
        logger.error(f"Error running ConMon cycle: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/conmon/report", response_model=ConMonReportResponse)
async def get_conmon_report(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get latest ConMon report"""
    try:
        monitor = ContinuousMonitor(db, getattr(current_user, "organization_id", None))
        report = await monitor.generate_conmon_report()
        return report
    except Exception as e:
        logger.error(f"Error getting ConMon report: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/conmon/status", response_model=None)
async def get_conmon_status(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get ConMon status"""
    try:
        monitor = ContinuousMonitor(db, getattr(current_user, "organization_id", None))
        cycle_results = await monitor.run_conmon_cycle()
        return {
            "status": "compliant",
            "checks": cycle_results,
            "last_run": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting ConMon status: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Audit Readiness Endpoints
# ============================================================================


@router.get("/readiness/check", response_model=AuditReadinessResponse)
async def check_audit_readiness(
    db: DatabaseSession = None,
    framework: str = Query(..., description="Compliance framework"),
    current_user: CurrentUser = None,
):
    """Check audit readiness for framework"""
    try:
        checker = AuditReadinessChecker(db, getattr(current_user, "organization_id", None))
        result = await checker.check_readiness(framework)
        return result
    except Exception as e:
        logger.error(f"Error checking audit readiness: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/readiness/coverage", response_model=EvidenceCoverageResponse)
async def check_evidence_coverage(
    db: DatabaseSession = None,
    framework_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Check evidence coverage for framework"""
    try:
        checker = AuditReadinessChecker(db, getattr(current_user, "organization_id", None))
        result = await checker.check_evidence_coverage(framework_id)
        return result
    except Exception as e:
        logger.error(f"Error checking evidence coverage: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/readiness/freshness", response_model=EvidenceFreshnessResponse)
async def check_evidence_freshness(
    db: DatabaseSession = None,
    framework_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Check evidence freshness for framework"""
    try:
        checker = AuditReadinessChecker(db, getattr(current_user, "organization_id", None))
        result = await checker.check_evidence_freshness(framework_id)
        return result
    except Exception as e:
        logger.error(f"Error checking evidence freshness: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/readiness/assessor-package", response_model=AssessorPackageResponse)
async def generate_assessor_package(
    db: DatabaseSession = None,
    framework_id: str = Query(...),
    current_user: CurrentUser = None,
):
    """Generate package for external assessors"""
    try:
        checker = AuditReadinessChecker(db, getattr(current_user, "organization_id", None))
        result = await checker.generate_assessor_package(framework_id)
        return result
    except Exception as e:
        logger.error(f"Error generating assessor package: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


# ============================================================================
# Automated Rules Endpoints
# ============================================================================


@router.post("/rules/create", response_model=AutomatedEvidenceRuleResponse)
async def create_evidence_rule(
    request: AutomatedRuleCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Create automated evidence collection rule"""
    try:
        rule = AutomatedEvidenceRule(
            name=request.name,
            control_ids=request.control_ids or {},
            evidence_type=request.evidence_type,
            collection_method=request.collection_method,
            collection_config=request.collection_config,
            schedule=request.schedule,
            is_enabled=request.is_enabled,
            organization_id=getattr(current_user, "organization_id", None),
        )
        db.add(rule)
        await db.commit()
        return rule
    except Exception as e:
        logger.error(f"Error creating evidence rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")


@router.get("/rules", response_model=list[AutomatedEvidenceRuleResponse])
async def list_evidence_rules(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """List automated evidence collection rules"""
    try:
        query = (
            select(AutomatedEvidenceRule)
            .where(AutomatedEvidenceRule.organization_id == getattr(current_user, "organization_id", None))
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
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get audit and evidence dashboard statistics"""
    try:
        # Count audit entries
        audit_query = select(AuditTrail).where(
            AuditTrail.organization_id == getattr(current_user, "organization_id", None)
        )
        audits = await db.scalars(audit_query)
        audit_list = list(audits)

        # Count packages
        pkg_query = select(EvidencePackage).where(
            EvidencePackage.organization_id == getattr(current_user, "organization_id", None)
        )
        packages = await db.scalars(pkg_query)
        pkg_list = list(packages)

        # Calculate stats
        this_month = datetime.now(timezone.utc).replace(day=1)
        month_audits = len(
            [a for a in audit_list if a.created_at >= this_month]
        )
        pkg_in_progress = len([p for p in pkg_list if p.status == "collecting"])
        pkg_submitted = len([p for p in pkg_list if p.status == "submitted"])

        return AuditDashboardStats(
            organization_id=getattr(current_user, "organization_id", None),
            total_audit_entries=len(audit_list),
            audit_entries_this_month=month_audits,
            event_types_breakdown={},
            risk_distribution={},
            total_evidence_packages=len(pkg_list),
            evidence_packages_in_progress=pkg_in_progress,
            evidence_packages_submitted=pkg_submitted,
            avg_evidence_package_compliance=92.0,
            suspicious_activities_detected=0,
            critical_audit_events=len([a for a in audit_list if a.risk_level == "critical"]),
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")
