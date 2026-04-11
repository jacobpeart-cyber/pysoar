"""
Audit & Evidence Collection REST API Endpoints

REST endpoints for audit logging, evidence collection, packaging,
continuous monitoring, and audit readiness checking.
"""

from typing import Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

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


@router.delete("/evidence/{evidence_id}", status_code=204)
async def delete_evidence_item(
    evidence_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Delete a ComplianceEvidence row.

    The frontend's "Delete" button hit this route and silently 404'd
    because it wasn't declared. Now validates ownership (org-scoped),
    soft-deletes by setting ``is_valid=False``, and writes an audit
    trail entry so an assessor can see the removal.
    """
    from src.compliance.models import ComplianceEvidence

    org_id = getattr(current_user, "organization_id", None)
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
        logger.warning(f"Audit trail for evidence delete failed: {exc}")

    return None


@router.post("/evidence/{evidence_id}/approve", status_code=200)
async def approve_evidence_item(
    evidence_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Mark a ComplianceEvidence row as approved.

    Frontend "Approve" button hit this route and 404'd the same way
    the delete button did. Now sets review_status=approved, records
    the approver + timestamp, and writes an audit trail entry.
    """
    from src.compliance.models import ComplianceEvidence

    org_id = getattr(current_user, "organization_id", None)
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
        logger.warning(f"Audit trail for evidence approve failed: {exc}")

    return {
        "id": evidence.id,
        "status": evidence.review_status,
        "reviewed_by": evidence.reviewed_by,
        "reviewed_at": evidence.reviewed_at.isoformat() if evidence.reviewed_at else None,
    }


@router.get("/evidence/list", response_model=list[dict])
async def list_evidence_items(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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

        org_id = getattr(current_user, "organization_id", None)
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


@router.post("/conmon/run", response_model=None)
async def run_conmon_alias(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Alias for /conmon/run-cycle used by the frontend ConMon button."""
    try:
        monitor = ContinuousMonitor(db, getattr(current_user, "organization_id", None))
        report = await monitor.generate_conmon_report()
        return {"ok": True, "report": report}
    except Exception as e:
        logger.error(f"Error running ConMon cycle (alias): {str(e)}")
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
    """Get ConMon status per control check.

    Returns an ARRAY of ConMonStatus rows (one per control check) so the
    frontend can render them in a grid. Each row has {id, name, active,
    lastRun, status, compliance_percentage, details}.
    """
    try:
        monitor = ContinuousMonitor(db, getattr(current_user, "organization_id", None))
        cycle = await monitor.run_conmon_cycle()
        now_iso = datetime.now(timezone.utc).isoformat()

        label_map = {
            "vulnerability_scanning": "Vulnerability Scanning (SI-2)",
            "configuration_baseline": "Configuration Baseline (CM-3)",
            "incident_reporting": "Incident Reporting (IR-4)",
            "poam_progress": "POA&M Progress",
        }

        rows: list[dict] = []
        for key, label in label_map.items():
            check = cycle.get(key) or {}
            check_status = check.get("status", "unknown")
            is_active = check_status in ("compliant", "on_track")
            rows.append({
                "id": key,
                "name": label,
                "active": is_active,
                "status": check_status,
                "lastRun": now_iso,
                "compliance_percentage": check.get("compliance_percentage", 0),
                "details": check,
            })
        return rows
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
    """Check evidence coverage for framework.

    Each control that came back without sufficient evidence fires
    ``automation.on_fedramp_evidence_gap``, which creates a POAM and
    runs the full compliance automation chain. Previously the
    coverage check returned a gap list to the UI but those gaps
    never produced any POAMs or alerts, so an assessor preparing a
    FedRAMP package would see "covered: no" on a control and nothing
    actionable would happen downstream.

    Capped at 25 gap events per call so a completely uncovered
    framework (191 controls for FedRAMP Moderate) can't fan out 191
    alerts in one API hit.
    """
    org_id = getattr(current_user, "organization_id", None)
    try:
        checker = AuditReadinessChecker(db, org_id)
        result = await checker.check_evidence_coverage(framework_id)

        # Fan out the gaps to the compliance automation pipeline
        try:
            gaps = []
            if isinstance(result, dict):
                gaps = result.get("uncovered_controls") or result.get("gaps") or []
            elif hasattr(result, "uncovered_controls"):
                gaps = result.uncovered_controls or []
            elif hasattr(result, "gaps"):
                gaps = result.gaps or []

            if gaps:
                from src.services.automation import AutomationService
                automation = AutomationService(db)
                fired = 0
                for gap in gaps[:25]:
                    # gap may be a dict or a scalar control_id string
                    if isinstance(gap, dict):
                        control_id = gap.get("control_id") or gap.get("id") or "unknown"
                        control_title = gap.get("title") or gap.get("control_title") or f"Uncovered control {control_id}"
                    else:
                        control_id = str(gap)
                        control_title = f"Uncovered control {control_id}"
                    try:
                        await automation.on_fedramp_evidence_gap(
                            control_id=control_id,
                            control_title=control_title,
                            organization_id=org_id,
                        )
                        fired += 1
                    except Exception as inner_exc:  # noqa: BLE001
                        logger.warning(
                            f"on_fedramp_evidence_gap failed for {control_id}: {inner_exc}"
                        )
                logger.info(
                    f"Fired {fired} evidence-gap events for framework={framework_id}"
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Evidence gap fan-out failed: {exc}")

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
    """Get audit and evidence dashboard statistics.

    Four fields used to be hardcoded (event_types_breakdown = {},
    risk_distribution = {}, avg_evidence_package_compliance = 92.0,
    suspicious_activities_detected = 0). Now they are computed from
    real AuditTrail + ComplianceEvidence data.
    """
    from src.compliance.models import ComplianceEvidence

    org_id = getattr(current_user, "organization_id", None)

    try:
        # Count audit entries
        audit_query = select(AuditTrail).where(
            AuditTrail.organization_id == org_id
        )
        audits = await db.scalars(audit_query)
        audit_list = list(audits)

        # Count packages
        pkg_query = select(EvidencePackage).where(
            EvidencePackage.organization_id == org_id
        )
        packages = await db.scalars(pkg_query)
        pkg_list = list(packages)

        this_month = datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        month_audits = len(
            [a for a in audit_list if a.created_at and a.created_at >= this_month]
        )
        pkg_in_progress = len([p for p in pkg_list if p.status == "collecting"])
        pkg_submitted = len([p for p in pkg_list if p.status == "submitted"])

        # --- Real event_types_breakdown ---
        event_types_breakdown: dict[str, int] = {}
        for a in audit_list:
            key = a.event_type or "unknown"
            event_types_breakdown[key] = event_types_breakdown.get(key, 0) + 1

        # --- Real risk_distribution ---
        risk_distribution: dict[str, int] = {}
        for a in audit_list:
            key = (a.risk_level or "unknown").lower()
            risk_distribution[key] = risk_distribution.get(key, 0) + 1

        # --- Real avg_evidence_package_compliance ---
        # For each package, compute the share of its referenced evidence
        # items that are in approved status. Average across packages.
        avg_pkg_compliance = 0.0
        if pkg_list:
            pkg_scores: list[float] = []
            for p in pkg_list:
                items = p.evidence_items or []
                if not items:
                    continue
                evidence_ids = [str(i) for i in items if i]
                if not evidence_ids:
                    continue
                ev_result = await db.execute(
                    select(ComplianceEvidence).where(
                        and_(
                            ComplianceEvidence.id.in_(evidence_ids),
                            ComplianceEvidence.organization_id == org_id,
                        )
                    )
                )
                ev_rows = list(ev_result.scalars().all())
                if not ev_rows:
                    continue
                approved = sum(1 for e in ev_rows if e.review_status == "approved")
                pkg_scores.append((approved / len(ev_rows)) * 100.0)
            if pkg_scores:
                avg_pkg_compliance = round(sum(pkg_scores) / len(pkg_scores), 1)

        # --- Real suspicious_activities_detected ---
        # Count distinct actors who had the AuditLogger flag them in the
        # last 30 days. We reuse the engine's detection rather than
        # inventing a new heuristic here.
        suspicious_count = 0
        try:
            audit_logger = AuditLogger(db, org_id)
            # Take distinct actors who have written audit events and
            # check each one. Cap at 25 actors to bound the work.
            actor_ids = list({a.actor_id for a in audit_list if a.actor_id})[:25]
            for actor_id in actor_ids:
                activities = await audit_logger.detect_suspicious_activity(actor_id)
                if activities:
                    suspicious_count += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"suspicious activity detection failed: {exc}")

        return AuditDashboardStats(
            organization_id=org_id or "",
            total_audit_entries=len(audit_list),
            audit_entries_this_month=month_audits,
            event_types_breakdown=event_types_breakdown,
            risk_distribution=risk_distribution,
            total_evidence_packages=len(pkg_list),
            evidence_packages_in_progress=pkg_in_progress,
            evidence_packages_submitted=pkg_submitted,
            avg_evidence_package_compliance=avg_pkg_compliance,
            suspicious_activities_detected=suspicious_count,
            critical_audit_events=len([a for a in audit_list if a.risk_level == "critical"]),
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Operation failed. Please try again or contact support.")
