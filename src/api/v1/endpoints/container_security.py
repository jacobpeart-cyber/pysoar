"""
Container Security REST API Endpoints

Complete API for managing container images, Kubernetes clusters,
security findings, runtime alerts, and compliance.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query
from src.api.deps import CurrentUser, DatabaseSession
from sqlalchemy import select, and_, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.api.deps import get_current_active_user as get_current_user
from src.core.database import get_db
from src.schemas.container_security import (
    ContainerImageResponse,
    ContainerImageCreateRequest,
    ContainerImageUpdateRequest,
    ImageVulnerabilityResponse,
    ImageVulnerabilityCreateRequest,
    KubernetesClusterResponse,
    KubernetesClusterCreateRequest,
    KubernetesClusterUpdateRequest,
    K8sSecurityFindingResponse,
    K8sSecurityFindingCreateRequest,
    K8sSecurityFindingUpdateRequest,
    RuntimeAlertResponse,
    RuntimeAlertCreateRequest,
    RuntimeAlertUpdateRequest,
    ImageScanRequest,
    ImageScanResponse,
    ClusterAuditRequest,
    ClusterAuditResponse,
    SecurityFindingRemediationRequest,
    SecurityFindingRemediationResponse,
    RuntimeAlertInvestigationRequest,
    PodQuarantineRequest,
    DashboardOverviewResponse,
    ComplianceMatrixResponse,
    ClusterComplianceResponse,
    PaginationParams,
)
from src.container_security.models import (
    ContainerImage,
    ImageVulnerability,
    KubernetesCluster,
    K8sSecurityFinding,
    RuntimeAlert,
)
from src.container_security.engine import (
    ImageScanner,
    K8sSecurityAuditor,
    RuntimeProtector,
    K8sRemediator,
    ComplianceChecker,
)
from src.container_security.tasks import (
    scheduled_image_scan,
    cluster_security_audit,
    runtime_monitoring,
    compliance_check,
    stale_image_report,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/container-security", tags=["container-security"])


# ============================================================================
# IMAGE ENDPOINTS
# ============================================================================


@router.get("/images", response_model=List[ContainerImageResponse])
async def list_images(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    compliance_status: Optional[str] = None,
    risk_score_min: Optional[int] = Query(None, ge=0, le=100),
    risk_score_max: Optional[int] = Query(None, ge=0, le=100),
):
    """
    List container images with optional filtering.

    Query Parameters:
    - compliance_status: Filter by compliance status
    - risk_score_min/max: Filter by risk score range
    - skip, limit: Pagination
    """
    stmt = select(ContainerImage).where(
        ContainerImage.organization_id == getattr(current_user, "organization_id", None)
    )

    if compliance_status:
        stmt = stmt.where(ContainerImage.compliance_status == compliance_status)

    if risk_score_min is not None:
        stmt = stmt.where(ContainerImage.risk_score >= risk_score_min)

    if risk_score_max is not None:
        stmt = stmt.where(ContainerImage.risk_score <= risk_score_max)

    stmt = stmt.order_by(desc(ContainerImage.risk_score)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    images = result.scalars().all()

    return images


@router.post("/images", response_model=ContainerImageResponse, status_code=201)
async def create_image(
    request: ContainerImageCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Create new container image record."""
    image = ContainerImage(
        registry=request.registry,
        repository=request.repository,
        tag=request.tag,
        digest_sha256=request.digest_sha256,
        image_size_mb=request.image_size_mb,
        os=request.os,
        architecture=request.architecture,
        base_image=request.base_image,
        labels=request.labels or {},
        compliance_status="not_scanned",
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(image)
    await db.commit()
    await db.refresh(image)

    logger.info(f"Created image {image.id}")
    return image


@router.get("/images/{image_id}", response_model=ContainerImageResponse)
async def get_image(
    image_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get image details."""
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    return image


@router.patch("/images/{image_id}", response_model=ContainerImageResponse)
async def update_image(
    image_id: str,
    request: ContainerImageUpdateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update image metadata."""
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    if request.labels is not None:
        image.labels = request.labels
    if request.base_image is not None:
        image.base_image = request.base_image
    if request.sbom_generated is not None:
        image.sbom_generated = request.sbom_generated

    await db.commit()
    await db.refresh(image)

    return image


@router.post("/images/{image_id}/scan", response_model=ImageScanResponse)
async def scan_image(
    image_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Trigger image vulnerability scan.

    Runs the scanner against the known CVE catalog and any existing DB
    vulnerability records, then updates the image's vuln counts and risk score.
    """
    org_id = getattr(current_user, "organization_id", None)
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == org_id,
        )
    )
    result = await db.execute(stmt)
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    # Run the actual scanner. If the scanner itself blows up, mark the scan
    # as failed on the row rather than pretending it succeeded.
    scanner = ImageScanner()
    try:
        scan_result = await scanner.scan_image(
            registry=image.registry or "docker.io",
            repository=image.repository or "",
            tag=image.tag or "latest",
            digest=image.digest_sha256 or "",
            db=db,
        )
    except Exception as scan_exc:
        logger.error(f"Image scan failed for {image_id}: {scan_exc}")
        image.scanned_at = datetime.now(timezone.utc)
        image.compliance_status = "scan_failed"
        await db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Image scan failed: {scan_exc}",
        )

    # Persist new vulnerabilities that aren't already in the DB (defense in depth)
    existing_stmt = select(ImageVulnerability.cve_id).where(
        and_(
            ImageVulnerability.image_id == image_id,
            ImageVulnerability.organization_id == org_id,
        )
    )
    existing_result = await db.execute(existing_stmt)
    existing_cves = {r[0] for r in existing_result.all()}

    for vuln in scan_result.get("vulnerabilities", []):
        if vuln["cve_id"] not in existing_cves:
            db.add(ImageVulnerability(
                image_id=image_id,
                cve_id=vuln["cve_id"],
                package_name=vuln.get("package", ""),
                package_version=vuln.get("version", ""),
                fixed_version=vuln.get("fixed_version"),
                severity=vuln.get("severity", "medium"),
                cvss_score=vuln.get("cvss", 0.0),
                exploit_available=vuln.get("exploit_available", False),
                description=vuln.get("description", ""),
                organization_id=org_id,
            ))

    # Recompute severity counts from the authoritative vuln list (scanner
    # returns same data, but this guards against any scanner bug where the
    # aggregate counters and the per-vuln list disagree).
    vulns_list = scan_result.get("vulnerabilities", [])
    critical_n = sum(1 for v in vulns_list if v.get("severity") == "critical")
    high_n = sum(1 for v in vulns_list if v.get("severity") == "high")
    medium_n = sum(1 for v in vulns_list if v.get("severity") == "medium")
    low_n = sum(1 for v in vulns_list if v.get("severity") == "low")

    # Persist counts onto the ACTUAL columns on ContainerImage (see
    # src/container_security/models.py). Previously these were being
    # assigned to `critical_count` / `high_count` / etc. which are not
    # mapped columns, so SQLAlchemy silently dropped them on commit and
    # the dashboard always read zeros.
    image.vulnerability_count_critical = critical_n
    image.vulnerability_count_high = high_n
    image.vulnerability_count_medium = medium_n
    image.vulnerability_count_low = low_n
    image.scanned_at = scan_result["scanned_at"]
    image.risk_score = scanner.calculate_image_risk_score(
        critical_n, high_n, medium_n,
        bool(image.is_signed), bool(image.sbom_generated),
    )
    image.compliance_status = (
        "compliant" if critical_n == 0 and high_n == 0
        else "non_compliant"
    )

    await db.commit()
    await db.refresh(image)

    # Trigger automation for each critical/high vulnerability found
    try:
        automation = AutomationService(db)
        image_name = f"{image.repository or ''}:{image.tag or 'latest'}"
        for vuln in scan_result.get("vulnerabilities", []):
            if vuln.get("severity") in ("critical", "high"):
                await automation.on_container_finding(
                    image_name=image_name,
                    finding_type=vuln.get("cve_id", "vulnerability"),
                    cve_id=vuln.get("cve_id", ""),
                    severity=vuln.get("severity", "medium"),
                    organization_id=org_id,
                )
    except Exception as e:
        logger.error(f"Automation failed for container scan {image_id}: {e}")

    logger.info(
        f"Scan complete for image {image_id}: "
        f"{scan_result['total_vulnerabilities']} vulns, risk={image.risk_score}"
    )

    return ImageScanResponse(
        status="completed",
        image_id=image_id,
        vulnerabilities=scan_result["total_vulnerabilities"],
        risk_score=image.risk_score,
        compliance_status=image.compliance_status,
    )


@router.get("/images/{image_id}/vulnerabilities", response_model=List[ImageVulnerabilityResponse])
async def get_image_vulnerabilities(
    image_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Get vulnerabilities for image."""
    # Verify image ownership
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Image not found")

    # Get vulnerabilities
    stmt = select(ImageVulnerability).where(ImageVulnerability.image_id == image_id)

    if severity:
        stmt = stmt.where(ImageVulnerability.severity == severity)

    stmt = stmt.order_by(desc(ImageVulnerability.cvss_score)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    vulnerabilities = result.scalars().all()

    return vulnerabilities


@router.post("/images/{image_id}/verify-signature")
async def verify_image_signature(
    image_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Verify image signature (cosign/notary).

    Validates image signature and updates verification status.
    """
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    scanner = ImageScanner()
    verification = await scanner.verify_image_signature(
        image.registry, image.repository, image.tag
    )

    image.is_signed = verification["is_signed"]
    image.signature_verified = verification["signature_verified"]

    await db.commit()

    return verification


@router.get("/images/{image_id}/risk-assessment")
async def assess_image_risk(
    image_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get image risk assessment."""
    stmt = select(ContainerImage).where(
        and_(
            ContainerImage.id == image_id,
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    image = result.scalar_one_or_none()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found")

    return {
        "image_id": image_id,
        "risk_score": image.risk_score,
        "compliance_status": image.compliance_status,
        "vulnerability_critical": image.vulnerability_count_critical,
        "vulnerability_high": image.vulnerability_count_high,
        "is_signed": image.is_signed,
        "signature_verified": image.signature_verified,
        "days_since_scan": (
            (datetime.utcnow() - image.scanned_at).days if image.scanned_at else None
        ),
        "recommendation": (
            "High risk - remediate immediately"
            if image.risk_score >= 80
            else "Medium risk - plan remediation"
            if image.risk_score >= 50
            else "Low risk - acceptable"
        ),
    }


# ============================================================================
# CLUSTER ENDPOINTS
# ============================================================================


@router.get("/clusters", response_model=List[KubernetesClusterResponse])
async def list_clusters(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    provider: Optional[str] = None,
):
    """List Kubernetes clusters."""
    stmt = select(KubernetesCluster).where(
        KubernetesCluster.organization_id == getattr(current_user, "organization_id", None)
    )

    if provider:
        stmt = stmt.where(KubernetesCluster.provider == provider)

    stmt = stmt.order_by(desc(KubernetesCluster.risk_score)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    clusters = result.scalars().all()

    return clusters


@router.post("/clusters", response_model=KubernetesClusterResponse, status_code=201)
async def create_cluster(
    request: KubernetesClusterCreateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Create Kubernetes cluster record."""
    cluster = KubernetesCluster(
        name=request.name,
        version=request.version,
        provider=request.provider,
        endpoint=request.endpoint,
        pod_security_standards=request.pod_security_standards,
        admission_controllers=request.admission_controllers or {},
        organization_id=getattr(current_user, "organization_id", None),
    )
    db.add(cluster)
    await db.commit()
    await db.refresh(cluster)

    logger.info(f"Created cluster {cluster.id}")
    return cluster


@router.get("/clusters/{cluster_id}", response_model=KubernetesClusterResponse)
async def get_cluster(
    cluster_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get cluster details."""
    stmt = select(KubernetesCluster).where(
        and_(
            KubernetesCluster.id == cluster_id,
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    return cluster


@router.patch("/clusters/{cluster_id}", response_model=KubernetesClusterResponse)
async def update_cluster(
    cluster_id: str,
    request: KubernetesClusterUpdateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update cluster configuration."""
    stmt = select(KubernetesCluster).where(
        and_(
            KubernetesCluster.id == cluster_id,
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    for field, value in request.dict(exclude_unset=True).items():
        setattr(cluster, field, value)

    await db.commit()
    await db.refresh(cluster)

    return cluster


@router.post("/clusters/{cluster_id}/audit", response_model=ClusterAuditResponse)
async def audit_cluster(
    cluster_id: str,
    request: ClusterAuditRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Trigger cluster security audit.

    Performs full security audit including CIS benchmarks, RBAC, network policies.
    """
    stmt = select(KubernetesCluster).where(
        and_(
            KubernetesCluster.id == cluster_id,
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Run the actual auditor
    auditor = K8sSecurityAuditor()
    audit_result = await auditor.audit_cluster_config(cluster)
    cis_result = await auditor.check_cis_k8s_benchmark(cluster)

    # Persist new findings to DB. Cluster-level findings (RBAC,
    # encryption-at-rest, CIS benchmark misses) store namespace=NULL —
    # the column is nullable specifically for these.
    org_id = getattr(current_user, "organization_id", None)
    for finding in audit_result.get("findings", []):
        db.add(K8sSecurityFinding(
            cluster_id=cluster_id,
            finding_type=finding["type"],
            severity=finding["severity"],
            description=finding.get("message", ""),
            namespace=finding.get("namespace"),
            resource_type=finding.get("resource_type") or "cluster",
            resource_name=finding.get("resource_name") or finding.get("resource") or cluster.name,
            status="open",
            detected_at=datetime.now(timezone.utc),
            organization_id=org_id,
        ))

    # Update cluster scores
    cluster.compliance_score = int(cis_result.get("compliance_percentage", 0))
    findings_count = audit_result.get("findings_count", 0)
    cluster.risk_score = min(100, findings_count * 15)
    cluster.last_audit = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(cluster)

    logger.info(
        f"Audit complete for cluster {cluster_id}: "
        f"{findings_count} findings, CIS {cis_result['compliance_percentage']}%"
    )

    return ClusterAuditResponse(
        status="completed",
        cluster_id=cluster_id,
        findings=findings_count,
        risk_score=cluster.risk_score,
        compliance_score=cluster.compliance_score,
        cis_compliance=cis_result["compliance_percentage"],
    )


@router.get("/clusters/{cluster_id}/compliance-check")
async def check_cluster_compliance(
    cluster_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get cluster compliance status."""
    stmt = select(KubernetesCluster).where(
        and_(
            KubernetesCluster.id == cluster_id,
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Run compliance checks
    checker = ComplianceChecker()
    matrix = await checker.generate_compliance_matrix(cluster)

    # Update cluster compliance score
    cluster.compliance_score = matrix.get("overall_compliance", 0)
    await db.commit()

    return {
        "status": "completed",
        "cluster_id": cluster_id,
        "compliance_score": cluster.compliance_score,
        "frameworks": matrix.get("frameworks", {}),
    }


@router.get("/clusters/{cluster_id}/findings", response_model=List[K8sSecurityFindingResponse])
async def get_cluster_findings(
    cluster_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Get security findings for cluster."""
    # Verify cluster ownership
    stmt = select(KubernetesCluster).where(
        and_(
            KubernetesCluster.id == cluster_id,
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Get findings
    stmt = select(K8sSecurityFinding).where(
        K8sSecurityFinding.cluster_id == cluster_id
    )

    if status:
        stmt = stmt.where(K8sSecurityFinding.status == status)

    if severity:
        stmt = stmt.where(K8sSecurityFinding.severity == severity)

    stmt = stmt.order_by(desc(K8sSecurityFinding.detected_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    findings = result.scalars().all()

    return findings


# ============================================================================
# SECURITY FINDINGS ENDPOINTS
# ============================================================================


@router.get("/findings", response_model=List[K8sSecurityFindingResponse])
async def list_findings(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """List security findings across clusters."""
    stmt = select(K8sSecurityFinding).where(
        K8sSecurityFinding.organization_id == getattr(current_user, "organization_id", None)
    )

    if status:
        stmt = stmt.where(K8sSecurityFinding.status == status)

    if severity:
        stmt = stmt.where(K8sSecurityFinding.severity == severity)

    stmt = stmt.order_by(desc(K8sSecurityFinding.detected_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    findings = result.scalars().all()

    return findings


@router.post("/findings/{finding_id}/remediate", response_model=SecurityFindingRemediationResponse)
async def remediate_finding(
    finding_id: str,
    request: SecurityFindingRemediationRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Generate and apply remediation for finding.

    Creates YAML manifest for remediation.
    """
    stmt = select(K8sSecurityFinding).where(
        and_(
            K8sSecurityFinding.id == finding_id,
            K8sSecurityFinding.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    remediator = K8sRemediator()
    manifest = await remediator.generate_remediation_manifest(
        finding.finding_type,
        finding.namespace,
        finding.resource_type,
        finding.resource_name,
    )

    finding.status = "remediated"
    await db.commit()

    logger.info(f"Generated remediation for finding {finding_id}")

    return SecurityFindingRemediationResponse(
        status="success",
        finding_id=finding_id,
        manifest=manifest,
        description=f"Remediation for {finding.finding_type}",
    )


@router.patch("/findings/{finding_id}", response_model=K8sSecurityFindingResponse)
async def update_finding(
    finding_id: str,
    request: K8sSecurityFindingUpdateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update finding status."""
    stmt = select(K8sSecurityFinding).where(
        and_(
            K8sSecurityFinding.id == finding_id,
            K8sSecurityFinding.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if request.status:
        finding.status = request.status
    if request.remediation:
        finding.remediation = request.remediation

    await db.commit()
    await db.refresh(finding)

    return finding


# ============================================================================
# RUNTIME ALERTS ENDPOINTS
# ============================================================================


@router.get("/runtime-alerts", response_model=List[RuntimeAlertResponse])
async def list_runtime_alerts(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """List runtime security alerts."""
    stmt = select(RuntimeAlert).where(
        RuntimeAlert.organization_id == getattr(current_user, "organization_id", None)
    )

    if status:
        stmt = stmt.where(RuntimeAlert.status == status)

    if severity:
        stmt = stmt.where(RuntimeAlert.severity == severity)

    stmt = stmt.order_by(desc(RuntimeAlert.created_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return alerts


@router.patch("/runtime-alerts/{alert_id}", response_model=RuntimeAlertResponse)
async def update_runtime_alert(
    alert_id: str,
    request: RuntimeAlertUpdateRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update runtime alert status."""
    stmt = select(RuntimeAlert).where(
        and_(
            RuntimeAlert.id == alert_id,
            RuntimeAlert.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if request.status:
        alert.status = request.status
    if request.mitre_technique:
        alert.mitre_technique = request.mitre_technique

    await db.commit()
    await db.refresh(alert)

    return alert


@router.post("/runtime-alerts/{alert_id}/investigate")
async def investigate_alert(
    alert_id: str,
    request: RuntimeAlertInvestigationRequest,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Investigate runtime alert."""
    stmt = select(RuntimeAlert).where(
        and_(
            RuntimeAlert.id == alert_id,
            RuntimeAlert.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "investigating"
    await db.commit()

    logger.info(f"Investigating alert {alert_id}")

    return {
        "status": "investigating",
        "alert_id": alert_id,
        "timestamp": datetime.utcnow(),
    }


@router.post("/runtime-alerts/{alert_id}/quarantine-pod")
async def quarantine_pod_from_alert(
    alert_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Quarantine pod from runtime alert."""
    stmt = select(RuntimeAlert).where(
        and_(
            RuntimeAlert.id == alert_id,
            RuntimeAlert.organization_id == getattr(current_user, "organization_id", None),
        )
    )
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    protector = RuntimeProtector()
    quarantine = await protector.quarantine_pod(
        alert.namespace, alert.pod_name, alert.description
    )

    alert.status = "contained"
    await db.commit()

    logger.info(f"Quarantined pod from alert {alert_id}")

    return quarantine


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================


@router.get("/dashboard/overview", response_model=DashboardOverviewResponse)
async def get_dashboard_overview(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """
    Get container security dashboard overview.

    Returns summary of images, clusters, vulnerabilities, and alerts.
    """
    # Count images
    img_stmt = select(func.count(ContainerImage.id)).where(
        ContainerImage.organization_id == getattr(current_user, "organization_id", None)
    )
    img_result = await db.execute(img_stmt)
    total_images = img_result.scalar() or 0

    # Count clusters
    cls_stmt = select(func.count(KubernetesCluster.id)).where(
        KubernetesCluster.organization_id == getattr(current_user, "organization_id", None)
    )
    cls_result = await db.execute(cls_stmt)
    total_clusters = cls_result.scalar() or 0

    # Count vulnerabilities by severity
    vuln_stmt = select(ImageVulnerability).where(
        ImageVulnerability.organization_id == getattr(current_user, "organization_id", None)
    )
    vuln_result = await db.execute(vuln_stmt)
    vulns = vuln_result.scalars().all()

    vuln_counts = {
        "critical": sum(1 for v in vulns if v.severity == "critical"),
        "high": sum(1 for v in vulns if v.severity == "high"),
        "medium": sum(1 for v in vulns if v.severity == "medium"),
        "low": sum(1 for v in vulns if v.severity == "low"),
        "negligible": sum(1 for v in vulns if v.severity == "negligible"),
    }

    # Count critical findings
    finding_stmt = select(func.count(K8sSecurityFinding.id)).where(
        and_(
            K8sSecurityFinding.organization_id == getattr(current_user, "organization_id", None),
            K8sSecurityFinding.severity == "critical",
        )
    )
    finding_result = await db.execute(finding_stmt)
    critical_findings = finding_result.scalar() or 0

    # Count all open findings (status == "open")
    open_stmt = select(func.count(K8sSecurityFinding.id)).where(
        and_(
            K8sSecurityFinding.organization_id == getattr(current_user, "organization_id", None),
            K8sSecurityFinding.status == "open",
        )
    )
    open_result = await db.execute(open_stmt)
    open_findings = open_result.scalar() or 0

    # Count new alerts
    alert_stmt = select(func.count(RuntimeAlert.id)).where(
        and_(
            RuntimeAlert.organization_id == getattr(current_user, "organization_id", None),
            RuntimeAlert.status == "new",
        )
    )
    alert_result = await db.execute(alert_stmt)
    new_alerts = alert_result.scalar() or 0

    # Count all active (not-resolved) runtime alerts
    active_alert_stmt = select(func.count(RuntimeAlert.id)).where(
        and_(
            RuntimeAlert.organization_id == getattr(current_user, "organization_id", None),
            RuntimeAlert.status.notin_(["resolved", "false_positive"]),
        )
    )
    active_alert_result = await db.execute(active_alert_stmt)
    active_alerts = active_alert_result.scalar() or 0

    # High risk images
    high_risk_stmt = select(func.count(ContainerImage.id)).where(
        and_(
            ContainerImage.organization_id == getattr(current_user, "organization_id", None),
            ContainerImage.risk_score >= 80,
        )
    )
    high_risk_result = await db.execute(high_risk_stmt)
    high_risk_images = high_risk_result.scalar() or 0

    # Non-compliant clusters
    non_compliant_stmt = select(func.count(KubernetesCluster.id)).where(
        and_(
            KubernetesCluster.organization_id == getattr(current_user, "organization_id", None),
            KubernetesCluster.compliance_score < 60,
        )
    )
    non_compliant_result = await db.execute(non_compliant_stmt)
    non_compliant_clusters = non_compliant_result.scalar() or 0

    # Top vulnerabilities (by severity, newest)
    top_vulns_stmt = (
        select(ImageVulnerability)
        .where(
            and_(
                ImageVulnerability.organization_id == getattr(current_user, "organization_id", None),
                ImageVulnerability.severity.in_(["critical", "high"]),
            )
        )
        .order_by(ImageVulnerability.created_at.desc())
        .limit(10)
    )
    top_vulns_result = await db.execute(top_vulns_stmt)
    top_vulnerabilities = [
        {
            "cve_id": getattr(v, "cve_id", None),
            "severity": v.severity,
            "package_name": getattr(v, "package_name", None),
            "image_id": getattr(v, "image_id", None),
            "cvss_score": getattr(v, "cvss_score", None),
        }
        for v in top_vulns_result.scalars().all()
    ]

    # Cluster compliance summary with REAL findings counts per cluster
    org_id = getattr(current_user, "organization_id", None)
    cluster_list_stmt = select(KubernetesCluster).where(
        KubernetesCluster.organization_id == org_id
    )
    cluster_list_result = await db.execute(cluster_list_stmt)
    clusters = list(cluster_list_result.scalars().all())

    # Fetch findings counts for all clusters in a single grouped query
    findings_by_cluster: dict = {}
    if clusters:
        findings_count_result = await db.execute(
            select(
                K8sSecurityFinding.cluster_id,
                func.count(K8sSecurityFinding.id),
            )
            .where(
                and_(
                    K8sSecurityFinding.organization_id == org_id,
                    K8sSecurityFinding.cluster_id.in_([c.id for c in clusters]),
                    K8sSecurityFinding.status == "open",
                )
            )
            .group_by(K8sSecurityFinding.cluster_id)
        )
        for cluster_id, count in findings_count_result.all():
            findings_by_cluster[cluster_id] = count

    cluster_compliance = []
    for c in clusters:
        score = getattr(c, "compliance_score", 0) or 0
        cluster_compliance.append(
            ClusterComplianceResponse(
                cluster_name=c.name,
                compliance_score=int(score),
                findings_count=findings_by_cluster.get(c.id, 0),
                status="compliant" if score >= 80 else ("non_compliant" if score < 60 else "partial"),
            )
        )

    return DashboardOverviewResponse(
        total_images=total_images,
        total_clusters=total_clusters,
        total_vulnerabilities=vuln_counts,
        critical_findings=critical_findings,
        runtime_alerts_new=new_alerts,
        high_risk_images=high_risk_images,
        non_compliant_clusters=non_compliant_clusters,
        open_findings=open_findings,
        active_alerts=active_alerts,
        critical_vulnerabilities=vuln_counts["critical"],
        high_vulnerabilities=vuln_counts["high"],
        top_vulnerabilities=top_vulnerabilities,
        cluster_compliance=cluster_compliance,
        runtime_alert_trends=[],
    )


@router.get("/dashboard/compliance-matrix", response_model=List[ComplianceMatrixResponse])
async def get_compliance_matrix(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get compliance matrix across frameworks."""
    stmt = select(KubernetesCluster).where(
        KubernetesCluster.organization_id == getattr(current_user, "organization_id", None)
    )
    result = await db.execute(stmt)
    clusters = result.scalars().all()

    checker = ComplianceChecker()
    matrices = []

    for cluster in clusters:
        nsa_cisa = await checker.check_nsa_cisa_hardening(cluster)
        dod_stig = await checker.check_dod_stig(cluster)
        soc2 = await checker.check_soc2_controls(cluster)

        matrices.append(
            ComplianceMatrixResponse(
                cluster_name=cluster.name,
                nsa_cisa_score=nsa_cisa["compliance_score"],
                dod_stig_score=dod_stig["compliance_score"],
                soc2_score=soc2["compliance_score"],
                overall_compliance=int(
                    (
                        nsa_cisa["compliance_score"]
                        + dod_stig["compliance_score"]
                        + soc2["compliance_score"]
                    )
                    / 3
                ),
                timestamp=datetime.utcnow(),
            )
        )

    return matrices
