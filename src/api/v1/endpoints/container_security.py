"""
Container Security REST API Endpoints

Container images, Kubernetes clusters, CIS findings, runtime alerts and
compliance, all scoped to the caller's organisation.

Wave 4 (W4-B):
- Images and clusters can be registered (``POST /images``, ``POST /clusters``)
  and deleted; cluster names are unique per organisation.
- ``POST /images/{id}/scan`` scans through an installed scanner integration
  (Trivy / Grype / Anchore) or a ``scan_container_image`` endpoint-agent
  command, or reports ``awaiting_integration`` without touching counts, scores
  or compliance (src/container_security/scanning.py).
- ``PUT /clusters/{id}/credential`` stores a kubeconfig / token encrypted;
  ``POST /clusters/{id}/audit`` then runs the CIS checks against the
  Kubernetes API through the pinned transport. Without a credential every
  check is ``not_assessed``; nothing is ever ``pass`` without API data
  (src/container_security/kube.py). Findings are deduplicated per
  (cluster, image, check).
- Compliance views read the stored CIS check results only.
"""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, delete, desc, func, select

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.container_security.engine import ImageScanner, K8sRemediator
from src.container_security.kube import (
    CIS_BENCHMARK,
    KubeCredentialError,
    normalise_credential,
    run_cis_audit,
    store_credential,
)
from src.container_security.models import (
    ContainerImage,
    ContainerImageScan,
    ImageVulnerability,
    K8sCheckResult,
    K8sSecurityFinding,
    KubernetesCluster,
    RuntimeAlert,
)
from src.container_security.scanning import (
    PENDING_SCAN_STATES,
    SCAN_CAPABILITY,
    reconcile_scan,
    request_scan,
    scan_agents,
    scanner_integrations,
)
from src.core.logging import get_logger
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.schemas.container_security import (
    ClusterAuditRequest,
    ClusterAuditResponse,
    ClusterComplianceResponse,
    ClusterCredentialRequest,
    ComplianceMatrixResponse,
    ContainerImageCreateRequest,
    ContainerImageResponse,
    ContainerImageUpdateRequest,
    DashboardOverviewResponse,
    ImageScanRecordResponse,
    ImageScanResponse,
    ImageVulnerabilityResponse,
    K8sCheckResultResponse,
    K8sSecurityFindingResponse,
    K8sSecurityFindingUpdateRequest,
    KubernetesClusterCreateRequest,
    KubernetesClusterResponse,
    KubernetesClusterUpdateRequest,
    RuntimeAlertInvestigationRequest,
    RuntimeAlertResponse,
    RuntimeAlertUpdateRequest,
    ScannerAvailabilityResponse,
    SecurityFindingRemediationRequest,
    SecurityFindingRemediationResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/container-security", tags=["container-security"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _days_since(moment: Optional[datetime]) -> Optional[int]:
    """Whole days between ``moment`` and now, tolerating naive timestamps.

    Postgres returns tz-aware values for ``timestamptz`` columns while SQLite
    returns naive ones; subtracting a naive ``utcnow()`` from an aware value
    raised TypeError (500). Naive values are treated as UTC.
    """
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - moment).days


async def _audit(
    db: DatabaseSession,
    user: Optional[User],
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    description: str,
    payload: Dict[str, Any],
    success: bool = True,
    error: Optional[str] = None,
) -> None:
    """One AuditLog row per container-security action."""
    import json as _json

    db.add(AuditLog(
        user_id=str(user.id) if user is not None else None,
        organization_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description[:4000],
        new_value=_json.dumps(payload, default=str),
        success=success,
        error_message=error,
    ))
    await db.flush()


async def _image_or_404(db: DatabaseSession, image_id: str, org_id: str) -> ContainerImage:
    image = (await db.execute(
        select(ContainerImage).where(
            ContainerImage.id == image_id, ContainerImage.organization_id == org_id,
        ),
    )).scalar_one_or_none()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")
    return image


async def _cluster_or_404(db: DatabaseSession, cluster_id: str, org_id: str) -> KubernetesCluster:
    cluster = (await db.execute(
        select(KubernetesCluster).where(
            KubernetesCluster.id == cluster_id, KubernetesCluster.organization_id == org_id,
        ),
    )).scalar_one_or_none()
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


# ============================================================================
# IMAGE ENDPOINTS
# ============================================================================


@router.get("/images", response_model=List[ContainerImageResponse])
async def list_images(
    org_id: OrganizationId,
    db: DatabaseSession = None,
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
        ContainerImage.organization_id == org_id
    )

    if compliance_status:
        stmt = stmt.where(ContainerImage.compliance_status == compliance_status)

    if risk_score_min is not None:
        stmt = stmt.where(ContainerImage.risk_score >= risk_score_min)

    if risk_score_max is not None:
        stmt = stmt.where(ContainerImage.risk_score <= risk_score_max)

    stmt = stmt.order_by(desc(ContainerImage.risk_score), ContainerImage.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/images", response_model=ContainerImageResponse, status_code=201)
async def create_image(
    request: ContainerImageCreateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Register a container image (registry/repository:tag, optional digest).

    The image starts ``not_scanned`` with no scan date; counts, risk and
    compliance change only when a real scanner reports. 409 when the same
    registry/repository:tag is already registered in this organisation.
    """
    dup = (await db.execute(
        select(ContainerImage.id).where(
            ContainerImage.organization_id == org_id,
            ContainerImage.registry == request.registry,
            ContainerImage.repository == request.repository,
            ContainerImage.tag == request.tag,
        ),
    )).first()
    if dup:
        raise HTTPException(
            status_code=409,
            detail={"error": "image_exists", "image_id": dup[0],
                    "detail": "This registry/repository:tag is already registered."},
        )
    image = ContainerImage(
        registry=request.registry,
        repository=request.repository,
        tag=request.tag,
        digest_sha256=request.digest_sha256 or "",
        image_size_mb=request.image_size_mb,
        os=request.os,
        architecture=request.architecture,
        base_image=request.base_image,
        labels=request.labels or {},
        compliance_status="not_scanned",
        scan_status="not_scanned",
        scanned_at=None,
        organization_id=org_id,
    )
    db.add(image)
    await db.flush()
    await _audit(db, _user, org_id, "container_image_registered", "container_image", image.id,
                 f"registered {request.registry}/{request.repository}:{request.tag}",
                 {"registry": request.registry, "repository": request.repository, "tag": request.tag})
    await db.commit()
    await db.refresh(image)
    logger.info("container_image_registered", image_id=image.id)
    return image


@router.get("/images/{image_id}", response_model=ContainerImageResponse)
async def get_image(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get image details (a pending agent scan is reconciled first)."""
    image = await _image_or_404(db, image_id, org_id)
    if image.last_scan_id and image.scan_status in PENDING_SCAN_STATES:
        scan = (await db.execute(
            select(ContainerImageScan).where(
                ContainerImageScan.id == image.last_scan_id,
                ContainerImageScan.organization_id == org_id,
            ),
        )).scalar_one_or_none()
        if scan is not None and await reconcile_scan(db, scan):
            await db.commit()
            await db.refresh(image)
    return image


@router.patch("/images/{image_id}", response_model=ContainerImageResponse)
async def update_image(
    image_id: str,
    request: ContainerImageUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update image metadata."""
    image = await _image_or_404(db, image_id, org_id)

    if request.labels is not None:
        image.labels = request.labels
    if request.base_image is not None:
        image.base_image = request.base_image
    if request.sbom_generated is not None:
        image.sbom_generated = request.sbom_generated

    await db.commit()
    await db.refresh(image)

    return image


@router.delete("/images/{image_id}", status_code=204)
async def delete_image(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Delete an image with its vulnerabilities and scan history."""
    image = await _image_or_404(db, image_id, org_id)
    await db.execute(delete(ImageVulnerability).where(
        ImageVulnerability.image_id == image.id, ImageVulnerability.organization_id == org_id,
    ))
    await db.execute(delete(ContainerImageScan).where(
        ContainerImageScan.image_id == image.id, ContainerImageScan.organization_id == org_id,
    ))
    await _audit(db, _user, org_id, "container_image_deleted", "container_image", image.id,
                 f"deleted {image.registry}/{image.repository}:{image.tag}", {})
    await db.delete(image)
    await db.commit()


@router.get("/scanners", response_model=ScannerAvailabilityResponse)
async def get_scanner_availability(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """The real scan paths available to this organisation (integrations, agents)."""
    integrations = await scanner_integrations(db, org_id)
    agents = await scan_agents(db, org_id)
    available = bool(integrations or agents)
    return ScannerAvailabilityResponse(
        status="available" if available else "awaiting_integration",
        integrations=[
            {"id": i.id, "display_name": i.display_name,
             "connector": (i.connector.name if i.connector is not None else None)}
            for i in integrations
        ],
        agents=[{"id": a.id, "hostname": a.hostname} for a in agents],
        reason=None if available else (
            "No image scanner: install an active Trivy, Grype or Anchore integration, or enrol an "
            f"endpoint agent with the '{SCAN_CAPABILITY}' capability."
        ),
    )


@router.post("/images/{image_id}/scan", response_model=ImageScanResponse)
async def scan_image(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
    agent_id: Optional[str] = Query(None, description="Scan on this container_scan agent"),
    scanner: str = Query("trivy", pattern="^(trivy|grype)$", description="Scanner the agent runs"),
):
    """Scan an image through a real scanner.

    Order: an installed scanner integration (answers synchronously:
    ``completed`` / ``failed``), else an endpoint agent with the
    ``container_scan`` capability (``pending`` / ``awaiting_approval``; the
    result is applied when the agent reports), else ``awaiting_integration``
    with the reason. Without a scanner nothing changes on the image beyond
    its scan status.
    """
    image = await _image_or_404(db, image_id, org_id)
    outcome = await request_scan(
        db, image, requested_by=str(_user.id) if _user is not None else None,
        agent_id=agent_id, scanner=scanner,
    )
    await _audit(
        db, _user, org_id, "container_image_scan", "container_image", image.id,
        f"image scan: {outcome.status}", {"status": outcome.status, "method": outcome.method,
                                          "scan_id": outcome.scan.id if outcome.scan else None,
                                          "detail": outcome.detail},
        success=outcome.status not in ("failed",),
        error=outcome.detail if outcome.status == "failed" else None,
    )
    await db.commit()
    await db.refresh(image)
    return ImageScanResponse(
        status=outcome.status,
        image_id=image_id,
        vulnerabilities=(outcome.scan.vulnerabilities_total if outcome.scan else 0),
        risk_score=image.risk_score or 0,
        compliance_status=image.compliance_status or "not_scanned",
        detail=outcome.detail,
        scan_id=outcome.scan.id if outcome.scan else None,
        method=outcome.method,
        scan_status=image.scan_status,
    )


@router.get("/images/{image_id}/scans", response_model=List[ImageScanRecordResponse])
async def list_image_scans(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    """Scan history of an image, newest first (pending agent scans reconciled)."""
    await _image_or_404(db, image_id, org_id)
    scans = list((await db.execute(
        select(ContainerImageScan).where(
            ContainerImageScan.image_id == image_id,
            ContainerImageScan.organization_id == org_id,
        ).order_by(desc(ContainerImageScan.created_at)).offset(skip).limit(limit),
    )).scalars())
    changed = False
    for scan in scans:
        if scan.status in PENDING_SCAN_STATES:
            changed = await reconcile_scan(db, scan) or changed
    if changed:
        await db.commit()
    return scans


@router.get("/scans/{scan_id}", response_model=ImageScanRecordResponse)
async def get_image_scan(
    scan_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """One scan (a pending agent scan is reconciled first)."""
    scan = (await db.execute(
        select(ContainerImageScan).where(
            ContainerImageScan.id == scan_id, ContainerImageScan.organization_id == org_id,
        ),
    )).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if await reconcile_scan(db, scan):
        await db.commit()
        await db.refresh(scan)
    return scan


@router.get("/images/{image_id}/vulnerabilities", response_model=List[ImageVulnerabilityResponse])
async def get_image_vulnerabilities(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Get vulnerabilities for image."""
    await _image_or_404(db, image_id, org_id)

    stmt = select(ImageVulnerability).where(
        ImageVulnerability.image_id == image_id,
        ImageVulnerability.organization_id == org_id,
    )

    if severity:
        stmt = stmt.where(ImageVulnerability.severity == severity)

    stmt = stmt.order_by(desc(ImageVulnerability.cvss_score), ImageVulnerability.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/images/{image_id}/verify-signature")
async def verify_image_signature(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """
    Report an image's signature state.

    No cosign/notary verifier is configured, so the signature is NOT checked:
    the response carries ``status: no_verifier_backend`` and repeats the
    recorded fields. The stored verification flags are left untouched.
    """
    image = await _image_or_404(db, image_id, org_id)

    scanner = ImageScanner()
    verification = await scanner.verify_image_signature(image)
    verification["image_id"] = image_id

    return verification


@router.get("/images/{image_id}/risk-assessment")
async def assess_image_risk(
    image_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get image risk assessment (only meaningful once a scanner reported)."""
    image = await _image_or_404(db, image_id, org_id)
    scanned = image.scan_status == "completed" and image.scanned_at is not None
    if not scanned:
        recommendation = "Not scanned: no scanner has reported on this image, so its risk is unknown"
    elif image.risk_score >= 80:
        recommendation = "High risk - remediate immediately"
    elif image.risk_score >= 50:
        recommendation = "Medium risk - plan remediation"
    else:
        recommendation = "Low risk - acceptable"

    return {
        "image_id": image_id,
        "risk_score": image.risk_score if scanned else None,
        "compliance_status": image.compliance_status,
        "scan_status": image.scan_status,
        "vulnerability_critical": image.vulnerability_count_critical,
        "vulnerability_high": image.vulnerability_count_high,
        "is_signed": image.is_signed,
        "signature_verified": image.signature_verified,
        "days_since_scan": _days_since(image.scanned_at),
        "recommendation": recommendation,
    }


# ============================================================================
# CLUSTER ENDPOINTS
# ============================================================================


@router.get("/clusters", response_model=List[KubernetesClusterResponse])
async def list_clusters(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    provider: Optional[str] = None,
):
    """List Kubernetes clusters."""
    stmt = select(KubernetesCluster).where(
        KubernetesCluster.organization_id == org_id
    )

    if provider:
        stmt = stmt.where(KubernetesCluster.provider == provider)

    stmt = stmt.order_by(desc(KubernetesCluster.risk_score), KubernetesCluster.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/clusters", response_model=KubernetesClusterResponse, status_code=201)
async def create_cluster(
    request: KubernetesClusterCreateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Register a Kubernetes cluster (name unique per organisation).

    The cluster starts ``not_assessed``; install a credential with
    ``PUT /clusters/{id}/credential`` and run ``POST /clusters/{id}/audit``.
    """
    dup = (await db.execute(
        select(KubernetesCluster.id).where(
            KubernetesCluster.organization_id == org_id, KubernetesCluster.name == request.name,
        ),
    )).first()
    if dup:
        raise HTTPException(
            status_code=409,
            detail={"error": "cluster_exists", "cluster_id": dup[0],
                    "detail": "A cluster with this name is already registered."},
        )
    cluster = KubernetesCluster(
        name=request.name,
        version=request.version,
        provider=request.provider,
        endpoint=request.endpoint,
        pod_security_standards=request.pod_security_standards,
        admission_controllers=request.admission_controllers or {},
        assessment_status="not_assessed",
        organization_id=org_id,
    )
    db.add(cluster)
    await db.flush()
    await _audit(db, _user, org_id, "k8s_cluster_registered", "kubernetes_cluster", cluster.id,
                 f"registered cluster {request.name}", {"name": request.name, "endpoint": request.endpoint})
    await db.commit()
    await db.refresh(cluster)
    logger.info("k8s_cluster_registered", cluster_id=cluster.id)
    return cluster


@router.get("/clusters/{cluster_id}", response_model=KubernetesClusterResponse)
async def get_cluster(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get cluster details."""
    return await _cluster_or_404(db, cluster_id, org_id)


@router.patch("/clusters/{cluster_id}", response_model=KubernetesClusterResponse)
async def update_cluster(
    cluster_id: str,
    request: KubernetesClusterUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Update the cluster's self-attested configuration.

    These booleans are recorded as given; they are not inputs to the CIS
    assessment, which reads the Kubernetes API.
    """
    cluster = await _cluster_or_404(db, cluster_id, org_id)

    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(cluster, field, value)

    await db.commit()
    await db.refresh(cluster)

    return cluster


@router.delete("/clusters/{cluster_id}", status_code=204)
async def delete_cluster(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Delete a cluster with its findings, check results, runtime alerts and credential."""
    cluster = await _cluster_or_404(db, cluster_id, org_id)
    for model in (K8sSecurityFinding, K8sCheckResult, RuntimeAlert):
        await db.execute(delete(model).where(
            model.cluster_id == cluster.id, model.organization_id == org_id,
        ))
    await _audit(db, _user, org_id, "k8s_cluster_deleted", "kubernetes_cluster", cluster.id,
                 f"deleted cluster {cluster.name}", {})
    await db.delete(cluster)
    await db.commit()


@router.put("/clusters/{cluster_id}/credential", response_model=KubernetesClusterResponse)
async def set_cluster_credential(
    cluster_id: str,
    request: ClusterCredentialRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Install the Kubernetes API credential (kubeconfig or bearer token).

    Stored encrypted (``enc:v1:``); never returned. A kubeconfig's server
    becomes the cluster endpoint. Supported user auth: token or inline client
    certificate; exec / auth-provider plugins and file references are refused
    (422 ``invalid_credential``).
    """
    cluster = await _cluster_or_404(db, cluster_id, org_id)
    try:
        ctype, cred = normalise_credential(
            kubeconfig=request.kubeconfig, token=request.token, ca_data=request.ca_data,
            context=request.context, endpoint=cluster.endpoint,
        )
    except KubeCredentialError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_credential", "detail": str(exc)},
        ) from exc
    store_credential(cluster, ctype, cred)
    cluster.assessment_status = "not_assessed"
    cluster.assessment_error = None
    await _audit(db, _user, org_id, "k8s_cluster_credential_set", "kubernetes_cluster", cluster.id,
                 f"stored {ctype} credential for cluster {cluster.name}",
                 {"credential_type": ctype, "server": cred["server"]})
    await db.commit()
    await db.refresh(cluster)
    return cluster


@router.delete("/clusters/{cluster_id}/credential", response_model=KubernetesClusterResponse)
async def delete_cluster_credential(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Remove the stored credential; the cluster can no longer be assessed."""
    cluster = await _cluster_or_404(db, cluster_id, org_id)
    cluster.credential_encrypted = None
    cluster.credential_type = None
    cluster.credential_set_at = None
    await _audit(db, _user, org_id, "k8s_cluster_credential_removed", "kubernetes_cluster", cluster.id,
                 f"removed credential of cluster {cluster.name}", {})
    await db.commit()
    await db.refresh(cluster)
    return cluster


@router.post("/clusters/{cluster_id}/audit", response_model=ClusterAuditResponse)
async def audit_cluster(
    cluster_id: str,
    request: ClusterAuditRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """
    Run the CIS Kubernetes checks against the cluster's Kubernetes API.

    ``status``: ``assessed`` (checks evaluated on API data), ``failed`` (the
    API could not be read; reason given) or ``not_assessed`` (no credential).
    Every check without API evidence is stored as ``not_assessed``, never as
    a pass. Findings are upserted per (cluster, image, check): a re-run never
    duplicates them, and an open finding whose check now passes is marked
    remediated.
    """
    cluster = await _cluster_or_404(db, cluster_id, org_id)
    summary = await run_cis_audit(db, cluster)
    open_findings = (await db.execute(
        select(func.count(K8sSecurityFinding.id)).where(
            K8sSecurityFinding.cluster_id == cluster.id,
            K8sSecurityFinding.organization_id == org_id,
            K8sSecurityFinding.status == "open",
        ),
    )).scalar() or 0
    await _audit(
        db, _user, org_id, "k8s_cluster_cis_audit", "kubernetes_cluster", cluster.id,
        f"CIS audit: {summary['assessment_status']}", summary,
        success=summary["assessment_status"] != "failed", error=summary["reason"],
    )
    await db.commit()
    await db.refresh(cluster)
    logger.info("k8s_cluster_cis_audit", cluster_id=cluster_id, status=summary["assessment_status"])
    return ClusterAuditResponse(
        status=summary["assessment_status"],
        cluster_id=cluster_id,
        findings=open_findings,
        risk_score=cluster.risk_score or 0,
        compliance_score=cluster.compliance_score or 0,
        cis_compliance=summary["cis_compliance"],
        compliance_status=cluster.compliance_status,
        reason=summary["reason"],
        checks=summary["checks"],
        findings_new=summary["findings_new"],
        findings_updated=summary["findings_updated"],
        findings_resolved=summary["findings_resolved"],
        benchmark=summary["benchmark"],
    )


async def _check_counts(db: DatabaseSession, org_id: str, cluster_ids: List[str]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {cid: {"pass": 0, "fail": 0, "not_assessed": 0} for cid in cluster_ids}
    if not cluster_ids:
        return out
    rows = await db.execute(
        select(K8sCheckResult.cluster_id, K8sCheckResult.status, func.count(K8sCheckResult.id))
        .where(K8sCheckResult.organization_id == org_id, K8sCheckResult.cluster_id.in_(cluster_ids))
        .group_by(K8sCheckResult.cluster_id, K8sCheckResult.status),
    )
    for cid, check_status, count in rows.all():
        out.setdefault(cid, {})[check_status] = count
    return out


def _cis_score(counts: Dict[str, int]) -> Optional[float]:
    assessed = counts.get("pass", 0) + counts.get("fail", 0)
    return round(counts.get("pass", 0) / assessed * 100, 1) if assessed else None


@router.get("/clusters/{cluster_id}/checks", response_model=List[K8sCheckResultResponse])
async def list_cluster_checks(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """Stored CIS check results of a cluster (pass / fail / not_assessed)."""
    await _cluster_or_404(db, cluster_id, org_id)
    stmt = select(K8sCheckResult).where(
        K8sCheckResult.cluster_id == cluster_id, K8sCheckResult.organization_id == org_id,
    )
    if status_filter:
        stmt = stmt.where(K8sCheckResult.status == status_filter)
    return (await db.execute(stmt.order_by(K8sCheckResult.check_id))).scalars().all()


@router.get("/clusters/{cluster_id}/compliance-check")
async def check_cluster_compliance(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Cluster compliance from the stored CIS check results (read only)."""
    cluster = await _cluster_or_404(db, cluster_id, org_id)
    counts = (await _check_counts(db, org_id, [cluster.id]))[cluster.id]
    score = _cis_score(counts)
    return {
        "status": cluster.compliance_status,
        "basis": "cis_checks_via_kubernetes_api",
        "benchmark": CIS_BENCHMARK,
        "cluster_id": cluster_id,
        "assessment_status": cluster.assessment_status,
        "assessment_error": cluster.assessment_error,
        "last_audit": cluster.last_audit,
        "compliance_score": score,
        "checks": counts,
        # No mapping from CIS results to these frameworks exists.
        "frameworks": {
            name: {"status": "not_assessed", "reason": "no control mapping from CIS Kubernetes checks"}
            for name in ("nsa_cisa", "dod_stig", "soc2")
        },
    }


@router.get("/clusters/{cluster_id}/findings", response_model=List[K8sSecurityFindingResponse])
async def get_cluster_findings(
    cluster_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Get security findings for cluster."""
    await _cluster_or_404(db, cluster_id, org_id)

    stmt = select(K8sSecurityFinding).where(
        K8sSecurityFinding.cluster_id == cluster_id,
        K8sSecurityFinding.organization_id == org_id,
    )

    if status_filter:
        stmt = stmt.where(K8sSecurityFinding.status == status_filter)

    if severity:
        stmt = stmt.where(K8sSecurityFinding.severity == severity)

    stmt = stmt.order_by(desc(K8sSecurityFinding.detected_at), K8sSecurityFinding.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


# ============================================================================
# SECURITY FINDINGS ENDPOINTS
# ============================================================================


@router.get("/findings", response_model=List[K8sSecurityFindingResponse])
async def list_findings(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """List security findings across clusters."""
    stmt = select(K8sSecurityFinding).where(
        K8sSecurityFinding.organization_id == org_id
    )

    if status_filter:
        stmt = stmt.where(K8sSecurityFinding.status == status_filter)

    if severity:
        stmt = stmt.where(K8sSecurityFinding.severity == severity)

    stmt = stmt.order_by(desc(K8sSecurityFinding.detected_at), K8sSecurityFinding.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/findings/{finding_id}/remediate", response_model=SecurityFindingRemediationResponse)
async def remediate_finding(
    finding_id: str,
    request: SecurityFindingRemediationRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """
    Generate a remediation manifest for a finding.

    The manifest is NOT applied (PySOAR only reads the Kubernetes API), so
    the finding stays in its current status and the response status is
    ``manifest_generated``. The next CIS audit marks the finding remediated
    once the check passes.
    """
    finding = (await db.execute(
        select(K8sSecurityFinding).where(
            and_(
                K8sSecurityFinding.id == finding_id,
                K8sSecurityFinding.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    remediator = K8sRemediator()
    manifest = await remediator.generate_remediation_manifest(
        finding.finding_type,
        finding.namespace,
        finding.resource_type,
        finding.resource_name,
    )

    logger.info("container_remediation_manifest_generated", finding_id=finding_id)

    return SecurityFindingRemediationResponse(
        status="manifest_generated",
        finding_id=finding_id,
        manifest=manifest,
        description=(
            f"Remediation manifest for {finding.finding_type}. Not applied: "
            "PySOAR has read-only Kubernetes access; apply it yourself and re-run "
            "the cluster audit (or mark the finding remediated)."
        ),
    )


@router.patch("/findings/{finding_id}", response_model=K8sSecurityFindingResponse)
async def update_finding(
    finding_id: str,
    request: K8sSecurityFindingUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update finding status."""
    finding = (await db.execute(
        select(K8sSecurityFinding).where(
            and_(
                K8sSecurityFinding.id == finding_id,
                K8sSecurityFinding.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()

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
    org_id: OrganizationId,
    db: DatabaseSession = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """List runtime security alerts (written only by a runtime sensor integration)."""
    stmt = select(RuntimeAlert).where(
        RuntimeAlert.organization_id == org_id
    )

    if status_filter:
        stmt = stmt.where(RuntimeAlert.status == status_filter)

    if severity:
        stmt = stmt.where(RuntimeAlert.severity == severity)

    stmt = stmt.order_by(desc(RuntimeAlert.created_at), RuntimeAlert.id).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.patch("/runtime-alerts/{alert_id}", response_model=RuntimeAlertResponse)
async def update_runtime_alert(
    alert_id: str,
    request: RuntimeAlertUpdateRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Update runtime alert status."""
    alert = (await db.execute(
        select(RuntimeAlert).where(
            and_(
                RuntimeAlert.id == alert_id,
                RuntimeAlert.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()

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
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AnalystUser = None,
):
    """Investigate runtime alert."""
    alert = (await db.execute(
        select(RuntimeAlert).where(
            and_(
                RuntimeAlert.id == alert_id,
                RuntimeAlert.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "investigating"
    await db.commit()

    logger.info("container_runtime_alert_investigating", alert_id=alert_id)

    return {
        "status": "investigating",
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc),
    }


@router.post("/runtime-alerts/{alert_id}/quarantine-pod")
async def quarantine_pod_from_alert(
    alert_id: str,
    org_id: OrganizationId,
    db: DatabaseSession = None,
    _user: AdminRoleUser = None,
):
    """Quarantine the pod named by a runtime alert: not implemented.

    PySOAR's Kubernetes access is read-only (CIS checks), so no NetworkPolicy
    can be applied. The previous version returned ``quarantined`` and marked
    the alert ``contained`` without touching the cluster. It returns 501 and
    leaves the alert unchanged.
    """
    alert = (await db.execute(
        select(RuntimeAlert).where(
            and_(
                RuntimeAlert.id == alert_id,
                RuntimeAlert.organization_id == org_id,
            )
        )
    )).scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    raise HTTPException(
        status_code=501,
        detail={
            "error": "not_implemented",
            "detail": (
                "Pod quarantine needs write access to the cluster, which PySOAR does "
                "not use (its Kubernetes access is read-only). No NetworkPolicy was "
                "applied and the alert status was not changed."
            ),
        },
    )


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================


async def _count(db: DatabaseSession, stmt: Any) -> int:
    return int((await db.execute(stmt)).scalar() or 0)


@router.get("/dashboard/overview", response_model=DashboardOverviewResponse)
async def get_dashboard_overview(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """
    Container security dashboard overview, from stored rows only.

    Cluster compliance is ``not_assessed`` until a CIS audit read the
    cluster's Kubernetes API; only assessed clusters count as non-compliant.
    """
    total_images = await _count(db, select(func.count(ContainerImage.id)).where(
        ContainerImage.organization_id == org_id))
    total_clusters = await _count(db, select(func.count(KubernetesCluster.id)).where(
        KubernetesCluster.organization_id == org_id))

    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    for sev, count in (await db.execute(
        select(ImageVulnerability.severity, func.count(ImageVulnerability.id))
        .where(ImageVulnerability.organization_id == org_id)
        .group_by(ImageVulnerability.severity),
    )).all():
        if sev in vuln_counts:
            vuln_counts[sev] = int(count)

    critical_findings = await _count(db, select(func.count(K8sSecurityFinding.id)).where(
        K8sSecurityFinding.organization_id == org_id,
        K8sSecurityFinding.severity == "critical",
        K8sSecurityFinding.status == "open",
    ))
    open_findings = await _count(db, select(func.count(K8sSecurityFinding.id)).where(
        K8sSecurityFinding.organization_id == org_id, K8sSecurityFinding.status == "open"))
    new_alerts = await _count(db, select(func.count(RuntimeAlert.id)).where(
        RuntimeAlert.organization_id == org_id, RuntimeAlert.status == "new"))
    active_alerts = await _count(db, select(func.count(RuntimeAlert.id)).where(
        RuntimeAlert.organization_id == org_id,
        RuntimeAlert.status.notin_(["resolved", "false_positive"]),
    ))
    high_risk_images = await _count(db, select(func.count(ContainerImage.id)).where(
        ContainerImage.organization_id == org_id,
        ContainerImage.scan_status == "completed",
        ContainerImage.risk_score >= 80,
    ))
    non_compliant_clusters = await _count(db, select(func.count(KubernetesCluster.id)).where(
        KubernetesCluster.organization_id == org_id,
        KubernetesCluster.assessment_status == "assessed",
        KubernetesCluster.compliance_score < 60,
    ))

    top_vulnerabilities = [
        {
            "cve_id": v.cve_id,
            "severity": v.severity,
            "package_name": v.package_name,
            "image_id": v.image_id,
            "cvss_score": v.cvss_score,
        }
        for v in (await db.execute(
            select(ImageVulnerability)
            .where(
                ImageVulnerability.organization_id == org_id,
                ImageVulnerability.severity.in_(["critical", "high"]),
            )
            .order_by(ImageVulnerability.created_at.desc())
            .limit(10)
        )).scalars().all()
    ]

    clusters = list((await db.execute(
        select(KubernetesCluster).where(KubernetesCluster.organization_id == org_id)
        .order_by(KubernetesCluster.name).limit(200),
    )).scalars().all())
    findings_by_cluster: Dict[str, int] = {}
    if clusters:
        for cid, count in (await db.execute(
            select(K8sSecurityFinding.cluster_id, func.count(K8sSecurityFinding.id))
            .where(
                K8sSecurityFinding.organization_id == org_id,
                K8sSecurityFinding.cluster_id.in_([c.id for c in clusters]),
                K8sSecurityFinding.status == "open",
            )
            .group_by(K8sSecurityFinding.cluster_id)
        )).all():
            findings_by_cluster[cid] = int(count)

    cluster_compliance = [
        ClusterComplianceResponse(
            cluster_name=c.name,
            risk_score=int(c.risk_score or 0),
            compliance_score=int(c.compliance_score or 0),
            findings_count=findings_by_cluster.get(c.id, 0),
            status=c.compliance_status,
            assessment_status=c.assessment_status,
        )
        for c in clusters
    ]

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
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Per-cluster compliance from stored CIS check results.

    Only CIS Kubernetes checks are evaluated (against the API); NSA/CISA,
    DoD STIG and SOC 2 have no mapping, so their scores are null.
    """
    clusters = list((await db.execute(
        select(KubernetesCluster).where(KubernetesCluster.organization_id == org_id)
        .order_by(KubernetesCluster.name).limit(200),
    )).scalars().all())
    counts = await _check_counts(db, org_id, [c.id for c in clusters])
    out = []
    for cluster in clusters:
        c_counts = counts.get(cluster.id, {})
        score = _cis_score(c_counts) if cluster.assessment_status == "assessed" else None
        out.append(ComplianceMatrixResponse(
            cluster_name=cluster.name,
            cluster_id=cluster.id,
            cis_score=score,
            overall_compliance=int(round(score)) if score is not None else None,
            status=cluster.compliance_status,
            reason=(
                None if score is not None
                else cluster.assessment_error or "not assessed: run a CIS audit with a stored credential"
            ),
            checks=c_counts,
            timestamp=cluster.last_audit,
        ))
    return out
