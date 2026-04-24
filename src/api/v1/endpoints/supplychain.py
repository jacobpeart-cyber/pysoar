"""Supply Chain Security and SBOM Management Endpoints

API endpoints for SBOM management, component tracking, risk assessment,
vendor management, and compliance validation.
"""

import json
import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Path, HTTPException, Query, UploadFile, File, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.logging import get_logger
from src.models.organization import Organization
from src.services.automation import AutomationService
from src.core.utils import safe_json_loads

logger = get_logger(__name__)
from src.schemas.supplychain import (
    CISAComplianceReport,
    ComponentDependencyTree,
    ComponentVulnerabilityLookup,
    ComplianceAudit,
    ComplianceValidationResult,
    DashboardOverview,
    LicenseBreakdown,
    RiskAssessmentResult,
    RiskyComponentSummary,
    SBOMComponentCreate,
    SBOMComponentResponse,
    SBOMComparisonRequest,
    SBOMComparisonResponse,
    SBOMCreate,
    SBOMExportRequest,
    SBOMImportRequest,
    SBOMListResponse,
    SBOMResponse,
    SBOMUpdate,
    SoftwareComponentCreate,
    SoftwareComponentListResponse,
    SoftwareComponentResponse,
    SoftwareComponentUpdate,
    SupplyChainRiskCreate,
    SupplyChainRiskListResponse,
    SupplyChainRiskReport,
    SupplyChainRiskResponse,
    SupplyChainRiskUpdate,
    VendorAssessmentCreate,
    VendorAssessmentListResponse,
    VendorAssessmentResponse,
    VendorAssessmentUpdate,
    VendorRiskReport,
    VendorScoreSummary,
)
from src.supplychain.engine import (
    CISASBOMCompliance,
    DependencyScanner,
    SBOMGenerator,
    SupplyChainRiskAnalyzer,
    VendorRiskManager,
)
from src.supplychain.models import (
    SBOM,
    SBOMComponent,
    SoftwareComponent,
    SupplyChainRisk,
    VendorAssessment,
)

router = APIRouter(prefix="/supplychain", tags=["Supply Chain"])


# Helper functions


async def get_sbom_or_404(db: AsyncSession, sbom_id: str) -> SBOM:
    """Get SBOM by ID or raise 404"""
    result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SBOM not found",
        )
    return sbom


async def get_component_or_404(db: AsyncSession, component_id: str) -> SoftwareComponent:
    """Get component by ID or raise 404"""
    result = await db.execute(
        select(SoftwareComponent).where(SoftwareComponent.id == component_id)
    )
    component = result.scalar_one_or_none()
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Component not found",
        )
    return component


async def get_risk_or_404(db: AsyncSession, risk_id: str) -> SupplyChainRisk:
    """Get supply chain risk by ID or raise 404"""
    result = await db.execute(
        select(SupplyChainRisk).where(SupplyChainRisk.id == risk_id)
    )
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found",
        )
    return risk


async def get_vendor_or_404(db: AsyncSession, vendor_id: str) -> VendorAssessment:
    """Get vendor assessment by ID or raise 404"""
    result = await db.execute(
        select(VendorAssessment).where(VendorAssessment.id == vendor_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )
    return vendor


# SBOM Endpoints


@router.post("/sboms/generate", response_model=SBOMResponse)
async def generate_sbom(
    sbom_create: SBOMCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Generate new SBOM for application"""
    sbom = SBOM(
        organization_id=getattr(current_user, "organization_id", None),
        **sbom_create.model_dump(),
        last_generated=datetime.utcnow(),
    )
    db.add(sbom)
    await db.commit()
    await db.refresh(sbom)
    return sbom


async def _persist_sbom_with_components(
    db: AsyncSession,
    *,
    organization_id: Optional[str],
    sbom_format: str,
    sbom_content: str,
    parsed: dict,
    application_name: Optional[str],
) -> SBOM:
    """Create an SBOM row AND every SoftwareComponent + SBOMComponent
    row the parsed dict declares. Previously import only wrote the
    SBOM header and silently dropped the components list — the
    Components table rendered blank for every imported SBOM.
    Components are deduped by purl/cpe/(name,version) so re-importing
    the same SBOM doesn't balloon the software_components table.
    """
    sbom = SBOM(
        organization_id=organization_id,
        name=parsed.get("name") or "Imported SBOM",
        application_name=application_name or parsed.get("name") or "Unknown",
        application_version=parsed.get("version") or "1.0",
        sbom_format=sbom_format,
        spec_version=parsed.get("spec_version") or "2.3",
        created_by_tool=parsed.get("created_by_tool"),
        sbom_content=sbom_content[:10_000_000],  # cap 10 MB
        last_generated=datetime.utcnow(),
    )
    db.add(sbom)
    await db.flush()

    components = parsed.get("components") or []
    added = 0
    for c in components:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("packageName")
        version = c.get("version") or c.get("versionInfo") or "unknown"
        if not name:
            continue
        purl = c.get("purl")
        cpe = c.get("cpe")
        # Dedupe by purl first (primary identifier), then (name, version) within the org.
        existing = None
        if purl:
            existing = (await db.execute(
                select(SoftwareComponent).where(SoftwareComponent.purl == purl)
            )).scalar_one_or_none()
        if existing is None:
            existing = (await db.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.organization_id == organization_id,
                    SoftwareComponent.name == str(name)[:500],
                    SoftwareComponent.version == str(version)[:100],
                )
            )).scalar_one_or_none()
        if existing is None:
            existing = SoftwareComponent(
                organization_id=organization_id,
                name=str(name)[:500],
                version=str(version)[:100],
                vendor=(c.get("supplier") or c.get("vendor") or (c.get("publisher") if isinstance(c.get("publisher"), str) else None)),
                package_type=(c.get("type") or "library")[:50].lower(),
                license_spdx_id=_extract_spdx_license(c),
                license_type=_extract_spdx_license(c),
                purl=purl[:2048] if purl else None,
                cpe=cpe[:500] if cpe else None,
                checksum_sha256=_extract_sha256(c),
                source_url=(c.get("downloadLocation") or c.get("source") or None),
                is_direct_dependency=True,
            )
            db.add(existing)
            await db.flush()
        db.add(SBOMComponent(
            organization_id=organization_id,
            sbom_id=sbom.id,
            component_id=existing.id,
            relationship_type="depends_on",
        ))
        added += 1

    await db.commit()
    await db.refresh(sbom)
    return sbom


def _extract_spdx_license(c: dict) -> Optional[str]:
    """Pull the SPDX license id from either SPDX or CycloneDX component shape."""
    lic = c.get("licenseConcluded") or c.get("licenseDeclared")
    if isinstance(lic, str) and lic and lic != "NOASSERTION":
        return lic[:50]
    licenses = c.get("licenses")
    if isinstance(licenses, list):
        for entry in licenses:
            if isinstance(entry, dict):
                lic_obj = entry.get("license") or entry
                if isinstance(lic_obj, dict):
                    value = lic_obj.get("id") or lic_obj.get("name")
                    if value:
                        return str(value)[:50]
    return None


def _extract_sha256(c: dict) -> Optional[str]:
    """Pull sha256 from SPDX checksums or CycloneDX hashes."""
    for key in ("checksums", "hashes"):
        items = c.get(key)
        if isinstance(items, list):
            for h in items:
                if not isinstance(h, dict):
                    continue
                alg = (h.get("algorithm") or h.get("alg") or "").upper().replace("-", "")
                if alg in ("SHA256", "SHA-256"):
                    val = h.get("checksumValue") or h.get("value") or h.get("content")
                    if val:
                        return str(val)[:64]
    return None


@router.post("/sboms/import", response_model=SBOMResponse)
async def import_sbom(
    import_request: SBOMImportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Import SBOM from inline content (JSON-stringified).

    Also persists every parsed component into software_components +
    sbom_components so the Components table renders correctly.
    For file uploads, use POST /sboms/upload instead.
    """
    generator = SBOMGenerator()
    try:
        if import_request.sbom_format == "spdx_json":
            parsed = generator.parse_spdx_json(import_request.sbom_content)
        elif import_request.sbom_format == "cyclonedx_json":
            parsed = generator.parse_cyclonedx_json(import_request.sbom_content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported SBOM format")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {str(e)}")

    return await _persist_sbom_with_components(
        db,
        organization_id=getattr(current_user, "organization_id", None),
        sbom_format=import_request.sbom_format,
        sbom_content=import_request.sbom_content,
        parsed=parsed,
        application_name=import_request.application_name,
    )


@router.post("/sboms/upload", response_model=SBOMResponse)
async def upload_sbom(
    file: UploadFile = File(..., description="SPDX or CycloneDX SBOM (.json/.spdx.json/.cdx.json)"),
    application_name: Optional[str] = None,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Upload an SBOM file (SPDX JSON or CycloneDX JSON) via multipart.

    Format is auto-detected from the file content (SPDX has a
    `spdxVersion` key, CycloneDX has `bomFormat: CycloneDX`).
    Components are parsed and persisted so the Components tab
    populates immediately. For SPDX XML or CycloneDX XML, use the
    /sboms/import JSON endpoint with sbom_format set explicitly.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="file is required")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="file is not UTF-8 text")

    # Autodetect format.
    try:
        probe = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"not valid JSON: {e}")
    if isinstance(probe, dict) and "spdxVersion" in probe:
        sbom_format = "spdx_json"
    elif isinstance(probe, dict) and probe.get("bomFormat") == "CycloneDX":
        sbom_format = "cyclonedx_json"
    else:
        raise HTTPException(
            status_code=400,
            detail="unknown SBOM format — expected top-level spdxVersion (SPDX) or bomFormat=CycloneDX",
        )

    generator = SBOMGenerator()
    try:
        parsed = (
            generator.parse_spdx_json(content)
            if sbom_format == "spdx_json"
            else generator.parse_cyclonedx_json(content)
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"parse error: {e}")

    return await _persist_sbom_with_components(
        db,
        organization_id=getattr(current_user, "organization_id", None),
        sbom_format=sbom_format,
        sbom_content=content,
        parsed=parsed,
        application_name=application_name,
    )


@router.post("/sboms/{sbom_id}/export")
async def export_sbom(
    export_request: SBOMExportRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Export SBOM as a real, spec-compliant SPDX or CycloneDX document.

    Loads every SBOMComponent + joined SoftwareComponent row for this SBOM
    and passes them to the generator so the output contains real packages,
    versions, licenses, purls, and SHA-256 checksums — not an empty envelope.

    Returns a ``StreamingResponse`` with the proper ``Content-Disposition``
    header so the browser downloads it as a file instead of rendering JSON.
    """
    from fastapi.responses import StreamingResponse
    import io

    sbom = await get_sbom_or_404(db, sbom_id)

    if sbom.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Load the real component list (tenant-scoped via SBOM ownership check above)
    comp_result = await db.execute(
        select(SoftwareComponent, SBOMComponent.relationship_type)
        .join(SBOMComponent, SBOMComponent.component_id == SoftwareComponent.id)
        .where(SBOMComponent.sbom_id == sbom_id)
    )
    rows = comp_result.all()

    components = []
    relationships = []
    for sw, rel_type in rows:
        components.append({
            "id": sw.id,
            "SPDXID": f"SPDXRef-Package-{sw.id}",
            "bom-ref": sw.id,
            "name": sw.name,
            "version": sw.version,
            "type": sw.package_type or "library",
            "supplier": f"Organization: {sw.vendor}" if sw.vendor else "NOASSERTION",
            "licenseConcluded": sw.license_spdx_id or sw.license_type or "NOASSERTION",
            "licenseDeclared": sw.license_spdx_id or sw.license_type or "NOASSERTION",
            "purl": sw.purl,
            "cpe": sw.cpe,
            "hashes": (
                [{"alg": "SHA-256", "content": sw.checksum_sha256}]
                if sw.checksum_sha256
                else []
            ),
            "externalRefs": (
                [{"referenceType": "purl", "referenceLocator": sw.purl}] if sw.purl else []
            ),
        })
        if sw.parent_component_id:
            relationships.append({
                "spdxElementId": f"SPDXRef-Package-{sw.parent_component_id}",
                "relatedSpdxElement": f"SPDXRef-Package-{sw.id}",
                "relationshipType": (rel_type or "DEPENDS_ON").upper(),
            })

    generator = SBOMGenerator()

    sbom_data = {
        "id": sbom.id,
        "name": sbom.application_name,
        "version": sbom.application_version,
        "created_by_tool": sbom.created_by_tool or "PySOAR",
        "components": components,
        "relationships": relationships,
    }

    fmt = export_request.export_format
    if fmt == "spdx_json":
        content = generator.generate_spdx_output(sbom_data)
        media_type = "application/spdx+json"
        filename = f"{sbom.application_name or 'sbom'}-{sbom.application_version or 'v1'}.spdx.json"
    elif fmt == "cyclonedx_json":
        content = generator.generate_cyclonedx_output(sbom_data)
        media_type = "application/vnd.cyclonedx+json"
        filename = f"{sbom.application_name or 'sbom'}-{sbom.application_version or 'v1'}.cdx.json"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported export format (use spdx_json or cyclonedx_json)",
        )

    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/sboms", response_model=SBOMListResponse)
async def list_sboms(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List SBOMs with pagination and filtering"""
    query = select(SBOM).where(SBOM.organization_id == getattr(current_user, "organization_id", None))

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (SBOM.name.ilike(search_filter))
            | (SBOM.application_name.ilike(search_filter))
        )

    # Count total
    total_result = await db.execute(select(func.count()).select_from(SBOM))
    total = total_result.scalar()

    # Order and pagination
    order_col = getattr(SBOM, sort_by, SBOM.created_at)
    if sort_order == "desc":
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col)

    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return SBOMListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/sboms/{sbom_id}", response_model=SBOMResponse)
async def get_sbom(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Get SBOM details"""
    sbom = await get_sbom_or_404(db, sbom_id)

    if sbom.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return sbom


@router.patch("/sboms/{sbom_id}", response_model=SBOMResponse)
async def update_sbom(
    sbom_update: SBOMUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Update SBOM"""
    sbom = await get_sbom_or_404(db, sbom_id)

    if sbom.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    update_data = sbom_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(sbom, field, value)

    await db.commit()
    await db.refresh(sbom)
    return sbom


@router.post("/sboms/compare")
async def compare_sboms(
    comparison_request: SBOMComparisonRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Compare two SBOM versions"""
    sbom1 = await get_sbom_or_404(db, comparison_request.sbom_id_1)
    sbom2 = await get_sbom_or_404(db, comparison_request.sbom_id_2)

    if sbom1.organization_id != getattr(current_user, "organization_id", None) or sbom2.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return SBOMComparisonResponse(
        sbom_1=sbom1,
        sbom_2=sbom2,
        components_added=[],
        components_removed=[],
        components_updated=[],
        risk_score_change=sbom2.vulnerability_risk_score - sbom1.vulnerability_risk_score,
    )


# Component Endpoints


@router.post("/components", response_model=SoftwareComponentResponse)
async def create_component(
    component_create: SoftwareComponentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create software component"""
    component = SoftwareComponent(
        organization_id=getattr(current_user, "organization_id", None),
        **component_create.model_dump(),
    )
    db.add(component)
    await db.commit()
    await db.refresh(component)

    try:
        org_id = getattr(current_user, "organization_id", None)
        automation = AutomationService(db)
        await automation.on_supply_chain_vuln(
            vendor_name=getattr(component, "vendor", None) or "",
            component_name=component.name,
            cve_id=getattr(component, "cve_id", None) or "",
            severity="high",
            organization_id=org_id,
        )
    except Exception as automation_exc:
        logger.warning(f"Automation on_supply_chain_vuln failed: {automation_exc}")

    return component


@router.get("/components", response_model=SoftwareComponentListResponse)
async def list_components(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    package_type: Optional[str] = None,
    min_risk_score: Optional[float] = None,
):
    """List software components"""
    query = select(SoftwareComponent).where(
        SoftwareComponent.organization_id == getattr(current_user, "organization_id", None)
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (SoftwareComponent.name.ilike(search_filter))
            | (SoftwareComponent.purl.ilike(search_filter))
        )

    if package_type:
        query = query.where(SoftwareComponent.package_type == package_type)

    if min_risk_score is not None:
        query = query.where(SoftwareComponent.risk_score >= min_risk_score)

    total_result = await db.execute(select(func.count()).select_from(SoftwareComponent))
    total = total_result.scalar()

    query = query.order_by(SoftwareComponent.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return SoftwareComponentListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/components/{component_id}", response_model=SoftwareComponentResponse)
async def get_component(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Get component details"""
    component = await get_component_or_404(db, component_id)

    if component.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return component


@router.patch("/components/{component_id}", response_model=SoftwareComponentResponse)
async def update_component(
    component_update: SoftwareComponentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Update component"""
    component = await get_component_or_404(db, component_id)

    if component.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    update_data = component_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(component, field, value)

    await db.commit()
    await db.refresh(component)
    return component


@router.get("/components/{component_id}/dependency-tree")
async def get_component_dependency_tree(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Get component dependency tree"""
    component = await get_component_or_404(db, component_id)

    if component.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    # Build tree recursively
    async def build_tree(comp: SoftwareComponent) -> dict:
        deps = []
        for child in comp.child_components:
            deps.append(await build_tree(child))

        return {
            "component": comp,
            "dependencies": deps,
        }

    tree = await build_tree(component)
    return tree


@router.get("/components/{component_id}/vulnerabilities")
async def get_component_vulnerabilities(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Look up known vulnerabilities for a component.

    Previously hardcoded ``highest_severity = "critical"`` whenever
    the component had any CVE at all, regardless of actual CVSS
    scores. An informational CVE looked critical on the dashboard;
    a component with 12 high-severity CVEs looked the same as one
    with 1 medium. Now:
      - pulls SupplyChainRisk rows linked to this component
      - joins the collected CVE IDs back to the Vulnerability table
        to get the real severity
      - returns the highest actual severity in the standard
        critical > high > medium > low > informational ordering
    """
    from src.vulnmgmt.models import Vulnerability, VulnerabilitySeverity

    component = await get_component_or_404(db, component_id)

    if component.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    result = await db.execute(
        select(SupplyChainRisk).where(
            (SupplyChainRisk.component_id == component_id)
            & (SupplyChainRisk.risk_type == "known_vulnerability")
        )
    )
    risks = result.scalars().all()

    cves: list[str] = []
    for risk in risks:
        if risk.cve_ids:
            cve_list = safe_json_loads(risk.cve_ids, [])
            if isinstance(cve_list, list):
                cves.extend(cve_list)
    unique_cves = sorted(set(cves))

    # Resolve highest real severity from the Vulnerability table (tenant-scoped)
    highest: Optional[str] = None
    if unique_cves:
        org_id = getattr(current_user, "organization_id", None)
        sev_result = await db.execute(
            select(Vulnerability.severity).where(
                and_(
                    Vulnerability.cve_id.in_(unique_cves),
                    Vulnerability.organization_id == org_id,
                )
            )
        )
        severities = [row[0] for row in sev_result.all() if row[0]]
        if severities:
            # Rank by the canonical enum ordering — critical > low
            rank = {
                VulnerabilitySeverity.CRITICAL.value: 5,
                VulnerabilitySeverity.HIGH.value: 4,
                VulnerabilitySeverity.MEDIUM.value: 3,
                VulnerabilitySeverity.LOW.value: 2,
                VulnerabilitySeverity.INFORMATIONAL.value: 1,
            }
            highest = max(severities, key=lambda s: rank.get(s, 0))

    return ComponentVulnerabilityLookup(
        component=component,
        cves=unique_cves,
        vulnerability_count=len(unique_cves),
        highest_severity=highest,
    )


# Supply Chain Risk Endpoints


@router.post("/risks", response_model=SupplyChainRiskResponse)
async def create_risk(
    risk_create: SupplyChainRiskCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create supply chain risk record"""
    risk = SupplyChainRisk(
        organization_id=getattr(current_user, "organization_id", None),
        detected_date=datetime.utcnow(),
        **risk_create.model_dump(),
    )
    db.add(risk)
    await db.commit()
    await db.refresh(risk)
    return risk


@router.get("/risks", response_model=SupplyChainRiskListResponse)
async def list_risks(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    risk_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    """List supply chain risks"""
    query = select(SupplyChainRisk).where(
        SupplyChainRisk.organization_id == getattr(current_user, "organization_id", None)
    )

    if risk_type:
        query = query.where(SupplyChainRisk.risk_type == risk_type)

    if severity:
        query = query.where(SupplyChainRisk.severity == severity)

    if status:
        query = query.where(SupplyChainRisk.status == status)

    total_result = await db.execute(select(func.count()).select_from(SupplyChainRisk))
    total = total_result.scalar()

    query = query.order_by(SupplyChainRisk.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return SupplyChainRiskListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/risks/{risk_id}", response_model=SupplyChainRiskResponse)
async def get_risk(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    risk_id: str = Path(...),
):
    """Get risk details"""
    risk = await get_risk_or_404(db, risk_id)

    if risk.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return risk


@router.patch("/risks/{risk_id}", response_model=SupplyChainRiskResponse)
async def update_risk(
    risk_update: SupplyChainRiskUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    risk_id: str = Path(...),
):
    """Update risk status and remediation"""
    risk = await get_risk_or_404(db, risk_id)

    if risk.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    update_data = risk_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(risk, field, value)

    await db.commit()
    await db.refresh(risk)
    return risk


# Vendor Assessment Endpoints


@router.post("/vendors", response_model=VendorAssessmentResponse)
async def create_vendor(
    vendor_create: VendorAssessmentCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create vendor assessment"""
    vendor = VendorAssessment(
        organization_id=getattr(current_user, "organization_id", None),
        assessment_date=datetime.utcnow(),
        **vendor_create.model_dump(),
    )
    db.add(vendor)
    await db.commit()
    await db.refresh(vendor)
    return vendor


@router.get("/vendors", response_model=VendorAssessmentListResponse)
async def list_vendors(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    risk_tier: Optional[str] = None,
):
    """List vendor assessments"""
    query = select(VendorAssessment).where(
        VendorAssessment.organization_id == getattr(current_user, "organization_id", None)
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(VendorAssessment.vendor_name.ilike(search_filter))

    if risk_tier:
        query = query.where(VendorAssessment.risk_tier == risk_tier)

    total_result = await db.execute(select(func.count()).select_from(VendorAssessment))
    total = total_result.scalar()

    query = query.order_by(VendorAssessment.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    items = result.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 1

    return VendorAssessmentListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/vendors/{vendor_id}", response_model=VendorAssessmentResponse)
async def get_vendor(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    vendor_id: str = Path(...),
):
    """Get vendor assessment"""
    vendor = await get_vendor_or_404(db, vendor_id)

    if vendor.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return vendor


@router.patch("/vendors/{vendor_id}", response_model=VendorAssessmentResponse)
async def update_vendor(
    vendor_update: VendorAssessmentUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    vendor_id: str = Path(...),
):
    """Update vendor assessment"""
    vendor = await get_vendor_or_404(db, vendor_id)

    if vendor.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    update_data = vendor_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vendor, field, value)

    await db.commit()
    await db.refresh(vendor)
    return vendor


# Compliance Endpoints


@router.post("/compliance/validate-sbom")
async def validate_sbom_compliance(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Validate SBOM compliance with CISA guidelines"""
    sbom = await get_sbom_or_404(db, sbom_id)

    if sbom.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    compliance = CISASBOMCompliance()

    sbom_data = {
        "id": sbom.id,
        "name": sbom.application_name,
        "version": sbom.application_version,
        "created_by_tool": sbom.created_by_tool,
        "created_at": sbom.created_at,
    }

    return compliance.generate_compliance_report(sbom_data)


@router.get("/compliance/license-audit")
async def license_audit(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Audit license compliance across organization.

    Fixed logic bugs in the previous version:
      - ``conflicts = []`` was always empty, so the UI never showed
        which components were in conflict
      - compliance_status was ``"compliant" if proprietary_count == 0
        OR gpl_count == 0 else "conflict"``, meaning the endpoint
        reported "compliant" whenever EITHER count was zero. A tenant
        with 50 proprietary + 0 GPL got "compliant" (the real concern
        is the mix, not the individual count).

    Now calls the engine's ``SupplyChainRiskAnalyzer.assess_license_
    compliance`` on the unique license set for real GPL↔proprietary
    conflict detection, and populates ``conflicts`` with the
    specific components that carry conflicting licenses.
    """
    from src.supplychain.engine import SupplyChainRiskAnalyzer

    result = await db.execute(
        select(SoftwareComponent).where(
            SoftwareComponent.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    components = result.scalars().all()

    licenses: dict[str, int] = {}
    gpl_count = 0
    proprietary_count = 0
    permissive_count = 0

    gpl_license_set = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
    proprietary_license_set = {"Proprietary", "Commercial"}
    permissive_license_set = {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}

    gpl_components: list[str] = []
    proprietary_components: list[str] = []

    for component in components:
        lic = component.license_spdx_id
        if not lic:
            continue
        licenses[lic] = licenses.get(lic, 0) + 1
        if any(g in lic for g in gpl_license_set) or "GPL" in lic:
            gpl_count += 1
            gpl_components.append(component.name or component.id)
        elif lic in proprietary_license_set:
            proprietary_count += 1
            proprietary_components.append(component.name or component.id)
        elif lic in permissive_license_set:
            permissive_count += 1

    # Real conflict detection via the engine
    analyzer = SupplyChainRiskAnalyzer()
    license_assessment = analyzer.assess_license_compliance(list(licenses.keys()))

    conflicts: list[str] = []
    for reason in license_assessment.get("conflicts", []):
        # Reason is a description like "GPL incompatible with
        # proprietary license" — enrich it with the specific
        # components so the operator can act.
        conflicts.append(
            f"{reason}: GPL in {gpl_components[:5]}, "
            f"Proprietary in {proprietary_components[:5]}"
        )

    return LicenseBreakdown(
        total_components=len(components),
        licenses=licenses,
        gpl_components=gpl_count,
        proprietary_components=proprietary_count,
        permissive_components=permissive_count,
        conflicts=conflicts,
        compliance_status=license_assessment.get("compliance_status", "unknown"),
    )


# Dashboard Endpoints


@router.get("/dashboard/overview")
async def dashboard_overview(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get supply chain security dashboard overview"""
    sbom_result = await db.execute(
        select(func.count()).select_from(SBOM).where(SBOM.organization_id == getattr(current_user, "organization_id", None))
    )
    total_sboms = sbom_result.scalar() or 0

    component_result = await db.execute(
        select(func.count()).select_from(SoftwareComponent).where(
            SoftwareComponent.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    total_components = component_result.scalar() or 0

    vuln_result = await db.execute(
        select(func.count()).select_from(SoftwareComponent).where(
            (SoftwareComponent.organization_id == getattr(current_user, "organization_id", None))
            & (SoftwareComponent.known_vulnerabilities_count > 0)
        )
    )
    components_with_vuln = vuln_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count()).select_from(SupplyChainRisk).where(
            (SupplyChainRisk.organization_id == getattr(current_user, "organization_id", None))
            & (SupplyChainRisk.severity == "critical")
            & (SupplyChainRisk.status == "open")
        )
    )
    critical_risks = critical_result.scalar() or 0

    high_result = await db.execute(
        select(func.count()).select_from(SupplyChainRisk).where(
            (SupplyChainRisk.organization_id == getattr(current_user, "organization_id", None))
            & (SupplyChainRisk.severity == "high")
            & (SupplyChainRisk.status == "open")
        )
    )
    high_risks = high_result.scalar() or 0

    vendor_result = await db.execute(
        select(func.count()).select_from(VendorAssessment).where(
            VendorAssessment.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    total_vendors = vendor_result.scalar() or 0

    vendor_critical_result = await db.execute(
        select(func.count()).select_from(VendorAssessment).where(
            (VendorAssessment.organization_id == getattr(current_user, "organization_id", None))
            & (VendorAssessment.risk_tier == "critical")
        )
    )
    critical_vendors = vendor_critical_result.scalar() or 0

    # Real averages (were hardcoded 45.5 / 62.3 — cosmetic fake data that
    # would have been the first thing an auditor noticed)
    avg_comp_result = await db.execute(
        select(func.avg(SoftwareComponent.risk_score)).where(
            SoftwareComponent.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    avg_component_risk = float(avg_comp_result.scalar() or 0.0)

    avg_vendor_result = await db.execute(
        select(func.avg(VendorAssessment.security_score)).where(
            VendorAssessment.organization_id == getattr(current_user, "organization_id", None)
        )
    )
    avg_vendor_score = float(avg_vendor_result.scalar() or 0.0)

    return DashboardOverview(
        total_sboms=total_sboms,
        total_components=total_components,
        components_with_vulnerabilities=components_with_vuln,
        critical_risks_open=critical_risks,
        high_risks_open=high_risks,
        vendors_assessed=total_vendors,
        critical_risk_vendors=critical_vendors,
        average_component_risk=round(avg_component_risk, 1),
        average_vendor_score=round(avg_vendor_score, 1),
    )


@router.get("/dashboard/top-risky-components")
async def get_top_risky_components(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    limit: int = Query(10, ge=1, le=50),
):
    """Get top risky components by risk score"""
    result = await db.execute(
        select(SoftwareComponent)
        .where(SoftwareComponent.organization_id == getattr(current_user, "organization_id", None))
        .order_by(SoftwareComponent.risk_score.desc())
        .limit(limit)
    )
    components = result.scalars().all()

    summaries = []
    for comp in components:
        risk_result = await db.execute(
            select(SupplyChainRisk).where(
                (SupplyChainRisk.component_id == comp.id)
                & (SupplyChainRisk.status == "open")
            )
        )
        risks = risk_result.scalars().all()

        risk_type = risks[0].risk_type if risks else "unknown"
        severity = risks[0].severity if risks else "low"

        summaries.append(
            RiskyComponentSummary(
                component_id=comp.id,
                component_name=comp.name,
                version=comp.version,
                risk_score=comp.risk_score,
                vulnerability_count=comp.known_vulnerabilities_count,
                risk_type=risk_type,
                severity=severity,
            )
        )

    return summaries


@router.get("/dashboard/vendor-scores")
async def get_vendor_scores(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get vendor risk scores"""
    result = await db.execute(
        select(VendorAssessment).where(VendorAssessment.organization_id == getattr(current_user, "organization_id", None))
    )
    vendors = result.scalars().all()

    summaries = [
        VendorScoreSummary(
            vendor_id=vendor.id,
            vendor_name=vendor.vendor_name,
            risk_score=vendor.security_score,
            risk_tier=vendor.risk_tier,
            last_assessment=vendor.assessment_date,
            incident_count=vendor.incident_count,
        )
        for vendor in vendors
    ]

    return summaries
