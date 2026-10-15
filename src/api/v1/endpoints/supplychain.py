"""Supply Chain Security and SBOM Management Endpoints

API endpoints for SBOM management, component tracking, risk assessment,
vendor management, and compliance validation, all scoped to the caller's
organisation.

Wave 4 (W4-B):
- Components are looked up in OSV (and NVD when ``NVD_API_KEY`` is set)
  through the pinned transport with per-organisation caching
  (``POST /components/lookup``, ``POST /components/{id}/lookup``,
  ``GET /vulnerability-sources``); results are ``known_vulnerability`` risks
  deduplicated per (component, advisory). A component never looked up reads
  ``vulnerability_scan_status: not_scanned``.
- SBOMs come from uploaded / imported CycloneDX or SPDX JSON (validated,
  size-capped, stored with their components and dependency counts) or are
  generated from stored components (``POST /sboms/generate``); nothing is
  synthesised.
- SBOM compliance is derived from the stored components (NTIA minimum
  elements) and cannot be set by hand; vendor scores are derived from stored
  questionnaire answers.
"""

import io
import json
import math
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import DatabaseSession, OrganizationId, require_role
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.models.audit import AuditLog
from src.models.user import User, UserRole
from src.schemas.supplychain import (
    ComponentDependencyTree,
    ComponentLookupRequest,
    ComponentVulnerabilityLookup,
    DashboardOverview,
    LicenseBreakdown,
    RiskyComponentSummary,
    SBOMComparisonRequest,
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
    SupplyChainRiskResponse,
    SupplyChainRiskUpdate,
    VendorAssessmentCreate,
    VendorAssessmentListResponse,
    VendorAssessmentResponse,
    VendorAssessmentUpdate,
    VendorScoreSummary,
)
from src.supplychain.assessment import (
    MAX_SBOM_BYTES,
    MAX_SBOM_COMPONENTS,
    VALID_ANSWERS,
    VENDOR_QUESTIONS,
    SBOMValidationError,
    assess_sbom,
    dependency_stats,
    detect_format,
    normalise_answers,
    stored_graph,
    summarise_answers,
    validate_sbom_document,
)
from src.supplychain.engine import (
    SBOMGenerator,
    SupplyChainRiskAnalyzer,
)
from src.supplychain.models import (
    SBOM,
    SBOMComponent,
    SoftwareComponent,
    SupplyChainRisk,
    VendorAssessment,
)
from src.supplychain.vulnlookup import MAX_COMPONENTS_PER_LOOKUP, lookup_components, provider_status

logger = get_logger(__name__)

router = APIRouter(prefix="/supplychain", tags=["Supply Chain"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1, "none": 0}


class SBOMValidationRequest(BaseModel):
    """Body for ``POST /compliance/validate-sbom``."""

    sbom_id: str = Field(..., min_length=1, description="SBOM to validate")


async def _audit(
    db: AsyncSession, user: Optional[User], org_id: str, action: str, resource_type: str,
    resource_id: Optional[str], description: str, payload: dict[str, Any],
) -> None:
    db.add(AuditLog(
        user_id=str(user.id) if user is not None else None,
        organization_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description[:4000],
        new_value=json.dumps(payload, default=str),
        success=True,
    ))
    await db.flush()


# Helper functions take the caller's organisation and 404 on any id outside
# it (they used to 403, which confirmed that another tenant's id exists).


async def get_sbom_or_404(db: AsyncSession, sbom_id: str, org_id: str) -> SBOM:
    """Get an SBOM in ``org_id`` by ID or raise 404"""
    result = await db.execute(
        select(SBOM).where(SBOM.id == sbom_id, SBOM.organization_id == org_id),
    )
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SBOM not found",
        )
    return sbom


async def get_component_or_404(
    db: AsyncSession, component_id: str, org_id: str,
) -> SoftwareComponent:
    """Get a component in ``org_id`` by ID or raise 404"""
    result = await db.execute(
        select(SoftwareComponent).where(
            SoftwareComponent.id == component_id,
            SoftwareComponent.organization_id == org_id,
        ),
    )
    component = result.scalar_one_or_none()
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Component not found",
        )
    return component


async def get_risk_or_404(db: AsyncSession, risk_id: str, org_id: str) -> SupplyChainRisk:
    """Get a supply chain risk in ``org_id`` by ID or raise 404"""
    result = await db.execute(
        select(SupplyChainRisk).where(
            SupplyChainRisk.id == risk_id,
            SupplyChainRisk.organization_id == org_id,
        ),
    )
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found",
        )
    return risk


async def get_vendor_or_404(db: AsyncSession, vendor_id: str, org_id: str) -> VendorAssessment:
    """Get a vendor assessment in ``org_id`` by ID or raise 404"""
    result = await db.execute(
        select(VendorAssessment).where(
            VendorAssessment.id == vendor_id,
            VendorAssessment.organization_id == org_id,
        ),
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )
    return vendor


# ---------------------------------------------------------------------------
# SBOM persistence and compliance
# ---------------------------------------------------------------------------


def _supplier(c: dict) -> Optional[str]:
    """Supplier name from SPDX ("Organization: X") or CycloneDX ({"name": X})."""
    for key in ("supplier", "manufacturer", "vendor", "publisher", "originator"):
        value = c.get(key)
        if isinstance(value, dict):
            value = value.get("name")
        if isinstance(value, str) and value.strip() and value.strip().upper() != "NOASSERTION":
            text = value.strip()
            for prefix in ("Organization:", "Person:", "Tool:"):
                if text.startswith(prefix):
                    text = text[len(prefix):].strip()
            return text[:255] or None
    return None


def _external_ref(c: dict, kinds: tuple[str, ...]) -> Optional[str]:
    for ref in c.get("externalRefs") or []:
        if isinstance(ref, dict) and ref.get("referenceType") in kinds and ref.get("referenceLocator"):
            return str(ref["referenceLocator"])
    return None


def _flatten_cdx(components: list, limit: int) -> list[dict]:
    out: list[dict] = []
    stack = list(reversed(components or []))
    while stack and len(out) <= limit:
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        out.append(c)
        stack.extend(reversed(c.get("components") or []))
    return out


async def _sbom_component_rows(db: AsyncSession, sbom_id: str, org_id: str) -> list[dict[str, Any]]:
    rows = (await db.execute(
        select(
            SoftwareComponent.name, SoftwareComponent.version, SoftwareComponent.vendor,
            SoftwareComponent.purl, SoftwareComponent.cpe, SoftwareComponent.checksum_sha256,
        )
        .join(SBOMComponent, SBOMComponent.component_id == SoftwareComponent.id)
        .where(SBOMComponent.sbom_id == sbom_id, SoftwareComponent.organization_id == org_id),
    )).all()
    return [dict(r._mapping) for r in rows]


async def _assess_and_store(db: AsyncSession, sbom: SBOM, org_id: str) -> dict[str, Any]:
    """NTIA assessment from the stored components; stores the derived status."""
    components = await _sbom_component_rows(db, sbom.id, org_id)
    graph = stored_graph(sbom.sbom_content, sbom.sbom_format)
    report = assess_sbom(
        components=components,
        author=sbom.created_by_tool or sbom.created_by_user,
        timestamp=sbom.last_generated or sbom.created_at,
        has_dependency_graph=graph["has_graph"],
        sbom_format=sbom.sbom_format,
        sbom_id=sbom.id,
    )
    sbom.compliance_status = report["status"]
    return report


async def _persist_sbom_with_components(
    db: AsyncSession,
    *,
    organization_id: str,
    sbom_format: str,
    sbom_content: str,
    parsed: dict,
    application_name: Optional[str],
    doc: dict,
    user: Optional[User],
) -> SBOM:
    """Create the SBOM row, every SoftwareComponent + SBOMComponent it declares,
    its dependency counts (from the document's graph) and its derived
    compliance status. Components are deduplicated within the organisation by
    purl, then CPE, then (name, version).
    """
    raw_components = parsed.get("components") or []
    if sbom_format == "cyclonedx_json":
        raw_components = _flatten_cdx(raw_components, MAX_SBOM_COMPONENTS)
    if len(raw_components) > MAX_SBOM_COMPONENTS:
        raise HTTPException(
            status_code=422,
            detail={"error": "too_many_components",
                    "detail": f"SBOM declares more than {MAX_SBOM_COMPONENTS} components"},
        )
    graph = dependency_stats(doc, sbom_format)
    sbom = SBOM(
        organization_id=organization_id,
        name=(parsed.get("name") or "Imported SBOM")[:500],
        application_name=(application_name or parsed.get("name") or "Unknown")[:500],
        application_version=str(parsed.get("version") or (
            ((doc.get("metadata") or {}).get("component") or {}).get("version")
        ) or "unspecified")[:100],
        sbom_format=sbom_format,
        spec_version=str(parsed.get("spec_version") or "")[:50] or "unknown",
        created_by_tool=(str(parsed.get("created_by_tool"))[:255] if parsed.get("created_by_tool") else None),
        created_by_user=str(user.id) if user is not None else None,
        sbom_content=sbom_content,
        last_generated=datetime.utcnow(),
    )
    db.add(sbom)
    await db.flush()

    linked: set[str] = set()
    for c in raw_components:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("packageName")
        version = c.get("version") or c.get("versionInfo") or "unknown"
        if not name:
            continue
        purl = c.get("purl") or _external_ref(c, ("purl",))
        cpe = c.get("cpe") or _external_ref(c, ("cpe23Type", "cpe22Type"))
        existing = None
        if purl:
            existing = (await db.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.organization_id == organization_id,
                    SoftwareComponent.purl == purl[:2048],
                ),
            )).scalars().first()
        if existing is None and cpe:
            existing = (await db.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.organization_id == organization_id,
                    SoftwareComponent.cpe == cpe[:500],
                ),
            )).scalars().first()
        if existing is None:
            existing = (await db.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.organization_id == organization_id,
                    SoftwareComponent.name == str(name)[:500],
                    SoftwareComponent.version == str(version)[:100],
                ),
            )).scalars().first()
        if existing is None:
            lic = _extract_spdx_license(c)
            existing = SoftwareComponent(
                organization_id=organization_id,
                name=str(name)[:500],
                version=str(version)[:100],
                vendor=_supplier(c),
                package_type=_derive_package_type(purl, c.get("type")),
                license_spdx_id=lic,
                license_type=lic,
                purl=purl[:2048] if purl else None,
                cpe=cpe[:500] if cpe else None,
                checksum_sha256=_extract_sha256(c),
                source_url=(c.get("downloadLocation") or c.get("source") or None),
                is_direct_dependency=True,
            )
            db.add(existing)
            await db.flush()
        if existing.id in linked:
            continue
        linked.add(existing.id)
        db.add(SBOMComponent(
            organization_id=organization_id,
            sbom_id=sbom.id,
            component_id=existing.id,
            relationship_type="depends_on",
        ))

    sbom.components_count = len(linked)
    sbom.total_dependencies = len(linked)
    sbom.direct_dependencies = graph["direct"]
    sbom.transitive_dependencies = graph["transitive"]
    await db.flush()
    await _assess_and_store(db, sbom, organization_id)
    await _audit(db, user, organization_id, "sbom_imported", "sbom", sbom.id,
                 f"imported {sbom_format} SBOM with {len(linked)} components",
                 {"format": sbom_format, "components": len(linked), "has_dependency_graph": graph["has_graph"]})
    await db.commit()
    await db.refresh(sbom)
    return sbom


def _parse_and_validate(content: str, sbom_format: Optional[str]) -> tuple[str, dict, dict]:
    """(format, parsed, document) or HTTPException 400/413/422."""
    if len(content.encode("utf-8")) > MAX_SBOM_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "sbom_too_large", "detail": f"SBOM larger than {MAX_SBOM_BYTES} bytes"},
        )
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"not valid JSON: {exc}") from exc
    detected = detect_format(doc)
    if detected is None:
        raise HTTPException(
            status_code=400,
            detail="unknown SBOM format — expected top-level spdxVersion (SPDX) or bomFormat=CycloneDX",
        )
    if sbom_format and sbom_format != detected:
        raise HTTPException(
            status_code=400, detail=f"sbom_format {sbom_format!r} does not match the document ({detected})",
        )
    try:
        validate_sbom_document(doc, detected)
    except SBOMValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_sbom", "errors": exc.errors[:50]},
        ) from exc
    generator = SBOMGenerator()
    parsed = generator.parse_spdx_json(content) if detected == "spdx_json" else generator.parse_cyclonedx_json(content)
    return detected, parsed, doc


# SBOM Endpoints


@router.post("/sboms/generate", response_model=SBOMResponse)
async def generate_sbom(
    sbom_create: SBOMCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Generate an SBOM document from stored components.

    Uses ``component_ids`` (or all of the organisation's components, up to
    the cap) and writes a real CycloneDX / SPDX document listing them, linked
    to the SBOM row. 422 ``no_components`` when there is nothing stored to
    describe; nothing is synthesised.
    """
    if sbom_create.sbom_format not in ("cyclonedx_json", "spdx_json"):
        raise HTTPException(status_code=400, detail="sbom_format must be cyclonedx_json or spdx_json")
    stmt = select(SoftwareComponent).where(SoftwareComponent.organization_id == org_id)
    if sbom_create.component_ids is not None:
        stmt = stmt.where(SoftwareComponent.id.in_(sbom_create.component_ids))
    components = list((await db.execute(
        stmt.order_by(SoftwareComponent.name, SoftwareComponent.id).limit(MAX_SBOM_COMPONENTS + 1),
    )).scalars())
    if sbom_create.component_ids is not None:
        found = {c.id for c in components}
        unknown = [cid for cid in sbom_create.component_ids if cid not in found]
        if unknown:
            raise HTTPException(status_code=404, detail={"error": "component_not_found", "component_ids": unknown[:20]})
    if not components:
        raise HTTPException(
            status_code=422,
            detail={"error": "no_components",
                    "detail": "No stored components to describe. Add components or upload an SBOM first."},
        )
    if len(components) > MAX_SBOM_COMPONENTS:
        raise HTTPException(
            status_code=422,
            detail={"error": "too_many_components", "detail": f"more than {MAX_SBOM_COMPONENTS} components"},
        )
    sbom = SBOM(
        organization_id=org_id,
        name=sbom_create.name,
        application_name=sbom_create.application_name,
        application_version=sbom_create.application_version,
        sbom_format=sbom_create.sbom_format,
        spec_version="",
        created_by_tool="PySOAR",
        created_by_user=str(_user.id) if _user is not None else None,
        last_generated=datetime.utcnow(),
    )
    db.add(sbom)
    await db.flush()
    ids = {c.id for c in components}
    shaped = [_export_shape(c) for c in components]
    relationships = [
        {
            "spdxElementId": f"SPDXRef-Package-{c.parent_component_id}",
            "relatedSpdxElement": f"SPDXRef-Package-{c.id}",
            "relationshipType": "DEPENDS_ON",
        }
        for c in components if c.parent_component_id and c.parent_component_id in ids
    ]
    data = {
        "id": sbom.id, "name": sbom.application_name, "version": sbom.application_version,
        "created_by_tool": "PySOAR", "components": shaped, "relationships": relationships,
    }
    generator = SBOMGenerator()
    if sbom_create.sbom_format == "spdx_json":
        sbom.sbom_content = generator.generate_spdx_output(data)
        sbom.spec_version = generator.SPDX_VERSION
    else:
        sbom.sbom_content = generator.generate_cyclonedx_output(data)
        sbom.spec_version = generator.CYCLONEDX_VERSION
    for c in components:
        db.add(SBOMComponent(organization_id=org_id, sbom_id=sbom.id, component_id=c.id,
                             relationship_type="depends_on"))
    graph = stored_graph(sbom.sbom_content, sbom.sbom_format)
    sbom.components_count = len(components)
    sbom.total_dependencies = len(components)
    sbom.direct_dependencies = graph["direct"]
    sbom.transitive_dependencies = graph["transitive"]
    scores = [c.risk_score for c in components if c.last_scanned is not None]
    sbom.vulnerability_risk_score = float(max(scores)) if scores else 0.0
    await db.flush()
    await _assess_and_store(db, sbom, org_id)
    await _audit(db, _user, org_id, "sbom_generated", "sbom", sbom.id,
                 f"generated {sbom.sbom_format} SBOM from {len(components)} stored components",
                 {"components": len(components)})
    await db.commit()
    await db.refresh(sbom)
    return sbom


def _derive_package_type(purl: Optional[str], cdx_type: Optional[str]) -> str:
    """Return the registry type (pypi/npm/maven/gem/golang/nuget/…) if the
    purl makes it clear, else fall back to the CycloneDX component type
    (library/application/framework/file/container). The typosquat + CVE
    sweeps filter by registry type, so "library" — CycloneDX's default —
    would make every imported component invisible to them.
    """
    if isinstance(purl, str) and purl.startswith("pkg:"):
        # pkg:<type>/<namespace>/<name>@<version>
        reg = purl[4:].split("/", 1)[0].split("@", 1)[0]
        if reg:
            return reg[:50].lower()
    if isinstance(cdx_type, str) and cdx_type:
        return cdx_type[:50].lower()
    return "library"


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
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Import an SBOM from inline JSON content (SPDX or CycloneDX).

    Validated against the spec structure (422 ``invalid_sbom`` with the
    errors), size-capped (413), then stored with its components. XML formats
    are not supported (400).
    """
    if import_request.sbom_format not in ("spdx_json", "cyclonedx_json"):
        raise HTTPException(status_code=400, detail="Unsupported SBOM format (spdx_json or cyclonedx_json)")
    fmt, parsed, doc = _parse_and_validate(import_request.sbom_content, import_request.sbom_format)
    return await _persist_sbom_with_components(
        db,
        organization_id=org_id,
        sbom_format=fmt,
        sbom_content=import_request.sbom_content,
        parsed=parsed,
        application_name=import_request.application_name,
        doc=doc,
        user=_user,
    )


@router.post("/sboms/upload", response_model=SBOMResponse)
async def upload_sbom(
    org_id: OrganizationId,
    file: UploadFile = File(..., description="SPDX or CycloneDX SBOM (.json/.spdx.json/.cdx.json)"),
    application_name: Optional[str] = None,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Upload an SBOM file (SPDX JSON or CycloneDX JSON) via multipart.

    Format is auto-detected (``spdxVersion`` / ``bomFormat: CycloneDX``),
    the document is validated (422 ``invalid_sbom``) and capped at
    ``MAX_SBOM_BYTES`` (413); components are stored so the Components tab
    populates immediately.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="file is required")
    raw = await file.read(MAX_SBOM_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=400, detail="empty file")
    if len(raw) > MAX_SBOM_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "sbom_too_large", "detail": f"SBOM larger than {MAX_SBOM_BYTES} bytes"},
        )
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="file is not UTF-8 text") from exc
    fmt, parsed, doc = _parse_and_validate(content, None)
    return await _persist_sbom_with_components(
        db,
        organization_id=org_id,
        sbom_format=fmt,
        sbom_content=content,
        parsed=parsed,
        application_name=application_name,
        doc=doc,
        user=_user,
    )


def _export_shape(sw: SoftwareComponent) -> dict[str, Any]:
    return {
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
    }


@router.post("/sboms/{sbom_id}/export")
async def export_sbom(
    export_request: SBOMExportRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Export SBOM as a real, spec-compliant SPDX or CycloneDX document.

    Built from every SBOMComponent + SoftwareComponent row of this SBOM in
    the caller's organisation; downloaded as a file.
    """
    sbom = await get_sbom_or_404(db, sbom_id, org_id)

    rows = (await db.execute(
        select(SoftwareComponent, SBOMComponent.relationship_type)
        .join(SBOMComponent, SBOMComponent.component_id == SoftwareComponent.id)
        .where(
            SBOMComponent.sbom_id == sbom_id,
            SBOMComponent.organization_id == org_id,
            SoftwareComponent.organization_id == org_id,
        ),
    )).all()

    components = []
    relationships = []
    for sw, rel_type in rows:
        components.append(_export_shape(sw))
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


_SBOM_SORT = {"created_at", "name", "application_name", "components_count", "vulnerability_risk_score"}


@router.get("/sboms", response_model=SBOMListResponse)
async def list_sboms(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List SBOMs with pagination and filtering"""
    query = select(SBOM).where(SBOM.organization_id == org_id)

    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (SBOM.name.ilike(search_filter))
            | (SBOM.application_name.ilike(search_filter))
        )

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    order_col = getattr(SBOM, sort_by if sort_by in _SBOM_SORT else "created_at")
    query = query.order_by(order_col.desc() if sort_order == "desc" else order_col, SBOM.id)
    query = query.offset((page - 1) * size).limit(size)

    items = (await db.execute(query)).scalars().all()
    pages = math.ceil(total / size) if total > 0 else 1

    return SBOMListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/sboms/{sbom_id}", response_model=SBOMResponse)
async def get_sbom(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Get SBOM details"""
    return await get_sbom_or_404(db, sbom_id, org_id)


@router.get("/sboms/{sbom_id}/compliance")
async def get_sbom_compliance(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """NTIA minimum-element assessment of the SBOM's stored components (read only)."""
    sbom = await get_sbom_or_404(db, sbom_id, org_id)
    components = await _sbom_component_rows(db, sbom.id, org_id)
    graph = stored_graph(sbom.sbom_content, sbom.sbom_format)
    return assess_sbom(
        components=components,
        author=sbom.created_by_tool or sbom.created_by_user,
        timestamp=sbom.last_generated or sbom.created_at,
        has_dependency_graph=graph["has_graph"],
        sbom_format=sbom.sbom_format,
        sbom_id=sbom.id,
    )


@router.patch("/sboms/{sbom_id}", response_model=SBOMResponse)
async def update_sbom(
    sbom_update: SBOMUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Rename an SBOM.

    ``compliance_status`` is derived from the stored components and is
    refused (422 ``derived_field``); the edit used to pre-select "compliant",
    so a rename silently certified the SBOM.
    """
    sbom = await get_sbom_or_404(db, sbom_id, org_id)
    update_data = sbom_update.model_dump(exclude_unset=True)
    if update_data.get("compliance_status") is not None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "derived_field",
                "detail": "compliance_status is computed from the SBOM's stored components "
                          "(GET /supplychain/sboms/{id}/compliance) and cannot be set.",
            },
        )
    if update_data.get("name"):
        sbom.name = update_data["name"]
    await db.commit()
    await db.refresh(sbom)
    return sbom


@router.delete("/sboms/{sbom_id}", status_code=204)
async def delete_sbom(
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    sbom_id: str = Path(...),
):
    """Delete an SBOM and its component links (the components stay)."""
    sbom = await get_sbom_or_404(db, sbom_id, org_id)
    await db.execute(delete(SBOMComponent).where(
        SBOMComponent.sbom_id == sbom.id, SBOMComponent.organization_id == org_id,
    ))
    await _audit(db, _user, org_id, "sbom_deleted", "sbom", sbom.id, f"deleted SBOM {sbom.name}", {})
    await db.delete(sbom)
    await db.commit()


@router.post("/sboms/compare")
async def compare_sboms(
    comparison_request: SBOMComparisonRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Compare the stored components of two SBOMs of this organisation.

    Components are matched by package identity (purl without version, else
    package type + name); a version change is reported as ``updated``.
    """
    sbom1 = await get_sbom_or_404(db, comparison_request.sbom_id_1, org_id)
    sbom2 = await get_sbom_or_404(db, comparison_request.sbom_id_2, org_id)

    async def components_of(sbom_id: str) -> dict[str, SoftwareComponent]:
        rows = (await db.execute(
            select(SoftwareComponent)
            .join(SBOMComponent, SBOMComponent.component_id == SoftwareComponent.id)
            .where(SBOMComponent.sbom_id == sbom_id, SoftwareComponent.organization_id == org_id),
        )).scalars().all()
        out: dict[str, SoftwareComponent] = {}
        for c in rows:
            ident = (c.purl.split("@", 1)[0] if c.purl else f"{c.package_type}:{c.name}").lower()
            out.setdefault(ident, c)
        return out

    first, second = await components_of(sbom1.id), await components_of(sbom2.id)
    added = [SoftwareComponentResponse.model_validate(second[k]) for k in sorted(second.keys() - first.keys())]
    removed = [SoftwareComponentResponse.model_validate(first[k]) for k in sorted(first.keys() - second.keys())]
    updated = [
        {"name": second[k].name, "from_version": first[k].version, "to_version": second[k].version,
         "component_id_1": first[k].id, "component_id_2": second[k].id}
        for k in sorted(first.keys() & second.keys()) if first[k].version != second[k].version
    ]
    return {
        "sbom_1": SBOMResponse.model_validate(sbom1),
        "sbom_2": SBOMResponse.model_validate(sbom2),
        "components_added": added,
        "components_removed": removed,
        "components_updated": updated,
        "unchanged": len(first.keys() & second.keys()) - len(updated),
        "risk_score_change": round((sbom2.vulnerability_risk_score or 0.0) - (sbom1.vulnerability_risk_score or 0.0), 1),
    }


# Component Endpoints


@router.post("/components", response_model=SoftwareComponentResponse)
async def create_component(
    component_create: SoftwareComponentCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create software component (``not_scanned`` until looked up).

    A manual add does not fire the supply-chain vulnerability automation:
    nothing has looked the component up yet. 409 when its purl or CPE is
    already registered in this organisation.
    """
    data = component_create.model_dump()
    license_value = data.pop("license", None)
    if license_value:
        data["license_spdx_id"] = data.get("license_spdx_id") or license_value[:50]
        data["license_type"] = data.get("license_type") or license_value[:100]
    if data.get("parent_component_id"):
        await get_component_or_404(db, data["parent_component_id"], org_id)
    for col in ("purl", "cpe"):
        if data.get(col):
            dup = (await db.execute(
                select(SoftwareComponent.id).where(
                    SoftwareComponent.organization_id == org_id, getattr(SoftwareComponent, col) == data[col],
                ),
            )).first()
            if dup:
                raise HTTPException(
                    status_code=409,
                    detail={"error": "component_exists", "component_id": dup[0], "detail": f"{col} already registered"},
                )
    component = SoftwareComponent(organization_id=org_id, **data)
    db.add(component)
    await db.commit()
    await db.refresh(component)

    return component


@router.get("/components", response_model=SoftwareComponentListResponse)
async def list_components(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    package_type: Optional[str] = None,
    min_risk_score: Optional[float] = None,
    scan_status: Optional[str] = Query(None, pattern="^(scanned|not_scanned)$"),
):
    """List software components"""
    query = select(SoftwareComponent).where(
        SoftwareComponent.organization_id == org_id
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

    if scan_status == "scanned":
        query = query.where(SoftwareComponent.last_scanned.is_not(None))
    elif scan_status == "not_scanned":
        query = query.where(SoftwareComponent.last_scanned.is_(None))

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.order_by(SoftwareComponent.created_at.desc(), SoftwareComponent.id)
    query = query.offset((page - 1) * size).limit(size)

    items = (await db.execute(query)).scalars().all()
    pages = math.ceil(total / size) if total > 0 else 1

    return SoftwareComponentListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.post("/components/lookup")
async def lookup_vulnerabilities(
    request: ComponentLookupRequest,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Look components up in OSV (and NVD with ``NVD_API_KEY``).

    ``component_ids`` or every component of the organisation (oldest lookup
    first, capped). Answers are cached per organisation for 24 hours. 502
    ``provider_unavailable`` when OSV could not be reached and nothing was
    looked up.
    """
    stmt = select(SoftwareComponent).where(SoftwareComponent.organization_id == org_id)
    if request.component_ids is not None:
        stmt = stmt.where(SoftwareComponent.id.in_(request.component_ids))
    components = list((await db.execute(
        stmt.order_by(SoftwareComponent.last_scanned.is_not(None), SoftwareComponent.last_scanned,
                      SoftwareComponent.id).limit(MAX_COMPONENTS_PER_LOOKUP + 1),
    )).scalars())
    if request.component_ids is not None:
        unknown = sorted(set(request.component_ids) - {c.id for c in components})
        if unknown:
            raise HTTPException(status_code=404, detail={"error": "component_not_found", "component_ids": unknown[:20]})
    return await _run_lookup(db, org_id, components, request.use_cache, _user)


@router.post("/components/{component_id}/lookup")
async def lookup_component_vulnerabilities(
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
    use_cache: bool = Query(True),
):
    """Look one component up in OSV (and NVD with ``NVD_API_KEY``)."""
    component = await get_component_or_404(db, component_id, org_id)
    return await _run_lookup(db, org_id, [component], use_cache, _user)


async def _run_lookup(
    db: AsyncSession, org_id: str, components: list[SoftwareComponent], use_cache: bool, user: Optional[User],
) -> dict[str, Any]:
    summary = await lookup_components(db, org_id, components, use_cache=use_cache)
    await _audit(db, user, org_id, "supplychain_vuln_lookup", "software_component",
                 components[0].id if len(components) == 1 else None,
                 f"OSV/NVD lookup of {len(components)} component(s)",
                 {k: summary[k] for k in ("components_checked", "components_failed", "risks_new", "providers")})
    await db.commit()
    osv = summary["providers"].get("osv", {})
    if osv.get("status") == "error" and summary["components_checked"] == 0 and components:
        raise HTTPException(
            status_code=502,
            detail={"error": "provider_unavailable", "detail": f"OSV lookup failed: {osv.get('error')}",
                    "summary": summary},
        )
    return summary


@router.get("/vulnerability-sources")
async def get_vulnerability_sources(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """OSV / NVD provider status and cache size for this organisation."""
    return await provider_status(db, org_id)


@router.get("/components/{component_id}", response_model=SoftwareComponentResponse)
async def get_component(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Get component details"""
    return await get_component_or_404(db, component_id, org_id)


@router.patch("/components/{component_id}", response_model=SoftwareComponentResponse)
async def update_component(
    component_update: SoftwareComponentUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Update component (a name / version change clears the lookup state)."""
    component = await get_component_or_404(db, component_id, org_id)

    update_data = component_update.model_dump(exclude_unset=True)
    identity_changed = any(
        k in update_data and update_data[k] != getattr(component, k) for k in ("name", "version")
    )
    for field, value in update_data.items():
        setattr(component, field, value)
    if identity_changed:
        # Previous advisories describe another package version.
        component.last_scanned = None
        component.known_vulnerabilities_count = 0
        component.risk_score = 0.0

    await db.commit()
    await db.refresh(component)
    return component


@router.get("/components/{component_id}/dependency-tree")
async def get_component_dependency_tree(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Get component dependency tree.

    Children are loaded with explicit org-scoped queries: touching the lazy
    ``child_components`` relationship in async code raised MissingGreenlet.
    A visited set stops parent cycles.
    """
    component = await get_component_or_404(db, component_id, org_id)

    visited: set[str] = set()

    async def build_tree(comp: SoftwareComponent) -> ComponentDependencyTree:
        visited.add(comp.id)
        children = (await db.execute(
            select(SoftwareComponent).where(
                SoftwareComponent.parent_component_id == comp.id,
                SoftwareComponent.organization_id == org_id,
            ),
        )).scalars().all()
        deps = [
            await build_tree(child) for child in children if child.id not in visited
        ]
        return ComponentDependencyTree(
            component=SoftwareComponentResponse.model_validate(comp),
            dependencies=deps,
        )

    return await build_tree(component)


@router.get("/components/{component_id}/vulnerabilities")
async def get_component_vulnerabilities(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    component_id: str = Path(...),
):
    """Known vulnerabilities of a component from its stored OSV / NVD risks.

    ``highest_severity`` is the highest severity among those advisories;
    ``scan_status`` is ``not_scanned`` until a lookup ran.
    """
    component = await get_component_or_404(db, component_id, org_id)

    risks = (await db.execute(
        select(SupplyChainRisk).where(
            SupplyChainRisk.component_id == component_id,
            SupplyChainRisk.organization_id == org_id,
            SupplyChainRisk.risk_type == "known_vulnerability",
        )
    )).scalars().all()

    cves: list[str] = []
    advisories: list[dict[str, Any]] = []
    highest: Optional[str] = None
    for risk in risks:
        cve_list = safe_json_loads(risk.cve_ids, []) if risk.cve_ids else []
        if isinstance(cve_list, list):
            cves.extend(str(c) for c in cve_list)
        advisories.append({
            "risk_id": risk.id, "advisory_id": risk.advisory_id, "source": risk.source,
            "severity": risk.severity, "status": risk.status, "cves": cve_list,
        })
        if risk.status == "open" and SEVERITY_RANK.get(risk.severity, 0) > SEVERITY_RANK.get(highest or "none", 0):
            highest = risk.severity
    unique_cves = sorted(set(cves))

    result = ComponentVulnerabilityLookup(
        component=component,
        cves=unique_cves,
        vulnerability_count=len(advisories),
        highest_severity=highest,
    ).model_dump()
    result["advisories"] = advisories
    result["scan_status"] = component.vulnerability_scan_status
    return result


# Supply Chain Risk Endpoints


def _json_text(value: Any) -> Optional[str]:
    return json.dumps(value, default=str) if value is not None else None


@router.post("/risks", response_model=SupplyChainRiskResponse)
async def create_risk(
    risk_create: SupplyChainRiskCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create supply chain risk record (component must belong to the org)."""
    if not risk_create.component_id:
        raise HTTPException(status_code=422, detail="component_id is required")
    await get_component_or_404(db, risk_create.component_id, org_id)
    data = risk_create.model_dump()
    data["evidence"] = _json_text(data.get("evidence"))
    data["cve_ids"] = _json_text(data.get("cve_ids"))
    risk = SupplyChainRisk(
        organization_id=org_id,
        detected_date=datetime.utcnow(),
        source="manual",
        **data,
    )
    db.add(risk)
    await db.commit()
    await db.refresh(risk)
    return risk


@router.get("/risks", response_model=SupplyChainRiskListResponse)
async def list_risks(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    risk_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    """List supply chain risks"""
    query = select(SupplyChainRisk).where(
        SupplyChainRisk.organization_id == org_id
    )

    if risk_type:
        query = query.where(SupplyChainRisk.risk_type == risk_type)

    if severity:
        query = query.where(SupplyChainRisk.severity == severity)

    if status:
        query = query.where(SupplyChainRisk.status == status)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.order_by(SupplyChainRisk.created_at.desc(), SupplyChainRisk.id)
    query = query.offset((page - 1) * size).limit(size)

    items = (await db.execute(query)).scalars().all()
    pages = math.ceil(total / size) if total > 0 else 1

    return SupplyChainRiskListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/risks/{risk_id}", response_model=SupplyChainRiskResponse)
async def get_risk(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    risk_id: str = Path(...),
):
    """Get risk details"""
    return await get_risk_or_404(db, risk_id, org_id)


@router.patch("/risks/{risk_id}", response_model=SupplyChainRiskResponse)
async def update_risk(
    risk_update: SupplyChainRiskUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    risk_id: str = Path(...),
):
    """Update risk status and remediation"""
    risk = await get_risk_or_404(db, risk_id, org_id)

    update_data = risk_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(risk, field, value)

    await db.commit()
    await db.refresh(risk)
    return risk


# Vendor Assessment Endpoints


def _vendor_values(data: dict[str, Any]) -> dict[str, Any]:
    """Validate answers and serialise the JSON-in-Text columns."""
    if "questionnaire_responses" in data:
        try:
            answers = normalise_answers(data["questionnaire_responses"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"error": "invalid_answers", "detail": str(exc)}) from exc
        data["questionnaire_responses"] = json.dumps(answers) if answers else None
    for key in ("certifications", "third_party_subprocessors"):
        if key in data:
            data[key] = _json_text(data[key])
    data.pop("security_score", None)
    return data


def _apply_score(vendor: VendorAssessment) -> None:
    summary = summarise_answers(vendor.questionnaire_responses)
    vendor.security_score = summary["score"] if summary["score"] is not None else 0.0


@router.get("/vendors/questionnaire")
async def get_vendor_questionnaire():
    """The questions a vendor security score is computed from."""
    return {
        "answers": list(VALID_ANSWERS),
        "scoring": "weighted share of yes (1) / partial (0.5) / no (0) answers; n/a excluded",
        "questions": [{"key": k, "question": q, "weight": w} for k, q, w in VENDOR_QUESTIONS],
    }


@router.post("/vendors", response_model=VendorAssessmentResponse)
async def create_vendor(
    vendor_create: VendorAssessmentCreate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Create vendor assessment; the score comes from the stored answers."""
    vendor = VendorAssessment(
        organization_id=org_id,
        assessment_date=datetime.utcnow(),
        **_vendor_values(vendor_create.model_dump()),
    )
    _apply_score(vendor)
    db.add(vendor)
    await db.commit()
    await db.refresh(vendor)
    return vendor


@router.get("/vendors", response_model=VendorAssessmentListResponse)
async def list_vendors(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    risk_tier: Optional[str] = None,
):
    """List vendor assessments"""
    query = select(VendorAssessment).where(
        VendorAssessment.organization_id == org_id
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(VendorAssessment.vendor_name.ilike(search_filter))

    if risk_tier:
        query = query.where(VendorAssessment.risk_tier == risk_tier)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.order_by(VendorAssessment.created_at.desc(), VendorAssessment.id)
    query = query.offset((page - 1) * size).limit(size)

    items = (await db.execute(query)).scalars().all()
    pages = math.ceil(total / size) if total > 0 else 1

    return VendorAssessmentListResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/vendors/{vendor_id}", response_model=VendorAssessmentResponse)
async def get_vendor(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    vendor_id: str = Path(...),
):
    """Get vendor assessment"""
    return await get_vendor_or_404(db, vendor_id, org_id)


@router.patch("/vendors/{vendor_id}", response_model=VendorAssessmentResponse)
async def update_vendor(
    vendor_update: VendorAssessmentUpdate,
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    vendor_id: str = Path(...),
):
    """Update vendor assessment; the score is recomputed from the stored answers."""
    vendor = await get_vendor_or_404(db, vendor_id, org_id)

    update_data = _vendor_values(vendor_update.model_dump(exclude_unset=True))
    for field, value in update_data.items():
        setattr(vendor, field, value)
    if "questionnaire_responses" in update_data:
        vendor.assessment_date = datetime.utcnow()
    _apply_score(vendor)

    await db.commit()
    await db.refresh(vendor)
    return vendor


# Compliance Endpoints


@router.post("/compliance/validate-sbom")
async def validate_sbom_compliance(
    request: SBOMValidationRequest,
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """NTIA minimum-element check of an SBOM's stored components.

    Body: ``{"sbom_id": "<id>"}``. Read only (nothing is persisted), so
    viewers may call it. ``status`` is compliant / non_compliant, or
    not_assessed for an SBOM without components.
    """
    sbom = await get_sbom_or_404(db, request.sbom_id, org_id)
    components = await _sbom_component_rows(db, sbom.id, org_id)
    graph = stored_graph(sbom.sbom_content, sbom.sbom_format)
    report = assess_sbom(
        components=components,
        author=sbom.created_by_tool or sbom.created_by_user,
        timestamp=sbom.last_generated or sbom.created_at,
        has_dependency_graph=graph["has_graph"],
        sbom_format=sbom.sbom_format,
        sbom_id=sbom.id,
    )
    report["report_generated"] = datetime.now(timezone.utc).isoformat()
    return report


@router.get("/compliance/license-audit")
async def license_audit(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Audit license compliance across the organisation's stored components.

    Real GPL / proprietary conflict detection over the stored SPDX license
    ids (``SupplyChainRiskAnalyzer.assess_license_compliance``); components
    without a license are counted, not guessed.
    """
    rows = (await db.execute(
        select(SoftwareComponent.id, SoftwareComponent.name, SoftwareComponent.license_spdx_id).where(
            SoftwareComponent.organization_id == org_id
        )
    )).all()

    licenses: dict[str, int] = {}
    gpl_count = 0
    proprietary_count = 0
    permissive_count = 0

    gpl_license_set = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
    proprietary_license_set = {"Proprietary", "Commercial"}
    permissive_license_set = {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}

    gpl_components: list[str] = []
    proprietary_components: list[str] = []

    for comp_id, name, lic in rows:
        if not lic:
            continue
        licenses[lic] = licenses.get(lic, 0) + 1
        if any(g in lic for g in gpl_license_set) or "GPL" in lic:
            gpl_count += 1
            gpl_components.append(name or comp_id)
        elif lic in proprietary_license_set:
            proprietary_count += 1
            proprietary_components.append(name or comp_id)
        elif lic in permissive_license_set:
            permissive_count += 1

    analyzer = SupplyChainRiskAnalyzer()
    license_assessment = analyzer.assess_license_compliance(list(licenses.keys()))

    conflicts: list[str] = [
        f"{reason}: GPL in {gpl_components[:5]}, Proprietary in {proprietary_components[:5]}"
        for reason in license_assessment.get("conflicts", [])
    ]

    status_value = license_assessment.get("compliance_status", "unknown") if licenses else "not_assessed"
    return LicenseBreakdown(
        total_components=len(rows),
        licenses=licenses,
        gpl_components=gpl_count,
        proprietary_components=proprietary_count,
        permissive_components=permissive_count,
        conflicts=conflicts,
        compliance_status=status_value,
    )


# Dashboard Endpoints


async def _scalar(db: AsyncSession, stmt: Any) -> Any:
    return (await db.execute(stmt)).scalar()


@router.get("/dashboard/overview")
async def dashboard_overview(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Supply chain overview from stored rows (scanned / assessed only for averages)."""
    total_sboms = await _scalar(db, select(func.count()).select_from(SBOM).where(SBOM.organization_id == org_id)) or 0
    total_components = await _scalar(db, select(func.count()).select_from(SoftwareComponent).where(
        SoftwareComponent.organization_id == org_id)) or 0
    components_scanned = await _scalar(db, select(func.count()).select_from(SoftwareComponent).where(
        SoftwareComponent.organization_id == org_id, SoftwareComponent.last_scanned.is_not(None))) or 0
    components_with_vuln = await _scalar(db, select(func.count()).select_from(SoftwareComponent).where(
        SoftwareComponent.organization_id == org_id, SoftwareComponent.known_vulnerabilities_count > 0)) or 0
    critical_risks = await _scalar(db, select(func.count()).select_from(SupplyChainRisk).where(
        SupplyChainRisk.organization_id == org_id, SupplyChainRisk.severity == "critical",
        SupplyChainRisk.status == "open")) or 0
    high_risks = await _scalar(db, select(func.count()).select_from(SupplyChainRisk).where(
        SupplyChainRisk.organization_id == org_id, SupplyChainRisk.severity == "high",
        SupplyChainRisk.status == "open")) or 0

    vendors = (await db.execute(
        select(VendorAssessment.questionnaire_responses, VendorAssessment.security_score,
               VendorAssessment.risk_tier)
        .where(VendorAssessment.organization_id == org_id).limit(50_000),
    )).all()
    assessed_scores = [
        float(score) for answers, score, _tier in vendors
        if summarise_answers(answers)["status"] != "not_assessed"
    ]
    critical_vendors = sum(1 for _a, _s, tier in vendors if tier == "critical")

    avg_component_risk = await _scalar(db, select(func.avg(SoftwareComponent.risk_score)).where(
        SoftwareComponent.organization_id == org_id, SoftwareComponent.last_scanned.is_not(None)))

    sbom_status = dict((await db.execute(
        select(SBOM.compliance_status, func.count(SBOM.id)).where(SBOM.organization_id == org_id)
        .group_by(SBOM.compliance_status),
    )).all())

    return DashboardOverview(
        total_sboms=total_sboms,
        total_components=total_components,
        components_with_vulnerabilities=components_with_vuln,
        critical_risks_open=critical_risks,
        high_risks_open=high_risks,
        vendors_assessed=len(assessed_scores),
        critical_risk_vendors=critical_vendors,
        average_component_risk=round(float(avg_component_risk), 1) if components_scanned and avg_component_risk is not None else None,
        average_vendor_score=round(sum(assessed_scores) / len(assessed_scores), 1) if assessed_scores else None,
        total_vendors=len(vendors),
        vendors_not_assessed=len(vendors) - len(assessed_scores),
        components_scanned=components_scanned,
        components_not_scanned=total_components - components_scanned,
        sboms_compliant=int(sbom_status.get("compliant", 0)),
        sboms_non_compliant=int(sbom_status.get("non_compliant", 0)),
        sboms_not_assessed=int(total_sboms - sbom_status.get("compliant", 0) - sbom_status.get("non_compliant", 0)),
        vulnerability_sources=await provider_status(db, org_id),
    )


@router.get("/dashboard/top-risky-components")
async def get_top_risky_components(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    limit: int = Query(10, ge=1, le=50),
):
    """Top looked-up components by risk score (highest CVSS of their advisories)."""
    components = (await db.execute(
        select(SoftwareComponent)
        .where(
            SoftwareComponent.organization_id == org_id,
            SoftwareComponent.last_scanned.is_not(None),
            SoftwareComponent.known_vulnerabilities_count > 0,
        )
        .order_by(SoftwareComponent.risk_score.desc(), SoftwareComponent.id)
        .limit(limit)
    )).scalars().all()

    summaries = []
    for comp in components:
        risks = (await db.execute(
            select(SupplyChainRisk.risk_type, SupplyChainRisk.severity).where(
                and_(
                    SupplyChainRisk.component_id == comp.id,
                    SupplyChainRisk.organization_id == org_id,
                    SupplyChainRisk.status == "open",
                )
            )
        )).all()
        top = max(risks, key=lambda r: SEVERITY_RANK.get(r.severity, 0), default=None)
        summaries.append(
            RiskyComponentSummary(
                component_id=comp.id,
                component_name=comp.name,
                version=comp.version,
                risk_score=comp.risk_score,
                vulnerability_count=comp.known_vulnerabilities_count,
                risk_type=top.risk_type if top else "",
                severity=top.severity if top else "",
            )
        )

    return summaries


@router.get("/dashboard/vendor-scores")
async def get_vendor_scores(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Vendor scores: security_score from stored answers, risk_score = 100 - it."""
    vendors = (await db.execute(
        select(VendorAssessment).where(VendorAssessment.organization_id == org_id)
        .order_by(VendorAssessment.vendor_name).limit(5_000)
    )).scalars().all()

    out = []
    for vendor in vendors:
        assessed = vendor.assessment_status != "not_assessed"
        out.append(VendorScoreSummary(
            vendor_id=vendor.id,
            vendor_name=vendor.vendor_name,
            risk_score=round(100.0 - vendor.security_score, 1) if assessed else None,
            security_score=vendor.security_score if assessed else None,
            assessment_status=vendor.assessment_status,
            risk_tier=vendor.risk_tier,
            last_assessment=vendor.assessment_date,
            incident_count=vendor.incident_count,
        ))
    return out
