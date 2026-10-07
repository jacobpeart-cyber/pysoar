"""Celery Tasks for Supply Chain Security Module

Background tasks for dependency scanning, vulnerability cross-reference,
vendor assessment, SBOM regeneration, and typosquatting detection.
"""

from datetime import datetime, timedelta
from typing import Any

from celery import shared_task
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.core.config import settings
from src.core.logging import get_logger
from src.supplychain.engine import (
    DependencyScanner,
    SupplyChainRiskAnalyzer,
)
from src.supplychain.models import (
    SBOM,
    SBOMComponent,
    SoftwareComponent,
    SupplyChainRisk,
    VendorAssessment,
)

logger = get_logger(__name__)

# Database session factory
_engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
_AsyncSessionLocal = sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

# --- Memory bounds ---------------------------------------------------------
# The cross-reference, cert-expiry and typosquat tasks and the daily
# cross-org sweep used to materialise every matching risk / vendor /
# component row (full ORM objects for most) with one unbounded read, and the
# sweep held every new SupplyChainRisk in one session until a single commit
# at the very end. Everything now reads in keyset windows of
# SUPPLYCHAIN_BATCH_SIZE on the primary key, selects only the columns it
# uses, and commits per window. Caps that fire set ``truncated``.
SUPPLYCHAIN_BATCH_SIZE = 1_000
MAX_CROSSREF_RISKS_PER_RUN = 10_000
MAX_VENDORS_PER_RUN = 50_000
MAX_TYPOSQUAT_PACKAGES_PER_RUN = 100_000
# Total component + vendor rows one cross-org sweep may read.
MAX_SUPPLYCHAIN_SWEEP_ROWS = 500_000


@shared_task(bind=True, max_retries=3)
def scheduled_dependency_scan(self, organization_id: str, scan_type: str = "full"):
    """
    Scheduled task to scan dependencies across organization applications.

    Executed periodically (daily/weekly) to detect new dependencies,
    outdated packages, and known vulnerabilities.

    Args:
        organization_id: Organization to scan
        scan_type: Type of scan ('full', 'incremental', 'critical')

    Returns:
        Dictionary with scan results
    """
    try:
        logger.info(
            f"Starting dependency scan for organization {organization_id} (type={scan_type})",
        )

        scanner = DependencyScanner()

        import asyncio

        async def _scan():
            async with _AsyncSessionLocal() as db:
                # Count SBOMs (applications) for this organization
                app_stmt = select(func.count(SBOM.id)).where(
                    SBOM.organization_id == organization_id,
                )
                app_count = (await db.execute(app_stmt)).scalar() or 0

                # Count total dependencies (components)
                dep_stmt = select(func.count(SBOMComponent.id)).where(
                    SBOMComponent.organization_id == organization_id,
                )
                dep_count = (await db.execute(dep_stmt)).scalar() or 0

                # Count risks (vulnerabilities) discovered recently
                cutoff = datetime.utcnow() - timedelta(days=1 if scan_type == "incremental" else 365)
                vuln_stmt = select(func.count(SupplyChainRisk.id)).where(
                    and_(
                        SupplyChainRisk.organization_id == organization_id,
                        SupplyChainRisk.created_at >= cutoff,
                    ),
                )
                vuln_count = (await db.execute(vuln_stmt)).scalar() or 0

                return {
                    "applications_scanned": app_count,
                    "total_dependencies_found": dep_count,
                    "new_vulnerabilities": vuln_count,
                }

        db_results = asyncio.run(_scan())

        scan_results = {
            "organization_id": organization_id,
            "scan_type": scan_type,
            "scan_started": datetime.utcnow().isoformat(),
            **db_results,
        }

        logger.info(
            f"Dependency scan completed: {scan_results['total_dependencies_found']} "
            f"dependencies, {scan_results['new_vulnerabilities']} new vulnerabilities",
        )

        return scan_results

    except Exception as exc:
        logger.error(f"Dependency scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _vulnerability_cross_reference_async(component_id: str) -> dict[str, Any]:
    """Known risks for one component, read in id windows of three columns."""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    cves: list[dict[str, Any]] = []
    max_severity = "none"
    cap_hit = False
    last_id: str | None = None

    async with _AsyncSessionLocal() as db:
        while len(cves) < MAX_CROSSREF_RISKS_PER_RUN:
            window = min(SUPPLYCHAIN_BATCH_SIZE, MAX_CROSSREF_RISKS_PER_RUN - len(cves))
            stmt = select(
                SupplyChainRisk.id, SupplyChainRisk.risk_type, SupplyChainRisk.created_at,
            ).where(SupplyChainRisk.component_id == component_id)
            if last_id is not None:
                stmt = stmt.where(SupplyChainRisk.id > last_id)
            rows = (await db.execute(stmt.order_by(SupplyChainRisk.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id

            for risk in rows:
                # SupplyChainRisk has no ``risk_details`` column, so the old
                # ``hasattr(risk, "risk_details")`` branch always produced {}:
                # the CVE id and description below are exactly what it emitted.
                cve_entry = {
                    "cve_id": f"RISK-{risk.id[:8]}",
                    "severity": risk.risk_type or "medium",
                    "description": "Supply chain risk identified",
                    "published_date": risk.created_at.isoformat() if risk.created_at else None,
                }
                cves.append(cve_entry)
                sev = cve_entry["severity"]
                if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                    max_severity = sev

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            f"vulnerability_cross_reference: cap of {MAX_CROSSREF_RISKS_PER_RUN} "
            f"risks hit for component {component_id}; remainder omitted",
        )
    return {"cves": cves, "max_severity": max_severity, "truncated": cap_hit}


@shared_task(bind=True, max_retries=3)
def vulnerability_cross_reference(
    self, component_id: str, component_name: str, component_version: str,
):
    """
    Cross-reference component against multiple vulnerability databases.

    Checks NVD, OSV, and other sources for known vulnerabilities
    related to the component.

    Args:
        component_id: Component database ID
        component_name: Component name
        component_version: Component version

    Returns:
        Dictionary with vulnerability findings
    """
    try:
        logger.info(
            f"Cross-referencing vulnerabilities for {component_name}@{component_version}",
        )

        import asyncio

        found = asyncio.run(_vulnerability_cross_reference_async(component_id))
        cves = found["cves"]

        result = {
            "component_id": component_id,
            "component_name": component_name,
            "component_version": component_version,
            "cross_reference_date": datetime.utcnow().isoformat(),
            "databases_checked": ["NVD", "OSV", "GitHub"],
            "vulnerabilities_found": cves,
            "total_cves": len(cves),
            "max_severity": found["max_severity"],
            "truncated": found["truncated"],
        }

        logger.info(
            f"Found {result['total_cves']} CVEs for {component_name}@{component_version}",
        )

        return result

    except Exception as exc:
        logger.error(f"Vulnerability cross-reference failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _vendor_certification_expiry_check_async(organization_id: str) -> dict[str, Any]:
    """Expiring / expired vendor certs for one org, in id windows."""
    import json as json_module

    now = datetime.utcnow()
    expiring_soon: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    vendor_count = 0
    cap_hit = False
    last_id: str | None = None

    async with _AsyncSessionLocal() as db:
        while vendor_count < MAX_VENDORS_PER_RUN:
            window = min(SUPPLYCHAIN_BATCH_SIZE, MAX_VENDORS_PER_RUN - vendor_count)
            stmt = select(
                VendorAssessment.id,
                VendorAssessment.vendor_name,
                VendorAssessment.certifications,
            ).where(VendorAssessment.organization_id == organization_id)
            if last_id is not None:
                stmt = stmt.where(VendorAssessment.id > last_id)
            vendors = (await db.execute(stmt.order_by(VendorAssessment.id).limit(window))).all()
            if not vendors:
                break
            last_id = vendors[-1].id
            vendor_count += len(vendors)

            for vendor in vendors:
                # Parse certifications JSON
                certs = []
                if vendor.certifications:
                    try:
                        certs = json_module.loads(vendor.certifications)
                    except (json_module.JSONDecodeError, TypeError):
                        certs = []

                for cert in certs:
                    expiry_str = cert.get("expiry_date")
                    if not expiry_str:
                        continue
                    try:
                        expiry_date = datetime.fromisoformat(expiry_str)
                    except (ValueError, TypeError):
                        continue

                    days_until = (expiry_date - now).days
                    cert_entry = {
                        "vendor_name": vendor.vendor_name,
                        "certification": cert.get("name", "unknown"),
                        "expiry_date": expiry_str,
                        "days_until_expiry": days_until,
                    }
                    if days_until < 0:
                        expired.append(cert_entry)
                    elif days_until < 90:
                        expiring_soon.append(cert_entry)

            if len(vendors) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            f"vendor_certification_expiry_check: cap of {MAX_VENDORS_PER_RUN} "
            f"vendors hit for {organization_id}; remainder deferred",
        )
    return {
        "vendor_count": vendor_count,
        "expiring_soon": expiring_soon,
        "expired": expired,
        "truncated": cap_hit,
    }


@shared_task(bind=True, max_retries=2)
def vendor_certification_expiry_check(self, organization_id: str):
    """
    Check for expiring vendor certifications and compliance deadlines.

    Runs periodically to identify vendors with certifications expiring
    within 90 days and alert for renewal.

    Args:
        organization_id: Organization to check

    Returns:
        Dictionary with expiring certification alerts
    """
    try:
        logger.info(f"Checking vendor certification expiry for {organization_id}")

        import asyncio

        found = asyncio.run(_vendor_certification_expiry_check_async(organization_id))

        result = {
            "organization_id": organization_id,
            "check_date": datetime.utcnow().isoformat(),
            "expiring_soon": found["expiring_soon"],
            "expired": found["expired"],
            "vendor_count": found["vendor_count"],
            "truncated": found["truncated"],
        }

        if result["expiring_soon"]:
            logger.warning(f"Found {len(result['expiring_soon'])} vendors with expiring certifications")

        return result

    except Exception as exc:
        logger.error(f"Certification expiry check failed: {exc}")
        raise self.retry(exc=exc, countdown=120)


@shared_task(bind=True, max_retries=3)
def sbom_regeneration(self, sbom_id: str, regeneration_type: str = "standard"):
    """
    Regenerate SBOM for an application with latest component data.

    Updates SBOM with current dependency tree, vulnerability status,
    and compliance information.

    Args:
        sbom_id: SBOM to regenerate
        regeneration_type: Type of regeneration ('standard', 'deep_scan')

    Returns:
        Dictionary with regeneration results
    """
    try:
        logger.info(f"Regenerating SBOM {sbom_id} (type={regeneration_type})")

        import asyncio

        async def _regenerate():
            async with _AsyncSessionLocal() as db:
                # Verify SBOM exists
                sbom_stmt = select(SBOM).where(SBOM.id == sbom_id)
                sbom = (await db.execute(sbom_stmt)).scalar_one_or_none()
                if not sbom:
                    return {"status": "error", "message": f"SBOM {sbom_id} not found"}

                # Count components in this SBOM
                comp_stmt = select(func.count(SBOMComponent.id)).where(
                    SBOMComponent.sbom_id == sbom_id,
                )
                components_count = (await db.execute(comp_stmt)).scalar() or 0

                # Count risks associated with components in this SBOM
                risk_stmt = (
                    select(func.count(SupplyChainRisk.id))
                    .join(SBOMComponent, SBOMComponent.component_id == SupplyChainRisk.component_id)
                    .where(SBOMComponent.sbom_id == sbom_id)
                )
                vuln_count = (await db.execute(risk_stmt)).scalar() or 0

                # Update SBOM timestamp
                sbom.updated_at = datetime.utcnow()
                await db.commit()

                compliance = "compliant" if vuln_count == 0 else "non_compliant"

                return {
                    "components_updated": components_count,
                    "vulnerabilities_updated": vuln_count,
                    "compliance_status": compliance,
                }

        db_result = asyncio.run(_regenerate())

        result = {
            "sbom_id": sbom_id,
            "regeneration_type": regeneration_type,
            "regeneration_started": datetime.utcnow().isoformat(),
            "status": db_result.get("status", "completed"),
            **{k: v for k, v in db_result.items() if k != "status" and k != "message"},
        }

        logger.info(
            f"SBOM regeneration complete: {result.get('components_updated', 0)} "
            f"components, {result.get('vulnerabilities_updated', 0)} vulnerabilities updated",
        )

        return result

    except Exception as exc:
        logger.error(f"SBOM regeneration failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


# Well-known popular packages per ecosystem for the on-demand scan
# (unchanged list).
_TYPOSQUAT_SCAN_POPULAR = {
    "pypi": [
        "requests", "django", "flask", "numpy", "pandas",
        "sqlalchemy", "celery", "boto3", "pillow", "cryptography",
    ],
    "npm": [
        "react", "vue", "angular", "express", "lodash",
        "moment", "axios", "webpack", "typescript", "next",
    ],
}

# The daily sweep's (slightly longer) list - unchanged.
_TYPOSQUAT_SWEEP_POPULAR = {
    "pypi": [
        "requests", "django", "flask", "numpy", "pandas",
        "sqlalchemy", "celery", "boto3", "pillow", "cryptography",
        "urllib3", "pytest", "pydantic", "fastapi", "redis",
    ],
    "npm": [
        "react", "vue", "angular", "express", "lodash",
        "moment", "axios", "webpack", "typescript", "next",
    ],
}


async def _typosquatting_scan_async(
    organization_id: str, package_type: str, threshold: float,
) -> dict[str, Any]:
    """Typosquat candidates among one org's components, one name window at a time.

    ``detect_typosquatting`` scores each name independently, so running it
    per window yields exactly the hits it produced over the whole list.
    """
    analyzer = SupplyChainRiskAnalyzer()
    popular = _TYPOSQUAT_SCAN_POPULAR.get(package_type)
    suspected: list[dict[str, Any]] = []
    scanned = 0
    cap_hit = False
    last_id: str | None = None

    async with _AsyncSessionLocal() as db:
        while scanned < MAX_TYPOSQUAT_PACKAGES_PER_RUN:
            window = min(SUPPLYCHAIN_BATCH_SIZE, MAX_TYPOSQUAT_PACKAGES_PER_RUN - scanned)
            stmt = select(SoftwareComponent.id, SoftwareComponent.name).where(
                and_(
                    SoftwareComponent.organization_id == organization_id,
                    SoftwareComponent.package_type == package_type,
                ),
            )
            if last_id is not None:
                stmt = stmt.where(SoftwareComponent.id > last_id)
            rows = (await db.execute(stmt.order_by(SoftwareComponent.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            if popular:
                suspected.extend(
                    analyzer.detect_typosquatting([r.name for r in rows], popular, threshold),
                )

            if len(rows) < window:
                break
        else:
            cap_hit = True

    if cap_hit:
        logger.warning(
            f"typosquatting_scan: cap of {MAX_TYPOSQUAT_PACKAGES_PER_RUN} packages "
            f"hit for {organization_id}; remainder deferred",
        )
    return {"packages_scanned": scanned, "suspected": suspected, "truncated": cap_hit}


@shared_task(bind=True, max_retries=3)
def typosquatting_scan(
    self,
    organization_id: str,
    package_type: str = "pypi",
    threshold: float = 0.85,
):
    """
    Scan organization dependencies for typosquatting attacks.

    Detects package names similar to popular packages using
    Levenshtein distance comparison.

    Args:
        organization_id: Organization to scan
        package_type: Package manager type
        threshold: Similarity threshold (0-1)

    Returns:
        Dictionary with suspected typosquatting packages
    """
    try:
        logger.info(
            f"Starting typosquatting scan for {organization_id} "
            f"(type={package_type}, threshold={threshold})",
        )

        import asyncio

        found = asyncio.run(
            _typosquatting_scan_async(organization_id, package_type, threshold),
        )
        suspected = found["suspected"]

        result = {
            "organization_id": organization_id,
            "package_type": package_type,
            "scan_date": datetime.utcnow().isoformat(),
            "suspected_typosquats": suspected,
            "packages_scanned": found["packages_scanned"],
            "suspicious_count": len(suspected),
            "truncated": found["truncated"],
        }

        if suspected:
            logger.warning(f"Found {len(suspected)} suspected typosquatting packages")

        return result

    except Exception as exc:
        logger.error(f"Typosquatting scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


class _RowBudget:
    """Per-run row budget shared by every paged read of one sweep."""

    def __init__(self, limit: int) -> None:
        self.remaining = limit
        self.exhausted = False

    def window(self) -> int:
        """Rows the next read may request; 0 (and exhausted) once spent."""
        size = min(SUPPLYCHAIN_BATCH_SIZE, self.remaining)
        if size <= 0:
            self.exhausted = True
        return size

    def spend(self, rows: int) -> None:
        self.remaining -= rows


async def _supplychain_cross_org_sweep_async(factory: Any) -> dict[str, Any]:
    """Async core of ``supplychain_cross_org_sweep``.

    Orgs, components and vendor assessments are all read in keyset windows
    of SUPPLYCHAIN_BATCH_SIZE (columns only), the "already open?" checks run
    once per window as an ``IN (...)`` lookup instead of once per component,
    and new SupplyChainRisk rows are committed per window instead of all at
    the end. One row budget (MAX_SUPPLYCHAIN_SWEEP_ROWS) covers the whole
    run; when it runs out the result says ``truncated``.
    """
    import json as _json

    from src.models.organization import Organization

    totals: dict[str, Any] = {
        "orgs_scanned": 0,
        "typosquat_risks_created": 0,
        "vuln_risks_created": 0,
        "cert_warnings": 0,
    }
    analyzer = SupplyChainRiskAnalyzer()
    budget = _RowBudget(MAX_SUPPLYCHAIN_SWEEP_ROWS)

    async def _open_risk_component_ids(db: Any, component_ids: list[str], risk_type: str) -> set[str]:
        if not component_ids:
            return set()
        return set(
            (
                await db.execute(
                    select(SupplyChainRisk.component_id).where(
                        and_(
                            SupplyChainRisk.component_id.in_(component_ids),
                            SupplyChainRisk.risk_type == risk_type,
                            SupplyChainRisk.status == "open",
                        ),
                    ),
                )
            ).scalars(),
        )

    async with factory() as db:
        last_org: str | None = None
        while not budget.exhausted:
            org_stmt = select(Organization.id)
            if last_org is not None:
                org_stmt = org_stmt.where(Organization.id > last_org)
            org_ids = list(
                (
                    await db.execute(
                        org_stmt.order_by(Organization.id).limit(SUPPLYCHAIN_BATCH_SIZE),
                    )
                ).scalars(),
            )
            if not org_ids:
                break
            last_org = org_ids[-1]

            for org_id in org_ids:
                if budget.exhausted:
                    break
                totals["orgs_scanned"] += 1

                # 1) typosquat
                for pkg_type, popular_list in _TYPOSQUAT_SWEEP_POPULAR.items():
                    last_comp: str | None = None
                    while True:
                        window = budget.window()
                        if not window:
                            break
                        stmt = select(SoftwareComponent.id, SoftwareComponent.name).where(
                            and_(
                                SoftwareComponent.organization_id == org_id,
                                SoftwareComponent.package_type == pkg_type,
                            ),
                        )
                        if last_comp is not None:
                            stmt = stmt.where(SoftwareComponent.id > last_comp)
                        comps = (
                            await db.execute(stmt.order_by(SoftwareComponent.id).limit(window))
                        ).all()
                        if not comps:
                            break
                        last_comp = comps[-1].id
                        budget.spend(len(comps))

                        # Threshold 0.70: the built-in similarity uses a lexical
                        # score where a single-char edit on an 8-char name lands at
                        # ~0.75. 0.85 was so strict it caught nothing in practice.
                        ids_by_name: dict[str, list[str]] = {}
                        for c in comps:
                            ids_by_name.setdefault(c.name, []).append(c.id)
                        suspected = analyzer.detect_typosquatting(
                            list(ids_by_name), popular_list, 0.70,
                        ) or []
                        hit_by_component: dict[str, dict[str, Any]] = {}
                        for hit in suspected:
                            sus_name = (
                                hit.get("component")
                                or hit.get("suspected")
                                or hit.get("suspected_package")
                                or hit.get("package")
                            )
                            for comp_id in ids_by_name.get(sus_name, ()):
                                # First hit per component wins, as before (later
                                # hits found the just-added open risk and skipped).
                                hit_by_component.setdefault(comp_id, hit)

                        already_open = await _open_risk_component_ids(
                            db, list(hit_by_component), "typosquat",
                        )
                        for comp_id, hit in hit_by_component.items():
                            if comp_id in already_open:
                                continue
                            sus_name = hit.get("component") or hit.get("suspected") or hit.get(
                                "suspected_package",
                            ) or hit.get("package")
                            similarity = (
                                hit.get("similarity_score")
                                or hit.get("similarity")
                                or 0.0
                            )
                            db.add(SupplyChainRisk(
                                organization_id=org_id,
                                component_id=comp_id,
                                risk_type="typosquat",
                                severity="high",
                                description=(
                                    f"Package '{sus_name}' is lexically similar to popular "
                                    f"'{hit.get('similar_to', 'unknown')}' ({similarity:.2f})"
                                ),
                                evidence=_json.dumps(hit),
                                status="open",
                                detected_date=datetime.utcnow(),
                            ))
                            totals["typosquat_risks_created"] += 1

                        await db.commit()
                        db.expunge_all()
                        if len(comps) < window:
                            break

                # 2) vuln cross-ref
                last_comp = None
                while True:
                    window = budget.window()
                    if not window:
                        break
                    stmt = select(
                        SoftwareComponent.id,
                        SoftwareComponent.name,
                        SoftwareComponent.version,
                        SoftwareComponent.risk_score,
                        SoftwareComponent.known_vulnerabilities_count,
                    ).where(
                        and_(
                            SoftwareComponent.organization_id == org_id,
                            SoftwareComponent.known_vulnerabilities_count > 0,
                        ),
                    )
                    if last_comp is not None:
                        stmt = stmt.where(SoftwareComponent.id > last_comp)
                    vuln_comps = (
                        await db.execute(stmt.order_by(SoftwareComponent.id).limit(window))
                    ).all()
                    if not vuln_comps:
                        break
                    last_comp = vuln_comps[-1].id
                    budget.spend(len(vuln_comps))

                    already_open = await _open_risk_component_ids(
                        db, [c.id for c in vuln_comps], "vulnerability",
                    )
                    for comp in vuln_comps:
                        if comp.id in already_open:
                            continue
                        sev = "critical" if (comp.risk_score or 0) >= 9 else (
                            "high" if (comp.risk_score or 0) >= 7 else "medium"
                        )
                        db.add(SupplyChainRisk(
                            organization_id=org_id,
                            component_id=comp.id,
                            risk_type="vulnerability",
                            severity=sev,
                            description=(
                                f"{comp.name}@{comp.version} carries "
                                f"{comp.known_vulnerabilities_count} known CVE(s); risk score {comp.risk_score}"
                            ),
                            status="open",
                            detected_date=datetime.utcnow(),
                        ))
                        totals["vuln_risks_created"] += 1

                    await db.commit()
                    db.expunge_all()
                    if len(vuln_comps) < window:
                        break

                # 3) vendor cert expiry (90d)
                now = datetime.utcnow()
                last_vendor: str | None = None
                while True:
                    window = budget.window()
                    if not window:
                        break
                    vstmt = select(VendorAssessment.id, VendorAssessment.certifications).where(
                        VendorAssessment.organization_id == org_id,
                    )
                    if last_vendor is not None:
                        vstmt = vstmt.where(VendorAssessment.id > last_vendor)
                    vendors = (
                        await db.execute(vstmt.order_by(VendorAssessment.id).limit(window))
                    ).all()
                    if not vendors:
                        break
                    last_vendor = vendors[-1].id
                    budget.spend(len(vendors))

                    for v in vendors:
                        if not v.certifications:
                            continue
                        try:
                            certs = _json.loads(v.certifications) if isinstance(
                                v.certifications, str,
                            ) else v.certifications
                        except (_json.JSONDecodeError, TypeError):
                            continue
                        if not isinstance(certs, list):
                            continue
                        for cert in certs:
                            if not isinstance(cert, dict):
                                continue
                            exp = cert.get("expiry_date")
                            if not exp:
                                continue
                            try:
                                exp_dt = datetime.fromisoformat(exp)
                            except (ValueError, TypeError):
                                continue
                            days = (exp_dt - now).days
                            if 0 <= days <= 90:
                                totals["cert_warnings"] += 1
                    if len(vendors) < window:
                        break

            if len(org_ids) < SUPPLYCHAIN_BATCH_SIZE:
                break

        await db.commit()

    totals["truncated"] = budget.exhausted
    if budget.exhausted:
        logger.warning(
            f"supplychain_cross_org_sweep: row budget {MAX_SUPPLYCHAIN_SWEEP_ROWS} "
            f"exhausted; remainder deferred to the next run",
        )
    logger.info(f"supplychain_cross_org_sweep: {totals}")
    return totals


@shared_task(bind=True, max_retries=1)
def supplychain_cross_org_sweep(self):
    """Daily cross-org supply-chain sweep.

    Iterates every Organization and runs three real queries per org:
      1. Typosquat detection against the org's declared SoftwareComponents
         (pypi + npm) — creates SupplyChainRisk rows on matches.
      2. CVE cross-reference: every component with declared
         known_vulnerabilities_count > 0 gets a SupplyChainRisk row
         linking to the Vulnerability table by CVE id.
      3. Vendor cert-expiry fires a WARN row for certs within 90 days.

    Without this, the beat-scheduled `supplychain-typosquat-sweep` fires
    into the void. Sweep is idempotent: skips risks that already exist
    for the same (component, risk_type) pair.
    """
    import asyncio as _asyncio

    from sqlalchemy.ext.asyncio import AsyncSession as _AS
    from sqlalchemy.ext.asyncio import create_async_engine as _cae
    from sqlalchemy.orm import sessionmaker as _sm
    from sqlalchemy.pool import NullPool

    async def _sweep() -> dict[str, Any]:
        engine = _cae(settings.database_url, echo=False, poolclass=NullPool)
        factory = _sm(engine, class_=_AS, expire_on_commit=False)
        try:
            return await _supplychain_cross_org_sweep_async(factory)
        finally:
            await engine.dispose()

    try:
        loop = _asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_sweep())
        finally:
            loop.close()
    except Exception as exc:
        logger.warning(f"supplychain_cross_org_sweep failed: {exc}")
        return {"error": str(exc)[:200]}
