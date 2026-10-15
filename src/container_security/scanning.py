"""Container image scans through a real scanner (wave 4).

An image is scanned by one of two real paths, tried in this order:

1. An installed scanner integration (connector ``trivy``, ``grype`` or
   ``anchore``, status ``active``) in the caller's organisation. PySOAR posts
   ``{"image": "<ref>"}`` to the integration's ``scan_path`` (config, default
   ``/scan``) under its configured ``base_url``. The call is confined to that
   base URL and pinned (``ActionExecutor._resolve_generic_target`` +
   ``merge_pinned_kwargs``), and the response must be a Trivy JSON report
   (``Results[].Vulnerabilities[]``) or a Grype JSON report (``matches[]``).
2. An endpoint agent enrolled with the ``container_scan`` capability: a
   ``scan_container_image`` command is queued (``AgentService.issue_command``)
   and the agent's stdout (the scanner's JSON report) is applied when the
   result arrives, by the read routes or the ``reconcile_image_scans`` beat
   task.

With neither, the image is marked ``awaiting_integration`` with the reason;
nothing is scanned and no count, score or compliance verdict changes.
A completed scan replaces the image's ImageVulnerability rows (deduplicated per
(image, CVE, package, version)); counts, risk score and compliance are
recomputed from the stored rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.container_security.engine import ImageScanner
from src.container_security.models import ContainerImage, ContainerImageScan, ImageVulnerability
from src.core.logging import get_logger
from src.core.utils import safe_json_loads

logger = get_logger(__name__)

SCANNER_CONNECTORS = ("trivy", "grype", "anchore")
SCAN_CAPABILITY = "container_scan"
SCAN_ACTION = "scan_container_image"
PENDING_SCAN_STATES = ("pending", "awaiting_approval")
FAILED_COMMAND_STATES = ("failed", "rejected", "expired", "denied", "cancelled")
#: Largest scanner report accepted (characters of JSON).
MAX_REPORT_CHARS = 20_000_000
#: Vulnerabilities kept from one report.
MAX_VULNS_PER_REPORT = 20_000
INTEGRATION_TIMEOUT = 300.0
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")


def image_ref(image: ContainerImage) -> str:
    ref = f"{image.registry}/{image.repository}" if image.registry else image.repository
    ref = f"{ref}:{image.tag}"
    digest = (image.digest_sha256 or "").strip()
    if digest:
        ref = f"{ref}@{digest if digest.startswith('sha256:') else 'sha256:' + digest}"
    return ref


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------


class ReportError(ValueError):
    """The scanner output is not a Trivy or Grype JSON report."""


def _sev(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in SEVERITIES else "unknown"


def _float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _trivy_cvss(vuln: dict[str, Any]) -> Optional[float]:
    best: Optional[float] = None
    for source in (vuln.get("CVSS") or {}).values():
        if isinstance(source, dict):
            score = _float(source.get("V3Score") or source.get("V2Score"))
            if score is not None and (best is None or score > best):
                best = score
    return best


def parse_report(report: Any) -> tuple[str, list[dict[str, Any]]]:
    """Return ``(scanner, vulnerabilities)`` from a Trivy or Grype JSON report."""
    if isinstance(report, str):
        if len(report) > MAX_REPORT_CHARS:
            raise ReportError(f"report larger than {MAX_REPORT_CHARS} characters")
        try:
            report = json.loads(report)
        except json.JSONDecodeError as exc:
            raise ReportError(f"report is not JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise ReportError("report is not a JSON object")
    vulns: list[dict[str, Any]] = []
    if "Results" in report or report.get("SchemaVersion") is not None:
        for result in report.get("Results") or []:
            if not isinstance(result, dict):
                continue
            for v in result.get("Vulnerabilities") or []:
                if not isinstance(v, dict) or not v.get("VulnerabilityID") or not v.get("PkgName"):
                    continue
                vulns.append({
                    "cve_id": str(v["VulnerabilityID"])[:100],
                    "package": str(v["PkgName"])[:255],
                    "version": str(v.get("InstalledVersion") or "")[:100],
                    "fixed_version": (str(v["FixedVersion"])[:100] if v.get("FixedVersion") else None),
                    "severity": _sev(v.get("Severity")),
                    "cvss": _trivy_cvss(v),
                    "description": str(v.get("Title") or v.get("Description") or "")[:4000] or None,
                    "layer": str((v.get("Layer") or {}).get("DiffID") or "")[:255] or None,
                })
        return "trivy", vulns[:MAX_VULNS_PER_REPORT]
    if "matches" in report:
        for m in report.get("matches") or []:
            if not isinstance(m, dict):
                continue
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            if not vuln.get("id") or not art.get("name"):
                continue
            fixes = (vuln.get("fix") or {}).get("versions") or []
            scores = [
                _float((c.get("metrics") or {}).get("baseScore"))
                for c in vuln.get("cvss") or [] if isinstance(c, dict)
            ]
            scores = [s for s in scores if s is not None]
            vulns.append({
                "cve_id": str(vuln["id"])[:100],
                "package": str(art["name"])[:255],
                "version": str(art.get("version") or "")[:100],
                "fixed_version": str(fixes[0])[:100] if fixes else None,
                "severity": _sev(vuln.get("severity")),
                "cvss": max(scores) if scores else None,
                "description": str(vuln.get("description") or "")[:4000] or None,
                "layer": None,
            })
        return "grype", vulns[:MAX_VULNS_PER_REPORT]
    raise ReportError("report is neither a Trivy (Results) nor a Grype (matches) JSON report")


# ---------------------------------------------------------------------------
# Applying a report
# ---------------------------------------------------------------------------


async def apply_report(
    db: AsyncSession,
    image: ContainerImage,
    scan: ContainerImageScan,
    scanner: str,
    vulns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace the image's vulnerabilities with the report; returns the new critical/high ones."""
    org_id = image.organization_id
    now = datetime.now(timezone.utc)
    existing = {
        (v.cve_id, v.package_name, v.package_version): v
        for v in (await db.execute(
            select(ImageVulnerability).where(
                ImageVulnerability.image_id == image.id,
                ImageVulnerability.organization_id == org_id,
            ),
        )).scalars()
    }
    seen: set[tuple[str, str, str]] = set()
    new_rows = updated = 0
    new_serious: list[dict[str, Any]] = []
    for v in vulns:
        key = (v["cve_id"], v["package"], v["version"])
        if key in seen:
            continue
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = ImageVulnerability(
                image_id=image.id, organization_id=org_id,
                cve_id=v["cve_id"], package_name=v["package"], package_version=v["version"],
                severity=v["severity"],
            )
            db.add(row)
            new_rows += 1
            if v["severity"] in ("critical", "high"):
                new_serious.append(v)
        else:
            updated += 1
        row.severity = v["severity"]
        row.fixed_version = v["fixed_version"]
        row.cvss_score = v["cvss"]
        row.description = v["description"]
        row.layer_introduced = v["layer"]
        row.remediation = (
            f"Upgrade {v['package']} to {v['fixed_version']}" if v["fixed_version"] else None
        )
    stale = [row.id for key, row in existing.items() if key not in seen]
    if stale:
        await db.execute(delete(ImageVulnerability).where(
            ImageVulnerability.id.in_(stale), ImageVulnerability.organization_id == org_id,
        ))

    counts = dict.fromkeys(SEVERITIES, 0)
    for v in {(x["cve_id"], x["package"], x["version"]): x for x in vulns}.values():
        counts[v["severity"]] += 1
    image.vulnerability_count_critical = counts["critical"]
    image.vulnerability_count_high = counts["high"]
    image.vulnerability_count_medium = counts["medium"]
    image.vulnerability_count_low = counts["low"]
    image.risk_score = ImageScanner().calculate_image_risk_score(
        counts["critical"], counts["high"], counts["medium"],
        bool(image.is_signed), bool(image.sbom_generated),
    )
    # A real scanner reported: zero critical/high is now evidence.
    image.compliance_status = "non_compliant" if (counts["critical"] or counts["high"]) else "compliant"
    image.scanned_at = now
    image.scan_status = "completed"
    image.scan_error = None
    image.last_scan_id = scan.id

    scan.status = "completed"
    scan.scanner = scanner
    scan.finished_at = now
    scan.error = None
    scan.vulnerabilities_new = new_rows
    scan.vulnerabilities_updated = updated
    scan.vulnerabilities_total = len(seen)
    await db.flush()
    return new_serious


def fail_scan(image: Optional[ContainerImage], scan: ContainerImageScan, error: str) -> None:
    now = datetime.now(timezone.utc)
    scan.status = "failed"
    scan.error = error[:4000]
    scan.finished_at = now
    if image is not None and image.last_scan_id in (None, scan.id):
        image.scan_status = "failed"
        image.scan_error = scan.error
        image.last_scan_id = scan.id


async def raise_alerts(db: AsyncSession, image: ContainerImage, serious: list[dict[str, Any]]) -> None:
    """One alert per newly found critical/high vulnerability, stamped with the org."""
    if not serious:
        return
    from src.services.automation import AutomationService

    automation = AutomationService(db)
    name = f"{image.repository}:{image.tag}"
    for v in serious[:50]:
        alert = await automation.on_container_finding(
            image_name=name, finding_type=v["cve_id"], cve_id=v["cve_id"],
            severity=v["severity"], organization_id=image.organization_id,
        )
        if alert is not None and getattr(alert, "organization_id", None) is None:
            alert.organization_id = image.organization_id
    await db.flush()


# ---------------------------------------------------------------------------
# Scan dispatch
# ---------------------------------------------------------------------------


@dataclass
class ScanDispatch:
    status: str  # completed | pending | awaiting_approval | failed | awaiting_integration
    detail: str
    scan: Optional[ContainerImageScan] = None
    method: Optional[str] = None


async def scanner_integrations(db: AsyncSession, org_id: str) -> list[Any]:
    from src.integrations.models import InstalledIntegration, IntegrationStatus

    rows = (await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.status == IntegrationStatus.ACTIVE.value,
        ),
    )).scalars().all()
    return [r for r in rows if _connector_name(r) in SCANNER_CONNECTORS]


def _connector_name(integration: Any) -> str:
    connector = integration.connector
    return (connector.name if connector is not None else str(integration.connector_id or "")).lower()


async def scan_agents(db: AsyncSession, org_id: str) -> list[Any]:
    from src.agents.models import EndpointAgent

    rows = (await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.organization_id == org_id,
            EndpointAgent.status == "active",
        ).order_by(EndpointAgent.hostname).limit(500),
    )).scalars().all()
    return [a for a in rows if SCAN_CAPABILITY in (a.capabilities or [])]


def _inner_transport() -> Optional[httpx.AsyncBaseTransport]:
    """Transport for scanner-integration calls (None = default). Tests replace it."""
    return None


async def _call_integration(integration: Any, ref: str) -> Any:
    from src.integrations.engine import ActionExecutor
    from src.integrations.netguard import merge_pinned_kwargs

    config = safe_json_loads(integration.config_encrypted, {}) or {}
    if not isinstance(config, dict):
        config = {}
    credentials = ActionExecutor()._decrypt_secret_json(integration.auth_credentials_encrypted)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    token = credentials.get("api_key") or credentials.get("token") or credentials.get("bearer_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    pinned = await ActionExecutor()._resolve_generic_target(str(config.get("scan_path") or "/scan"), config)
    pin = merge_pinned_kwargs(pinned.target, headers)
    async with httpx.AsyncClient(
        timeout=INTEGRATION_TIMEOUT, follow_redirects=False, transport=_inner_transport(),
    ) as client:
        resp = await client.post(
            str(pinned), headers=pin["headers"], extensions=pin["extensions"], json={"image": ref},
        )
    if resp.status_code >= 400:
        raise ReportError(f"scanner integration answered HTTP {resp.status_code}")
    if len(resp.content) > MAX_REPORT_CHARS:
        raise ReportError(f"report larger than {MAX_REPORT_CHARS} bytes")
    try:
        return resp.json()
    except ValueError as exc:
        raise ReportError("scanner integration did not answer with JSON") from exc


async def request_scan(
    db: AsyncSession,
    image: ContainerImage,
    *,
    requested_by: Optional[str],
    agent_id: Optional[str] = None,
    scanner: str = "trivy",
) -> ScanDispatch:
    """Scan ``image`` through an installed integration or an agent, else awaiting_integration."""
    from src.integrations.netguard import OutboundTargetRefused

    org_id = image.organization_id
    ref = image_ref(image)
    now = datetime.now(timezone.utc)

    integrations = [] if agent_id else await scanner_integrations(db, org_id)
    if integrations:
        integration = integrations[0]
        scan = ContainerImageScan(
            image_id=image.id, organization_id=org_id, method="integration",
            scanner=_connector_name(integration), status="pending",
            integration_id=integration.id, requested_by=requested_by, started_at=now,
        )
        db.add(scan)
        await db.flush()
        try:
            report = await _call_integration(integration, ref)
            used, vulns = parse_report(report)
        except (ReportError, OutboundTargetRefused, httpx.HTTPError, ValueError) as exc:
            error = f"scanner integration {integration.display_name}: {type(exc).__name__}: {exc}"
            fail_scan(image, scan, error)
            await db.flush()
            return ScanDispatch("failed", error, scan, "integration")
        serious = await apply_report(db, image, scan, used, vulns)
        await raise_alerts(db, image, serious)
        return ScanDispatch(
            "completed", f"scanned by {integration.display_name} ({used})", scan, "integration",
        )

    agents = await scan_agents(db, org_id)
    if agent_id:
        agents = [a for a in agents if a.id == agent_id]
    if agents:
        from src.agents.service import AgentService, AgentServiceError

        agent = agents[0]
        scan = ContainerImageScan(
            image_id=image.id, organization_id=org_id, method="agent",
            scanner=scanner, status="pending", agent_id=agent.id,
            requested_by=requested_by, started_at=now,
        )
        db.add(scan)
        await db.flush()
        try:
            cmd = await AgentService(db).issue_command(
                agent=agent, action=SCAN_ACTION,
                payload={"image_ref": ref, "scanner": scanner, "scan_id": scan.id},
                issued_by=requested_by,
            )
        except AgentServiceError as exc:
            fail_scan(image, scan, f"agent {agent.hostname} refused the command: {exc}")
            await db.flush()
            return ScanDispatch("failed", scan.error or "", scan, "agent")
        scan.command_id = cmd.id
        scan.status = "awaiting_approval" if cmd.status == "awaiting_approval" else "pending"
        image.scan_status = scan.status
        image.scan_error = None
        image.last_scan_id = scan.id
        await db.flush()
        return ScanDispatch(
            scan.status, f"{SCAN_ACTION} queued on agent {agent.hostname} (command {cmd.id})", scan, "agent",
        )

    reason = (
        "No image scanner is available: install an active Trivy, Grype or Anchore integration, "
        f"or enrol an endpoint agent with the '{SCAN_CAPABILITY}' capability."
        if not agent_id else f"agent {agent_id} is not an active '{SCAN_CAPABILITY}' agent in this organisation"
    )
    if image.scan_status in (None, "not_scanned", "awaiting_integration"):
        image.scan_status = "awaiting_integration"
        image.scan_error = reason
    await db.flush()
    return ScanDispatch("awaiting_integration", reason)


def _report_from_result(result: Any) -> Any:
    artifacts = result.artifacts if isinstance(result.artifacts, dict) else {}
    if isinstance(artifacts.get("report"), (dict, str)):
        return artifacts["report"]
    return result.stdout or ""


async def reconcile_scan(
    db: AsyncSession,
    scan: ContainerImageScan,
    *,
    command_status: Optional[str] = None,
    result: Any = None,
    loaded: bool = False,
) -> bool:
    """Apply the agent's result to a pending scan. Returns True when it changed."""
    from src.agents.models import AgentCommand, AgentResult

    if scan.status not in PENDING_SCAN_STATES or not scan.command_id:
        return False
    if not loaded:
        result = (await db.execute(
            select(AgentResult).where(AgentResult.command_id == scan.command_id)
            .order_by(AgentResult.reported_at.desc()).limit(1),
        )).scalar_one_or_none()
        command_status = (await db.execute(
            select(AgentCommand.status).where(AgentCommand.id == scan.command_id),
        )).scalar_one_or_none()
    image = (await db.execute(
        select(ContainerImage).where(
            ContainerImage.id == scan.image_id,
            ContainerImage.organization_id == scan.organization_id,
        ),
    )).scalar_one_or_none()

    if result is None:
        if command_status in FAILED_COMMAND_STATES or command_status is None:
            fail_scan(image, scan, f"agent command {command_status or 'missing'}")
            await db.flush()
            return True
        wanted = "awaiting_approval" if command_status == "awaiting_approval" else "pending"
        if scan.status != wanted:
            scan.status = wanted
            if image is not None and image.last_scan_id == scan.id:
                image.scan_status = wanted
            await db.flush()
            return True
        return False

    if result.status != "success":
        fail_scan(image, scan, (result.stderr or f"agent reported {result.status}")[:4000])
        await db.flush()
        return True
    if image is None:
        fail_scan(None, scan, "image was deleted before the scan finished")
        await db.flush()
        return True
    try:
        used, vulns = parse_report(_report_from_result(result))
    except ReportError as exc:
        fail_scan(image, scan, f"agent output is not a scanner report: {exc}")
        await db.flush()
        return True
    serious = await apply_report(db, image, scan, used, vulns)
    await raise_alerts(db, image, serious)
    logger.info("container_scan_reconciled", scan_id=scan.id, image_id=image.id, vulns=scan.vulnerabilities_total)
    return True

