"""External scanner result parsers.

Previously ``POST /exposure/scans/import`` swallowed the entire
``scan_data`` payload and returned ``vulnerabilities_imported: 0`` —
a Nessus or Qualys export handed to the platform vanished without a
trace, and the Vulnerabilities tab stayed empty forever.

This module parses the common scanner outputs into a canonical
finding shape and exposes a single ``ingest_findings`` entrypoint
that creates/updates ``ExposureVulnerability`` + ``AssetVulnerability``
rows. It accepts Nessus (JSON export, CSV, or raw .nessus XML),
Qualys (JSON), Tenable.io (JSON), generic JSON arrays, and CSVs
with recognizable column headers. Unrecognized formats return an
empty finding list plus an error string so the caller sees "imported
0 out of 47 findings — format not recognized" rather than silent
success.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.exposure.models import (
    AssetVulnerability,
    ExposureAsset,
    ExposureVulnerability,
)

logger = logging.getLogger(__name__)


@dataclass
class ParsedFinding:
    """Canonical shape produced by every parser."""

    cve_id: Optional[str] = None
    title: str = ""
    description: Optional[str] = None
    severity: str = "medium"
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    asset_identifier: Optional[str] = None  # hostname / ip / fqdn
    asset_ip: Optional[str] = None
    asset_hostname: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    solution: Optional[str] = None
    references: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Severity / score normalizers
# --------------------------------------------------------------------------- #


_SEV_MAP = {
    "0": "informational", "info": "informational", "informational": "informational", "none": "informational",
    "1": "low", "low": "low",
    "2": "medium", "medium": "medium", "moderate": "medium",
    "3": "high", "high": "high",
    "4": "critical", "critical": "critical",
}


def _normalize_severity(s: Any) -> str:
    if s is None:
        return "medium"
    key = str(s).strip().lower()
    return _SEV_MAP.get(key, "medium")


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "informational"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _extract_cve(text: Any) -> Optional[str]:
    if not text:
        return None
    m = _CVE_RE.search(str(text))
    return m.group(0).upper() if m else None


# --------------------------------------------------------------------------- #
# Per-format parsers
# --------------------------------------------------------------------------- #


def _parse_nessus_xml(xml_text: str) -> list[ParsedFinding]:
    """Parse a .nessus XML report export."""
    out: list[ParsedFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("Nessus XML parse failed: %s", exc)
        return out

    # Nessus structure: <NessusClientData_v2>/<Report>/<ReportHost>/<ReportItem>
    for host in root.iter("ReportHost"):
        host_name = host.get("name") or ""
        host_ip = host_name
        for tag in host.findall("./HostProperties/tag"):
            if tag.get("name") == "host-ip":
                host_ip = tag.text or host_name

        for item in host.iter("ReportItem"):
            sev_num = item.get("severity", "2")
            plugin_name = item.get("pluginName") or "Unknown finding"
            port = item.get("port")
            protocol = item.get("protocol")
            desc = (item.findtext("description") or "").strip()
            solution = (item.findtext("solution") or "").strip() or None
            cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
            cvss_v3 = float(cvss) if cvss and cvss.replace(".", "", 1).isdigit() else None
            cve = item.findtext("cve") or _extract_cve(plugin_name) or _extract_cve(desc)
            refs = [e.text for e in item.findall("see_also") if e.text]
            out.append(
                ParsedFinding(
                    cve_id=cve,
                    title=plugin_name,
                    description=desc or None,
                    severity=_normalize_severity(sev_num),
                    cvss_v3_score=cvss_v3,
                    asset_identifier=host_name,
                    asset_ip=host_ip,
                    asset_hostname=host_name,
                    port=int(port) if port and port.isdigit() else None,
                    protocol=protocol,
                    solution=solution,
                    references=refs,
                )
            )
    return out


def _parse_nessus_json(payload: Any) -> list[ParsedFinding]:
    """Parse a Tenable.io / Nessus-style JSON export."""
    out: list[ParsedFinding] = []
    # Tenable.io exports have `vulnerabilities` or `hosts[].vulnerabilities`
    vulns = []
    if isinstance(payload, dict):
        if "vulnerabilities" in payload and isinstance(payload["vulnerabilities"], list):
            vulns = payload["vulnerabilities"]
        elif "hosts" in payload and isinstance(payload["hosts"], list):
            for host in payload["hosts"]:
                host_name = host.get("hostname") or host.get("ip") or host.get("host") or ""
                for v in host.get("vulnerabilities", []) or []:
                    v = dict(v)
                    v.setdefault("asset_hostname", host_name)
                    v.setdefault("asset_ip", host.get("ip"))
                    vulns.append(v)
    elif isinstance(payload, list):
        vulns = payload

    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = v.get("cve") or _extract_cve(v.get("plugin_name") or v.get("name") or v.get("title"))
        cvss = v.get("cvss3_base_score") or v.get("cvss_base_score") or v.get("cvss3") or v.get("cvss")
        try:
            cvss_f = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_f = None
        sev = v.get("severity") or v.get("risk_factor")
        out.append(
            ParsedFinding(
                cve_id=cve,
                title=v.get("plugin_name") or v.get("name") or v.get("title") or "Finding",
                description=v.get("description") or v.get("synopsis"),
                severity=_normalize_severity(sev) if sev is not None else _severity_from_cvss(cvss_f),
                cvss_v3_score=cvss_f,
                asset_identifier=v.get("asset") or v.get("host") or v.get("asset_hostname") or v.get("asset_ip"),
                asset_ip=v.get("asset_ip") or v.get("ip"),
                asset_hostname=v.get("asset_hostname") or v.get("hostname"),
                port=v.get("port") if isinstance(v.get("port"), int) else None,
                protocol=v.get("protocol"),
                solution=v.get("solution"),
                references=v.get("references") if isinstance(v.get("references"), list) else [],
            )
        )
    return out


def _parse_qualys_json(payload: Any) -> list[ParsedFinding]:
    """Parse a Qualys JSON export."""
    out: list[ParsedFinding] = []
    items = []
    if isinstance(payload, dict):
        items = payload.get("vulnerabilities") or payload.get("findings") or payload.get("results") or []
    elif isinstance(payload, list):
        items = payload

    for v in items:
        if not isinstance(v, dict):
            continue
        cve = v.get("cve_id") or v.get("cve") or _extract_cve(v.get("title") or v.get("name"))
        cvss = v.get("cvss3_base") or v.get("cvss_base") or v.get("cvss")
        try:
            cvss_f = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_f = None
        sev_in = v.get("severity")
        if isinstance(sev_in, int) or (isinstance(sev_in, str) and sev_in.isdigit()):
            # Qualys severity 1..5 maps to info..critical
            num = int(sev_in)
            sev = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(num, "medium")
        else:
            sev = _normalize_severity(sev_in) if sev_in else _severity_from_cvss(cvss_f)
        out.append(
            ParsedFinding(
                cve_id=cve,
                title=v.get("title") or v.get("name") or "Finding",
                description=v.get("description") or v.get("threat"),
                severity=sev,
                cvss_v3_score=cvss_f,
                asset_identifier=v.get("asset") or v.get("host") or v.get("ip"),
                asset_ip=v.get("ip"),
                asset_hostname=v.get("hostname") or v.get("dns"),
                port=v.get("port") if isinstance(v.get("port"), int) else None,
                protocol=v.get("protocol"),
                solution=v.get("solution") or v.get("remediation"),
                references=v.get("references") if isinstance(v.get("references"), list) else [],
            )
        )
    return out


def _parse_csv(csv_text: str) -> list[ParsedFinding]:
    """Parse a CSV export. Works for Nessus CSV, Qualys CSV, and the
    generic "Host,IP,Port,CVE,Severity,CVSS,Title,Description" format."""
    out: list[ParsedFinding] = []
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        lower = {k.lower().strip(): v for k, v in row.items() if k}
        cve = (
            lower.get("cve")
            or lower.get("cve id")
            or lower.get("cve_id")
            or _extract_cve(lower.get("title") or lower.get("name") or lower.get("plugin name"))
        )
        cvss = lower.get("cvss") or lower.get("cvss v3") or lower.get("cvss_v3") or lower.get("cvss3")
        try:
            cvss_f = float(cvss) if cvss else None
        except (TypeError, ValueError):
            cvss_f = None
        sev = lower.get("severity") or lower.get("risk")
        port = lower.get("port")
        out.append(
            ParsedFinding(
                cve_id=cve,
                title=lower.get("title") or lower.get("name") or lower.get("plugin name") or "Finding",
                description=lower.get("description") or lower.get("synopsis"),
                severity=_normalize_severity(sev) if sev else _severity_from_cvss(cvss_f),
                cvss_v3_score=cvss_f,
                asset_identifier=lower.get("host") or lower.get("ip") or lower.get("hostname") or lower.get("asset"),
                asset_ip=lower.get("ip") or lower.get("ip address"),
                asset_hostname=lower.get("hostname") or lower.get("dns") or lower.get("host"),
                port=int(port) if port and str(port).isdigit() else None,
                protocol=lower.get("protocol"),
                solution=lower.get("solution") or lower.get("remediation"),
                references=[],
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Public entrypoints
# --------------------------------------------------------------------------- #


def parse_scan_data(scan_format: str, scan_data: str) -> tuple[list[ParsedFinding], list[str]]:
    """Dispatch on format. Returns (findings, errors)."""
    errors: list[str] = []
    fmt = (scan_format or "").lower().strip()
    data = (scan_data or "").strip()
    if not data:
        return [], ["scan_data is empty"]

    # Auto-detect by sniffing the payload if the format is generic.
    if fmt in ("auto", "", "generic"):
        if data.startswith("<?xml") or data.startswith("<NessusClientData"):
            fmt = "nessus_xml"
        elif data[0] in ("{", "["):
            fmt = "json"
        else:
            fmt = "csv"

    try:
        if fmt in ("nessus", "nessus_xml", "xml"):
            return _parse_nessus_xml(data), errors
        if fmt in ("nessus_json", "tenable", "tenable_io"):
            return _parse_nessus_json(json.loads(data)), errors
        if fmt in ("qualys", "qualys_vm", "qualys_json"):
            return _parse_qualys_json(json.loads(data)), errors
        if fmt == "json":
            payload = json.loads(data)
            # Try Nessus then Qualys then generic list — merge whichever
            # produces findings.
            for parser in (_parse_nessus_json, _parse_qualys_json):
                findings = parser(payload)
                if findings:
                    return findings, errors
            if isinstance(payload, list):
                return _parse_nessus_json(payload), errors
            return [], [f"JSON payload shape not recognized (keys={list(payload.keys()) if isinstance(payload, dict) else 'list'})"]
        if fmt in ("csv", "openvas_csv"):
            return _parse_csv(data), errors
    except (json.JSONDecodeError, ET.ParseError) as exc:
        return [], [f"Parse error ({fmt}): {exc}"]
    except Exception as exc:  # noqa: BLE001
        logger.error("Scan parser error: %s", exc, exc_info=True)
        return [], [f"Unexpected parser error: {exc}"]

    return [], [f"Unsupported scan_format: {scan_format!r}"]


async def _get_or_create_asset(
    db: AsyncSession,
    finding: ParsedFinding,
    organization_id: str,
) -> Optional[ExposureAsset]:
    """Find an existing asset by hostname/IP or create a minimal one."""
    ident = finding.asset_hostname or finding.asset_ip or finding.asset_identifier
    if not ident or not organization_id:
        return None

    # Try hostname then IP
    match = None
    if finding.asset_hostname:
        res = await db.execute(
            select(ExposureAsset).where(
                ExposureAsset.hostname == finding.asset_hostname,
                ExposureAsset.organization_id == organization_id,
            ).limit(1)
        )
        match = res.scalars().first()
    if match is None and finding.asset_ip:
        res = await db.execute(
            select(ExposureAsset).where(
                ExposureAsset.ip_address == finding.asset_ip,
                ExposureAsset.organization_id == organization_id,
            ).limit(1)
        )
        match = res.scalars().first()
    if match:
        return match

    new_asset = ExposureAsset(
        name=ident[:255],
        asset_type="host",
        hostname=finding.asset_hostname,
        ip_address=finding.asset_ip,
        environment="unknown",
        criticality="medium",
        is_monitored=True,
        organization_id=organization_id,
    )
    db.add(new_asset)
    await db.flush()
    return new_asset


async def _get_or_create_vulnerability(
    db: AsyncSession,
    finding: ParsedFinding,
    organization_id: str,
) -> ExposureVulnerability:
    """Upsert a vulnerability row. Key by CVE when available, else by title."""
    existing: Optional[ExposureVulnerability] = None
    if finding.cve_id:
        res = await db.execute(
            select(ExposureVulnerability).where(
                ExposureVulnerability.cve_id == finding.cve_id,
                ExposureVulnerability.organization_id == organization_id,
            ).limit(1)
        )
        existing = res.scalars().first()
    if existing is None:
        res = await db.execute(
            select(ExposureVulnerability).where(
                ExposureVulnerability.title == finding.title,
                ExposureVulnerability.organization_id == organization_id,
            ).limit(1)
        )
        existing = res.scalars().first()

    if existing:
        # Refresh severity/cvss if the new scan has richer data.
        if finding.cvss_v3_score and not existing.cvss_v3_score:
            existing.cvss_v3_score = finding.cvss_v3_score
        if finding.severity and existing.severity != finding.severity:
            # Only escalate severity (critical > high > medium > low > informational).
            order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if order.get(finding.severity, 0) > order.get(existing.severity, 0):
                existing.severity = finding.severity
        return existing

    vuln = ExposureVulnerability(
        cve_id=finding.cve_id,
        title=(finding.title or "Finding")[:500],
        description=finding.description,
        severity=finding.severity,
        cvss_v3_score=finding.cvss_v3_score,
        cvss_v2_score=finding.cvss_v2_score,
        references=finding.references or [],
        organization_id=organization_id,
    )
    db.add(vuln)
    await db.flush()
    return vuln


async def ingest_findings(
    db: AsyncSession,
    findings: list[ParsedFinding],
    scanner: str,
    scan_id: str,
    organization_id: str,
) -> tuple[int, int, list[str]]:
    """Persist parsed findings as Asset + Vulnerability + AssetVulnerability rows.

    Returns ``(vulnerabilities_imported, assets_updated, errors)``.
    vulnerabilities_imported is the number of NEW AssetVulnerability
    rows created (existing ones are re-detected by bumping detected_at).
    assets_updated is the count of distinct assets that received at
    least one finding (existing or new).
    """
    errors: list[str] = []
    created = 0
    touched_assets: set[str] = set()

    for f in findings:
        try:
            asset = await _get_or_create_asset(db, f, organization_id)
            if asset is None:
                errors.append(f"No asset identifier on finding: {f.title[:80]}")
                continue
            touched_assets.add(asset.id)
            vuln = await _get_or_create_vulnerability(db, f, organization_id)

            # Upsert the asset-vulnerability join so re-imports advance
            # detected_at without duplicating rows.
            res = await db.execute(
                select(AssetVulnerability).where(
                    AssetVulnerability.asset_id == asset.id,
                    AssetVulnerability.vulnerability_id == vuln.id,
                ).limit(1)
            )
            join = res.scalars().first()
            if join:
                join.detected_at = datetime.now(timezone.utc)
                join.scan_reference = scan_id
                join.detected_by = scanner
            else:
                join = AssetVulnerability(
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    status="open",
                    detected_at=datetime.now(timezone.utc),
                    detected_by=scanner,
                    scan_reference=scan_id,
                    risk_score=f.cvss_v3_score or 0.0,
                    organization_id=organization_id,
                )
                db.add(join)
                created += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Ingest error on {f.title[:60]}: {exc}")
            logger.error("ingest_findings: %s", exc, exc_info=True)

    await db.flush()
    return created, len(touched_assets), errors
