"""External scanner result parsers (shared by exposure and vulnmgmt imports).

Parses the common scanner outputs into one canonical finding shape:

* Nessus: ``.nessus`` XML (v2), Nessus / Tenable.io JSON exports and Nessus
  CSV exports.
* OpenVAS / Greenbone: XML report exports and CSV result exports.
* Qualys: JSON exports and CSV exports (preamble lines before the header row
  are skipped).
* Generic JSON arrays and CSV files whose column headers name a host and a
  vulnerability (``Host``/``IP`` plus ``CVE``/``Title``/``Plugin ID``...).

``parse_scan_data`` never invents a finding: a payload it cannot read returns
no findings plus an error naming the problem, and a row without a host or
without any vulnerability identifier is still returned so the importer can
count it as skipped with that reason.

``ingest_findings`` persists findings into the exposure store
(``exposure_assets`` / ``exposure_vulnerabilities`` / ``asset_vulnerabilities``)
and reports what it did: links created / updated / reopened, catalogue rows
and assets created, and skipped findings grouped by reason.
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

#: Upper bound on findings one import processes; the rest are reported as
#: skipped (reason ``import_cap``) so a huge file cannot hold a request or a
#: worker for unbounded time.
MAX_FINDINGS_PER_IMPORT = 50_000

#: Formats accepted by ``parse_scan_data`` (family names; the payload is
#: sniffed inside a family: XML, JSON or CSV).
SUPPORTED_FORMATS: tuple[str, ...] = (
    "nessus", "nessus_xml", "nessus_json", "nessus_csv", "tenable", "tenable_io",
    "openvas", "openvas_xml", "openvas_csv", "gvm", "greenbone",
    "qualys", "qualys_json", "qualys_csv", "qualys_vm",
    "rapid7", "custom", "auto", "generic", "json", "csv",
)


@dataclass
class ParsedFinding:
    """Canonical shape produced by every parser."""

    cve_id: Optional[str] = None
    title: str = ""
    description: Optional[str] = None
    severity: str = "unknown"
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    asset_identifier: Optional[str] = None  # hostname / ip / fqdn
    asset_ip: Optional[str] = None
    asset_hostname: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    solution: Optional[str] = None
    references: list[str] = field(default_factory=list)
    # Scanner plugin / check id (Nessus pluginID, OpenVAS NVT OID, Qualys QID).
    plugin_id: Optional[str] = None
    # Which parser family produced the finding ("nessus", "openvas", "qualys", "generic").
    source: str = "generic"

    @property
    def has_asset(self) -> bool:
        return bool(self.asset_hostname or self.asset_ip or self.asset_identifier)

    @property
    def vulnerability_key(self) -> Optional[str]:
        """CVE when known, else ``<SOURCE>-<plugin id>``; None when neither exists."""
        if self.cve_id:
            return self.cve_id
        if self.plugin_id:
            return f"{self.source.upper()}-{self.plugin_id}"[:50]
        return None


# --------------------------------------------------------------------------- #
# Severity / score normalizers
# --------------------------------------------------------------------------- #


_SEV_MAP = {
    "0": "informational", "info": "informational", "informational": "informational", "none": "informational",
    "log": "informational", "debug": "informational",
    "1": "low", "low": "low",
    "2": "medium", "medium": "medium", "moderate": "medium",
    "3": "high", "high": "high", "important": "high",
    "4": "critical", "critical": "critical", "urgent": "critical",
}

SEVERITY_ORDER = {"unknown": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _to_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        f = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "informational"


def _normalize_severity(s: Any, cvss: Optional[float] = None) -> str:
    """Scanner label -> canonical severity; CVSS-derived when the label is
    missing or unrecognised; ``unknown`` when neither is available."""
    if s is not None:
        key = str(s).strip().lower()
        if key in _SEV_MAP:
            return _SEV_MAP[key]
    return _severity_from_cvss(cvss)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _extract_cve(text: Any) -> Optional[str]:
    if not text:
        return None
    m = _CVE_RE.search(str(text))
    return m.group(0).upper() if m else None


def _all_cves(text: Any) -> list[str]:
    if not text:
        return []
    seen: list[str] = []
    for m in _CVE_RE.findall(str(text)):
        cve = m.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def _parse_port(value: Any, protocol: Any = None) -> tuple[Optional[int], Optional[str]]:
    """``443`` / ``"443"`` / ``"443/tcp"`` / ``"general/tcp"`` -> (port, protocol).

    Port 0 (Nessus host-level findings) is no port.
    """
    proto = str(protocol).strip().lower() if protocol else None
    if value is None or value == "":
        return None, proto
    if isinstance(value, int):
        return (value if 0 < value <= 65535 else None), proto
    text = str(value).strip().lower()
    if "/" in text:
        head, _, tail = text.partition("/")
        proto = proto or (tail.strip() or None)
        text = head.strip()
    if text.isdigit():
        n = int(text)
        return (n if 0 < n <= 65535 else None), proto
    return None, proto


def _looks_like_ip(text: Optional[str]) -> bool:
    return bool(text) and bool(re.fullmatch(r"[0-9a-fA-F:.]+", text or "")) and any(c in (text or "") for c in ".:")


def _split_host(identifier: Optional[str], ip: Optional[str], hostname: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (ip, hostname) with an IP-looking identifier treated as the IP."""
    ip = (ip or "").strip() or None
    hostname = (hostname or "").strip() or None
    ident = (identifier or "").strip() or None
    if ident and not ip and _looks_like_ip(ident):
        ip = ident
    elif ident and not hostname and not _looks_like_ip(ident):
        hostname = ident
    if hostname and _looks_like_ip(hostname) and not ip:
        ip, hostname = hostname, None
    return ip, hostname


def _refuse_entities(xml_text: str) -> Optional[str]:
    """Scanner exports never carry a DTD; refuse payloads that declare one.

    The stdlib parser never fetches external entities, and refusing any
    DOCTYPE / ENTITY declaration up front also rules out entity-expansion
    ("billion laughs") payloads.
    """
    # XML markup declarations are case-sensitive, so no upper-casing copy.
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return "XML payload declares a DTD or entities; refused"
    return None


# --------------------------------------------------------------------------- #
# Per-format parsers
# --------------------------------------------------------------------------- #


def _parse_nessus_xml(xml_text: str) -> list[ParsedFinding]:
    """Parse a .nessus (v2) XML export: one finding per ReportItem and CVE."""
    out: list[ParsedFinding] = []
    root = ET.fromstring(xml_text)
    for host in root.iter("ReportHost"):
        host_name = host.get("name") or ""
        host_ip: Optional[str] = None
        fqdn: Optional[str] = None
        for tag in host.findall("./HostProperties/tag"):
            if tag.get("name") == "host-ip":
                host_ip = (tag.text or "").strip() or None
            elif tag.get("name") in ("host-fqdn", "hostname"):
                fqdn = fqdn or ((tag.text or "").strip() or None)
        ip, hostname = _split_host(host_name, host_ip, fqdn)

        for item in host.iter("ReportItem"):
            plugin_name = item.get("pluginName") or item.findtext("plugin_name") or "Unknown finding"
            port, protocol = _parse_port(item.get("port"), item.get("protocol"))
            desc = (item.findtext("description") or "").strip()
            solution = (item.findtext("solution") or "").strip() or None
            cvss3 = _to_float(item.findtext("cvss3_base_score"))
            cvss2 = _to_float(item.findtext("cvss_base_score"))
            refs = [e.text.strip() for e in item.findall("see_also") if e.text]
            cves = [c.text.strip().upper() for c in item.findall("cve") if c.text and c.text.strip()]
            if not cves:
                extracted = _extract_cve(plugin_name) or _extract_cve(desc)
                cves = [extracted] if extracted else []
            base = dict(
                title=plugin_name,
                description=desc or None,
                severity=_normalize_severity(item.get("severity"), cvss3 or cvss2),
                cvss_v3_score=cvss3,
                cvss_v2_score=cvss2,
                asset_identifier=host_name or ip or hostname,
                asset_ip=ip,
                asset_hostname=hostname,
                port=port,
                protocol=protocol,
                solution=solution,
                references=refs,
                plugin_id=item.get("pluginID") or None,
                source="nessus",
            )
            for cve in cves or [None]:
                out.append(ParsedFinding(cve_id=cve, **base))
    return out


def _parse_openvas_xml(xml_text: str) -> list[ParsedFinding]:
    """Parse an OpenVAS / Greenbone XML report (``<result>`` elements)."""
    out: list[ParsedFinding] = []
    root = ET.fromstring(xml_text)
    for result in root.iter("result"):
        host_el = result.find("host")
        if host_el is None:
            continue
        host_text = (host_el.text or "").strip() or None
        hostname = (host_el.findtext("hostname") or "").strip() or None
        ip, hostname = _split_host(host_text, None, hostname)
        nvt = result.find("nvt")
        oid = nvt.get("oid") if nvt is not None else None
        name = (result.findtext("name") or (nvt.findtext("name") if nvt is not None else None) or "OpenVAS finding").strip()
        cvss = _to_float(result.findtext("severity")) or (_to_float(nvt.findtext("cvss_base")) if nvt is not None else None)
        threat = result.findtext("threat")
        cves: list[str] = []
        if nvt is not None:
            for ref in nvt.iter("ref"):
                if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
                    cves.append(ref.get("id").strip().upper())
            cves.extend(c for c in _all_cves(nvt.findtext("cve")) if c not in cves)
        port, protocol = _parse_port(result.findtext("port"))
        base = dict(
            title=name,
            description=(result.findtext("description") or "").strip() or None,
            severity=_normalize_severity(threat, cvss),
            cvss_v3_score=cvss,
            asset_identifier=host_text or hostname,
            asset_ip=ip,
            asset_hostname=hostname,
            port=port,
            protocol=protocol,
            solution=(nvt.findtext("solution") if nvt is not None else None),
            plugin_id=oid,
            source="openvas",
        )
        for cve in cves or [None]:
            out.append(ParsedFinding(cve_id=cve, **base))
    return out


def _parse_nessus_json(payload: Any) -> list[ParsedFinding]:
    """Parse a Tenable.io / Nessus-style JSON export."""
    out: list[ParsedFinding] = []
    vulns: list[Any] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            vulns = payload["vulnerabilities"]
        elif isinstance(payload.get("hosts"), list):
            for host in payload["hosts"]:
                if not isinstance(host, dict):
                    continue
                host_name = host.get("hostname") or host.get("ip") or host.get("host") or ""
                for v in host.get("vulnerabilities", []) or []:
                    if not isinstance(v, dict):
                        continue
                    v = dict(v)
                    v.setdefault("asset_hostname", host_name)
                    v.setdefault("asset_ip", host.get("ip"))
                    vulns.append(v)
    elif isinstance(payload, list):
        vulns = payload

    for v in vulns:
        if not isinstance(v, dict):
            continue
        cvss3 = _to_float(v.get("cvss3_base_score") or v.get("cvss3") or v.get("cvss_v3_score"))
        cvss2 = _to_float(v.get("cvss_base_score") or v.get("cvss"))
        cvss_any = cvss3 if cvss3 is not None else cvss2
        title = v.get("plugin_name") or v.get("name") or v.get("title") or "Finding"
        cve = v.get("cve") or v.get("cve_id") or _extract_cve(title)
        if isinstance(cve, list):
            cves = [str(c).upper() for c in cve if c]
        else:
            cves = _all_cves(cve) or ([str(cve).upper()] if cve else [])
        port, protocol = _parse_port(v.get("port"), v.get("protocol"))
        ip, hostname = _split_host(
            v.get("asset") or v.get("host"), v.get("asset_ip") or v.get("ip"), v.get("asset_hostname") or v.get("hostname"),
        )
        base = dict(
            title=str(title),
            description=v.get("description") or v.get("synopsis"),
            severity=_normalize_severity(v.get("severity") if v.get("severity") is not None else v.get("risk_factor"), cvss_any),
            cvss_v3_score=cvss3 if cvss3 is not None else cvss2,
            cvss_v2_score=cvss2,
            asset_identifier=v.get("asset") or v.get("host") or hostname or ip,
            asset_ip=ip,
            asset_hostname=hostname,
            port=port,
            protocol=protocol,
            solution=v.get("solution"),
            references=v.get("references") if isinstance(v.get("references"), list) else [],
            plugin_id=str(v.get("plugin_id") or v.get("pluginID") or "") or None,
            source="nessus",
        )
        for c in cves or [None]:
            out.append(ParsedFinding(cve_id=c, **base))
    return out


def _parse_qualys_json(payload: Any) -> list[ParsedFinding]:
    """Parse a Qualys JSON export."""
    out: list[ParsedFinding] = []
    items: list[Any] = []
    if isinstance(payload, dict):
        items = payload.get("vulnerabilities") or payload.get("findings") or payload.get("results") or []
    elif isinstance(payload, list):
        items = payload

    for v in items:
        if not isinstance(v, dict):
            continue
        cvss = _to_float(v.get("cvss3_base") or v.get("cvss_base") or v.get("cvss"))
        sev_in = v.get("severity")
        if isinstance(sev_in, int) or (isinstance(sev_in, str) and sev_in.strip().isdigit()):
            # Qualys severity 1..5 maps to info..critical
            sev = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(int(sev_in), _severity_from_cvss(cvss))
        else:
            sev = _normalize_severity(sev_in, cvss)
        title = v.get("title") or v.get("name") or "Finding"
        cves = _all_cves(v.get("cve_id") or v.get("cve")) or ([_extract_cve(title)] if _extract_cve(title) else [])
        port, protocol = _parse_port(v.get("port"), v.get("protocol"))
        ip, hostname = _split_host(v.get("asset") or v.get("host"), v.get("ip"), v.get("hostname") or v.get("dns"))
        base = dict(
            title=str(title),
            description=v.get("description") or v.get("threat"),
            severity=sev,
            cvss_v3_score=cvss,
            asset_identifier=v.get("asset") or v.get("host") or ip or hostname,
            asset_ip=ip,
            asset_hostname=hostname,
            port=port,
            protocol=protocol,
            solution=v.get("solution") or v.get("remediation"),
            references=v.get("references") if isinstance(v.get("references"), list) else [],
            plugin_id=str(v.get("qid") or v.get("QID") or "") or None,
            source="qualys",
        )
        for c in cves or [None]:
            out.append(ParsedFinding(cve_id=c, **base))
    return out


_HOST_COLUMNS = {"host", "ip", "hostname", "ip address", "dns", "asset", "host ip", "netbios"}
_VULN_COLUMNS = {
    "cve", "cve id", "cve_id", "cves", "qid", "plugin id", "plugin", "nvt oid", "oid",
    "title", "name", "plugin name", "vulnerability", "nvt name",
}


def _first(row: dict[str, str], *keys: str) -> Optional[str]:
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


def _parse_csv(csv_text: str, source: str = "generic") -> list[ParsedFinding]:
    """Parse a CSV export (Nessus, Qualys, OpenVAS or the generic
    ``Host,IP,Port,CVE,Severity,CVSS,Title,Description`` shape).

    Lines before the first row that names both a host column and a
    vulnerability column (Qualys report preambles) are skipped.
    """
    out: list[ParsedFinding] = []
    lines = csv_text.splitlines()
    start = 0
    for idx, line in enumerate(lines[:50]):
        cells = {c.strip().strip('"').lower() for c in next(csv.reader([line]), [])}
        if cells & _HOST_COLUMNS and cells & _VULN_COLUMNS:
            start = idx
            break
    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    for row in reader:
        lower = {k.lower().strip(): (v or "") for k, v in row.items() if k}
        cvss3 = _to_float(_first(lower, "cvss v3.0 base score", "cvss3 base", "cvss v3", "cvss_v3", "cvss3", "cvss"))
        cvss2 = _to_float(_first(lower, "cvss v2.0 base score", "cvss base", "cvss_base"))
        cvss_any = cvss3 if cvss3 is not None else cvss2
        title = _first(lower, "title", "name", "plugin name", "nvt name", "vulnerability") or "Finding"
        cves = _all_cves(_first(lower, "cve", "cve id", "cve_id", "cves")) or (
            [_extract_cve(title)] if _extract_cve(title) else []
        )
        sev = _first(lower, "severity", "risk", "threat")
        port, protocol = _parse_port(_first(lower, "port"), _first(lower, "protocol"))
        ip, hostname = _split_host(
            _first(lower, "host", "asset"), _first(lower, "ip", "ip address", "host ip"), _first(lower, "hostname", "dns", "netbios"),
        )
        plugin = _first(lower, "plugin id", "plugin", "qid", "nvt oid", "oid")
        base = dict(
            title=title,
            description=_first(lower, "description", "synopsis", "summary", "threat description"),
            severity=_normalize_severity(sev, cvss_any),
            cvss_v3_score=cvss_any,
            cvss_v2_score=cvss2,
            asset_identifier=_first(lower, "host", "asset") or ip or hostname,
            asset_ip=ip,
            asset_hostname=hostname,
            port=port,
            protocol=protocol,
            solution=_first(lower, "solution", "remediation"),
            references=[],
            plugin_id=plugin,
            source=("qualys" if "qid" in lower else source),
        )
        for c in cves or [None]:
            out.append(ParsedFinding(cve_id=c, **base))
    return out


# --------------------------------------------------------------------------- #
# Public entrypoints
# --------------------------------------------------------------------------- #


def _sniff(data: str) -> str:
    if data.startswith("<"):
        return "xml"
    if data[0] in ("{", "["):
        return "json"
    return "csv"


def parse_scan_data(scan_format: str, scan_data: str) -> tuple[list[ParsedFinding], list[str]]:
    """Dispatch on format family and payload shape. Returns (findings, errors).

    An empty finding list always comes with at least one error naming why.
    """
    findings, errors = _dispatch(scan_format, scan_data)
    if not findings and not errors:
        errors = [
            "No findings could be read from the payload (a CSV needs a header row naming a host "
            "column and a CVE / title / plugin column; XML must be a .nessus or OpenVAS report)"
        ]
    return findings, errors


def _dispatch(scan_format: str, scan_data: str) -> tuple[list[ParsedFinding], list[str]]:
    fmt = (scan_format or "").lower().strip()
    data = (scan_data or "").lstrip("\ufeff").strip()
    if not data:
        return [], ["scan_data is empty"]
    if fmt and fmt not in SUPPORTED_FORMATS:
        return [], [f"Unsupported scan_format {scan_format!r}; supported: {', '.join(SUPPORTED_FORMATS)}"]

    shape = _sniff(data)
    if shape == "xml":
        refused = _refuse_entities(data)
        if refused:
            return [], [refused]
    try:
        if fmt.startswith("nessus") or fmt in ("tenable", "tenable_io"):
            if shape == "xml":
                return _parse_nessus_xml(data), []
            if shape == "json":
                return _parse_nessus_json(json.loads(data)), []
            return _parse_csv(data, "nessus"), []
        if fmt.startswith("openvas") or fmt in ("gvm", "greenbone"):
            if shape == "xml":
                return _parse_openvas_xml(data), []
            if shape == "json":
                return [], ["OpenVAS JSON is not a format OpenVAS exports; upload the XML or CSV report"]
            return _parse_csv(data, "openvas"), []
        if fmt.startswith("qualys"):
            if shape == "json":
                return _parse_qualys_json(json.loads(data)), []
            if shape == "xml":
                return [], ["Qualys XML is not supported; export the scan as CSV or JSON"]
            return _parse_csv(data, "qualys"), []

        # rapid7 / custom / auto / generic / json / csv: sniff the payload.
        if shape == "xml":
            if "NessusClientData" in data[:2048] or "<ReportHost" in data:
                return _parse_nessus_xml(data), []
            if "<result" in data:
                return _parse_openvas_xml(data), []
            return [], ["XML payload is neither a .nessus report nor an OpenVAS report"]
        if shape == "json":
            payload = json.loads(data)
            for parser in (_parse_nessus_json, _parse_qualys_json):
                found = parser(payload)
                if found:
                    return found, []
            keys = list(payload.keys())[:10] if isinstance(payload, dict) else "list"
            return [], [f"JSON payload shape not recognized (keys={keys})"]
        return _parse_csv(data), []
    except (json.JSONDecodeError, ET.ParseError) as exc:
        return [], [f"Parse error ({fmt or shape}): {exc}"]


def summarize_skips(skipped: dict[str, list[str]]) -> list[dict[str, Any]]:
    """``{reason: [examples...]}`` -> ``[{reason, count, examples}]`` (5 examples max)."""
    return [
        {"reason": reason, "count": len(examples), "examples": examples[:5]}
        for reason, examples in sorted(skipped.items())
    ]


async def _get_or_create_asset(
    db: AsyncSession,
    finding: ParsedFinding,
    organization_id: str,
    cache: dict[str, ExposureAsset],
) -> tuple[Optional[ExposureAsset], bool]:
    """Find an active-or-inactive asset by IP, then hostname; create one from
    the scanned host otherwise. Returns (asset, created)."""
    ip, hostname = finding.asset_ip, finding.asset_hostname
    if not ip and not hostname:
        return None, False
    for key in (f"ip:{ip}" if ip else None, f"host:{hostname.lower()}" if hostname else None):
        if key and key in cache:
            return cache[key], False

    match: Optional[ExposureAsset] = None
    if ip:
        match = (
            await db.execute(
                select(ExposureAsset).where(
                    ExposureAsset.ip_address == ip, ExposureAsset.organization_id == organization_id,
                ).limit(1)
            )
        ).scalars().first()
    if match is None and hostname:
        match = (
            await db.execute(
                select(ExposureAsset).where(
                    ExposureAsset.hostname == hostname, ExposureAsset.organization_id == organization_id,
                ).limit(1)
            )
        ).scalars().first()
    created = False
    if match is None:
        match = ExposureAsset(
            asset_type="host",
            hostname=hostname,
            ip_address=ip,
            environment="unknown",
            criticality="medium",
            is_active=True,
            tags=["scan-import"],
            extra_metadata={"discovery_source": f"scan_import:{finding.source}"},
            organization_id=organization_id,
        )
        db.add(match)
        await db.flush()
        created = True
    if ip:
        cache[f"ip:{ip}"] = match
    if hostname:
        cache[f"host:{hostname.lower()}"] = match
    return match, created


async def _get_or_create_vulnerability(
    db: AsyncSession,
    finding: ParsedFinding,
    organization_id: str,
    cache: dict[str, ExposureVulnerability],
) -> tuple[ExposureVulnerability, bool]:
    """Upsert the catalogue row: keyed by CVE when available, else by title."""
    key = f"cve:{finding.cve_id}" if finding.cve_id else f"title:{finding.title[:500]}"
    if key in cache:
        existing = cache[key]
    else:
        stmt = select(ExposureVulnerability).where(ExposureVulnerability.organization_id == organization_id)
        if finding.cve_id:
            stmt = stmt.where(ExposureVulnerability.cve_id == finding.cve_id)
        else:
            stmt = stmt.where(ExposureVulnerability.title == finding.title[:500])
        existing = (await db.execute(stmt.limit(1))).scalars().first()

    if existing is not None:
        cache[key] = existing
        if finding.cvss_v3_score is not None and existing.cvss_v3_score is None:
            existing.cvss_v3_score = finding.cvss_v3_score
        if finding.cvss_v2_score is not None and existing.cvss_v2_score is None:
            existing.cvss_v2_score = finding.cvss_v2_score
        # Only escalate severity.
        if SEVERITY_ORDER.get(finding.severity, -1) > SEVERITY_ORDER.get(existing.severity, -1):
            existing.severity = finding.severity
        return existing, False

    vuln = ExposureVulnerability(
        cve_id=finding.cve_id,
        title=(finding.title or "Finding")[:500],
        description=finding.description,
        severity=finding.severity,
        cvss_v3_score=finding.cvss_v3_score,
        cvss_v2_score=finding.cvss_v2_score,
        references=[r for r in (finding.references or []) if isinstance(r, str)][:50],
        tags=[f"plugin:{finding.source}:{finding.plugin_id}"] if finding.plugin_id else [],
        organization_id=organization_id,
    )
    db.add(vuln)
    await db.flush()
    cache[key] = vuln
    return vuln, True


async def ingest_findings(
    db: AsyncSession,
    findings: list[ParsedFinding],
    scanner: str,
    scan_id: str,
    organization_id: str,
) -> dict[str, Any]:
    """Persist parsed findings as asset + vulnerability + asset-vulnerability rows.

    A link is unique per (asset, catalogue vulnerability). Re-detection of an
    existing link updates ``detected_at`` / ``scan_reference``; a link that was
    ``remediated`` is reopened (the scanner still sees it). Returns counts and
    skipped findings grouped by reason; ``touched_asset_ids`` lets the caller
    rescore the affected assets.
    """
    now = datetime.now(timezone.utc)
    counts = {
        "findings_read": len(findings),
        "links_created": 0,
        "links_updated": 0,
        "links_reopened": 0,
        "vulnerabilities_created": 0,
        "assets_created": 0,
        "assets_matched": 0,
    }
    skipped: dict[str, list[str]] = {}
    errors: list[str] = []
    touched_assets: set[str] = set()
    asset_cache: dict[str, ExposureAsset] = {}
    vuln_cache: dict[str, ExposureVulnerability] = {}
    seen_links: set[tuple[str, str]] = set()

    for index, f in enumerate(findings):
        label = f"{f.title[:60]} @ {f.asset_identifier or '?'}"
        if index >= MAX_FINDINGS_PER_IMPORT:
            skipped.setdefault("import_cap", []).append(label)
            continue
        if not f.has_asset:
            skipped.setdefault("no_asset_identifier", []).append(label)
            continue
        if not f.cve_id and not f.title.strip():
            skipped.setdefault("no_vulnerability_identifier", []).append(label)
            continue
        try:
            asset, asset_created = await _get_or_create_asset(db, f, organization_id, asset_cache)
            if asset is None:
                skipped.setdefault("no_asset_identifier", []).append(label)
                continue
            if asset_created:
                counts["assets_created"] += 1
            elif asset.id not in touched_assets:
                counts["assets_matched"] += 1
            touched_assets.add(asset.id)
            asset.last_scan_at = now
            asset.last_seen = now
            if f.port and f.port not in (asset.open_ports or []):
                asset.open_ports = sorted({*(asset.open_ports or []), f.port})

            vuln, vuln_created = await _get_or_create_vulnerability(db, f, organization_id, vuln_cache)
            if vuln_created:
                counts["vulnerabilities_created"] += 1

            if (asset.id, vuln.id) in seen_links:
                skipped.setdefault("duplicate_in_file", []).append(label)
                continue
            seen_links.add((asset.id, vuln.id))

            link = (
                await db.execute(
                    select(AssetVulnerability).where(
                        AssetVulnerability.asset_id == asset.id,
                        AssetVulnerability.vulnerability_id == vuln.id,
                        AssetVulnerability.organization_id == organization_id,
                    ).limit(1)
                )
            ).scalars().first()
            if link is not None:
                link.detected_at = now
                link.scan_reference = scan_id
                link.detected_by = scanner
                if link.status == "remediated":
                    link.status = "open"
                    link.remediated_at = None
                    link.verification_status = "unverified"
                    counts["links_reopened"] += 1
                else:
                    counts["links_updated"] += 1
            else:
                db.add(
                    AssetVulnerability(
                        asset_id=asset.id,
                        vulnerability_id=vuln.id,
                        status="open",
                        detected_at=now,
                        detected_by=scanner,
                        scan_reference=scan_id,
                        organization_id=organization_id,
                    )
                )
                counts["links_created"] += 1
        except Exception as exc:  # noqa: BLE001 - recorded per finding, import continues
            errors.append(f"Ingest error on {label}: {exc}")
            logger.error("ingest_findings: %s", exc, exc_info=True)

    await db.flush()
    return {
        **counts,
        "skipped": summarize_skips(skipped),
        "skipped_count": sum(len(v) for v in skipped.values()),
        "errors": errors,
        "touched_asset_ids": sorted(touched_assets),
    }
