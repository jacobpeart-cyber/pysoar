"""Vulnerability management engine: scanner import, risk and SLA scoring,
patch record-keeping, lifecycle metrics and the CISA KEV catalogue.

Everything is computed from stored rows:

* Scanner import (``VulnerabilityScanner``) parses Nessus / OpenVAS / Qualys /
  CSV / JSON exports with the shared parser (src/exposure/scan_parser.py),
  links each finding to an inventory ``Asset`` (matched by IP, then hostname;
  created from the scanned host otherwise), keeps one catalogue
  ``Vulnerability`` per (organisation, CVE or scanner plugin id) and one
  ``VulnerabilityInstance`` per (asset, catalogue vulnerability, port /
  protocol). The result reports new / updated / reopened instances and the
  skipped findings grouped by reason.
* Risk and SLA (``refresh_instances``) are written onto the instance rows
  from the catalogue CVSS / EPSS / KEV / exploit columns, the asset
  criticality and the instance timestamps; formulas in ``compute_risk`` and
  ``policy_deadline``.
* KEV (``KEVMonitor``) only flags catalogue rows the tenant already has; it
  never creates vulnerabilities from the feed.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

import httpx
from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.exposure.scan_parser import (
    MAX_FINDINGS_PER_IMPORT,
    SEVERITY_ORDER,
    ParsedFinding,
    parse_scan_data,
    summarize_skips,
)
from src.vulnmgmt.models import (
    DeploymentStatus,
    ExploitMaturity,
    PatchOperation,
    PatchType,
    ScanProfile,
    Vulnerability,
    VulnerabilityException,
    VulnerabilityInstance,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Policy constants
# --------------------------------------------------------------------------- #

#: Instance statuses that end the remediation clock.
REMEDIATED_STATUSES = frozenset({VulnerabilityStatus.PATCHED.value, VulnerabilityStatus.MITIGATED.value})
#: Statuses excluded from SLA accounting (not a remediation, not open work).
EXCLUDED_STATUSES = frozenset({VulnerabilityStatus.FALSE_POSITIVE.value, VulnerabilityStatus.ACCEPTED.value})
CLOSED_STATUSES = REMEDIATED_STATUSES | EXCLUDED_STATUSES
NOT_PATCHABLE_STATUSES = frozenset({VulnerabilityStatus.PATCHED.value, VulnerabilityStatus.FALSE_POSITIVE.value})
OPEN_STATUSES = frozenset(s.value for s in VulnerabilityStatus) - CLOSED_STATUSES
VALID_STATUSES = frozenset(s.value for s in VulnerabilityStatus)

#: Remediation SLA in days from first detection, by severity. Informational
#: and unknown-severity findings carry no SLA.
SLA_DAYS: dict[str, int] = {"critical": 15, "high": 30, "medium": 90, "low": 180}
#: BOD 22-01 window used for a KEV-listed CVE when the catalogue row has no
#: CISA due date.
KEV_DEFAULT_DAYS = 15
#: "Approaching" = inside the last 20 % of the SLA window (at least 3 days).
APPROACHING_FRACTION = 0.2
APPROACHING_MIN_DAYS = 3

#: CVSS used for the risk score when the catalogue row has no CVSS.
SEVERITY_CVSS_DEFAULT: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 0.0,
}
EXPLOIT_MATURITY_POINTS: dict[str, float] = {"weaponized": 10.0, "functional": 7.0, "poc": 4.0, "unproven": 0.0}
#: business_criticality (1 = low ... 4 = critical) -> multiplier.
CRITICALITY_FACTOR: dict[int, float] = {1: 0.8, 2: 1.0, 3: 1.1, 4: 1.2}
ASSET_CRITICALITY_LEVEL: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

#: Exception type -> the instance status it puts the finding in.
EXCEPTION_STATUS: dict[str, str] = {
    "risk_accepted": VulnerabilityStatus.ACCEPTED.value,
    "false_positive": VulnerabilityStatus.FALSE_POSITIVE.value,
    "compensating_control": VulnerabilityStatus.MITIGATED.value,
    "deferred": VulnerabilityStatus.DEFERRED.value,
    "not_applicable": VulnerabilityStatus.ACCEPTED.value,
}

REFRESH_BATCH = 500
MAX_REFRESH_PER_RUN = 50_000
METRIC_ROW_CAP = 100_000

#: Formats the vulnmgmt import accepts (the parser families).
IMPORT_FORMATS: tuple[str, ...] = (
    "nessus", "nessus_xml", "nessus_json", "nessus_csv", "tenable", "tenable_io",
    "openvas", "openvas_xml", "openvas_csv", "gvm", "greenbone",
    "qualys", "qualys_json", "qualys_csv", "qualys_vm", "json", "csv", "auto", "generic",
)


class ScanImportError(ValueError):
    """The scan payload could not be read; ``errors`` names why."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class KEVFeedUnavailable(RuntimeError):
    """The CISA KEV feed could not be fetched or parsed."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utc_now().isoformat()


def parse_iso(value: Any) -> Optional[datetime]:
    """ISO date / datetime string -> aware datetime (UTC assumed); None if unparseable."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def asset_reference(asset_id: Optional[str], asset_ip: Optional[str], asset_name: Optional[str]) -> Optional[str]:
    if asset_id:
        return f"asset:{asset_id}"
    if asset_ip:
        return f"ip:{asset_ip.strip()}"
    if asset_name:
        return f"host:{asset_name.strip().lower()}"
    return None


def instance_dedupe_key(
    asset_ref: str, vulnerability_id: str, port: Optional[int], protocol: Optional[str],
) -> str:
    """Stable key for (asset, catalogue vulnerability, port/protocol)."""
    raw = f"{asset_ref}|{vulnerability_id}|{port if port else '-'}/{(protocol or '-').lower()}"
    return "v1:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_risk(
    *,
    cvss: Optional[float],
    severity: Optional[str],
    epss: Optional[float],
    kev_listed: bool,
    exploit_maturity: Optional[str],
    business_criticality: Optional[int],
) -> tuple[float, Optional[float]]:
    """Instance risk (0-100) and exploitability (0-100 or None when unknown).

    risk = min(100, (CVSS x 7 + EPSS x 15 + 15 if KEV + maturity points)
               x criticality factor)
    where CVSS falls back to the severity default when the catalogue row has
    none, maturity points are 10 / 7 / 4 / 0 for weaponized / functional /
    poc / unproven, and the criticality factor is 0.8 / 1.0 / 1.1 / 1.2 for
    business_criticality 1-4 (1.0 when unset).

    exploitability = EPSS x 100 when EPSS is stored, 100 for a KEV-listed
    CVE without EPSS, otherwise None.
    """
    base = float(cvss) if cvss is not None else SEVERITY_CVSS_DEFAULT.get((severity or "").lower(), 5.0)
    points = base * 7.0
    if epss is not None:
        points += float(epss) * 15.0
    if kev_listed:
        points += 15.0
    points += EXPLOIT_MATURITY_POINTS.get((exploit_maturity or "").lower(), 0.0)
    factor = CRITICALITY_FACTOR.get(int(business_criticality), 1.0) if business_criticality else 1.0
    risk = round(min(100.0, max(0.0, points * factor)), 2)
    if epss is not None:
        exploitability: Optional[float] = round(float(epss) * 100.0, 2)
    elif kev_listed:
        exploitability = 100.0
    else:
        exploitability = None
    return risk, exploitability


def policy_deadline(
    severity: Optional[str],
    first_seen: Optional[datetime],
    kev_listed: bool,
    kev_due_date: Optional[str],
) -> Optional[datetime]:
    """Remediation deadline from the SLA policy (None when no SLA applies)."""
    candidates: list[datetime] = []
    if first_seen is not None:
        days = SLA_DAYS.get((severity or "").lower())
        if days:
            candidates.append(first_seen + timedelta(days=days))
    if kev_listed:
        due = parse_iso(kev_due_date)
        if due is None and first_seen is not None:
            due = first_seen + timedelta(days=KEV_DEFAULT_DAYS)
        if due is not None:
            candidates.append(due)
    return min(candidates) if candidates else None


def sla_state(
    status: str,
    deadline: Optional[datetime],
    first_seen: Optional[datetime],
    remediated_at: Optional[datetime],
    now: datetime,
) -> str:
    """within_sla / approaching / breached for one instance."""
    if deadline is None:
        return "within_sla"
    if status in REMEDIATED_STATUSES:
        done = remediated_at or now
        return "within_sla" if done <= deadline else "breached"
    if now > deadline:
        return "breached"
    window = (deadline - first_seen) if first_seen is not None else timedelta(days=APPROACHING_MIN_DAYS)
    margin = max(window * APPROACHING_FRACTION, timedelta(days=APPROACHING_MIN_DAYS))
    return "approaching" if deadline - now <= margin else "within_sla"


async def refresh_instances(
    db: AsyncSession,
    organization_id: str,
    instance_ids: Optional[Iterable[str]] = None,
    *,
    max_rows: int = MAX_REFRESH_PER_RUN,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Recompute risk, exploitability, deadline and SLA status on stored rows.

    Reads instance + catalogue columns in windows of REFRESH_BATCH (by id
    list when ``instance_ids`` is given, else keyset over the whole org,
    capped at ``max_rows``) and writes with bulk UPDATEs by primary key.

    Deadline: a deadline already on the row (analyst-set or computed earlier)
    is kept, except that a KEV listing can only tighten it; rows without one
    get the policy deadline (``policy_deadline``).
    """
    now = now or utc_now()
    columns = (
        VulnerabilityInstance.id,
        VulnerabilityInstance.status,
        VulnerabilityInstance.first_seen,
        VulnerabilityInstance.created_at,
        VulnerabilityInstance.remediated_at,
        VulnerabilityInstance.remediation_deadline,
        VulnerabilityInstance.business_criticality,
        Vulnerability.severity,
        Vulnerability.cvss_v3_score,
        Vulnerability.epss_score,
        Vulnerability.kev_listed,
        Vulnerability.kev_due_date,
        Vulnerability.exploit_maturity,
    )
    base = (
        select(*columns)
        .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
        .where(VulnerabilityInstance.organization_id == organization_id)
    )
    wanted = sorted({i for i in instance_ids if i}) if instance_ids is not None else None
    refreshed = 0
    breached = 0
    truncated = False
    last_id: Optional[str] = None
    offset = 0
    while True:
        if refreshed >= max_rows:
            truncated = True
            break
        window = min(REFRESH_BATCH, max_rows - refreshed)
        if wanted is not None:
            chunk = wanted[offset : offset + window]
            if not chunk:
                break
            offset += len(chunk)
            rows = (await db.execute(base.where(VulnerabilityInstance.id.in_(chunk)))).all()
        else:
            stmt = base if last_id is None else base.where(VulnerabilityInstance.id > last_id)
            rows = (await db.execute(stmt.order_by(VulnerabilityInstance.id).limit(window))).all()
            if not rows:
                break
            last_id = rows[-1].id
        updates: list[dict[str, Any]] = []
        for r in rows:
            kev = bool(r.kev_listed)
            risk, exploitability = compute_risk(
                cvss=float(r.cvss_v3_score) if r.cvss_v3_score is not None else None,
                severity=r.severity,
                epss=float(r.epss_score) if r.epss_score is not None else None,
                kev_listed=kev,
                exploit_maturity=r.exploit_maturity,
                business_criticality=r.business_criticality,
            )
            first_seen = parse_iso(r.first_seen) or parse_iso(r.created_at)
            stored = parse_iso(r.remediation_deadline)
            policy = policy_deadline(r.severity, first_seen, kev, r.kev_due_date)
            if stored is None:
                deadline = policy
            elif kev and policy is not None:
                deadline = min(stored, policy)
            else:
                deadline = stored
            state = sla_state(r.status, deadline, first_seen, parse_iso(r.remediated_at), now)
            breached += state == "breached"
            updates.append(
                {
                    "id": r.id,
                    "risk_score": risk,
                    "exploitability_score": exploitability,
                    "remediation_deadline": deadline.isoformat() if deadline else None,
                    "sla_status": state,
                }
            )
        if updates:
            await db.execute(update(VulnerabilityInstance), updates)
        refreshed += len(rows)
        if wanted is None and len(rows) < window:
            break
    await db.flush()
    if truncated:
        logger.warning("vulnmgmt refresh hit its per-run cap", organization_id=organization_id, cap=max_rows)
    return {"instances_refreshed": refreshed, "breached": breached, "truncated": truncated}


async def reopen_expired_exceptions(db: AsyncSession, organization_id: str, now: Optional[datetime] = None) -> int:
    """Instances whose every exception has expired go back to ``open``."""
    now_s = (now or utc_now()).isoformat()
    expired_ids = select(VulnerabilityException.vulnerability_instance_id).where(
        VulnerabilityException.organization_id == organization_id,
        VulnerabilityException.expiry_date.is_not(None),
        VulnerabilityException.expiry_date < now_s,
    )
    active_ids = select(VulnerabilityException.vulnerability_instance_id).where(
        VulnerabilityException.organization_id == organization_id,
        or_(VulnerabilityException.expiry_date.is_(None), VulnerabilityException.expiry_date >= now_s),
    )
    result = await db.execute(
        update(VulnerabilityInstance)
        .where(
            VulnerabilityInstance.organization_id == organization_id,
            VulnerabilityInstance.id.in_(expired_ids),
            VulnerabilityInstance.id.not_in(active_ids),
            VulnerabilityInstance.status.in_(sorted(set(EXCEPTION_STATUS.values()))),
        )
        .values(status=VulnerabilityStatus.OPEN.value, remediated_at=None)
        .execution_options(synchronize_session=False)
    )
    return int(result.rowcount or 0)


def apply_status_change(instance: VulnerabilityInstance, new_status: str, when: Optional[str] = None) -> None:
    """Set ``status`` and keep ``remediated_at`` consistent with it."""
    if new_status not in VALID_STATUSES:
        raise ValueError(f"unknown status {new_status!r}; expected one of {sorted(VALID_STATUSES)}")
    if new_status in REMEDIATED_STATUSES:
        if instance.status not in REMEDIATED_STATUSES or not instance.remediated_at:
            instance.remediated_at = when or now_iso()
    else:
        instance.remediated_at = None
    instance.status = new_status


# --------------------------------------------------------------------------- #
# Scanner import
# --------------------------------------------------------------------------- #


class VulnerabilityScanner:
    """Scanner import into vulnerabilities + vulnerability_instances."""

    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.logger = logger

    async def import_scan_results(
        self,
        db: AsyncSession,
        scan_format: str,
        scan_data: str,
        scan_id: str,
        discovery_source: str,
        scan_profile_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Parse, link to assets, dedupe and persist; return honest counts.

        Raises ``ScanImportError`` when the payload yields no readable finding.
        """
        fmt = (scan_format or "").strip().lower()
        if fmt not in IMPORT_FORMATS:
            raise ScanImportError(
                [f"Unsupported scan_format {scan_format!r}; supported: {', '.join(IMPORT_FORMATS)}"]
            )
        findings, errors = parse_scan_data(fmt, scan_data)
        if not findings:
            raise ScanImportError(errors or ["The scan file contains no findings"])

        now = now_iso()
        skipped: dict[str, list[str]] = {}
        counts = {
            "findings_read": len(findings),
            "instances_created": 0,
            "instances_updated": 0,
            "instances_reopened": 0,
            "vulnerabilities_created": 0,
            "assets_linked": 0,
            "assets_created": 0,
        }

        usable: list[ParsedFinding] = []
        for index, f in enumerate(findings):
            label = f"{(f.vulnerability_key or f.title)[:60]} @ {f.asset_identifier or '?'}"
            if index >= MAX_FINDINGS_PER_IMPORT:
                skipped.setdefault("import_cap", []).append(label)
            elif not f.has_asset:
                skipped.setdefault("no_asset_identifier", []).append(label)
            elif f.vulnerability_key is None:
                skipped.setdefault("no_cve_or_plugin_id", []).append(label)
            elif f.severity == "informational":
                skipped.setdefault("informational_finding", []).append(label)
            else:
                usable.append(f)

        assets = await self._link_assets(db, usable, counts)
        vulns = await self._upsert_catalogue(db, usable, counts, now)

        # Resolve every instance key, then load the existing rows in chunks.
        keyed: list[tuple[str, ParsedFinding, Any, Vulnerability]] = []
        seen: set[str] = set()
        for f in usable:
            asset = assets.get(self._host_key(f))
            vuln = vulns[f.vulnerability_key]
            ref = asset_reference(asset.id if asset else None, f.asset_ip, f.asset_hostname)
            key = instance_dedupe_key(ref or "unknown", vuln.id, f.port, f.protocol)
            if key in seen:
                skipped.setdefault("duplicate_in_file", []).append(
                    f"{f.vulnerability_key} @ {f.asset_identifier} port {f.port or '-'}"
                )
                continue
            seen.add(key)
            keyed.append((key, f, asset, vuln))

        existing: dict[str, VulnerabilityInstance] = {}
        keys = [k for k, *_ in keyed]
        for offset in range(0, len(keys), REFRESH_BATCH):
            chunk = keys[offset : offset + REFRESH_BATCH]
            for row in (
                await db.execute(
                    select(VulnerabilityInstance).where(
                        VulnerabilityInstance.organization_id == self.organization_id,
                        VulnerabilityInstance.dedupe_key.in_(chunk),
                    )
                )
            ).scalars():
                existing[row.dedupe_key] = row

        touched: list[str] = []
        new_critical: list[dict[str, Any]] = []
        source = (discovery_source or fmt or "manual")[:50]
        for key, f, asset, vuln in keyed:
            inst = existing.get(key)
            if inst is None:
                inst = VulnerabilityInstance(
                    vulnerability_id=vuln.id,
                    asset_id=asset.id if asset else None,
                    asset_name=(f.asset_hostname or f.asset_identifier or f.asset_ip or "")[:255] or None,
                    asset_ip=f.asset_ip,
                    asset_type=getattr(asset, "asset_type", None),
                    business_criticality=ASSET_CRITICALITY_LEVEL.get(getattr(asset, "criticality", None) or ""),
                    discovered_by=source,
                    scan_id=(scan_id or None),
                    first_seen=now,
                    last_seen=now,
                    status=VulnerabilityStatus.OPEN.value,
                    port=f.port,
                    protocol=f.protocol,
                    plugin_id=f.plugin_id,
                    dedupe_key=key,
                    organization_id=self.organization_id,
                )
                db.add(inst)
                counts["instances_created"] += 1
                if vuln.severity in ("critical", "high"):
                    new_critical.append(
                        {
                            "cve_id": vuln.cve_id,
                            "title": vuln.title,
                            "severity": vuln.severity,
                            "asset_name": inst.asset_name or inst.asset_ip or "unknown",
                        }
                    )
            else:
                inst.last_seen = now
                inst.scan_id = scan_id or inst.scan_id
                inst.discovered_by = source
                inst.plugin_id = inst.plugin_id or f.plugin_id
                if asset is not None and not inst.asset_id:
                    inst.asset_id = asset.id
                if inst.status in REMEDIATED_STATUSES:
                    # The scanner still sees it: the fix did not hold.
                    apply_status_change(inst, VulnerabilityStatus.OPEN.value)
                    inst.remediation_deadline = None
                    counts["instances_reopened"] += 1
                else:
                    counts["instances_updated"] += 1
            touched.append(inst)

        await db.flush()
        refreshed = await refresh_instances(db, self.organization_id, [i.id for i in touched])

        if scan_profile_id:
            profile = (
                await db.execute(
                    select(ScanProfile).where(
                        ScanProfile.id == scan_profile_id, ScanProfile.organization_id == self.organization_id,
                    )
                )
            ).scalar_one_or_none()
            if profile is not None:
                profile.last_scan_date = now
        await db.commit()

        skipped_list = summarize_skips(skipped)
        skipped_count = sum(len(v) for v in skipped.values())
        updated = counts["instances_updated"] + counts["instances_reopened"]
        return {
            "scan_id": scan_id,
            "scan_format": fmt,
            **counts,
            "skipped": skipped_list,
            "skipped_count": skipped_count,
            "parse_errors": errors,
            "sla_breached": refreshed["breached"],
            # Backward-compatible fields the page already reads.
            "imported": counts["findings_read"],
            "normalized": len(usable),
            "persisted": counts["vulnerabilities_created"],
            "new": counts["instances_created"],
            "updated": updated,
            "existing": updated,
            "new_critical": new_critical,
        }

    @staticmethod
    def _host_key(f: ParsedFinding) -> str:
        return f"ip:{f.asset_ip}" if f.asset_ip else f"host:{(f.asset_hostname or f.asset_identifier or '').lower()}"

    async def _link_assets(
        self, db: AsyncSession, findings: list[ParsedFinding], counts: dict[str, int],
    ) -> dict[str, Any]:
        """Map each finding host to an inventory Asset (match by IP, then
        hostname, case-insensitive); create the Asset from the scanned host
        when the inventory has none."""
        from src.models.asset import Asset

        hosts: dict[str, ParsedFinding] = {}
        for f in findings:
            hosts.setdefault(self._host_key(f), f)
        ips = sorted({f.asset_ip for f in hosts.values() if f.asset_ip})
        names = sorted({(f.asset_hostname or "").lower() for f in hosts.values() if f.asset_hostname})
        by_ip: dict[str, Any] = {}
        by_name: dict[str, Any] = {}
        for offset in range(0, max(len(ips), len(names)), REFRESH_BATCH):
            ip_chunk = ips[offset : offset + REFRESH_BATCH]
            name_chunk = names[offset : offset + REFRESH_BATCH]
            conditions = []
            if ip_chunk:
                conditions.append(Asset.ip_address.in_(ip_chunk))
            if name_chunk:
                conditions.append(func.lower(Asset.hostname).in_(name_chunk))
            if not conditions:
                continue
            for a in (
                await db.execute(
                    select(Asset).where(Asset.organization_id == self.organization_id, or_(*conditions))
                )
            ).scalars():
                if a.ip_address:
                    by_ip.setdefault(a.ip_address, a)
                if a.hostname:
                    by_name.setdefault(a.hostname.lower(), a)

        linked: dict[str, Any] = {}
        for key, f in hosts.items():
            asset = (by_ip.get(f.asset_ip) if f.asset_ip else None) or (
                by_name.get(f.asset_hostname.lower()) if f.asset_hostname else None
            )
            if asset is None:
                name = (f.asset_hostname or f.asset_ip or f.asset_identifier or "unknown")[:255]
                asset = Asset(
                    organization_id=self.organization_id,
                    name=name,
                    hostname=f.asset_hostname,
                    ip_address=f.asset_ip,
                    description=f"Created by a {f.source} scan import (host seen by the scanner).",
                )
                db.add(asset)
                counts["assets_created"] += 1
                if f.asset_ip:
                    by_ip[f.asset_ip] = asset
                if f.asset_hostname:
                    by_name[f.asset_hostname.lower()] = asset
            else:
                counts["assets_linked"] += 1
            linked[key] = asset
        await db.flush()
        return linked

    async def _upsert_catalogue(
        self, db: AsyncSession, findings: list[ParsedFinding], counts: dict[str, int], now: str,
    ) -> dict[str, Vulnerability]:
        """One catalogue row per CVE / plugin key in the org (escalate-only severity)."""
        first: dict[str, ParsedFinding] = {}
        for f in findings:
            key = f.vulnerability_key
            prev = first.get(key)
            if prev is None or SEVERITY_ORDER.get(f.severity, -1) > SEVERITY_ORDER.get(prev.severity, -1):
                first[key] = f
        keys = sorted(first)
        found: dict[str, Vulnerability] = {}
        for offset in range(0, len(keys), REFRESH_BATCH):
            chunk = keys[offset : offset + REFRESH_BATCH]
            for v in (
                await db.execute(
                    select(Vulnerability).where(
                        Vulnerability.organization_id == self.organization_id, Vulnerability.cve_id.in_(chunk),
                    )
                )
            ).scalars():
                found[v.cve_id] = v
        for key in keys:
            f = first[key]
            vuln = found.get(key)
            if vuln is None:
                vuln = Vulnerability(
                    cve_id=key,
                    title=(f.title or key)[:500],
                    description=f.description,
                    severity=f.severity if f.severity != "unknown" else VulnerabilitySeverity.MEDIUM.value,
                    cvss_v3_score=f.cvss_v3_score,
                    exploit_maturity=ExploitMaturity.UNPROVEN.value,
                    patch_available=bool(f.solution),
                    references=[{"url": r} for r in (f.references or [])[:50] if isinstance(r, str)] or None,
                    organization_id=self.organization_id,
                )
                if f.severity == "unknown":
                    # The scanner gave neither a severity nor a CVSS; say so
                    # instead of presenting the default as a scanner verdict.
                    vuln.description = (
                        (f.description or "") + "\n\n[pysoar] Severity not reported by the scanner; recorded as medium."
                    ).strip()
                db.add(vuln)
                counts["vulnerabilities_created"] += 1
                found[key] = vuln
            else:
                if f.cvss_v3_score is not None and vuln.cvss_v3_score is None:
                    vuln.cvss_v3_score = f.cvss_v3_score
                if SEVERITY_ORDER.get(f.severity, -1) > SEVERITY_ORDER.get(vuln.severity, -1):
                    vuln.severity = f.severity
                if f.solution and not vuln.patch_available:
                    vuln.patch_available = True
        await db.flush()
        return found


# --------------------------------------------------------------------------- #
# Risk / SLA aggregates
# --------------------------------------------------------------------------- #


class RiskPrioritizer:
    """Risk scoring and SLA aggregates over stored instances."""

    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.logger = logger

    async def calculate_risk_score(
        self,
        vulnerability: Vulnerability,
        instance: VulnerabilityInstance,
        asset_criticality: Optional[float] = None,
    ) -> float:
        """Risk score (0-100) for one instance; see ``compute_risk``."""
        risk, _ = compute_risk(
            cvss=float(vulnerability.cvss_v3_score) if vulnerability.cvss_v3_score is not None else None,
            severity=vulnerability.severity,
            epss=float(vulnerability.epss_score) if vulnerability.epss_score is not None else None,
            kev_listed=bool(vulnerability.kev_listed),
            exploit_maturity=vulnerability.exploit_maturity,
            business_criticality=instance.business_criticality,
        )
        return risk

    async def generate_risk_matrix(self, db: AsyncSession) -> dict[str, dict[str, int]]:
        """Open instances by (catalogue severity x exploit maturity)."""
        matrix: dict[str, dict[str, int]] = {
            s.value: {e.value: 0 for e in ExploitMaturity} for s in VulnerabilitySeverity
        }
        rows = (
            await db.execute(
                select(Vulnerability.severity, Vulnerability.exploit_maturity, func.count(VulnerabilityInstance.id))
                .join(VulnerabilityInstance, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
                .where(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    VulnerabilityInstance.status.in_(sorted(OPEN_STATUSES)),
                )
                .group_by(Vulnerability.severity, Vulnerability.exploit_maturity)
            )
        ).all()
        for severity, exploit, count in rows:
            if severity in matrix and exploit in matrix[severity]:
                matrix[severity][exploit] = int(count or 0)
        return matrix

    async def assess_sla_compliance(self, db: AsyncSession) -> dict[str, Any]:
        """Stored ``sla_status`` counts over open and remediated instances
        (false positives and accepted risk are excluded)."""
        rows = (
            await db.execute(
                select(VulnerabilityInstance.sla_status, func.count(VulnerabilityInstance.id))
                .where(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    VulnerabilityInstance.status.not_in(sorted(EXCLUDED_STATUSES)),
                )
                .group_by(VulnerabilityInstance.sla_status)
            )
        ).all()
        by_state = {state: int(n) for state, n in rows}
        total = sum(by_state.values())
        within = by_state.get("within_sla", 0)
        return {
            "total": total,
            "within_sla": within,
            "approaching": by_state.get("approaching", 0),
            "breached": by_state.get("breached", 0),
            "compliance_percentage": round(within / total * 100, 1) if total else 0.0,
        }


# --------------------------------------------------------------------------- #
# Patch record-keeping
# --------------------------------------------------------------------------- #


class PatchOrchestrator:
    """Patch operation records. No patch is pushed to any host: there is no
    patch-deployment integration, so schedule / verify / rollback record what
    the operator reports."""

    SCHEDULABLE = frozenset({DeploymentStatus.PENDING.value, DeploymentStatus.SCHEDULED.value, DeploymentStatus.FAILED.value})
    ROLLBACKABLE = frozenset({DeploymentStatus.DEPLOYED.value, DeploymentStatus.VERIFIED.value, DeploymentStatus.FAILED.value})
    ACTIVE = frozenset({DeploymentStatus.PENDING.value, DeploymentStatus.SCHEDULED.value, DeploymentStatus.DEPLOYING.value})

    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.logger = logger

    async def create_patch_operations(
        self,
        db: AsyncSession,
        vulnerability_instances: list[VulnerabilityInstance],
        maintenance_window: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> tuple[list[PatchOperation], list[dict[str, str]]]:
        """One PatchOperation per instance; instances that already have an
        active (pending / scheduled / deploying) operation, are already
        patched or are false positives are skipped with the reason (accepted
        risk and compensating controls can still be patched)."""
        if not vulnerability_instances:
            return [], []
        ids = [i.id for i in vulnerability_instances]
        active = set(
            (
                await db.execute(
                    select(PatchOperation.vulnerability_instance_id).where(
                        PatchOperation.organization_id == self.organization_id,
                        PatchOperation.vulnerability_instance_id.in_(ids),
                        PatchOperation.deployment_status.in_(sorted(self.ACTIVE)),
                    )
                )
            ).scalars()
        )
        vulns = {
            v.id: v
            for v in (
                await db.execute(
                    select(Vulnerability).where(
                        Vulnerability.organization_id == self.organization_id,
                        Vulnerability.id.in_({i.vulnerability_id for i in vulnerability_instances}),
                    )
                )
            ).scalars()
        }
        created: list[PatchOperation] = []
        skipped: list[dict[str, str]] = []
        for instance in vulnerability_instances:
            if instance.id in active:
                skipped.append({"instance_id": instance.id, "reason": "active_patch_operation_exists"})
                continue
            if instance.status in NOT_PATCHABLE_STATUSES:
                skipped.append({"instance_id": instance.id, "reason": f"instance_{instance.status}"})
                continue
            vuln = vulns.get(instance.vulnerability_id)
            target = instance.asset_name or instance.asset_ip or instance.asset_id or "unknown asset"
            op = PatchOperation(
                vulnerability_instance_id=instance.id,
                patch_type=PatchType.OS_PATCH.value,
                patch_name=f"{vuln.cve_id if vuln else 'vulnerability'} on {target}"[:500],
                deployment_status=(
                    DeploymentStatus.SCHEDULED.value if maintenance_window else DeploymentStatus.PENDING.value
                ),
                deployment_date=maintenance_window,
                rollback_available=True,
                deployment_notes=notes,
                organization_id=self.organization_id,
            )
            db.add(op)
            created.append(op)
            if instance.status == VulnerabilityStatus.OPEN.value:
                instance.status = VulnerabilityStatus.IN_PROGRESS.value
        await db.flush()
        self.logger.info("Created patch operations", created=len(created), skipped=len(skipped))
        return created, skipped

    async def create_patch_plan(
        self,
        db: AsyncSession,
        vulnerability_instances: list[VulnerabilityInstance],
        maintenance_window: Optional[str] = None,
    ) -> str:
        """Backward-compatible wrapper: first created PatchOperation id ("" if none)."""
        created, _ = await self.create_patch_operations(db, vulnerability_instances, maintenance_window)
        return created[0].id if created else ""

    async def _get(self, db: AsyncSession, patch_operation_id: str) -> Optional[PatchOperation]:
        return (
            await db.execute(
                select(PatchOperation).where(
                    and_(PatchOperation.id == patch_operation_id, PatchOperation.organization_id == self.organization_id)
                )
            )
        ).scalar_one_or_none()

    async def _instance(self, db: AsyncSession, op: PatchOperation) -> Optional[VulnerabilityInstance]:
        return (
            await db.execute(
                select(VulnerabilityInstance).where(
                    VulnerabilityInstance.id == op.vulnerability_instance_id,
                    VulnerabilityInstance.organization_id == self.organization_id,
                )
            )
        ).scalar_one_or_none()

    async def schedule_deployment(self, db: AsyncSession, patch_operation_id: str, deployment_date: str) -> bool:
        """Record the planned date; False when the operation is not schedulable."""
        op = await self._get(db, patch_operation_id)
        if op is None or op.deployment_status not in self.SCHEDULABLE:
            return False
        op.deployment_status = DeploymentStatus.SCHEDULED.value
        op.deployment_date = deployment_date
        await db.commit()
        return True

    async def verify_patch(self, db: AsyncSession, patch_operation_id: str, verification_results: dict[str, Any]) -> bool:
        """Record the operator's verification. ``passed`` closes the instance
        as patched (remediated_at = now); a failure re-opens it."""
        op = await self._get(db, patch_operation_id)
        if op is None:
            return False
        passed = bool(verification_results.get("passed", False))
        instance = await self._instance(db, op)
        now = now_iso()
        if passed:
            op.deployment_status = DeploymentStatus.VERIFIED.value
            op.verification_date = now
            if instance is not None:
                apply_status_change(instance, VulnerabilityStatus.PATCHED.value, now)
        else:
            op.deployment_status = DeploymentStatus.FAILED.value
            if instance is not None and instance.status in REMEDIATED_STATUSES | {VulnerabilityStatus.IN_PROGRESS.value}:
                apply_status_change(instance, VulnerabilityStatus.OPEN.value)
        await db.flush()
        if instance is not None:
            await refresh_instances(db, self.organization_id, [instance.id])
        await db.commit()
        return passed

    async def rollback_patch(self, db: AsyncSession, patch_operation_id: str, reason: str) -> bool:
        """Record a rollback; False when nothing was deployed (not reversible)."""
        op = await self._get(db, patch_operation_id)
        if op is None or not op.rollback_available or op.deployment_status not in self.ROLLBACKABLE:
            return False
        op.deployment_status = DeploymentStatus.ROLLED_BACK.value
        op.deployment_notes = f"Rolled back: {reason}"
        instance = await self._instance(db, op)
        if instance is not None and instance.status == VulnerabilityStatus.PATCHED.value:
            apply_status_change(instance, VulnerabilityStatus.OPEN.value)
            await db.flush()
            await refresh_instances(db, self.organization_id, [instance.id])
        await db.commit()
        return True

    async def generate_patch_report(self, db: AsyncSession) -> dict[str, Any]:
        rows = (
            await db.execute(
                select(PatchOperation.deployment_status, func.count(PatchOperation.id))
                .where(PatchOperation.organization_id == self.organization_id)
                .group_by(PatchOperation.deployment_status)
            )
        ).all()
        by_status = {status: int(n) for status, n in rows}
        report = {"total_operations": sum(by_status.values())}
        for status in DeploymentStatus:
            report[status.value] = by_status.get(status.value, 0)
        return report

    async def track_patch_compliance(self, db: AsyncSession) -> dict[str, Any]:
        rows = (
            await db.execute(
                select(VulnerabilityInstance.status, func.count(VulnerabilityInstance.id))
                .where(VulnerabilityInstance.organization_id == self.organization_id)
                .group_by(VulnerabilityInstance.status)
            )
        ).all()
        by_status = {s: int(n) for s, n in rows}
        total = sum(n for s, n in by_status.items() if s not in EXCLUDED_STATUSES)
        patched = by_status.get(VulnerabilityStatus.PATCHED.value, 0)
        return {
            "total_vulnerabilities": total,
            "patched": patched,
            "compliance_percentage": round(patched / total * 100, 1) if total else 0.0,
        }


# --------------------------------------------------------------------------- #
# Lifecycle metrics
# --------------------------------------------------------------------------- #


class VulnerabilityLifecycle:
    """Lifecycle metrics from instance timestamps (SQL aggregates)."""

    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.logger = logger

    async def track_mean_time_to_remediate(self, db: AsyncSession) -> Optional[float]:
        """Mean days first_seen -> remediated_at over remediated instances; None without any."""
        rows = (
            await db.execute(
                select(VulnerabilityInstance.first_seen, VulnerabilityInstance.created_at, VulnerabilityInstance.remediated_at)
                .where(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    VulnerabilityInstance.status.in_(sorted(REMEDIATED_STATUSES)),
                    VulnerabilityInstance.remediated_at.is_not(None),
                )
                .order_by(VulnerabilityInstance.remediated_at.desc())
                .limit(METRIC_ROW_CAP)
            )
        ).all()
        durations: list[float] = []
        for first_seen, created_at, remediated_at in rows:
            start = parse_iso(first_seen) or parse_iso(created_at)
            end = parse_iso(remediated_at)
            if start is not None and end is not None and end >= start:
                durations.append((end - start).total_seconds() / 86400.0)
        return round(sum(durations) / len(durations), 1) if durations else None

    async def track_sla_compliance(self, db: AsyncSession) -> dict[str, Any]:
        sla = await RiskPrioritizer(self.organization_id).assess_sla_compliance(db)
        return {k: sla[k] for k in ("total", "within_sla", "approaching", "breached")}

    async def aging_analysis(self, db: AsyncSession) -> dict[str, int]:
        """Open instances by age since first detection."""
        now = utc_now()
        bounds = [(now - timedelta(days=d)) for d in (30, 60, 90)]
        open_filter = and_(
            VulnerabilityInstance.organization_id == self.organization_id,
            VulnerabilityInstance.status.in_(sorted(OPEN_STATUSES)),
        )

        def bucket(column: Any, b30: Any, b60: Any, b90: Any) -> Any:
            return case(
                (column >= b30, "0-30_days"),
                (column >= b60, "31-60_days"),
                (column >= b90, "61-90_days"),
                else_="90+_days",
            )

        aging = {"0-30_days": 0, "31-60_days": 0, "61-90_days": 0, "90+_days": 0}
        iso = [b.isoformat() for b in bounds]
        by_first_seen = bucket(VulnerabilityInstance.first_seen, *iso)
        for label, n in (
            await db.execute(
                select(by_first_seen, func.count(VulnerabilityInstance.id))
                .where(open_filter, VulnerabilityInstance.first_seen.is_not(None))
                .group_by(by_first_seen)
            )
        ).all():
            aging[label] += int(n)
        by_created = bucket(VulnerabilityInstance.created_at, *bounds)
        for label, n in (
            await db.execute(
                select(by_created, func.count(VulnerabilityInstance.id))
                .where(open_filter, VulnerabilityInstance.first_seen.is_(None))
                .group_by(by_created)
            )
        ).all():
            aging[label] += int(n)
        return aging

    async def trend_analysis(self, db: AsyncSession, days: int = 30) -> dict[str, Any]:
        """Instances created vs remediated in the last ``days`` days."""
        cutoff = utc_now() - timedelta(days=days)
        new_count = int(
            (
                await db.execute(
                    select(func.count(VulnerabilityInstance.id)).where(
                        VulnerabilityInstance.organization_id == self.organization_id,
                        VulnerabilityInstance.created_at >= cutoff,
                    )
                )
            ).scalar()
            or 0
        )
        closed_count = int(
            (
                await db.execute(
                    select(func.count(VulnerabilityInstance.id)).where(
                        VulnerabilityInstance.organization_id == self.organization_id,
                        VulnerabilityInstance.remediated_at.is_not(None),
                        VulnerabilityInstance.remediated_at >= cutoff.isoformat(),
                    )
                )
            ).scalar()
            or 0
        )
        return {
            "period_days": days,
            "new_discovered": new_count,
            "closed": closed_count,
            "net_change": new_count - closed_count,
        }

    async def severity_counts(self, db: AsyncSession, open_only: bool = True) -> dict[str, int]:
        """Instances by catalogue severity (open ones by default)."""
        stmt = (
            select(Vulnerability.severity, func.count(VulnerabilityInstance.id))
            .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
            .where(VulnerabilityInstance.organization_id == self.organization_id)
            .group_by(Vulnerability.severity)
        )
        if open_only:
            stmt = stmt.where(VulnerabilityInstance.status.in_(sorted(OPEN_STATUSES)))
        counts = {s.value: 0 for s in VulnerabilitySeverity}
        for severity, n in (await db.execute(stmt)).all():
            counts[severity or "unknown"] = counts.get(severity or "unknown", 0) + int(n)
        return counts

    async def generate_executive_report(self, db: AsyncSession) -> dict[str, Any]:
        rows = (
            await db.execute(
                select(VulnerabilityInstance.status, func.count(VulnerabilityInstance.id))
                .where(VulnerabilityInstance.organization_id == self.organization_id)
                .group_by(VulnerabilityInstance.status)
            )
        ).all()
        by_status = {s: int(n) for s, n in rows}
        severities = await self.severity_counts(db)
        return {
            "total_vulnerabilities": sum(by_status.values()),
            "open_vulnerabilities": sum(n for s, n in by_status.items() if s in OPEN_STATUSES),
            "critical_count": severities.get("critical", 0),
            "high_count": severities.get("high", 0),
            "by_status": by_status,
            "mttr_days": await self.track_mean_time_to_remediate(db),
            "sla_compliance": await self.track_sla_compliance(db),
            "aging": await self.aging_analysis(db),
        }


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_KEV_ENTRIES = 50_000


async def fetch_kev_catalog(transport: Optional[httpx.AsyncBaseTransport] = None) -> dict[str, Any]:
    """Fetch the CISA KEV JSON through the pinned outbound transport."""
    from src.integrations.netguard import PinnedTransport

    try:
        async with httpx.AsyncClient(
            timeout=30.0, transport=transport or PinnedTransport(), follow_redirects=False,
        ) as client:
            resp = await client.get(KEV_FEED_URL)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KEVFeedUnavailable(f"CISA KEV feed fetch failed: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise KEVFeedUnavailable("CISA KEV feed returned an unexpected document")
    return data


def kev_index(kev_data: dict[str, Any]) -> dict[str, dict[str, Optional[str]]]:
    """``{CVE: {date_added, due_date}}`` from a KEV document (capped)."""
    out: dict[str, dict[str, Optional[str]]] = {}
    for entry in (kev_data.get("vulnerabilities") or [])[:MAX_KEV_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "").strip().upper()
        if cve.startswith("CVE-"):
            out[cve] = {"date_added": entry.get("dateAdded"), "due_date": entry.get("dueDate")}
    return out


class KEVMonitor:
    """Flag the org's catalogue rows that CISA lists as known exploited."""

    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.logger = logger
        self.kev_url = KEV_FEED_URL

    async def sync_cisa_kev(self, db: AsyncSession, kev_data: dict[str, Any]) -> dict[str, int]:
        """Flag existing catalogue rows whose CVE is in the KEV document.

        Never creates a vulnerability: a KEV entry the tenant does not track is
        not a finding in its environment. The exposure catalogue
        (``exposure_vulnerabilities``) of the same org is flagged too
        (``is_exploited_in_wild``), so both pages read the same feed.
        """
        from src.exposure.models import ExposureVulnerability

        index = kev_index(kev_data)
        cves = sorted(index)
        matched = newly_flagged = exposure_flagged = 0
        for offset in range(0, len(cves), REFRESH_BATCH):
            chunk = cves[offset : offset + REFRESH_BATCH]
            for vuln in (
                await db.execute(
                    select(Vulnerability).where(
                        Vulnerability.organization_id == self.organization_id, Vulnerability.cve_id.in_(chunk),
                    )
                )
            ).scalars():
                matched += 1
                entry = index[vuln.cve_id]
                if not vuln.kev_listed:
                    newly_flagged += 1
                vuln.kev_listed = True
                vuln.exploit_available = True
                vuln.kev_date_added = entry.get("date_added")
                vuln.kev_due_date = entry.get("due_date")
            res = await db.execute(
                update(ExposureVulnerability)
                .where(
                    ExposureVulnerability.organization_id == self.organization_id,
                    ExposureVulnerability.cve_id.in_(chunk),
                    ExposureVulnerability.is_exploited_in_wild == False,  # noqa: E712
                )
                .values(is_exploited_in_wild=True, exploit_available=True)
                .execution_options(synchronize_session=False)
            )
            exposure_flagged += int(res.rowcount or 0)
            await db.flush()
        await refresh_instances(db, self.organization_id)
        await db.commit()
        result = {
            "catalog_entries": len(index),
            "matched": matched,
            "newly_flagged": newly_flagged,
            "already_flagged": matched - newly_flagged,
            "exposure_vulnerabilities_flagged": exposure_flagged,
            # Kept for callers of the old shape: ``updated`` = rows flagged,
            # ``added`` is always 0 (the feed no longer creates rows).
            "updated": matched,
            "added": 0,
        }
        self.logger.info("KEV sync completed", organization_id=self.organization_id, **result)
        return result

    async def check_kev_compliance(self, db: AsyncSession) -> dict[str, Any]:
        """BOD 22-01 status of instances of KEV-listed CVEs.

        Deadline = the CISA due date, else first detection + 15 days.
        Compliant: remediated on or before the deadline, or still open and
        not yet past it. Accepted / false-positive instances are excluded.
        """
        rows = (
            await db.execute(
                select(
                    VulnerabilityInstance.status,
                    VulnerabilityInstance.first_seen,
                    VulnerabilityInstance.created_at,
                    VulnerabilityInstance.remediated_at,
                    Vulnerability.kev_due_date,
                )
                .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
                .where(
                    VulnerabilityInstance.organization_id == self.organization_id,
                    Vulnerability.kev_listed == True,  # noqa: E712
                    VulnerabilityInstance.status.not_in(sorted(EXCLUDED_STATUSES)),
                )
                .limit(METRIC_ROW_CAP)
            )
        ).all()
        now = utc_now()
        compliant = non_compliant = patched = 0
        for status, first_seen, created_at, remediated_at, due in rows:
            start = parse_iso(first_seen) or parse_iso(created_at)
            deadline = parse_iso(due) or (start + timedelta(days=KEV_DEFAULT_DAYS) if start else None)
            if status in REMEDIATED_STATUSES:
                patched += 1
                done = parse_iso(remediated_at) or now
                ok = deadline is None or done <= deadline
            else:
                ok = deadline is None or now <= deadline
            compliant += ok
            non_compliant += not ok
        tracked = len(rows)
        return {
            "tracked": tracked,
            "patched": patched,
            "compliant": compliant,
            "non_compliant": non_compliant,
            # None (not 100 %) when no KEV-listed instance is tracked.
            "compliance_percentage": round(compliant / tracked * 100, 1) if tracked else None,
            "bod_22_01_deadline_days": KEV_DEFAULT_DAYS,
        }

    async def generate_bod_22_01_report(self, db: AsyncSession) -> dict[str, Any]:
        compliance = await self.check_kev_compliance(db)
        return {
            "report_date": now_iso(),
            "mandate": "BOD 22-01",
            "deadline_days": KEV_DEFAULT_DAYS,
            "total_kev_tracked": compliance["tracked"],
            "kev_patched": compliance["patched"],
            "kev_compliant": compliance["compliant"],
            "kev_non_compliant": compliance["non_compliant"],
            "compliance_percentage": compliance["compliance_percentage"],
        }
