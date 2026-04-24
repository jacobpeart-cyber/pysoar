"""Celery Tasks for Dark Web Monitoring

Scheduled and background tasks for dark web scanning, credential leak detection,
brand monitoring, and threat intelligence correlation.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import select

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.darkweb.engine import (
    DarkWebScanner,
    CredentialAnalyzer,
    BrandProtection,
    ThreatIntelCorrelator,
)
from src.darkweb.models import (
    CredentialLeak,
    DarkWebFinding,
    DarkWebMonitor,
)
from src.models.incident import Incident
from src.intel.models import ThreatIndicator as IOC

logger = get_logger(__name__)


def _fresh_darkweb_session_factory():
    """Per-task NullPool engine to avoid 'Future attached to a different loop'
    errors under Celery prefork — same pattern as itdr/agentic/supplychain."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool
    e = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return e, sessionmaker(e, class_=AsyncSession, expire_on_commit=False)


def _map_source_to_finding_types(source: str) -> tuple[str, str]:
    """Return (source_platform, finding_type) enum values for a scanner source key."""
    mapping = {
        "paste_sites": ("paste_site", "paste_site_exposure"),           # URLhaus malicious URLs
        "breach_databases": ("breach_database", "data_breach_listing"),
        "forums": ("tor_forum", "forum_mention"),                        # ThreatFox IOCs
        "telegram": ("telegram", "forum_mention"),                       # OTX pulses
        # Tier 2 HIBP sources — per-email / per-domain lookups
        "hibp_account": ("breach_database", "credential_leak"),
        "hibp_stealer": ("breach_database", "credential_leak"),
        "hibp_paste": ("paste_site", "credential_leak"),
        "hibp_domain": ("breach_database", "data_breach_listing"),
    }
    return mapping.get(source, ("breach_database", "data_breach_listing"))


def _derive_finding_severity(source: str, raw: dict) -> str:
    """Pick severity from the underlying feed payload.

    - URLhaus "threat" containing malware/ransomware → critical
    - HIBP breach with > 10M accounts or IsVerified=True → critical
    - ThreatFox confidence_level >= 75 → high
    - OTX with TLP amber/red → high
    - everything else → medium
    """
    threat_type = str(raw.get("threat_type", "")).lower()
    if source == "paste_sites" and any(k in threat_type for k in ("malware", "ransomware", "phishing", "c2")):
        return "critical"
    if source == "breach_databases":
        if int(raw.get("affected_count") or 0) >= 10_000_000 or raw.get("is_verified"):
            return "critical"
        return "high"
    if source == "forums":
        try:
            if int(raw.get("confidence", 0) or 0) >= 75:
                return "high"
        except (TypeError, ValueError):
            pass
        return "medium"
    if source == "telegram":
        tlp = str(raw.get("tlp", "")).lower()
        return "high" if tlp in ("amber", "red") else "medium"
    # Tier 2 HIBP — employee credentials in a breach is always serious
    if source in ("hibp_account", "hibp_stealer"):
        return "critical"
    if source == "hibp_paste":
        return "high"
    if source == "hibp_domain":
        # Domain-scoped breach: severity scales with affected count
        if int(raw.get("affected_count") or 0) >= 10_000_000 or raw.get("is_verified"):
            return "critical"
        return "high"
    return "medium"


async def _persist_findings(
    db,
    organization_id: str,
    monitor_id: str | None,
    findings: list[dict],
    monitor_alert_severity: str = "medium",
) -> tuple[int, int, list[dict], int]:
    """Write findings to darkweb_findings with dedup by content_hash.

    For Tier 2 HIBP per-email findings (sources hibp_account, hibp_stealer,
    hibp_paste) we also create a CredentialLeak row linked to the
    DarkWebFinding so the Credentials tab / remediation flow works.

    Returns (created_count, skipped_duplicate_count,
             critical_findings_for_automation, credential_leaks_created).
    """
    created = 0
    skipped = 0
    cred_leaks_created = 0
    criticals: list[dict] = []
    for f in findings:
        content_hash = f.get("content_hash")
        if not content_hash:
            # Engine already stamps a hash; if missing, skip — without a
            # stable identity we'd duplicate rows on every scan.
            skipped += 1
            continue
        # Dedup inside this org.
        existing = (await db.execute(
            select(DarkWebFinding).where(
                DarkWebFinding.organization_id == organization_id,
                DarkWebFinding.raw_data_hash == content_hash,
            )
        )).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            continue

        source_key = f.get("source") or ""
        source_platform, finding_type = _map_source_to_finding_types(source_key)
        severity = _derive_finding_severity(source_key, f)

        # Pack a sensible title + description from whichever fields the
        # underlying feed used (each feed's payload shape differs).
        title = (
            f.get("title")
            or f.get("breach_name")
            or f.get("message")
            or f.get("url")
            or f.get("ioc_value")
            or "dark web finding"
        )
        description = (
            f.get("description")
            or f.get("content_snippet")
            or f.get("malware")
            or ""
        )
        source_url = f.get("url") or f.get("source_url") or ""
        import hashlib
        source_url_hash = (
            hashlib.sha256(source_url.encode()).hexdigest()
            if source_url else None
        )

        row = DarkWebFinding(
            organization_id=organization_id,
            monitor_id=monitor_id,
            finding_type=finding_type,
            source_platform=source_platform,
            source_url_hash=source_url_hash,
            title=str(title)[:500],
            description=str(description)[:4000],
            raw_data_hash=str(content_hash)[:128],
            affected_count=int(f.get("affected_count") or 1),
            severity=severity,
            confidence_score=int(f.get("confidence") or 50),
            status="new",
            discovered_date=datetime.now(timezone.utc).isoformat(),
        )
        db.add(row)
        await db.flush()  # assign row.id so CredentialLeak can reference it
        created += 1

        # Tier 2 HIBP per-email hit -> CredentialLeak row.
        if source_key in ("hibp_account", "hibp_stealer", "hibp_paste"):
            email = f.get("email")
            if email:
                db.add(CredentialLeak(
                    organization_id=organization_id,
                    finding_id=row.id,
                    email=str(email)[:255],
                    username=str(email).split("@", 1)[0][:255] if "@" in str(email) else None,
                    password_hash=None,  # HIBP doesn't expose password hashes
                    password_type="unknown",
                    breach_source=(
                        f.get("breach_name")
                        or f.get("site")
                        or f.get("paste_source")
                        or "hibp"
                    )[:255],
                    breach_date=f.get("breach_date") or f.get("paste_date"),
                    is_valid=False,  # Requires confirmation via /unifiedsearch workflow
                    is_remediated=False,
                ))
                cred_leaks_created += 1

        if severity == "critical":
            criticals.append({
                "finding_type": finding_type,
                "description": str(description or title)[:500],
                "source_url": source_url,
                "severity": severity,
            })
    if created:
        await db.commit()
    return created, skipped, criticals, cred_leaks_created


@shared_task(bind=True, max_retries=3)
def scheduled_dark_web_scan(
    self,
    monitor_id: str | None = None,
    scan_type: str = "full",
    organization_id: str | None = None,
) -> dict[str, Any]:
    """
    Real dark web scan against URLhaus, HIBP /breaches, ThreatFox, and
    OTX (when API key is set). Persists findings into darkweb_findings
    with dedup by content_hash. Fires ``AutomationService.on_darkweb_finding``
    on critical findings so the agentic SOC pipeline opens an alert →
    investigator chain. Updates the monitor's ``last_check`` and
    ``findings_count`` so the UI can show a real "last scan" timestamp.

    Args:
        monitor_id: Optional specific monitor to scan. If omitted, scans
            at org-level (requires organization_id) and attributes
            findings to no specific monitor.
        scan_type: "full" for all sources, "quick" to skip OTX/paste feeds.
        organization_id: Required when monitor_id is None. Scoping is
            enforced: findings only land against this org.
    """
    async def _run():
        engine, factory = _fresh_darkweb_session_factory()
        try:
            async with factory() as db:
                monitor = None
                org_id = organization_id
                if monitor_id:
                    monitor = (await db.execute(
                        select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id)
                    )).scalar_one_or_none()
                    if monitor is None:
                        return {"status": "error", "error": f"monitor {monitor_id} not found"}
                    org_id = monitor.organization_id
                if not org_id:
                    return {"status": "error", "error": "organization_id required when monitor_id is not provided"}

                scanner = DarkWebScanner()
                if scan_type == "quick":
                    # Only hit the cheap / high-value feeds.
                    results = {
                        "paste_sites": await scanner.search_paste_sites(),
                        "breach_databases": await scanner.search_breach_databases(),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                else:
                    results = await scanner.run_scan_cycle()
                    # run_scan_cycle returns {total_findings, findings, timestamp}
                    # but _persist_findings wants the raw per-source list.
                    # Fetch again via aggregate_findings or re-run sources.
                    # Simplest: use the aggregated 'findings' list the engine
                    # already deduped in-memory.
                    findings_list = results.get("findings", [])

                if scan_type == "quick":
                    findings_list = []
                    for source, items in results.items():
                        if source == "timestamp" or not isinstance(items, list):
                            continue
                        for item in items:
                            item["source"] = source
                            # Engine's deduplicate_results sets content_hash; the
                            # quick path skips it so stamp one here.
                            import hashlib as _h, json as _j
                            if "content_hash" not in item:
                                item["content_hash"] = _h.sha256(
                                    _j.dumps(item, sort_keys=True, default=str).encode()
                                ).hexdigest()
                            findings_list.append(item)

# ---- Tier 2: per-monitor HIBP account & domain lookups ----
# Runs when the monitor has emails_watched / domains_watched
# AND either the API key is set (for per-email) or not (for
# domain-level breach list which is free).
                if monitor is not None:
                    import json as _json
                    emails = monitor.emails_watched
                    if isinstance(emails, str):
                        try:
                            emails = _json.loads(emails)
                        except Exception:  # noqa: BLE001
                            emails = []
                    domains = monitor.domains_watched
                    if isinstance(domains, str):
                        try:
                            domains = _json.loads(domains)
                        except Exception:  # noqa: BLE001
                            domains = []
                    emails = list(emails or [])
                    domains = list(domains or [])
                    if emails:
                        findings_list.extend(
                            await scanner.hibp_lookup_emails(emails)
                        )
                    if domains:
                        findings_list.extend(
                            await scanner.hibp_lookup_domains(domains)
                        )

                alert_severity = (monitor.alert_severity if monitor else "medium") or "medium"
                created, skipped, criticals, cred_leaks_created = await _persist_findings(
                    db,
                    organization_id=org_id,
                    monitor_id=monitor.id if monitor else None,
                    findings=findings_list,
                    monitor_alert_severity=alert_severity,
                )

                # Update monitor health fields — the UI renders "last
                # scan" from these; previously stayed null because no
                # real scan ever ran.
                if monitor is not None:
                    monitor.last_check = datetime.now(timezone.utc).isoformat()
                    monitor.findings_count = (monitor.findings_count or 0) + created
                    await db.commit()

                # Fire the agentic pipeline for critical findings so the
                # investigator picks them up like it does ITDR / supply-
                # chain threats today.
                automation_fired = 0
                if criticals:
                    from src.services.automation import AutomationService
                    svc = AutomationService(db)
                    for c in criticals:
                        try:
                            await svc.on_darkweb_finding(
                                finding_type=c["finding_type"],
                                description=c["description"],
                                source_url=c["source_url"],
                                severity=c["severity"],
                                organization_id=org_id,
                            )
                            automation_fired += 1
                        except Exception as exc:  # noqa: BLE001
                            logger.warning(f"on_darkweb_finding fire failed: {exc}")

                return {
                    "scan_id": f"scan_{monitor_id or org_id}_{datetime.now(timezone.utc).timestamp()}",
                    "monitor_id": monitor_id,
                    "organization_id": org_id,
                    "created": created,
                    "credential_leaks_created": cred_leaks_created,
                    "skipped_duplicate": skipped,
                    "critical_fired": automation_fired,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "completed",
                }
        finally:
            await engine.dispose()

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Dark web scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=1)
def darkweb_cross_org_sweep(self) -> dict[str, Any]:
    """Periodic cross-org dark-web sweep.

    Iterates every Organization with at least one enabled DarkWebMonitor
    and runs ``scheduled_dark_web_scan`` against each monitor. Gives us
    a single beat-schedule entry that fans out properly instead of
    requiring one beat entry per monitor.
    """
    async def _sweep():
        from src.models.organization import Organization
        engine, factory = _fresh_darkweb_session_factory()
        totals = {"orgs_scanned": 0, "monitors_scanned": 0, "findings_created": 0}
        try:
            async with factory() as db:
                orgs = list((await db.execute(select(Organization))).scalars().all())
                for org in orgs:
                    monitors = list((await db.execute(
                        select(DarkWebMonitor).where(
                            DarkWebMonitor.organization_id == org.id,
                            DarkWebMonitor.enabled == True,  # noqa: E712
                        )
                    )).scalars().all())
                    if not monitors:
                        continue
                    totals["orgs_scanned"] += 1
                    for m in monitors:
                        totals["monitors_scanned"] += 1
                        # Delegate to the per-monitor task in-process
                        # (sync Celery .apply() so we can collect totals).
                        res = scheduled_dark_web_scan.apply(
                            kwargs={"monitor_id": m.id, "scan_type": "full"}
                        ).get()
                        if isinstance(res, dict):
                            totals["findings_created"] += int(res.get("created") or 0)
        finally:
            await engine.dispose()
        logger.info(f"darkweb_cross_org_sweep: {totals}")
        return totals

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_sweep())
        finally:
            loop.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"darkweb_cross_org_sweep failed: {exc}")
        return {"error": str(exc)[:200]}


@shared_task(bind=True, max_retries=3)
def credential_leak_check(
    self,
    finding_id: str,
    extract_credentials: bool = True,
) -> dict[str, Any]:
    """
    Check credential leak for organizational exposure.

    Extracts credentials from leaked data, analyzes hash types,
    and correlates with organizational user database.

    Args:
        finding_id: ID of the dark web finding to analyze
        extract_credentials: Whether to extract and parse credentials

    Returns:
        Dictionary with credential analysis results
    """
    try:
        logger.info(
            f"Analyzing credential leak (finding={finding_id}, "
            f"extract={extract_credentials})"
        )

        analyzer = CredentialAnalyzer()

        async def _fetch_credential_context() -> dict[str, Any]:
            async with async_session_factory() as session:
                # Load the specific finding
                finding_stmt = select(DarkWebFinding).where(
                    DarkWebFinding.id == finding_id
                )
                finding = (await session.scalars(finding_stmt)).first()

                raw_text = ""
                org_id: str | None = None
                monitor_id: str | None = None
                if finding is not None:
                    org_id = finding.organization_id
                    monitor_id = finding.monitor_id
                    # DarkWebFinding stores a raw_data_hash, not raw text; use the
                    # finding description and any analyst notes as the credential
                    # text source. (Full raw payloads live in object storage
                    # which is not yet wired up to the DB layer.)
                    raw_text = "\n".join(
                        part
                        for part in (finding.description, finding.analyst_notes)
                        if part
                    )

                monitored_domains: list[str] = []
                monitored_emails: list[str] = []
                if org_id:
                    mon_stmt = select(DarkWebMonitor).where(
                        DarkWebMonitor.organization_id == org_id
                    )
                    monitors = list((await session.scalars(mon_stmt)).all())
                    for m in monitors:
                        if m.domains_watched:
                            monitored_domains.extend(m.domains_watched or [])
                        if m.emails_watched:
                            monitored_emails.extend(m.emails_watched or [])

                return {
                    "raw_text": raw_text,
                    "monitored_domains": sorted(set(monitored_domains)),
                    "monitored_emails": sorted(set(monitored_emails)),
                    "organization_id": org_id,
                    "monitor_id": monitor_id,
                    "finding_found": finding is not None,
                }

        ctx = asyncio.run(_fetch_credential_context())

        if not ctx["finding_found"]:
            logger.warning(f"Credential leak check: finding {finding_id} not found")
            return {
                "finding_id": finding_id,
                "credentials_extracted": 0,
                "organizational_credentials": 0,
                "analyzed_credentials": [],
                "organizational_matches": [],
                "status": "finding_not_found",
            }

        # Parse credentials from the finding's actual content
        credentials = (
            analyzer.parse_credential_dumps(ctx["raw_text"])
            if extract_credentials and ctx["raw_text"]
            else []
        )
        logger.info(f"Extracted {len(credentials)} credentials")

        # Assess password risk for each credential
        analyzed_creds = []
        for cred in credentials:
            password_hash = cred.get("password", "")
            risk_assessment = analyzer.assess_password_risk(password_hash)

            analyzed_creds.append(
                {
                    "credential": cred,
                    "risk_assessment": risk_assessment,
                }
            )

        # Identify organizational credentials against this org's monitored assets
        organizational_creds = analyzer.identify_organizational_credentials(
            credentials,
            monitored_domains=ctx["monitored_domains"],
            monitored_emails=ctx["monitored_emails"],
        )

        logger.info(f"Found {len(organizational_creds)} organizational credentials")

        return {
            "finding_id": finding_id,
            "credentials_extracted": len(credentials),
            "organizational_credentials": len(organizational_creds),
            "analyzed_credentials": analyzed_creds,
            "organizational_matches": organizational_creds,
            "status": "completed",
        }

    except Exception as exc:
        logger.error(f"Credential leak check failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def brand_monitoring_scan(
    self,
    monitor_id: str,
    target_brand: str,
    monitored_domains: list[str] | None = None,
) -> dict[str, Any]:
    """
    Scan for brand impersonation and domain spoofing threats.

    Detects typosquatting, lookalike sites, phishing kits, and
    unauthorized use of brand assets.

    Args:
        monitor_id: ID of the brand monitoring configuration
        target_brand: Brand name to monitor
        monitored_domains: List of legitimate domains to monitor

    Returns:
        Dictionary with brand threat detection results
    """
    try:
        logger.info(
            f"Starting brand monitoring scan (brand={target_brand}, "
            f"monitor={monitor_id})"
        )

        brand_protection = BrandProtection()
        monitored_domains = monitored_domains or [f"{target_brand.lower()}.com"]

        threats = {
            "typosquats": [],
            "lookalikes": [],
            "phishing_kits": [],
            "ct_anomalies": [],
        }

        # Detect typosquatting
        for domain in monitored_domains:
            typosquat_detections = brand_protection.detect_typosquatting(domain)
            threats["typosquats"].extend(typosquat_detections)

        # Monitor certificate transparency logs
        ct_anomalies = brand_protection.monitor_certificate_transparency_logs(
            monitored_domains
        )
        threats["ct_anomalies"].extend(ct_anomalies)

        total_threats = sum(len(v) for v in threats.values() if isinstance(v, list))
        logger.info(f"Brand scan detected {total_threats} potential threats")

        return {
            "monitor_id": monitor_id,
            "target_brand": target_brand,
            "total_threats": total_threats,
            "threats": threats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
        }

    except Exception as exc:
        logger.error(f"Brand monitoring scan failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def takedown_status_check(
    self,
    takedown_id: str,
    threat_id: str,
) -> dict[str, Any]:
    """
    Check status of ongoing takedown requests.

    Queries takedown service providers for status updates on
    phishing sites, cloned websites, and other brand threats.

    Args:
        takedown_id: ID of the takedown request
        threat_id: ID of the associated threat

    Returns:
        Dictionary with updated takedown status
    """
    try:
        logger.info(f"Checking takedown status (takedown={takedown_id})")

        brand_protection = BrandProtection()

        # Query the DarkWebMonitor/DarkWebFinding for real takedown status
        import asyncio
        from src.core.database import async_session_factory

        async def _check_status():
            async with async_session_factory() as db:
                # Look up the finding associated with this takedown
                finding_query = select(DarkWebFinding).where(
                    DarkWebFinding.id == threat_id
                )
                result = await db.execute(finding_query)
                finding = result.scalar_one_or_none()

                if finding:
                    return {
                        "takedown_id": takedown_id,
                        "status": finding.status if hasattr(finding, 'status') else "in_progress",
                        "last_updated": finding.updated_at.isoformat() if hasattr(finding, 'updated_at') and finding.updated_at else datetime.now(timezone.utc).isoformat(),
                        "finding_type": finding.finding_type,
                        "source_platform": finding.source_platform,
                    }
                else:
                    # Fall back to the brand_protection engine
                    return await brand_protection.track_takedown_status(takedown_id)

        status = asyncio.run(_check_status())

        logger.info(f"Takedown {takedown_id} status: {status.get('status')}")

        return {
            "takedown_id": takedown_id,
            "threat_id": threat_id,
            "status": status.get("status"),
            "progress": status.get("progress"),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as exc:
        logger.error(f"Takedown status check failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def threat_correlation(
    self,
    finding_id: str,
    organization_id: str,
) -> dict[str, Any]:
    """
    Correlate dark web finding with threat intelligence and incidents.

    Matches findings against IOC databases, active incidents,
    and historical threat intelligence.

    Args:
        finding_id: ID of the dark web finding
        organization_id: ID of the organization

    Returns:
        Dictionary with correlation results
    """
    try:
        logger.info(
            f"Correlating dark web finding (finding={finding_id}, "
            f"org={organization_id})"
        )

        correlator = ThreatIntelCorrelator()

        async def _run_correlation() -> dict[str, Any]:
            async with async_session_factory() as session:
                # Load finding
                finding = (
                    await session.scalars(
                        select(DarkWebFinding).where(DarkWebFinding.id == finding_id)
                    )
                ).first()
                if finding is None:
                    return {"finding_found": False}

                affected = finding.affected_assets or {}
                if isinstance(affected, str):
                    try:
                        import json as _json
                        affected = _json.loads(affected)
                    except Exception:  # noqa: BLE001
                        affected = {}

                finding_data = {
                    "id": finding.id,
                    "domain": affected.get("domain") if isinstance(affected, dict) else None,
                    "ip": affected.get("ip") if isinstance(affected, dict) else None,
                    "email": affected.get("email") if isinstance(affected, dict) else None,
                    "hash": finding.raw_data_hash,
                    "severity": finding.severity,
                    "confidence_score": finding.confidence_score,
                    "finding_type": finding.finding_type,
                    "source_platform": finding.source_platform,
                    "title": finding.title,
                    "description": finding.description,
                }

                # Load recent IOCs (last 90 days) for this org
                ioc_cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                ioc_stmt = select(IOC).where(
                    (IOC.organization_id == organization_id)
                    & (IOC.created_at >= ioc_cutoff)
                )
                iocs = list((await session.scalars(ioc_stmt)).all())
                ioc_database = [
                    {
                        "id": i.id,
                        "value": i.value,
                        "type": i.indicator_type,
                        "source": i.source,
                        "threat_level": i.severity,
                        "confidence": i.confidence,
                    }
                    for i in iocs
                ]

                # Load recent incidents (last 90 days) for this org
                inc_cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                inc_stmt = select(Incident).where(
                    Incident.created_at >= inc_cutoff
                )
                incidents = list((await session.scalars(inc_stmt)).all())

                import json as _json
                incident_database = []
                for inc in incidents:
                    iocs_list: list[str] = []
                    if inc.indicators:
                        try:
                            parsed = _json.loads(inc.indicators)
                            if isinstance(parsed, list):
                                iocs_list = [str(x) for x in parsed]
                        except Exception:  # noqa: BLE001
                            pass
                    incident_database.append(
                        {
                            "id": inc.id,
                            "title": inc.title,
                            "status": inc.status,
                            "severity": inc.severity,
                            "iocs": iocs_list,
                        }
                    )

                ioc_corr = await correlator.correlate_with_iocs(
                    finding_data, ioc_database
                )
                incident_corr = await correlator.correlate_with_incidents(
                    finding_data, incident_database
                )
                score = await correlator.calculate_risk_score(finding_data)

                return {
                    "finding_found": True,
                    "finding_data": finding_data,
                    "ioc_correlations": ioc_corr,
                    "incident_correlations": incident_corr,
                    "risk_score": score,
                    "ioc_count": len(ioc_database),
                    "incident_count": len(incident_database),
                }

        result = asyncio.run(_run_correlation())

        if not result.get("finding_found"):
            logger.warning(f"Threat correlation: finding {finding_id} not found")
            return {
                "finding_id": finding_id,
                "ioc_matches": 0,
                "incident_matches": 0,
                "risk_score": 0,
                "ioc_correlations": [],
                "incident_correlations": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "finding_not_found",
            }

        ioc_correlations = result["ioc_correlations"]
        incident_correlations = result["incident_correlations"]
        risk_score = result["risk_score"]

        logger.info(
            f"Finding {finding_id} correlated: "
            f"{len(ioc_correlations)} IOC matches, "
            f"risk_score={risk_score}"
        )

        return {
            "finding_id": finding_id,
            "ioc_matches": len(ioc_correlations),
            "incident_matches": len(incident_correlations),
            "risk_score": risk_score,
            "ioc_correlations": ioc_correlations,
            "incident_correlations": incident_correlations,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
        }

    except Exception as exc:
        logger.error(f"Threat correlation failed: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


def await_sync_wrapper(coro: Any) -> Any:
    """Helper to run async functions in sync Celery tasks"""
    import asyncio

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(coro)
