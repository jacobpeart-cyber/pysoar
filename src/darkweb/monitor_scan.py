"""One dark-web monitor scan: the monitor's own terms against real sources.

Used by ``POST /darkweb/monitors/{id}/trigger-scan`` (inline) and by the
``scheduled_dark_web_scan`` Celery task (the 30-minute cross-org sweep), so
both paths record the same findings.

A monitor carries three kinds of terms: ``search_terms`` (brand names,
product names, keywords), ``domains_watched`` and ``emails_watched``. A scan:

* looks up every watched email in Have I Been Pwned (breached accounts,
  infostealer logs, pastes) when ``HIBP_API_KEY`` is set, otherwise reports
  ``hibp_account`` as ``not_configured``;
* looks up every watched domain in HIBP's breach list (keyless);
* reads the HIBP recent-breach catalogue and, for a full scan, the abuse.ch
  URLhaus / ThreatFox feeds (``ABUSECH_AUTH_KEY``), AlienVault OTX pulses
  (``OTX_API_KEY``) and an operator marketplace feed
  (``DARKWEB_MARKETPLACE_FEED_URL``), keeping only the items that mention one
  of the monitor's terms (search terms, watched domains, the domains of
  watched emails). Feed matches are labelled ``threat_intel_feed`` /
  ``threat_feed_match``: these are threat-intelligence feeds, not paste
  sites, Tor forums or Telegram channels.

Every source reports its own status (``ok``, ``not_configured``, ``error``,
``skipped``) with the reason; a source failure is never turned into "no
findings". A monitor with no terms reports ``no_terms`` and searches nothing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.darkweb import engine as dw_engine
from src.darkweb.models import CredentialLeak, DarkWebFinding, DarkWebMonitor

logger = get_logger(__name__)

#: Human description of every source a scan can consult.
SOURCE_LABELS: dict[str, str] = {
    "hibp_account": "Have I Been Pwned account search for the watched emails (HIBP_API_KEY)",
    "hibp_domain": "Have I Been Pwned breaches for the watched domains",
    "hibp_breach_catalogue": "Have I Been Pwned breach catalogue (last 90 days), matched against the monitor terms",
    "urlhaus": "abuse.ch URLhaus recent malicious URLs (threat-intel feed, ABUSECH_AUTH_KEY), matched against the monitor terms",
    "threatfox": "abuse.ch ThreatFox recent IOCs (threat-intel feed, ABUSECH_AUTH_KEY), matched against the monitor terms",
    "otx": "AlienVault OTX subscribed pulses (threat-intel feed, OTX_API_KEY), matched against the monitor terms",
    "marketplace_feed": "Operator-configured marketplace feed (DARKWEB_MARKETPLACE_FEED_URL), matched against the monitor terms",
}

#: Sources a quick scan consults (the HIBP lookups and catalogue only).
QUICK_SOURCES = ("hibp_account", "hibp_domain", "hibp_breach_catalogue")
FULL_SOURCES = tuple(SOURCE_LABELS)

#: (source_platform, finding_type) per source key.
_FINDING_KIND: dict[str, tuple[str, str]] = {
    "hibp_account": ("breach_database", "credential_leak"),
    "hibp_stealer": ("breach_database", "credential_leak"),
    "hibp_paste": ("paste_site", "credential_leak"),
    "hibp_domain": ("breach_database", "data_breach_listing"),
    "hibp_breach_catalogue": ("breach_database", "data_breach_listing"),
    "urlhaus": ("threat_intel_feed", "threat_feed_match"),
    "threatfox": ("threat_intel_feed", "threat_feed_match"),
    "otx": ("threat_intel_feed", "threat_feed_match"),
    "marketplace_feed": ("marketplace", "marketplace_listing"),
}

#: Shortest search term matched against feed text (shorter ones match noise).
MIN_TERM_LENGTH = 3


def parse_term_list(value: Any) -> list[str]:
    """A monitor list column as a list of strings.

    Rows written before wave 3 hold a JSON-encoded string inside the JSON
    column (sometimes encoded twice); newer rows hold the list itself.
    """
    for _ in range(3):
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                value = json.loads(text)
            except ValueError:
                return [text]
        else:
            break
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if isinstance(v, (str, int)) and str(v).strip()]
    return []


@dataclass
class MonitorTerms:
    search_terms: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    @classmethod
    def from_monitor(cls, monitor: DarkWebMonitor) -> "MonitorTerms":
        return cls(
            search_terms=parse_term_list(monitor.search_terms),
            domains=[d.lower().strip(".") for d in parse_term_list(monitor.domains_watched)],
            emails=[e.lower() for e in parse_term_list(monitor.emails_watched) if "@" in e],
        )

    def match_terms(self) -> list[str]:
        """Lower-case terms matched against feed text."""
        terms: list[str] = []
        for term in self.search_terms + self.domains + [e.rsplit("@", 1)[1] for e in self.emails]:
            term = term.lower().strip()
            if len(term) >= MIN_TERM_LENGTH and term not in terms:
                terms.append(term)
        return terms

    def is_empty(self) -> bool:
        return not (self.search_terms or self.domains or self.emails)


def _haystack(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "title", "description", "url", "host", "ioc_value", "malware", "breach_name",
        "domain", "author", "adversary", "marketplace_name",
    ):
        value = item.get(key)
        if value:
            parts.append(str(value))
    for key in ("tags", "indicator_values", "compromised_data", "industries"):
        value = item.get(key)
        if isinstance(value, list):
            parts.extend(str(v) for v in value if v)
    return " ".join(parts).lower()


def match_item(item: dict[str, Any], terms: list[str]) -> list[str]:
    """The monitor terms ``item`` mentions (case-insensitive substring)."""
    text = _haystack(item)
    return [term for term in terms if term in text]


@dataclass
class ScanResult:
    status: str  # completed | no_terms | failed
    terms_searched: list[str]
    sources: dict[str, dict[str, Any]]
    findings: list[dict[str, Any]]
    detail: Optional[str] = None


def _source_entry(source: str, status: str, **extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"label": SOURCE_LABELS[source], "status": status}
    entry.update({k: v for k, v in extra.items() if v is not None})
    return entry


async def collect_findings(
    terms: MonitorTerms,
    *,
    scan_type: str = "full",
    scanner: Optional[dw_engine.DarkWebScanner] = None,
) -> ScanResult:
    """Run every applicable source for ``terms`` and return the matching items."""
    scanner = scanner or dw_engine.DarkWebScanner()
    wanted = QUICK_SOURCES if scan_type == "quick" else FULL_SOURCES
    match_terms = terms.match_terms()
    sources: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []

    if terms.is_empty():
        for source in wanted:
            sources[source] = _source_entry(source, "skipped", reason="the monitor has no search terms, domains or emails")
        return ScanResult(
            "no_terms", [], sources, [],
            detail="add search terms, watched domains or watched emails to the monitor; nothing was searched",
        )

    # --- Direct lookups --------------------------------------------------
    if "hibp_account" in wanted:
        emails = terms.emails[: dw_engine.MAX_EMAILS_PER_SCAN]
        if not terms.emails:
            sources["hibp_account"] = _source_entry("hibp_account", "skipped", reason="no watched emails")
        elif not dw_engine.hibp_api_key():
            sources["hibp_account"] = _source_entry(
                "hibp_account", "not_configured", reason="set HIBP_API_KEY to look up the watched emails",
            )
        else:
            try:
                items, errors = await scanner.hibp_lookup_emails(emails)
            except dw_engine.DarkWebSourceError as exc:
                sources["hibp_account"] = _source_entry("hibp_account", "error", error=exc.message)
            else:
                findings.extend(items)
                sources["hibp_account"] = _source_entry(
                    "hibp_account",
                    "error" if errors and not items and len(errors) >= len(emails) * 3 else "ok",
                    checked=len(emails),
                    matched=len(items),
                    errors=errors or None,
                    truncated=len(terms.emails) > len(emails) or None,
                )

    if "hibp_domain" in wanted:
        domains = terms.domains[: dw_engine.MAX_DOMAINS_PER_SCAN]
        if not domains:
            sources["hibp_domain"] = _source_entry("hibp_domain", "skipped", reason="no watched domains")
        else:
            items, errors = await scanner.hibp_lookup_domains(domains)
            findings.extend(items)
            sources["hibp_domain"] = _source_entry(
                "hibp_domain",
                "error" if errors and len(errors) >= len(domains) else "ok",
                checked=len(domains),
                matched=len(items),
                errors=errors or None,
                truncated=len(terms.domains) > len(domains) or None,
            )

    # --- Feeds matched against the monitor terms ---------------------------
    feed_fetchers: list[tuple[str, Callable[[], Awaitable[list[dict[str, Any]]]], Optional[str]]] = [
        ("hibp_breach_catalogue", scanner.search_breach_databases, None),
        ("urlhaus", scanner.fetch_urlhaus_recent, None if dw_engine.abusech_auth_key() else "set ABUSECH_AUTH_KEY (abuse.ch requires an Auth-Key)"),
        ("threatfox", scanner.fetch_threatfox_recent, None if dw_engine.abusech_auth_key() else "set ABUSECH_AUTH_KEY (abuse.ch requires an Auth-Key)"),
        ("otx", scanner.fetch_otx_pulses, None if dw_engine.otx_api_key() else "set OTX_API_KEY"),
        ("marketplace_feed", scanner.fetch_marketplace_feed, None if dw_engine.marketplace_feed_url() else "set DARKWEB_MARKETPLACE_FEED_URL"),
    ]
    for source, fetch, missing in feed_fetchers:
        if source not in wanted:
            continue
        if missing:
            sources[source] = _source_entry(source, "not_configured", reason=missing)
            continue
        if not match_terms:
            sources[source] = _source_entry(
                source, "skipped", reason=f"no term of at least {MIN_TERM_LENGTH} characters to match",
            )
            continue
        try:
            items = await fetch()
        except dw_engine.DarkWebSourceError as exc:
            sources[source] = _source_entry(source, "error", error=exc.message)
            continue
        matched = 0
        for item in items:
            hits = match_item(item, match_terms)
            if hits:
                item = dict(item)
                item["source"] = source
                item["matched_terms"] = hits
                findings.append(item)
                matched += 1
        sources[source] = _source_entry(source, "ok", checked=len(items), matched=matched)

    attempted = [s for s in sources.values() if s["status"] in ("ok", "error")]
    if attempted and all(s["status"] == "error" for s in attempted):
        return ScanResult(
            "failed", match_terms, sources, findings,
            detail="every source the monitor could use failed; see sources",
        )
    if not attempted:
        return ScanResult(
            "completed", match_terms, sources, findings,
            detail="no source is configured for this monitor's terms; see sources",
        )
    return ScanResult("completed", match_terms, sources, findings)


def finding_kind(source: str) -> tuple[str, str]:
    return _FINDING_KIND.get(source, ("threat_intel_feed", "threat_feed_match"))


def finding_severity(source: str, raw: dict[str, Any]) -> str:
    """Severity from the source and its payload.

    HIBP account / infostealer hits are critical (a watched employee account
    is in a breach); HIBP pastes are high; a breach of a watched domain is
    critical when verified or over 10M accounts, otherwise high. Threat-feed
    matches: URLhaus items naming malware / phishing / C2 and ThreatFox items
    with confidence >= 75 are high, OTX pulses with TLP amber/red are high,
    everything else medium. Marketplace listings with confidence >= 75 are
    critical, otherwise high.
    """
    if source in ("hibp_account", "hibp_stealer"):
        return "critical"
    if source == "hibp_paste":
        return "high"
    if source in ("hibp_domain", "hibp_breach_catalogue"):
        if int(raw.get("affected_count") or 0) >= 10_000_000 or raw.get("is_verified"):
            return "critical"
        return "high"
    if source == "urlhaus":
        threat = str(raw.get("threat_type", "")).lower()
        tags = " ".join(str(t) for t in raw.get("tags") or []).lower()
        if any(k in threat or k in tags for k in ("malware", "ransomware", "phishing", "c2")):
            return "high"
        return "medium"
    if source == "threatfox":
        try:
            return "high" if int(raw.get("confidence") or 0) >= 75 else "medium"
        except (TypeError, ValueError):
            return "medium"
    if source == "otx":
        return "high" if str(raw.get("tlp", "")).lower() in ("amber", "red") else "medium"
    if source == "marketplace_feed":
        try:
            return "critical" if int(raw.get("confidence") or 0) >= 75 else "high"
        except (TypeError, ValueError):
            return "high"
    return "medium"


def _confidence(raw: dict[str, Any]) -> int:
    """The source's own confidence when it supplies one, else the column default (50)."""
    try:
        value = int(raw.get("confidence"))
    except (TypeError, ValueError):
        return 50
    return max(0, min(100, value))


async def persist_findings(
    db: AsyncSession,
    organization_id: str,
    monitor_id: str,
    findings: list[dict[str, Any]],
) -> tuple[int, int, list[dict[str, Any]], int]:
    """Write findings with dedup by content hash inside the organisation.

    HIBP account hits (``hibp_account``, ``hibp_stealer``, ``hibp_paste``)
    also create a CredentialLeak row linked to the finding.

    Returns ``(created, skipped_duplicate, critical_findings, credential_leaks_created)``.
    The caller commits.
    """
    created = 0
    skipped = 0
    cred_leaks_created = 0
    criticals: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for f in findings:
        content_hash = f.get("content_hash")
        if not content_hash:
            skipped += 1
            continue
        existing = (
            await db.execute(
                select(DarkWebFinding.id).where(
                    DarkWebFinding.organization_id == organization_id,
                    DarkWebFinding.raw_data_hash == str(content_hash)[:128],
                ).limit(1),
            )
        ).first()
        if existing is not None:
            skipped += 1
            continue

        source_key = f.get("source") or ""
        source_platform, finding_type = finding_kind(source_key)
        severity = finding_severity(source_key, f)
        title = (
            f.get("title") or f.get("breach_name") or f.get("url") or f.get("ioc_value") or "dark web finding"
        )
        description = f.get("description") or f.get("malware") or ""
        matched_terms = f.get("matched_terms") or []
        if matched_terms:
            description = f"{description}\n\nMatched monitor terms: {', '.join(matched_terms)}".strip()
        source_url = f.get("url") or f.get("reference") or ""
        affected: dict[str, Any] = {"source": source_key}
        if matched_terms:
            affected["matched_terms"] = matched_terms
        for key in ("email", "domain", "url", "ioc_value", "breach_name", "site"):
            if f.get(key):
                affected[key] = f[key]

        row = DarkWebFinding(
            organization_id=organization_id,
            monitor_id=monitor_id,
            finding_type=finding_type,
            source_platform=source_platform,
            source_url_hash=hashlib.sha256(source_url.encode()).hexdigest() if source_url else None,
            title=str(title)[:500],
            description=str(description)[:4000],
            raw_data_hash=str(content_hash)[:128],
            affected_assets=affected,
            affected_count=max(1, int(f.get("affected_count") or 1)),
            severity=severity,
            confidence_score=_confidence(f),
            status="new",
            discovered_date=now_iso,
        )
        db.add(row)
        await db.flush()
        created += 1

        if source_key in ("hibp_account", "hibp_stealer", "hibp_paste") and f.get("email"):
            email = str(f["email"])
            db.add(CredentialLeak(
                organization_id=organization_id,
                finding_id=row.id,
                email=email[:255],
                username=email.split("@", 1)[0][:255],
                password_hash=None,  # HIBP does not expose password hashes
                password_type="unknown",
                breach_source=str(f.get("breach_name") or f.get("site") or f.get("paste_source") or "hibp")[:255],
                breach_date=f.get("breach_date") or f.get("paste_date"),
                is_valid=False,
                is_remediated=False,
            ))
            cred_leaks_created += 1

        if severity == "critical":
            criticals.append({
                "finding_id": row.id,
                "finding_type": finding_type,
                "description": str(description or title)[:500],
                "source_url": source_url,
                "severity": severity,
            })
    return created, skipped, criticals, cred_leaks_created


@dataclass
class MonitorScanOutcome:
    status: str
    terms_searched: list[str]
    sources: dict[str, dict[str, Any]]
    matched: int
    created: int
    skipped_duplicate: int
    credential_leaks_created: int
    criticals: list[dict[str, Any]]
    started_at: str
    finished_at: str
    detail: Optional[str] = None


async def scan_monitor(
    db: AsyncSession,
    monitor: DarkWebMonitor,
    *,
    scan_type: str = "full",
    scanner: Optional[dw_engine.DarkWebScanner] = None,
) -> MonitorScanOutcome:
    """Scan one monitor, persist its new findings and stamp ``last_check``.

    Findings are flushed, not committed; the caller commits. A ``failed``
    scan (every usable source errored) persists nothing and leaves
    ``last_check`` unchanged.
    """
    started = datetime.now(timezone.utc)
    terms = MonitorTerms.from_monitor(monitor)
    result = await collect_findings(terms, scan_type=scan_type, scanner=scanner)
    created = skipped = leaks = 0
    criticals: list[dict[str, Any]] = []
    if result.status != "failed":
        created, skipped, criticals, leaks = await persist_findings(
            db, monitor.organization_id, monitor.id, result.findings,
        )
        monitor.last_check = started.isoformat()
        monitor.findings_count = (monitor.findings_count or 0) + created
        await db.flush()
    logger.info(
        "darkweb_monitor_scanned",
        monitor_id=monitor.id,
        organization_id=monitor.organization_id,
        status=result.status,
        matched=len(result.findings),
        created=created,
    )
    return MonitorScanOutcome(
        status=result.status,
        terms_searched=result.terms_searched,
        sources=result.sources,
        matched=len(result.findings),
        created=created,
        skipped_duplicate=skipped,
        credential_leaks_created=leaks,
        criticals=criticals,
        started_at=started.isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
        detail=result.detail,
    )
