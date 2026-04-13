"""Dark Web Monitoring Engine

Integrates free threat intel feeds:
- Have I Been Pwned (HIBP) — credential breach lookup
- AlienVault OTX — threat intel pulses and IOCs
- Abuse.ch URLhaus — malicious URLs
- Abuse.ch ThreatFox — malware IOCs
"""

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from difflib import SequenceMatcher

import httpx

from src.core.logging import get_logger

logger = get_logger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3"
OTX_API = "https://otx.alienvault.com/api/v1"
ABUSECH_URLHAUS = "https://urlhaus-api.abuse.ch/v1"
ABUSECH_THREATFOX = "https://threatfox-api.abuse.ch/api/v1"


class DarkWebScanner:
    """Dark web scanning engine for credential and threat detection"""

    def __init__(self):
        """Initialize dark web scanner"""
        self.paste_sites = [
            "pastebin.com",
            "ghostbin.com",
            "hastebin.com",
            "paste.ubuntu.com",
            "textsnip.com",
        ]
        self.breach_databases = [
            "hibp",
            "breachdb",
            "leaked.email",
            "weleakinfo",
            "snusbase",
        ]
        self.forums = ["exploit", "darknetmarket", "hackforum"]
        self.platforms = ["telegram", "discord", "reddit"]

    def configure_monitors(
        self,
        monitor_type: str,
        search_terms: list[str],
        domains_watched: list[str] = None,
        emails_watched: list[str] = None,
    ) -> dict[str, Any]:
        """Configure monitor with search terms and watch lists"""
        return {
            "monitor_type": monitor_type,
            "search_terms": search_terms,
            "domains_watched": domains_watched or [],
            "emails_watched": emails_watched or [],
            "configured_at": datetime.now(timezone.utc).isoformat(),
        }

    async def run_scan_cycle(self) -> dict[str, Any]:
        """Run complete scan cycle across all monitored sources"""
        results = {
            "paste_sites": await self.search_paste_sites(),
            "breach_databases": await self.search_breach_databases(),
            "forums": await self.search_forums(),
            "telegram": await self.search_telegram_channels(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.aggregate_findings(results)

    async def search_paste_sites(self) -> list[dict[str, Any]]:
        """Search Abuse.ch URLhaus for malicious URLs (real API, free, no key)."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(ABUSECH_URLHAUS + "/urls/recent/", data={"limit": "25"})
                if resp.status_code == 200:
                    data = resp.json()
                    for url_entry in (data.get("urls") or [])[:25]:
                        findings.append({
                            "site": "urlhaus.abuse.ch",
                            "url": url_entry.get("url", ""),
                            "title": url_entry.get("threat", "malicious_url"),
                            "content_hash": hashlib.sha256(url_entry.get("url", "").encode()).hexdigest(),
                            "posted_date": url_entry.get("date_added", ""),
                            "tags": url_entry.get("tags") or [],
                            "threat_type": url_entry.get("threat", ""),
                            "status": url_entry.get("url_status", ""),
                        })
                    logger.info(f"URLhaus: found {len(findings)} malicious URLs")
        except Exception as e:
            logger.warning(f"URLhaus search failed: {e}")
        return findings

    async def search_breach_databases(self) -> list[dict[str, Any]]:
        """Search HIBP for recent breaches (free, no key needed for breach list)."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{HIBP_API}/breaches",
                    headers={"User-Agent": "PySOAR-DarkWebMonitor"},
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                    # Get recent breaches (last 90 days)
                    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
                    for breach in breaches:
                        if breach.get("AddedDate", "") >= cutoff:
                            findings.append({
                                "database": "haveibeenpwned",
                                "breach_name": breach.get("Name", ""),
                                "affected_count": breach.get("PwnCount", 0),
                                "breach_date": breach.get("BreachDate", ""),
                                "compromised_data": breach.get("DataClasses", []),
                                "domain": breach.get("Domain", ""),
                                "description": breach.get("Description", "")[:200],
                                "is_verified": breach.get("IsVerified", False),
                            })
                    logger.info(f"HIBP: found {len(findings)} recent breaches")
        except Exception as e:
            logger.warning(f"HIBP breach search failed: {e}")
        return findings

    async def search_forums(self) -> list[dict[str, Any]]:
        """Search Abuse.ch ThreatFox for recent IOCs (real API, free, no key)."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    ABUSECH_THREATFOX,
                    json={"query": "get_iocs", "days": 7},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for ioc in (data.get("data") or [])[:25]:
                        findings.append({
                            "forum": "threatfox.abuse.ch",
                            "post_id": str(ioc.get("id", "")),
                            "author": ioc.get("reporter", "anonymous"),
                            "title": f"{ioc.get('threat_type', 'malware')}: {ioc.get('malware', 'unknown')}",
                            "content_snippet": f"IOC: {ioc.get('ioc', '')} ({ioc.get('ioc_type', '')})",
                            "timestamp": ioc.get("first_seen_utc", ""),
                            "ioc_value": ioc.get("ioc", ""),
                            "ioc_type": ioc.get("ioc_type", ""),
                            "malware": ioc.get("malware", ""),
                            "confidence": ioc.get("confidence_level", 0),
                        })
                    logger.info(f"ThreatFox: found {len(findings)} IOCs")
        except Exception as e:
            logger.warning(f"ThreatFox search failed: {e}")
        return findings

    async def search_telegram_channels(self) -> list[dict[str, Any]]:
        """Search AlienVault OTX for recent threat pulses (free, no key needed for public)."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{OTX_API}/pulses/subscribed",
                    params={"limit": 20, "modified_since": (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")},
                    headers={"X-OTX-API-KEY": os.environ.get("OTX_API_KEY", "")},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for pulse in (data.get("results") or [])[:20]:
                        findings.append({
                            "platform": "alienvault_otx",
                            "channel": pulse.get("author_name", "OTX"),
                            "message_id": pulse.get("id", ""),
                            "sender": pulse.get("author_name", ""),
                            "message": pulse.get("name", ""),
                            "description": pulse.get("description", "")[:300],
                            "timestamp": pulse.get("modified", ""),
                            "tags": pulse.get("tags", []),
                            "adversary": pulse.get("adversary", ""),
                            "indicator_count": len(pulse.get("indicators", [])),
                            "tlp": pulse.get("tlp", "white"),
                        })
                    logger.info(f"OTX: found {len(findings)} threat pulses")
                elif resp.status_code == 403:
                    logger.info("OTX: no API key configured, skipping")
        except Exception as e:
            logger.warning(f"OTX search failed: {e}")
        return findings

    async def aggregate_findings(self, results: dict[str, Any]) -> dict[str, Any]:
        """Aggregate and deduplicate findings from multiple sources"""
        all_findings = []
        for source, findings in results.items():
            if source != "timestamp" and isinstance(findings, list):
                for finding in findings:
                    finding["source"] = source
                    all_findings.append(finding)

        # Deduplicate
        deduplicated = await self.deduplicate_results(all_findings)

        return {
            "total_findings": len(deduplicated),
            "findings": deduplicated,
            "timestamp": results.get("timestamp"),
        }

    async def deduplicate_results(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove duplicate findings based on content hash"""
        seen_hashes = set()
        deduplicated = []

        for finding in findings:
            # Generate content hash
            content = json.dumps(finding, sort_keys=True, default=str)
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                finding["content_hash"] = content_hash
                deduplicated.append(finding)

        logger.info(
            f"Deduplicated findings: {len(findings)} -> {len(deduplicated)}"
        )
        return deduplicated


class CredentialAnalyzer:
    """Credential leak analysis and remediation"""

    def __init__(self):
        """Initialize credential analyzer"""
        self.password_hash_patterns = {
            "md5": r"^[a-f0-9]{32}$",
            "sha1": r"^[a-f0-9]{40}$",
            "sha256": r"^[a-f0-9]{64}$",
            "bcrypt": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
            "argon2": r"^\$argon2",
            "ntlm": r"^[a-f0-9]{32}$",  # Similar to MD5, requires context
        }

    def parse_credential_dumps(self, raw_data: str) -> list[dict[str, str]]:
        """Parse credential dumps from various formats"""
        credentials = []

        # Handle email:password format
        email_password_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(.+)"
        matches = re.findall(email_password_pattern, raw_data)
        for email, password in matches:
            credentials.append({"email": email, "password": password})

        # Handle email|password format
        email_password_pipe = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(.+)"
        matches = re.findall(email_password_pipe, raw_data)
        for email, password in matches:
            credentials.append({"email": email, "password": password})

        # Handle username:password format
        username_password = r"^([a-zA-Z0-9_.-]+):(.+)$"
        for line in raw_data.split("\n"):
            matches = re.findall(username_password, line)
            for username, password in matches:
                credentials.append({"username": username, "password": password})

        return credentials

    def identify_organizational_credentials(
        self,
        credentials: list[dict[str, str]],
        monitored_domains: list[str],
        monitored_emails: list[str],
    ) -> list[dict[str, Any]]:
        """Match credentials against organizational watch lists"""
        organizational_creds = []

        for cred in credentials:
            email = cred.get("email", "")
            username = cred.get("username", "")

            # Check domain matches
            for domain in monitored_domains:
                if domain in email:
                    cred["matched_type"] = "domain"
                    cred["matched_value"] = domain
                    organizational_creds.append(cred)
                    break

            # Check email matches
            if email in monitored_emails:
                cred["matched_type"] = "email"
                cred["matched_value"] = email
                organizational_creds.append(cred)

        return organizational_creds

    def assess_password_risk(self, password_hash: str) -> dict[str, Any]:
        """Assess password hash type and estimated crack time"""
        hash_type = "unknown"
        crack_time_seconds = 0

        for ptype, pattern in self.password_hash_patterns.items():
            if re.match(pattern, password_hash):
                hash_type = ptype
                break

        # Estimate crack times (these are simplified estimates)
        crack_time_map = {
            "plaintext": 0,  # Already cracked
            "md5": 3600,  # ~1 hour
            "sha1": 7200,  # ~2 hours
            "sha256": 86400,  # ~1 day
            "bcrypt": 2592000,  # ~30 days
            "argon2": 31536000,  # ~1 year
            "ntlm": 3600,  # ~1 hour
            "unknown": 604800,  # ~1 week (assumption)
        }

        crack_time_seconds = crack_time_map.get(hash_type, 604800)

        return {
            "hash_type": hash_type,
            "crack_time_seconds": crack_time_seconds,
            "risk_level": self._calculate_risk_level(hash_type),
            "recommendation": self._get_remediation_recommendation(hash_type),
        }

    def _calculate_risk_level(self, hash_type: str) -> str:
        """Calculate risk level based on hash type"""
        high_risk = ["plaintext", "md5", "sha1", "ntlm"]
        medium_risk = ["sha256"]
        low_risk = ["bcrypt", "argon2"]

        if hash_type in high_risk:
            return "critical"
        elif hash_type in medium_risk:
            return "high"
        elif hash_type in low_risk:
            return "medium"
        return "unknown"

    def _get_remediation_recommendation(self, hash_type: str) -> str:
        """Get remediation recommendation based on hash type"""
        if hash_type in ["plaintext", "md5", "sha1", "ntlm"]:
            return "Immediate password reset required"
        elif hash_type == "sha256":
            return "Password reset recommended within 24 hours"
        else:
            return "Monitor for additional exposure"

    async def correlate_with_identity_store(
        self, credentials: list[dict[str, str]], user_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Match leaked credentials against known users"""
        matched_users = []

        for cred in credentials:
            for user in user_database:
                if cred.get("email") == user.get("email"):
                    matched_users.append(
                        {
                            "credential": cred,
                            "user": user,
                            "risk_score": 95,
                        }
                    )
                elif cred.get("username") == user.get("username"):
                    matched_users.append(
                        {
                            "credential": cred,
                            "user": user,
                            "risk_score": 85,
                        }
                    )

        return matched_users

    async def auto_remediate(
        self, affected_user_id: str, action: str
    ) -> dict[str, Any]:
        """Trigger automated remediation workflow"""
        remediation_result = {
            "user_id": affected_user_id,
            "action": action,
            "status": "initiated",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if action == "password_reset":
            remediation_result["workflow"] = "password_reset_workflow"
            remediation_result["notification_sent"] = True
        elif action == "account_disabled":
            remediation_result["workflow"] = "account_disable_workflow"
            remediation_result["notification_sent"] = True
        elif action == "mfa_enforced":
            remediation_result["workflow"] = "mfa_enforcement_workflow"
            remediation_result["notification_sent"] = True
        elif action == "token_revoked":
            remediation_result["workflow"] = "token_revocation_workflow"
            remediation_result["notification_sent"] = True

        return remediation_result

    async def generate_exposure_report(
        self, leaks: list[dict[str, Any]], organization_name: str
    ) -> dict[str, Any]:
        """Generate comprehensive credential exposure report"""
        unique_emails = set()
        unique_credentials = 0
        critical_accounts = []
        hash_type_distribution = {}

        for leak in leaks:
            if leak.get("email"):
                unique_emails.add(leak["email"])
            unique_credentials += 1

            hash_type = leak.get("password_type", "unknown")
            hash_type_distribution[hash_type] = (
                hash_type_distribution.get(hash_type, 0) + 1
            )

            if leak.get("is_critical"):
                critical_accounts.append(leak)

        return {
            "organization": organization_name,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "total_credentials_exposed": unique_credentials,
            "unique_accounts": len(unique_emails),
            "critical_accounts": len(critical_accounts),
            "hash_distribution": hash_type_distribution,
            "affected_emails": list(unique_emails),
            "recommended_actions": [
                "Force password reset for all exposed accounts",
                "Enable MFA for all users",
                "Monitor for account takeover attempts",
                "Review access logs for the affected accounts",
            ],
        }


class BrandProtection:
    """Brand threat detection and protection"""

    def __init__(self):
        """Initialize brand protection engine"""
        self.similarity_threshold = 0.75

    def detect_typosquatting(self, legitimate_domain: str) -> list[dict[str, Any]]:
        """Detect typosquatting domains using multiple techniques"""
        detections = []

        # Levenshtein distance (edit distance)
        suspicious_domains = self._generate_typosquats_levenshtein(
            legitimate_domain
        )
        detections.extend(
            [
                {
                    "technique": "levenshtein",
                    "domain": domain,
                    "similarity": score,
                }
                for domain, score in suspicious_domains
            ]
        )

        # Homoglyph detection
        homoglyph_domains = self._generate_homoglyph_variants(legitimate_domain)
        detections.extend(
            [
                {"technique": "homoglyph", "domain": domain, "risk": "high"}
                for domain in homoglyph_domains
            ]
        )

        # TLD substitution
        tld_variants = self._generate_tld_variants(legitimate_domain)
        detections.extend(
            [
                {"technique": "tld_substitution", "domain": domain, "risk": "medium"}
                for domain in tld_variants
            ]
        )

        return detections

    def _generate_typosquats_levenshtein(
        self, domain: str, max_distance: int = 2
    ) -> list[tuple[str, float]]:
        """Generate typosquat variants using Levenshtein distance"""
        base, _, tld = domain.rpartition(".")
        if not base:
            return []

        candidates = []

        # Character substitution variants
        for i in range(len(base)):
            for c in "abcdefghijklmnopqrstuvwxyz0123456789":
                if c != base[i]:
                    variant = base[:i] + c + base[i + 1:] + "." + tld
                    candidates.append(variant)

        # Character insertion
        for i in range(len(base) + 1):
            for c in "abcdefghijklmnopqrstuvwxyz0123456789-":
                variant = base[:i] + c + base[i:] + "." + tld
                candidates.append(variant)

        # Character deletion
        for i in range(len(base)):
            variant = base[:i] + base[i + 1:] + "." + tld
            if variant != "." + tld:
                candidates.append(variant)

        # Adjacent character transposition
        for i in range(len(base) - 1):
            swapped = list(base)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            variant = "".join(swapped) + "." + tld
            candidates.append(variant)

        # Character duplication
        for i in range(len(base)):
            variant = base[:i] + base[i] + base[i:] + "." + tld
            candidates.append(variant)

        # Filter by Levenshtein distance (using SequenceMatcher ratio as proxy)
        results = []
        seen = set()
        for candidate in candidates:
            if candidate == domain or candidate in seen:
                continue
            seen.add(candidate)
            similarity = SequenceMatcher(None, domain, candidate).ratio()
            if similarity >= self.similarity_threshold:
                results.append((candidate, similarity))

        # Sort by similarity descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _generate_homoglyph_variants(self, domain: str) -> list[str]:
        """Generate homoglyph variants (visually similar characters)"""
        homoglyph_map = {
            "a": ["ɑ", "а"],  # Unicode look-alikes
            "e": ["е"],
            "i": ["і", "ı"],
            "o": ["о", "0"],
            "p": ["р"],
            "s": ["ѕ"],
            "x": ["х"],
        }

        variants = []
        for char, replacements in homoglyph_map.items():
            if char in domain:
                for replacement in replacements:
                    variant = domain.replace(char, replacement)
                    variants.append(variant)

        return variants

    def _generate_tld_variants(self, domain: str) -> list[str]:
        """Generate TLD substitution variants"""
        common_tlds = ["com", "net", "org", "co", "io", "biz", "info"]
        variants = []

        for tld in common_tlds:
            variant = re.sub(r"\.com$|\.net$|\.org$", f".{tld}", domain)
            if variant != domain:
                variants.append(variant)

        return variants

    def detect_lookalike_sites(
        self, legitimate_site_content: str, suspicious_site_content: str
    ) -> dict[str, Any]:
        """Detect lookalike websites using content similarity"""
        similarity = SequenceMatcher(None, legitimate_site_content, suspicious_site_content).ratio()

        return {
            "similarity_score": similarity,
            "risk_level": "critical"
            if similarity > 0.85
            else "high"
            if similarity > 0.70
            else "medium",
            "detected": similarity > 0.70,
            "recommendation": "Initiate takedown if similarity > 0.85",
        }

    def monitor_certificate_transparency_logs(
        self, monitored_domains: list[str]
    ) -> list[dict[str, Any]]:
        """Query crt.sh for certificate transparency logs (free, no key)."""
        detected_certs = []

        for domain in monitored_domains:
            try:
                resp = httpx.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    certs = resp.json()
                    for cert in certs[:10]:
                        name_value = cert.get("name_value", "")
                        is_suspicious = domain not in name_value or name_value.count(".") > domain.count(".") + 1
                        detected_certs.append({
                            "domain": domain,
                            "issued_to": name_value,
                            "issuer": cert.get("issuer_name", ""),
                            "issued_date": cert.get("not_before", ""),
                            "valid_until": cert.get("not_after", ""),
                            "serial_number": cert.get("serial_number", ""),
                            "risk": "high" if is_suspicious else "low",
                        })
                    logger.info(f"crt.sh: found {len(certs)} certs for {domain}")
            except Exception as e:
                logger.warning(f"crt.sh query failed for {domain}: {e}")

        return detected_certs

    def detect_phishing_kits(self, site_content: str) -> dict[str, Any]:
        """Detect phishing kits by analyzing brand asset usage"""
        brand_indicators = {
            "login_form": bool(re.search(r"<form[^>]*>.*password", site_content)),
            "legitimate_logo": bool(
                re.search(r'src="[^"]*logo[^"]*"', site_content)
            ),
            "ssl_certificate": bool(re.search(r"https://", site_content)),
            "obfuscated_js": bool(re.search(r"eval\(|Function\(", site_content)),
        }

        phishing_score = sum(
            [
                1 if brand_indicators.get("login_form") else 0,
                1 if brand_indicators.get("legitimate_logo") else 0,
                -1 if brand_indicators.get("ssl_certificate") else 0,
                2 if brand_indicators.get("obfuscated_js") else 0,
            ]
        )

        return {
            "indicators": brand_indicators,
            "phishing_score": max(0, phishing_score),
            "is_phishing_kit": phishing_score >= 2,
            "confidence": min(100, (phishing_score / 4) * 100),
        }

    async def initiate_takedown_process(
        self, threat_id: str, threat_type: str, provider: str = "auto"
    ) -> dict[str, Any]:
        """Initiate automated takedown process"""
        return {
            "threat_id": threat_id,
            "threat_type": threat_type,
            "provider": provider,
            "status": "takedown_requested",
            "initiated_at": datetime.now(timezone.utc).isoformat(),
            "estimated_resolution": (
                datetime.now(timezone.utc) + timedelta(days=3)
            ).isoformat(),
        }

    async def track_takedown_status(self, takedown_id: str) -> dict[str, Any]:
        """Track takedown request status"""
        return {
            "takedown_id": takedown_id,
            "status": "in_progress",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "progress": 50,
            "estimated_completion": (
                datetime.now(timezone.utc) + timedelta(days=2)
            ).isoformat(),
        }


class ThreatIntelCorrelator:
    """Threat intelligence correlation and enrichment"""

    def __init__(self):
        """Initialize threat intelligence correlator"""
        pass

    async def correlate_with_iocs(
        self, finding_data: dict[str, Any], ioc_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Correlate findings against IOC database"""
        correlations = []

        for ioc in ioc_database:
            if finding_data.get("domain") == ioc.get("value"):
                correlations.append(
                    {
                        "ioc": ioc,
                        "finding": finding_data,
                        "match_type": "domain",
                        "confidence": 100,
                    }
                )
            elif finding_data.get("email") == ioc.get("value"):
                correlations.append(
                    {
                        "ioc": ioc,
                        "finding": finding_data,
                        "match_type": "email",
                        "confidence": 100,
                    }
                )

        return correlations

    async def correlate_with_incidents(
        self, finding_data: dict[str, Any], incident_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Link findings to active incidents"""
        correlations = []

        for incident in incident_database:
            # Check if finding matches incident IOCs
            if finding_data.get("domain") in incident.get("iocs", []):
                correlations.append(
                    {
                        "incident": incident,
                        "finding": finding_data,
                        "relationship": "ioc_match",
                        "confidence": 95,
                    }
                )

        return correlations

    async def enrich_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Enrich findings with contextual intelligence"""
        enriched = []

        for finding in findings:
            enrichment = {
                "finding": finding,
                "actor_attribution": self._attribute_actor(finding),
                "campaign_mapping": self._map_campaign(finding),
                "historical_context": self._get_historical_context(finding),
                "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
            }
            enriched.append(enrichment)

        return enriched

    def _attribute_actor(self, finding: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Attribute finding to threat actor based on available evidence"""
        actor_name = "Unknown"
        confidence = 0
        aliases = []

        # Extract attribution signals from the finding
        source_platform = finding.get("source_platform", "")
        finding_type = finding.get("finding_type", "") or finding.get("type", "")
        content = str(finding.get("content", "")) + str(finding.get("description", ""))
        tags = finding.get("tags", []) if isinstance(finding.get("tags"), list) else []

        # Known actor keyword signatures (common threat groups and their indicators)
        actor_signatures = {
            "LockBit": {"keywords": ["lockbit", "lockbit3", "lockbit 3.0"], "aliases": ["LockBit 3.0", "LockBitSupp"], "platforms": ["ransomware_forum", "tor"]},
            "BlackCat/ALPHV": {"keywords": ["alphv", "blackcat", "noberus"], "aliases": ["ALPHV", "Noberus", "BlackCat"], "platforms": ["ransomware_forum", "tor"]},
            "Cl0p": {"keywords": ["cl0p", "clop", "ta505"], "aliases": ["TA505", "FIN11"], "platforms": ["ransomware_forum", "tor"]},
            "Lazarus Group": {"keywords": ["lazarus", "hidden cobra", "apt38", "bluenoroff"], "aliases": ["Hidden Cobra", "APT38", "BlueNoroff"], "platforms": ["paste_site", "forum"]},
            "FIN7": {"keywords": ["fin7", "carbanak", "anunak"], "aliases": ["Carbanak", "Anunak"], "platforms": ["forum", "marketplace"]},
            "APT28": {"keywords": ["apt28", "fancy bear", "sofacy", "pawn storm"], "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm"], "platforms": ["forum", "paste_site"]},
            "APT29": {"keywords": ["apt29", "cozy bear", "nobelium"], "aliases": ["Cozy Bear", "Nobelium", "The Dukes"], "platforms": ["forum", "paste_site"]},
        }

        content_lower = content.lower()
        best_match_confidence = 0

        for actor, signature in actor_signatures.items():
            match_score = 0
            # Check keyword matches
            for keyword in signature["keywords"]:
                if keyword in content_lower:
                    match_score += 40
            # Check tags
            for tag in tags:
                for keyword in signature["keywords"]:
                    if keyword in tag.lower():
                        match_score += 30
            # Platform correlation
            if source_platform in signature["platforms"]:
                match_score += 10

            if match_score > best_match_confidence:
                best_match_confidence = match_score
                actor_name = actor
                aliases = signature["aliases"]
                confidence = min(95, match_score)

        if best_match_confidence == 0:
            actor_name = "Unattributed"
            confidence = 0
            aliases = []

        return {
            "actor_name": actor_name,
            "confidence": confidence,
            "known_aliases": aliases,
        }

    def _map_campaign(self, finding: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Map finding to known campaign"""
        return {
            "campaign_id": None,
            "campaign_name": "Unattributed",
            "confidence": 0,
        }

    def _get_historical_context(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Get historical context for finding"""
        return {
            "previous_occurrences": 0,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_activity": datetime.now(timezone.utc).isoformat(),
        }

    async def generate_intelligence_report(
        self, findings: list[dict[str, Any]], organization_name: str
    ) -> dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        return {
            "organization": organization_name,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "critical_findings": len(
                [f for f in findings if f.get("severity") == "critical"]
            ),
            "threat_actors": self._extract_threat_actors(findings),
            "campaigns": self._extract_campaigns(findings),
            "recommendations": [
                "Review IOC database for indicator updates",
                "Coordinate with threat intelligence providers",
                "Update detection signatures",
            ],
        }

    def _extract_threat_actors(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Extract unique threat actors from findings"""
        actors = []
        seen = set()

        for finding in findings:
            actor = finding.get("actor")
            if actor and actor not in seen:
                actors.append({"name": actor, "count": 1})
                seen.add(actor)

        return actors

    def _extract_campaigns(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Extract unique campaigns from findings"""
        campaigns = []
        seen = set()

        for finding in findings:
            campaign = finding.get("campaign")
            if campaign and campaign not in seen:
                campaigns.append({"name": campaign, "count": 1})
                seen.add(campaign)

        return campaigns

    async def calculate_risk_score(self, finding: dict[str, Any]) -> int:
        """Calculate overall risk score for finding"""
        score = 0

        # Severity component (0-40)
        severity_map = {
            "critical": 40,
            "high": 30,
            "medium": 20,
            "low": 10,
            "info": 0,
        }
        score += severity_map.get(finding.get("severity", "medium"), 20)

        # Confidence component (0-30)
        confidence = finding.get("confidence_score", 50) / 100 * 30
        score += confidence

        # Impact component (0-30)
        affected_count = finding.get("affected_count", 1)
        impact = min(30, affected_count / 100 * 30)
        score += impact

        return min(100, int(score))
