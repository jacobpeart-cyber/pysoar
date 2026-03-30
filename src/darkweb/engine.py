"""Dark Web Monitoring Engine

Core scanning, analysis, and correlation engine for dark web monitoring.
Handles credential analysis, brand protection, and threat intelligence correlation.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from difflib import SequenceMatcher

from src.core.logging import get_logger

logger = get_logger(__name__)


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
        """Simulate searching paste sites for leaked content"""
        findings = []
        for site in self.paste_sites:
            # Simulate API calls to paste sites
            simulated_pastes = [
                {
                    "site": site,
                    "url": f"https://{site}/paste123456",
                    "title": "admin credentials dump",
                    "content_hash": hashlib.sha256(
                        f"creds_from_{site}".encode()
                    ).hexdigest(),
                    "posted_date": (
                        datetime.now(timezone.utc) - timedelta(hours=12)
                    ).isoformat(),
                    "credentials": [
                        {
                            "email": "admin@company.com",
                            "password": "hashed_password_1",
                        },
                    ],
                }
            ]
            findings.extend(simulated_pastes)
        return findings

    async def search_breach_databases(self) -> list[dict[str, Any]]:
        """Simulate searching breach databases for organization data"""
        findings = []
        for db in self.breach_databases:
            # Simulate HIBP-style API queries
            simulated_breaches = [
                {
                    "database": db,
                    "breach_name": f"breach_{db}_2024",
                    "affected_count": 10000 + (hash(db) % 100000),
                    "breach_date": "2024-01-15",
                    "compromised_data": [
                        "emails",
                        "passwords",
                        "usernames",
                    ],
                    "affected_emails": [
                        f"user_{i}@company.com" for i in range(5)
                    ],
                },
            ]
            findings.extend(simulated_breaches)
        return findings

    async def search_forums(self) -> list[dict[str, Any]]:
        """Simulate dark web forum crawling"""
        findings = []
        for forum in self.forums:
            simulated_posts = [
                {
                    "forum": forum,
                    "post_id": f"post_{hash(forum)}",
                    "author": f"user_{hash(forum) % 1000}",
                    "title": f"Selling {forum} database access",
                    "content_snippet": "Database contains user credentials and PII",
                    "timestamp": (
                        datetime.now(timezone.utc) - timedelta(days=1)
                    ).isoformat(),
                    "pricing": "$5000-$10000",
                    "seller_reputation": "trusted",
                },
            ]
            findings.extend(simulated_posts)
        return findings

    async def search_telegram_channels(self) -> list[dict[str, Any]]:
        """Simulate Telegram channel monitoring"""
        findings = [
            {
                "platform": "telegram",
                "channel": "@leaks_channel_1",
                "message_id": "msg_123456",
                "sender": "anonymous_leaker",
                "message": "Leaked company database available",
                "timestamp": (
                    datetime.now(timezone.utc) - timedelta(hours=2)
                ).isoformat(),
                "has_attachment": True,
                "attachment_type": "file",
            },
        ]
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
        # Simulated suspicious domains
        suspicious = [
            f"{domain.replace('.com', '.co')}",
            f"{domain.replace('a', 'e')}",
            f"{domain}s",
        ]

        results = []
        for susp in suspicious:
            similarity = SequenceMatcher(None, domain, susp).ratio()
            if similarity >= self.similarity_threshold:
                results.append((susp, similarity))

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
        """Monitor certificate transparency logs for suspicious certificates"""
        detected_certs = []

        for domain in monitored_domains:
            # Simulate CT log queries
            simulated_certs = [
                {
                    "domain": domain,
                    "issued_to": f"suspicious-{domain}",
                    "issuer": "Let's Encrypt",
                    "issued_date": datetime.now(timezone.utc).isoformat(),
                    "valid_until": (
                        datetime.now(timezone.utc) + timedelta(days=90)
                    ).isoformat(),
                    "risk": "high",
                },
            ]
            detected_certs.extend(simulated_certs)

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
        """Attribute finding to threat actor"""
        # Simplified actor attribution
        return {
            "actor_name": "Unknown Threat Actor",
            "confidence": 30,
            "known_aliases": [],
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
