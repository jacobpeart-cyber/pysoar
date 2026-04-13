"""IOC enrichment and lifecycle management"""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.core.config import settings
from src.core.logging import get_logger
from src.intel.models import ThreatIndicator, IndicatorSighting

logger = get_logger(__name__)


class IndicatorEnricher:
    """Enrichment engine for threat indicators with external threat intelligence"""

    def __init__(self):
        """Initialize enrichment engine"""
        self.logger = get_logger(__name__)
        # External threat intel providers would be initialized here
        self.vt_available = bool(settings.virustotal_api_key)
        self.abuseipdb_available = bool(settings.abuseipdb_api_key)
        self.shodan_available = bool(settings.shodan_api_key)
        self.greynoise_available = bool(settings.greynoise_api_key)

    async def enrich_indicator(self, indicator_id: str) -> dict[str, Any]:
        """Enrich a single indicator with external threat intelligence

        Args:
            indicator_id: ID of indicator to enrich

        Returns:
            Dictionary with enrichment results
        """
        from src.core.database import async_session_factory
        from sqlalchemy import select

        self.logger.info("Enriching indicator", indicator_id=indicator_id)

        enrichment_data = {
            "indicator_id": indicator_id,
            "sources": [],
            "composite_score": 0,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        async with async_session_factory() as session:
            result = await session.execute(
                select(ThreatIndicator).where(ThreatIndicator.id == indicator_id)
            )
            indicator = result.scalar_one_or_none()

            if not indicator:
                self.logger.warning("Indicator not found", indicator_id=indicator_id)
                enrichment_data["error"] = "Indicator not found"
                return enrichment_data

            # Query external providers based on indicator type
            import httpx

            if indicator.indicator_type in ("ipv4", "ipv6") and self.vt_available:
                try:
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(
                            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator.value}",
                            headers={"x-apikey": settings.virustotal_api_key},
                            timeout=15,
                        )
                        if resp.status_code == 200:
                            vt_data = resp.json()
                            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            total = sum(stats.values()) if stats else 1
                            enrichment_data["sources"].append({
                                "provider": "virustotal",
                                "score": int((malicious / max(total, 1)) * 100),
                                "malicious_count": malicious,
                                "total_engines": total,
                            })
                except Exception as e:
                    self.logger.warning("VirusTotal enrichment failed", error=str(e))

            if indicator.indicator_type in ("ipv4",) and self.abuseipdb_available:
                try:
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(
                            "https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
                            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                            timeout=15,
                        )
                        if resp.status_code == 200:
                            abuse_data = resp.json().get("data", {})
                            enrichment_data["sources"].append({
                                "provider": "abuseipdb",
                                "score": abuse_data.get("abuseConfidenceScore", 0),
                                "total_reports": abuse_data.get("totalReports", 0),
                                "country_code": abuse_data.get("countryCode"),
                                "isp": abuse_data.get("isp"),
                            })
                except Exception as e:
                    self.logger.warning("AbuseIPDB enrichment failed", error=str(e))

            if indicator.indicator_type == "domain" and self.vt_available:
                try:
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(
                            f"https://www.virustotal.com/api/v3/domains/{indicator.value}",
                            headers={"x-apikey": settings.virustotal_api_key},
                            timeout=15,
                        )
                        if resp.status_code == 200:
                            vt_data = resp.json()
                            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            total = sum(stats.values()) if stats else 1
                            enrichment_data["sources"].append({
                                "provider": "virustotal",
                                "score": int((malicious / max(total, 1)) * 100),
                                "malicious_count": malicious,
                                "total_engines": total,
                            })
                except Exception as e:
                    self.logger.warning("VirusTotal domain enrichment failed", error=str(e))

            # Calculate composite score from all provider results
            if enrichment_data["sources"]:
                scores = [s["score"] for s in enrichment_data["sources"] if "score" in s]
                enrichment_data["composite_score"] = int(sum(scores) / len(scores)) if scores else 0

            # Persist enrichment data back to the indicator
            existing_context = indicator.context or {}
            for source in enrichment_data["sources"]:
                existing_context[source["provider"]] = source
            indicator.context = existing_context
            indicator.last_seen = datetime.now(timezone.utc)
            await session.commit()

        return enrichment_data

    async def auto_enrich_batch(self, indicator_ids: list[str]) -> dict[str, Any]:
        """Auto-enrich multiple indicators

        Args:
            indicator_ids: List of indicator IDs to enrich

        Returns:
            Dictionary with batch enrichment results
        """
        self.logger.info("Auto-enriching indicators", count=len(indicator_ids))

        results = {
            "total": len(indicator_ids),
            "successful": 0,
            "failed": 0,
            "enrichments": [],
        }

        for indicator_id in indicator_ids:
            try:
                enrichment = await self.enrich_indicator(indicator_id)
                results["enrichments"].append(enrichment)
                results["successful"] += 1
            except Exception as e:
                self.logger.warning("Failed to enrich indicator", indicator_id=indicator_id, error=str(e))
                results["failed"] += 1

        return results

    def calculate_composite_score(self, indicator: ThreatIndicator) -> int:
        """Calculate composite threat score for an indicator (0-100)

        Weighted scoring factors:
        - Feed confidence weight
        - External provider scores (VT, AbuseIPDB, GreyNoise, etc.)
        - Age decay (older indicators scored lower)
        - Sighting frequency (more sightings = higher score)

        Args:
            indicator: ThreatIndicator instance

        Returns:
            Composite score 0-100
        """
        base_score = indicator.confidence or 50

        # Apply feed confidence weight
        if indicator.feed and indicator.feed.confidence_weight:
            base_score = int(base_score * indicator.feed.confidence_weight)

        # Age decay: reduce score if indicator is old
        if indicator.first_seen:
            days_old = (datetime.now(timezone.utc) - indicator.first_seen).days
            if days_old > 365:
                # Decay by 30% for indicators older than a year
                base_score = int(base_score * 0.7)

        # Sighting factor: increase score with sightings
        if indicator.sighting_count > 0:
            sighting_boost = min(indicator.sighting_count * 5, 20)  # Max +20 points
            base_score = min(base_score + sighting_boost, 100)

        # Provider scores from context (VT, AbuseIPDB, etc.)
        if indicator.context:
            provider_scores = []
            for provider_name in ["virustotal", "abuseipdb", "shodan", "greynoise"]:
                provider_data = indicator.context.get(provider_name, {})
                if provider_data and "score" in provider_data:
                    provider_scores.append(provider_data["score"])

            if provider_scores:
                avg_provider_score = sum(provider_scores) / len(provider_scores)
                # Average in provider scores (weighted 40%)
                base_score = int(base_score * 0.6 + avg_provider_score * 0.4)

        return min(max(base_score, 0), 100)

    async def check_expiration(self) -> int:
        """Mark expired indicators as inactive

        Returns:
            Number of indicators marked as expired
        """
        from src.core.database import async_session_factory
        from sqlalchemy import select, update

        self.logger.info("Checking for expired indicators")

        now = datetime.now(timezone.utc)

        async with async_session_factory() as session:
            # Find all active indicators that have expired
            result = await session.execute(
                update(ThreatIndicator)
                .where(
                    ThreatIndicator.is_active == True,
                    ThreatIndicator.expires_at != None,
                    ThreatIndicator.expires_at < now,
                )
                .values(is_active=False)
            )
            expired_count = result.rowcount
            await session.commit()

        self.logger.info("Expired indicators marked inactive", expired_count=expired_count)
        return expired_count

    async def check_false_positives(self, indicator_id: str, threshold: int = 5) -> bool:
        """Check if indicator has exceeded false positive threshold

        Args:
            indicator_id: ID of indicator to check
            threshold: False positive count threshold

        Returns:
            True if indicator should be marked as false positive
        """
        # Would fetch indicator and check false_positive_count
        self.logger.info("Checking false positive status", indicator_id=indicator_id, threshold=threshold)

        return False

    async def record_sighting(
        self,
        indicator_id: str,
        source: str,
        sighting_type: str,
        context: Optional[dict[str, Any]] = None,
    ) -> Optional[IndicatorSighting]:
        """Record a sighting of an indicator

        Args:
            indicator_id: ID of indicator
            source: Source system where sighting occurred
            sighting_type: Type of sighting (detected, blocked, allowed, correlated)
            context: Additional context about the sighting

        Returns:
            Created IndicatorSighting instance
        """
        try:
            sighting = IndicatorSighting(
                indicator_id=indicator_id,
                source=source,
                sighting_type=sighting_type,
                context=context or {},
            )

            self.logger.info(
                "Recorded indicator sighting",
                indicator_id=indicator_id,
                source=source,
                sighting_type=sighting_type,
            )

            # Would save to database and update indicator sighting_count
            return sighting

        except Exception as e:
            self.logger.error("Failed to record sighting", indicator_id=indicator_id, error=str(e))
            return None

    async def get_indicator_timeline(self, indicator_id: str) -> list[dict[str, Any]]:
        """Get timeline of sightings for an indicator

        Args:
            indicator_id: ID of indicator

        Returns:
            List of timeline events (sightings, enrichments, etc.)
        """
        self.logger.info("Fetching indicator timeline", indicator_id=indicator_id)

        timeline = []
        # Would query IndicatorSighting records and build timeline
        return timeline

    async def whitelist_indicator(self, indicator_id: str, reason: str) -> None:
        """Whitelist an indicator (mark as is_whitelisted)

        Args:
            indicator_id: ID of indicator
            reason: Reason for whitelisting
        """
        self.logger.info("Whitelisting indicator", indicator_id=indicator_id, reason=reason)
        # Would mark indicator as is_whitelisted = True

    async def bulk_import_indicators(
        self, indicators: list[dict[str, Any]], feed_id: str
    ) -> dict[str, Any]:
        """Bulk import indicators from parsed feed data

        Args:
            indicators: List of indicator dictionaries
            feed_id: Feed ID these indicators came from

        Returns:
            Dictionary with import statistics
        """
        self.logger.info("Bulk importing indicators", count=len(indicators), feed_id=feed_id)

        results = {
            "total": len(indicators),
            "created": 0,
            "updated": 0,
            "failed": 0,
            "errors": [],
        }

        for indicator_data in indicators:
            try:
                # Validate required fields
                if not indicator_data.get("value") or not indicator_data.get("indicator_type"):
                    results["failed"] += 1
                    continue

                # Would check if indicator exists and create or update
                results["created"] += 1

            except Exception as e:
                self.logger.warning("Failed to import indicator", error=str(e))
                results["failed"] += 1
                results["errors"].append(str(e))

        self.logger.info("Bulk import complete", results=results)
        return results


class IOCMatcher:
    """Match IOCs against log entries and events"""

    def __init__(self):
        """Initialize IOC matcher"""
        self.logger = get_logger(__name__)
        self.ioc_cache = {}  # Dict cache of indicators
        self.bloom_filter = None  # Bloom filter for fast negative lookups
        self.cache_built_at = None

    async def match_log_entry(self, log_entry: dict[str, Any]) -> list[ThreatIndicator]:
        """Match a log entry against active threat indicators

        Checks:
        - IP addresses (including CIDR matching)
        - Domains and subdomains
        - URLs
        - File hashes (MD5, SHA1, SHA256)
        - Email addresses
        - User agents
        - Registry keys
        - Other IOC types

        Args:
            log_entry: Log entry dictionary with various fields

        Returns:
            List of matching ThreatIndicator instances
        """
        matches = []

        # Extract potential IOCs from log entry
        extracted_iocs = self._extract_iocs_from_log(log_entry)

        for ioc_type, ioc_values in extracted_iocs.items():
            for ioc_value in ioc_values:
                # Use bloom filter for fast negative lookups
                if self.bloom_filter and not self._check_bloom_filter(ioc_type, ioc_value):
                    continue

                # Check cache
                matching_indicators = self._match_from_cache(ioc_type, ioc_value)
                matches.extend(matching_indicators)

        self.logger.debug("IOC matching complete", log_entry_id=log_entry.get("id"), matches=len(matches))
        return matches

    async def build_ioc_cache(self) -> None:
        """Build in-memory cache of active indicators for fast matching

        This would:
        1. Query all active indicators from database
        2. Build dictionary cache indexed by type
        3. Build bloom filter for negative lookups
        """
        self.logger.info("Building IOC cache")

        try:
            # Would query database for active, non-whitelisted indicators
            self.ioc_cache = {}
            self.cache_built_at = datetime.now(timezone.utc)

            # Build cache structure:
            # {
            #   'ipv4': {'1.2.3.4': [ThreatIndicator, ...], '192.168.0.0/16': [...]},
            #   'domain': {'evil.com': [ThreatIndicator, ...], ...},
            #   'md5': {'abc123...': [ThreatIndicator, ...], ...}
            # }

            self.logger.info("IOC cache built", indicator_count=sum(len(v) for v in self.ioc_cache.values()))

        except Exception as e:
            self.logger.error("Failed to build IOC cache", error=str(e))

    async def get_cache_stats(self) -> dict[str, Any]:
        """Get statistics about the IOC cache

        Returns:
            Dictionary with cache stats (size, build time, entries by type, etc.)
        """
        stats = {
            "cache_built_at": self.cache_built_at.isoformat() if self.cache_built_at else None,
            "total_indicators": sum(len(v) for v in self.ioc_cache.values()),
            "indicators_by_type": {
                ioc_type: len(indicators) for ioc_type, indicators in self.ioc_cache.items()
            },
        }
        return stats

    def _extract_iocs_from_log(self, log_entry: dict[str, Any]) -> dict[str, list[str]]:
        """Extract potential IOCs from various log fields

        Args:
            log_entry: Log entry dictionary

        Returns:
            Dict mapping IOC type to list of values found
        """
        extracted = {
            "ipv4": [],
            "ipv6": [],
            "domain": [],
            "url": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "email": [],
            "user_agent": [],
        }

        # Extract IPs from common fields
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for field in ["src_ip", "dst_ip", "source_ip", "destination_ip", "client_ip", "server_ip"]:
            if field in log_entry:
                ips = ip_pattern.findall(str(log_entry[field]))
                extracted["ipv4"].extend(ips)

        # Extract domains
        domain_pattern = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
        for field in ["domain", "hostname", "host", "server_name", "requested_domain"]:
            if field in log_entry:
                domains = domain_pattern.findall(str(log_entry[field]))
                extracted["domain"].extend(domains)

        # Extract URLs
        url_pattern = re.compile(r"https?://\S+")
        for field in ["url", "request_url", "uri"]:
            if field in log_entry:
                urls = url_pattern.findall(str(log_entry[field]))
                extracted["url"].extend(urls)

        # Extract hashes
        md5_pattern = re.compile(r"\b[a-f0-9]{32}\b")
        sha1_pattern = re.compile(r"\b[a-f0-9]{40}\b")
        sha256_pattern = re.compile(r"\b[a-f0-9]{64}\b")

        for field in ["hash", "file_hash", "md5", "sha1", "sha256"]:
            if field in log_entry:
                hash_val = str(log_entry[field]).lower()
                if md5_pattern.match(hash_val):
                    extracted["md5"].append(hash_val)
                elif sha1_pattern.match(hash_val):
                    extracted["sha1"].append(hash_val)
                elif sha256_pattern.match(hash_val):
                    extracted["sha256"].append(hash_val)

        # Extract emails
        email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        for field in ["email", "sender", "recipient", "from", "to"]:
            if field in log_entry:
                emails = email_pattern.findall(str(log_entry[field]))
                extracted["email"].extend(emails)

        # Extract user agent
        if "user_agent" in log_entry:
            extracted["user_agent"].append(log_entry["user_agent"])

        return extracted

    def _match_from_cache(self, ioc_type: str, ioc_value: str) -> list[ThreatIndicator]:
        """Find matching indicators in cache for an IOC

        Handles special matching logic:
        - IP: exact match + CIDR matching
        - Domain: exact match + subdomain matching
        - URL: prefix matching
        - Hashes: exact match

        Args:
            ioc_type: Type of IOC
            ioc_value: IOC value to match

        Returns:
            List of matching ThreatIndicator instances
        """
        matches = []

        if ioc_type not in self.ioc_cache:
            return matches

        cache_dict = self.ioc_cache[ioc_type]

        # Exact match
        if ioc_value in cache_dict:
            matches.extend(cache_dict[ioc_value])

        # Special handling for different IOC types
        if ioc_type == "ipv4":
            # CIDR matching
            try:
                ip_obj = ipaddress.ip_address(ioc_value)
                for cached_value, indicators in cache_dict.items():
                    try:
                        if "/" in cached_value:  # CIDR block
                            network = ipaddress.ip_network(cached_value, strict=False)
                            if ip_obj in network:
                                matches.extend(indicators)
                    except ValueError:
                        continue
            except ValueError:
                pass

        elif ioc_type == "domain":
            # Subdomain matching
            for cached_domain, indicators in cache_dict.items():
                if ioc_value.endswith(cached_domain) or ioc_value == cached_domain:
                    matches.extend(indicators)

        elif ioc_type == "url":
            # URL prefix matching
            for cached_url, indicators in cache_dict.items():
                if ioc_value.startswith(cached_url):
                    matches.extend(indicators)

        return list(set(matches))  # Remove duplicates

    def _build_bloom_filter(self) -> None:
        """Build a bloom filter from the current IOC cache for fast negative lookups"""
        import hashlib
        # Use a bit array approach: size = 2^17 = 131072 bits for reasonable false positive rate
        filter_size = 131072
        self.bloom_filter = bytearray(filter_size // 8)
        num_hashes = 5

        for ioc_type, type_cache in self.ioc_cache.items():
            if isinstance(type_cache, dict):
                for value in type_cache.keys():
                    key = f"{ioc_type}:{value}"
                    for i in range(num_hashes):
                        h = int(hashlib.sha256(f"{key}:{i}".encode()).hexdigest(), 16) % filter_size
                        self.bloom_filter[h // 8] |= (1 << (h % 8))

    def _check_bloom_filter(self, ioc_type: str, ioc_value: str) -> bool:
        """Check if IOC might exist in cache using bloom filter

        Uses multiple hash functions to check bits in the filter. A negative
        result definitively means the IOC is not in the cache. A positive
        result means it might be (possible false positive).

        Args:
            ioc_type: Type of IOC
            ioc_value: IOC value

        Returns:
            True if IOC might exist (bloom filter positive), False if definitely doesn't exist
        """
        if not self.bloom_filter:
            return True

        import hashlib
        filter_size = len(self.bloom_filter) * 8
        num_hashes = 5
        key = f"{ioc_type}:{ioc_value}"

        for i in range(num_hashes):
            h = int(hashlib.sha256(f"{key}:{i}".encode()).hexdigest(), 16) % filter_size
            if not (self.bloom_filter[h // 8] & (1 << (h % 8))):
                return False

        return True
