"""Threat feed parsing and management engine"""

import ipaddress
import json
import re
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from src.core.config import settings
from src.core.logging import get_logger
from src.intel.models import ThreatFeed, ThreatIndicator

logger = get_logger(__name__)


def _validate_url_not_internal(url: str) -> bool:
    """Prevent SSRF by blocking requests to internal/private IP ranges."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block common internal hostnames
        blocked_hostnames = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in blocked_hostnames:
            return False
        # Resolve and check IP ranges
        resolved_ips = socket.getaddrinfo(hostname, None)
        for family, type_, proto, canonname, sockaddr in resolved_ips:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except Exception:
        return False


class FeedParser(ABC):
    """Abstract base class for feed parsers"""

    @abstractmethod
    def parse(self, raw_data: bytes) -> list[dict[str, Any]]:
        """Parse raw feed data and return list of indicator dictionaries

        Args:
            raw_data: Raw bytes from feed source

        Returns:
            List of parsed indicator dictionaries with keys: indicator_type, value, confidence, severity, etc.
        """
        pass


class STIXFeedParser(FeedParser):
    """Parser for STIX 2.1 JSON bundles"""

    def parse(self, raw_data: bytes) -> list[dict[str, Any]]:
        """Parse STIX 2.1 JSON bundle"""
        try:
            bundle = json.loads(raw_data.decode("utf-8"))
            indicators = []

            if bundle.get("type") != "bundle":
                logger.warning("STIX data is not a bundle")
                return indicators

            for obj in bundle.get("objects", []):
                # Parse indicators (Observable patterns)
                if obj.get("type") == "indicator":
                    parsed = self._parse_stix_indicator(obj)
                    if parsed:
                        indicators.append(parsed)

                # Parse threat actors
                elif obj.get("type") == "threat-actor":
                    logger.debug("Threat actor found in STIX", name=obj.get("name"))

                # Parse attack patterns (techniques)
                elif obj.get("type") == "attack-pattern":
                    logger.debug("Attack pattern found in STIX", name=obj.get("name"))

            logger.info("Parsed STIX bundle", indicator_count=len(indicators))
            return indicators

        except json.JSONDecodeError as e:
            logger.error("Failed to parse STIX JSON", error=str(e))
            return []
        except Exception as e:
            logger.error("Error parsing STIX data", error=str(e))
            return []

    def _parse_stix_indicator(self, indicator_obj: dict) -> Optional[dict[str, Any]]:
        """Parse individual STIX indicator pattern"""
        try:
            pattern = indicator_obj.get("pattern", "")
            if not pattern:
                return None

            # Extract indicator type and value from STIX pattern
            # Pattern format: [observable_type:observable_property = 'value']
            match = re.search(r"\[([^:]+):([^\s=]+)\s*=\s*['\"]([^'\"]+)['\"]", pattern)
            if not match:
                return None

            obs_type, obs_prop, value = match.groups()

            # Map STIX observable types to our indicator types
            indicator_type = self._map_stix_observable_type(obs_type, obs_prop)
            if not indicator_type:
                return None

            return {
                "indicator_type": indicator_type,
                "value": value,
                "confidence": indicator_obj.get("confidence", 50),
                "severity": self._map_severity(indicator_obj.get("labels", [])),
                "tlp": indicator_obj.get("x_mitre_tlp", "amber"),
                "first_seen": indicator_obj.get("created"),
                "last_seen": indicator_obj.get("modified"),
                "mitre_techniques": self._extract_mitre_techniques(indicator_obj),
                "tags": indicator_obj.get("labels", []),
            }

        except Exception as e:
            logger.warning("Failed to parse STIX indicator", error=str(e))
            return None

    def _map_stix_observable_type(self, obs_type: str, obs_prop: str) -> Optional[str]:
        """Map STIX observable types to our indicator types"""
        mapping = {
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "domain-name": "domain",
            "url": "url",
            "file": {
                "hashes.MD5": "md5",
                "hashes.MD-5": "md5",
                "hashes.SHA-1": "sha1",
                "hashes.SHA1": "sha1",
                "hashes.SHA-256": "sha256",
                "hashes.SHA256": "sha256",
            },
            "email-addr": "email",
            "windows-registry-key": "registry_key",
        }

        if obs_type in mapping:
            val = mapping[obs_type]
            if isinstance(val, dict):
                return val.get(obs_prop)
            return val

        return None

    def _map_severity(self, labels: list[str]) -> str:
        """Map STIX labels to severity levels"""
        for label in labels:
            if "critical" in label.lower():
                return "critical"
            elif "high" in label.lower():
                return "high"
            elif "medium" in label.lower():
                return "medium"
            elif "low" in label.lower():
                return "low"
        return "informational"

    def _extract_mitre_techniques(self, obj: dict) -> list[str]:
        """Extract MITRE ATT&CK techniques from STIX object"""
        techniques = []
        # Look for external references with MITRE ATT&CK references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                if technique_id:
                    techniques.append(technique_id)
        return techniques


class CSVFeedParser(FeedParser):
    """Parser for CSV threat feeds with configurable column mapping"""

    def __init__(self, column_mapping: Optional[dict[str, str]] = None):
        """Initialize CSV parser with optional column mapping

        Args:
            column_mapping: Dict mapping feed columns to our fields (e.g., {'ip': 'value', 'severity': 'severity'})
        """
        self.column_mapping = column_mapping or {
            "indicator": "value",
            "type": "indicator_type",
            "confidence": "confidence",
            "severity": "severity",
        }

    def parse(self, raw_data: bytes) -> list[dict[str, Any]]:
        """Parse CSV feed data"""
        try:
            lines = raw_data.decode("utf-8").split("\n")
            if not lines:
                return []

            # Parse header
            header = lines[0].split(",")
            indicators = []

            for line in lines[1:]:
                if not line.strip():
                    continue

                values = line.split(",")
                if len(values) != len(header):
                    logger.warning("CSV line has mismatched column count", line=line)
                    continue

                # Map columns to indicator fields
                indicator_dict = {}
                for col_idx, col_name in enumerate(header):
                    if col_name in self.column_mapping:
                        indicator_dict[self.column_mapping[col_name]] = values[col_idx].strip()

                # Validate required fields
                if "value" in indicator_dict and "indicator_type" in indicator_dict:
                    # Set defaults
                    indicator_dict.setdefault("confidence", 50)
                    indicator_dict.setdefault("severity", "medium")
                    indicators.append(indicator_dict)

            logger.info("Parsed CSV feed", indicator_count=len(indicators))
            return indicators

        except Exception as e:
            logger.error("Failed to parse CSV feed", error=str(e))
            return []


class MISPFeedParser(FeedParser):
    """Parser for MISP JSON event format"""

    def parse(self, raw_data: bytes) -> list[dict[str, Any]]:
        """Parse MISP JSON event"""
        try:
            data = json.loads(raw_data.decode("utf-8"))
            indicators = []

            if "Event" not in data:
                logger.warning("MISP data does not contain Event object")
                return indicators

            event = data["Event"]
            for attribute in event.get("Attribute", []):
                parsed = self._parse_misp_attribute(attribute)
                if parsed:
                    indicators.append(parsed)

            logger.info("Parsed MISP event", indicator_count=len(indicators), event_id=event.get("id"))
            return indicators

        except json.JSONDecodeError as e:
            logger.error("Failed to parse MISP JSON", error=str(e))
            return []
        except Exception as e:
            logger.error("Error parsing MISP data", error=str(e))
            return []

    def _parse_misp_attribute(self, attribute: dict) -> Optional[dict[str, Any]]:
        """Parse individual MISP attribute"""
        try:
            attr_type = attribute.get("type", "")
            value = attribute.get("value", "")

            # Map MISP types to our indicator types
            indicator_type = self._map_misp_type(attr_type)
            if not indicator_type:
                return None

            return {
                "indicator_type": indicator_type,
                "value": value,
                "confidence": 75,  # MISP events are typically high confidence
                "severity": attribute.get("category", "medium"),
                "first_seen": attribute.get("timestamp"),
                "tags": attribute.get("Tag", []),
            }

        except Exception as e:
            logger.warning("Failed to parse MISP attribute", error=str(e))
            return None

    def _map_misp_type(self, misp_type: str) -> Optional[str]:
        """Map MISP attribute types to our indicator types"""
        mapping = {
            "ip-dst": "ipv4",
            "ip-src": "ipv4",
            "ip-dst|port": "ipv4",
            "ip-src|port": "ipv4",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "email-dst": "email",
            "email-src": "email",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "filename": "filename",
            "windows-registry-key": "registry_key",
            "user-agent": "user_agent",
            "vulnerability": "cve",
        }
        return mapping.get(misp_type)


class TAXIIFeedClient:
    """TAXII 2.1 client for polling threat intelligence collections"""

    def __init__(self, server_url: str, collection_id: str, auth_config: Optional[dict] = None):
        """Initialize TAXII client

        Args:
            server_url: TAXII 2.1 server URL
            collection_id: Collection ID to poll
            auth_config: Authentication configuration (api_key, username/password, etc.)
        """
        self.server_url = server_url
        self.collection_id = collection_id
        self.auth_config = auth_config or {}
        self.logger = get_logger(__name__)

    async def fetch_collection(self, modified_after: Optional[datetime] = None) -> bytes:
        """Fetch objects from TAXII collection with optional delta polling

        Args:
            modified_after: Only retrieve objects modified after this timestamp

        Returns:
            Raw TAXII response data (STIX bundle)
        """
        try:
            headers = self._build_headers()
            url = f"{self.server_url}/collections/{self.collection_id}/objects"

            # SSRF protection
            if not _validate_url_not_internal(url):
                self.logger.error("URL validation failed: blocked internal/private address", url=url)
                return b""

            params = {}
            if modified_after:
                # ISO 8601 format required by TAXII
                params["added_after"] = modified_after.isoformat()

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=30) as resp:
                    if resp.status == 200:
                        self.logger.info("TAXII fetch successful", collection=self.collection_id)
                        return await resp.read()
                    else:
                        self.logger.error(
                            "TAXII fetch failed",
                            collection=self.collection_id,
                            status=resp.status,
                        )
                        return b""

        except Exception as e:
            self.logger.error("Error fetching from TAXII", error=str(e))
            return b""

    def _build_headers(self) -> dict[str, str]:
        """Build headers for TAXII request including authentication"""
        headers = {"Accept": "application/stix+json;version=2.1"}

        if self.auth_config.get("api_key"):
            headers["X-API-Key"] = self.auth_config["api_key"]

        if self.auth_config.get("username") and self.auth_config.get("password"):
            import base64

            credentials = base64.b64encode(
                f"{self.auth_config['username']}:{self.auth_config['password']}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers


class FeedManager:
    """Manager for threat feeds: polling, parsing, and indicator ingestion"""

    def __init__(self):
        """Initialize feed manager"""
        self.logger = get_logger(__name__)
        self.parsers = {
            "stix": STIXFeedParser(),
            "csv": CSVFeedParser(),
            "misp": MISPFeedParser(),
            "json": STIXFeedParser(),  # Default to STIX for JSON
            "taxii": STIXFeedParser(),  # TAXII returns STIX
            "openioc": STIXFeedParser(),  # Will parse as STIX
        }

        # Built-in feeds configuration
        self.builtin_feeds = [
            {
                "name": "AlienVault OTX",
                "feed_type": "csv",
                "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "provider": "AT&T Cybersecurity",
                "description": "AlienVault Open Threat Exchange - community-sourced threat intelligence",
                "is_builtin": True,
                "poll_interval_minutes": 60,
            },
            {
                "name": "Abuse.ch URLhaus",
                "feed_type": "csv",
                "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                "provider": "Abuse.ch",
                "description": "Malicious URLs database",
                "is_builtin": True,
                "poll_interval_minutes": 60,
            },
            {
                "name": "Abuse.ch MalwareBazaar",
                "feed_type": "json",
                "url": "https://mb-api.abuse.ch/api/v1/",
                "provider": "Abuse.ch",
                "description": "Malware samples and hashes",
                "is_builtin": True,
                "poll_interval_minutes": 120,
            },
            {
                "name": "EmergingThreats",
                "feed_type": "csv",
                "url": "https://rules.emergingthreats.net/blocklist/",
                "provider": "Proofpoint",
                "description": "Emerging threats IOC feed",
                "is_builtin": True,
                "poll_interval_minutes": 60,
            },
            {
                "name": "PhishTank",
                "feed_type": "json",
                "url": "https://phishtank.com/api_info.php",
                "provider": "OpenDNS",
                "description": "Phishing URLs database",
                "is_builtin": True,
                "poll_interval_minutes": 240,
            },
        ]

    async def poll_feed(self, feed_id: str) -> int:
        """Poll a single threat feed and ingest indicators

        Args:
            feed_id: ID of feed to poll

        Returns:
            Number of new indicators ingested
        """
        # This would fetch the feed from database, poll it, parse it, and ingest
        # For now, return placeholder
        self.logger.info("Polling feed", feed_id=feed_id)
        return 0

    async def poll_all_feeds(self) -> dict[str, int]:
        """Poll all enabled threat feeds

        Returns:
            Dict with feed_id as key and count of new indicators as value
        """
        # This would iterate through all enabled feeds and call poll_feed
        self.logger.info("Polling all enabled feeds")
        return {}

    async def _fetch_feed_data(self, feed: ThreatFeed) -> bytes:
        """Fetch raw data from feed source

        Args:
            feed: ThreatFeed model instance

        Returns:
            Raw bytes from feed
        """
        if not feed.url:
            self.logger.warning("Feed has no URL", feed_id=feed.id)
            return b""

        # SSRF protection
        if not _validate_url_not_internal(feed.url):
            self.logger.error("URL validation failed: blocked internal/private address", feed_id=feed.id, url=feed.url)
            feed.last_error = "URL validation failed: blocked internal/private address"
            return b""

        try:
            headers = self._build_feed_headers(feed)

            async with aiohttp.ClientSession() as session:
                async with session.get(feed.url, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        self.logger.info("Feed fetch successful", feed_id=feed.id, feed_name=feed.name)
                        return await resp.read()
                    else:
                        self.logger.error(
                            "Feed fetch failed",
                            feed_id=feed.id,
                            feed_name=feed.name,
                            status=resp.status,
                        )
                        feed.last_error = f"HTTP {resp.status}"
                        return b""

        except Exception as e:
            self.logger.error("Error fetching feed", feed_id=feed.id, error=str(e))
            feed.last_error = str(e)
            return b""

    def _build_feed_headers(self, feed: ThreatFeed) -> dict[str, str]:
        """Build HTTP headers for feed request including authentication"""
        headers = {
            "User-Agent": f"PySOAR/{settings.app_name}",
        }

        if feed.auth_type == "api_key" and feed.auth_config:
            api_key = feed.auth_config.get("api_key", "")
            headers["X-API-Key"] = api_key

        elif feed.auth_type == "basic" and feed.auth_config:
            import base64

            username = feed.auth_config.get("username", "")
            password = feed.auth_config.get("password", "")
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    async def _process_indicators(self, feed: ThreatFeed, parsed_data: list[dict]) -> int:
        """Process and ingest parsed indicators from feed

        Args:
            feed: ThreatFeed model instance
            parsed_data: List of parsed indicator dictionaries

        Returns:
            Number of new indicators ingested
        """
        new_count = 0

        for indicator_dict in parsed_data:
            try:
                # Deduplicate
                indicator = await self._deduplicate_indicator(
                    indicator_dict.get("indicator_type"),
                    indicator_dict.get("value"),
                    feed.id,
                )

                if indicator:
                    new_count += 1
                    self.logger.debug("Ingested indicator", indicator_id=indicator.id, feed_id=feed.id)

            except Exception as e:
                self.logger.warning("Failed to ingest indicator", feed_id=feed.id, error=str(e))
                continue

        self.logger.info("Feed processing complete", feed_id=feed.id, new_indicators=new_count)
        return new_count

    async def _deduplicate_indicator(
        self, indicator_type: str, value: str, feed_id: str
    ) -> Optional[ThreatIndicator]:
        """Check for existing indicator or create new one

        Args:
            indicator_type: Type of indicator
            value: Indicator value
            feed_id: Source feed ID

        Returns:
            ThreatIndicator instance (existing or new)
        """
        # This would query the database for existing indicator
        # and either return it or create a new one
        # Placeholder implementation
        return None

    async def enable_feed(self, feed_id: str) -> bool:
        """Enable a threat feed"""
        self.logger.info("Enabling feed", feed_id=feed_id)
        return True

    async def disable_feed(self, feed_id: str) -> bool:
        """Disable a threat feed"""
        self.logger.info("Disabling feed", feed_id=feed_id)
        return True

    async def get_feed_stats(self, feed_id: str) -> dict[str, Any]:
        """Get statistics for a threat feed

        Returns:
            Dict with feed stats (indicator_count, last_poll, success_rate, etc.)
        """
        return {
            "feed_id": feed_id,
            "total_indicators": 0,
            "last_poll_at": None,
            "last_success_at": None,
            "success_rate": 0.0,
        }

    async def register_builtin_feeds(self) -> int:
        """Register built-in threat feeds in database

        Returns:
            Number of feeds registered
        """
        self.logger.info("Registering built-in feeds", count=len(self.builtin_feeds))
        # This would create ThreatFeed entries in database for each builtin feed
        return len(self.builtin_feeds)
