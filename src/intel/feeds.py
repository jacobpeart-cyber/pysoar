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


class PlainListFeedParser(FeedParser):
    """Parser for plain-text threat feeds (one indicator per line).

    Handles the common abuse.ch / emerging threats / blocklist format:
    comment lines starting with ``#`` are ignored, and each remaining
    line is one indicator. The indicator type is auto-detected from the
    value (ipv4, ipv6, cidr, url, domain, md5, sha1, sha256).

    For CSVs like feodotracker's ipblocklist (with multiple columns),
    the first column is assumed to be the indicator value.
    """

    IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
    CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
    MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
    DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

    def __init__(self, default_severity: str = "medium", default_confidence: int = 70):
        self.default_severity = default_severity
        self.default_confidence = default_confidence

    def _detect_type(self, value: str) -> Optional[str]:
        v = value.strip()
        if not v:
            return None
        if self.CIDR_RE.match(v):
            return "cidr"
        if self.IPV4_RE.match(v):
            try:
                ipaddress.IPv4Address(v)
                return "ipv4"
            except ValueError:
                return None
        if ":" in v and self.IPV6_RE.match(v):
            try:
                ipaddress.IPv6Address(v)
                return "ipv6"
            except ValueError:
                pass
        if v.startswith(("http://", "https://", "ftp://")):
            return "url"
        if self.SHA256_RE.match(v):
            return "sha256"
        if self.SHA1_RE.match(v):
            return "sha1"
        if self.MD5_RE.match(v):
            return "md5"
        if self.DOMAIN_RE.match(v):
            return "domain"
        return None

    def parse(self, raw_data: bytes) -> list[dict[str, Any]]:
        try:
            text = raw_data.decode("utf-8", errors="replace")
        except Exception as e:
            logger.error("Failed to decode plain feed", error=str(e))
            return []

        indicators: list[dict[str, Any]] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            # Strip Spamhaus-style trailing "; comment" from data lines
            if ";" in line and not line.startswith(";"):
                line = line.split(";", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("#", "//", ";")):
                continue

            # Try each comma-separated field in order. This handles:
            #   * single-value lines (urlhaus text_online, spamhaus)
            #   * multi-column CSVs where the indicator is not column 0
            #     (feodotracker ipblocklist.csv puts IP in col 1 after
            #     the timestamp column)
            fields = [f.strip().strip('"') for f in line.split(",")]
            chosen_value = None
            chosen_type = None
            for field in fields:
                ind_type = self._detect_type(field)
                if ind_type:
                    chosen_value = field
                    chosen_type = ind_type
                    break

            if not chosen_value or not chosen_type:
                continue

            indicators.append({
                "value": chosen_value,
                "indicator_type": chosen_type,
                "confidence": self.default_confidence,
                "severity": self.default_severity,
            })

        logger.info("Parsed plain-list feed", indicator_count=len(indicators))
        return indicators


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
            "plain": PlainListFeedParser(),  # abuse.ch style plain-text lists
        }

        # Built-in feeds — all keyless, all free, all publicly accessible.
        # The "plain" feed_type uses PlainListFeedParser which auto-detects
        # indicator_type from each line (IPv4/CIDR/URL/domain/hash).
        self.builtin_feeds = [
            {
                "name": "Abuse.ch Feodo Tracker (Aggressive)",
                "feed_type": "plain",
                # The "aggressive" list includes historical C2 infrastructure
                # (~8000 IPs) — operators reuse infra, so historical is the
                # signal, not noise. The "recommended" list only has ~5
                # currently-online IPs which is useless for detection.
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
                "provider": "Abuse.ch",
                "description": "Historical + active botnet C&C IPs (Emotet, Dridex, QakBot, TrickBot, BazarLoader)",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 60,
                "confidence_weight": 0.9,
            },
            {
                "name": "Abuse.ch URLhaus",
                "feed_type": "plain",
                "url": "https://urlhaus.abuse.ch/downloads/text_online/",
                "provider": "Abuse.ch",
                "description": "Active malware distribution URLs",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 30,
                "confidence_weight": 0.95,
            },
            {
                "name": "Emerging Threats Compromised IPs",
                "feed_type": "plain",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "provider": "Proofpoint ET",
                "description": "Known compromised hosts (open proxies, malware infected)",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 120,
                "confidence_weight": 0.8,
            },
            {
                "name": "Spamhaus DROP",
                "feed_type": "plain",
                "url": "https://www.spamhaus.org/drop/drop.txt",
                "provider": "Spamhaus",
                "description": "Don't Route Or Peer netblocks (hijacked or known criminal)",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 360,
                "confidence_weight": 1.0,
            },
            {
                "name": "CINS Army List",
                "feed_type": "plain",
                "url": "http://cinsscore.com/list/ci-badguys.txt",
                "provider": "Sentinel IPS",
                "description": "Top ~15,000 highest-scoring attacker IPs seen by Sentinel IPS sensor network",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 180,
                "confidence_weight": 0.85,
            },
            {
                "name": "Blocklist.de All",
                "feed_type": "plain",
                "url": "https://lists.blocklist.de/lists/all.txt",
                "provider": "blocklist.de",
                "description": "Attackers seen by >700 fail2ban / log analyzer sensors (SSH brute force, web attacks, IMAP, mail)",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 120,
                "confidence_weight": 0.85,
            },
            {
                "name": "Binary Defense Banlist",
                "feed_type": "plain",
                "url": "https://www.binarydefense.com/banlist.txt",
                "provider": "Binary Defense",
                "description": "Artillery Threat Intelligence Feed — curated attacker IPs",
                "is_builtin": True,
                "is_enabled": True,
                "poll_interval_minutes": 360,
                "confidence_weight": 0.9,
            },
        ]

    async def poll_feed(self, feed_id: str) -> int:
        """Poll a single threat feed and ingest indicators

        Args:
            feed_id: ID of feed to poll

        Returns:
            Number of new indicators ingested
        """
        from src.core.database import async_session_factory
        from sqlalchemy import select

        self.logger.info("Polling feed", feed_id=feed_id)

        async with async_session_factory() as session:
            result = await session.execute(
                select(ThreatFeed).where(ThreatFeed.id == feed_id)
            )
            feed = result.scalar_one_or_none()

            if not feed:
                self.logger.error("Feed not found", feed_id=feed_id)
                return 0

            if not feed.is_enabled:
                self.logger.warning("Feed is disabled, skipping", feed_id=feed_id)
                return 0

            # Fetch raw data from feed URL
            raw_data = await self._fetch_feed_data(feed)
            if not raw_data:
                feed.last_error = feed.last_error or "Empty response from feed"
                feed.last_poll_at = datetime.now(timezone.utc)
                await session.commit()
                return 0

            # Parse using the appropriate parser
            parser = self.parsers.get(feed.feed_type)
            if not parser:
                self.logger.error("No parser for feed type", feed_type=feed.feed_type)
                feed.last_error = f"No parser for feed type: {feed.feed_type}"
                feed.last_poll_at = datetime.now(timezone.utc)
                await session.commit()
                return 0

            parsed_indicators = parser.parse(raw_data)
            self.logger.info("Parsed indicators from feed", feed_id=feed_id, count=len(parsed_indicators))

            # Ingest parsed indicators into the database
            new_count = 0
            for indicator_dict in parsed_indicators:
                ind_type = indicator_dict.get("indicator_type")
                ind_value = indicator_dict.get("value")
                if not ind_type or not ind_value:
                    continue

                # Check for existing indicator
                existing = await session.execute(
                    select(ThreatIndicator).where(
                        ThreatIndicator.indicator_type == ind_type,
                        ThreatIndicator.value == ind_value,
                        ThreatIndicator.feed_id == feed.id,
                    )
                )
                existing_ind = existing.scalar_one_or_none()

                if existing_ind:
                    # Update last_seen and sighting_count
                    existing_ind.last_seen = datetime.now(timezone.utc)
                    existing_ind.sighting_count += 1
                else:
                    new_indicator = ThreatIndicator(
                        indicator_type=ind_type,
                        value=ind_value,
                        feed_id=feed.id,
                        source=feed.name,
                        confidence=indicator_dict.get("confidence", 50),
                        severity=indicator_dict.get("severity", "medium"),
                        tlp=indicator_dict.get("tlp", "amber"),
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        is_active=True,
                        mitre_techniques=indicator_dict.get("mitre_techniques", []),
                        tags=indicator_dict.get("tags", []),
                    )
                    session.add(new_indicator)
                    new_count += 1

            # Update feed metadata
            feed.last_poll_at = datetime.now(timezone.utc)
            feed.last_success_at = datetime.now(timezone.utc)
            feed.last_error = None
            feed.total_indicators += new_count
            await session.commit()

            self.logger.info("Feed poll complete", feed_id=feed_id, new_indicators=new_count)
            return new_count

    async def poll_all_feeds(self) -> dict[str, int]:
        """Poll all enabled threat feeds

        Returns:
            Dict with feed_id as key and count of new indicators as value
        """
        from src.core.database import async_session_factory
        from sqlalchemy import select

        self.logger.info("Polling all enabled feeds")
        results = {}

        async with async_session_factory() as session:
            query = select(ThreatFeed).where(ThreatFeed.is_enabled == True)
            result = await session.execute(query)
            feeds = list(result.scalars().all())

        self.logger.info("Found enabled feeds to poll", count=len(feeds))

        for feed in feeds:
            try:
                count = await self.poll_feed(feed.id)
                results[feed.id] = count
            except Exception as e:
                self.logger.error("Failed to poll feed", feed_id=feed.id, feed_name=feed.name, error=str(e))
                results[feed.id] = 0

        return results

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

    # Feeds that used to be built-in but are deprecated/upstream-dead.
    # Rows with these names (is_builtin=True) are removed on startup.
    _DEPRECATED_FEED_NAMES = (
        "Abuse.ch SSL Blacklist",  # abuse.ch deprecated it 2025-01-03
        "Abuse.ch Feodo Tracker",  # replaced by "Abuse.ch Feodo Tracker (Aggressive)"
        "Abuse.ch MalwareBazaar",  # old stub, no parser
        "AlienVault OTX",  # old stub, needs API key
        "PhishTank",  # old stub, needs API key
        "EmergingThreats",  # old stub, wrong URL
    )

    async def register_builtin_feeds(self) -> int:
        """Register built-in threat feeds in the database.

        Idempotent — existing builtin feeds (matched by name) are updated
        in place, not duplicated. Deprecated built-ins are removed.
        Returns the number of NEW feeds created this call.
        """
        from src.core.database import async_session_factory
        from sqlalchemy import select, delete

        self.logger.info("Registering built-in feeds", count=len(self.builtin_feeds))

        created = 0
        async with async_session_factory() as session:
            # 1. Purge any deprecated built-in feeds (and their indicators
            #    cascade-delete via the ThreatFeed.indicators relationship).
            for dead_name in self._DEPRECATED_FEED_NAMES:
                result = await session.execute(
                    select(ThreatFeed).where(
                        ThreatFeed.name == dead_name,
                        ThreatFeed.is_builtin == True,  # noqa: E712
                    )
                )
                dead = result.scalar_one_or_none()
                if dead:
                    self.logger.info("Removing deprecated builtin feed", name=dead_name)
                    await session.delete(dead)
            await session.flush()
            for feed_def in self.builtin_feeds:
                existing = await session.execute(
                    select(ThreatFeed).where(ThreatFeed.name == feed_def["name"])
                )
                row = existing.scalar_one_or_none()

                if row:
                    # Update mutable config on every call so URL/description
                    # changes in code propagate without a migration.
                    row.feed_type = feed_def["feed_type"]
                    row.url = feed_def.get("url")
                    row.provider = feed_def.get("provider")
                    row.description = feed_def.get("description")
                    row.is_builtin = True
                    row.poll_interval_minutes = feed_def.get("poll_interval_minutes", 60)
                    if "confidence_weight" in feed_def:
                        row.confidence_weight = feed_def["confidence_weight"]
                    # Don't clobber is_enabled if an operator disabled it
                    continue

                new_feed = ThreatFeed(
                    name=feed_def["name"],
                    feed_type=feed_def["feed_type"],
                    url=feed_def.get("url"),
                    provider=feed_def.get("provider"),
                    description=feed_def.get("description"),
                    is_enabled=feed_def.get("is_enabled", True),
                    is_builtin=True,
                    poll_interval_minutes=feed_def.get("poll_interval_minutes", 60),
                    confidence_weight=feed_def.get("confidence_weight", 1.0),
                    total_indicators=0,
                    tags=[],
                )
                session.add(new_feed)
                created += 1
                self.logger.info("Registered builtin feed", name=feed_def["name"])

            await session.commit()

        self.logger.info("Built-in feeds registration complete", created=created)
        return created
