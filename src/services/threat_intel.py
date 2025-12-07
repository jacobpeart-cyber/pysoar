"""Threat Intelligence Feed Service for auto-importing IOCs"""

import asyncio
import csv
import io
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.models.ioc import IOC

logger = logging.getLogger(__name__)


class ThreatIntelFeed:
    """Base class for threat intelligence feeds"""

    name: str = "base"
    display_name: str = "Base Feed"
    feed_type: str = "generic"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", False)
        self.api_key = config.get("api_key", "")
        self.update_interval = config.get("update_interval", 3600)  # seconds
        self.last_update: Optional[datetime] = None

    async def fetch_indicators(self) -> list[dict]:
        """Fetch indicators from the feed - override in subclasses"""
        raise NotImplementedError

    async def import_to_db(self, db: AsyncSession, indicators: list[dict]) -> int:
        """Import indicators to database"""
        imported = 0
        for indicator in indicators:
            # Check if IOC already exists
            existing = await db.execute(
                select(IOC).where(
                    IOC.value == indicator["value"],
                    IOC.ioc_type == indicator["ioc_type"],
                )
            )
            if existing.scalar_one_or_none():
                continue

            ioc = IOC(
                value=indicator["value"],
                ioc_type=indicator["ioc_type"],
                threat_level=indicator.get("threat_level", "medium"),
                source=f"threat_intel:{self.name}",
                description=indicator.get("description"),
                tags=indicator.get("tags", []),
                first_seen=datetime.utcnow().isoformat(),
                is_active=True,
            )
            db.add(ioc)
            imported += 1

        if imported > 0:
            await db.commit()
            logger.info(f"Imported {imported} indicators from {self.name}")

        return imported


class AlienVaultOTXFeed(ThreatIntelFeed):
    """AlienVault OTX threat intelligence feed"""

    name = "alienvault_otx"
    display_name = "AlienVault OTX"
    feed_type = "premium"

    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def fetch_indicators(self) -> list[dict]:
        """Fetch indicators from AlienVault OTX"""
        if not self.api_key:
            logger.warning("AlienVault OTX API key not configured")
            return []

        indicators = []

        try:
            async with httpx.AsyncClient() as client:
                # Fetch subscribed pulses
                response = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers={"X-OTX-API-KEY": self.api_key},
                    params={"modified_since": self._get_modified_since()},
                    timeout=30.0,
                )

                if response.status_code != 200:
                    logger.error(f"OTX API error: {response.status_code}")
                    return []

                data = response.json()
                for pulse in data.get("results", []):
                    for indicator in pulse.get("indicators", []):
                        ioc_type = self._map_indicator_type(indicator.get("type"))
                        if ioc_type:
                            indicators.append({
                                "value": indicator.get("indicator"),
                                "ioc_type": ioc_type,
                                "threat_level": "high",
                                "description": pulse.get("name"),
                                "tags": pulse.get("tags", []),
                            })

        except Exception as e:
            logger.error(f"Failed to fetch OTX indicators: {e}")

        return indicators

    def _get_modified_since(self) -> str:
        """Get modified_since timestamp"""
        if self.last_update:
            return self.last_update.isoformat()
        return (datetime.utcnow() - timedelta(days=7)).isoformat()

    def _map_indicator_type(self, otx_type: str) -> Optional[str]:
        """Map OTX indicator type to internal type"""
        mapping = {
            "IPv4": "ip_address",
            "IPv6": "ip_address",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "file_hash",
            "FileHash-SHA1": "file_hash",
            "FileHash-SHA256": "file_hash",
            "email": "email",
        }
        return mapping.get(otx_type)


class AbuseIPDBFeed(ThreatIntelFeed):
    """AbuseIPDB threat intelligence feed"""

    name = "abuseipdb"
    display_name = "AbuseIPDB"
    feed_type = "premium"

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    async def fetch_indicators(self) -> list[dict]:
        """Fetch malicious IPs from AbuseIPDB"""
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return []

        indicators = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}/blacklist",
                    headers={
                        "Key": self.api_key,
                        "Accept": "application/json",
                    },
                    params={"confidenceMinimum": 90, "limit": 1000},
                    timeout=30.0,
                )

                if response.status_code != 200:
                    logger.error(f"AbuseIPDB API error: {response.status_code}")
                    return []

                data = response.json()
                for entry in data.get("data", []):
                    threat_level = "critical" if entry.get("abuseConfidenceScore", 0) >= 95 else "high"
                    indicators.append({
                        "value": entry.get("ipAddress"),
                        "ioc_type": "ip_address",
                        "threat_level": threat_level,
                        "description": f"AbuseIPDB confidence: {entry.get('abuseConfidenceScore')}%",
                        "tags": ["abuseipdb", "malicious_ip"],
                    })

        except Exception as e:
            logger.error(f"Failed to fetch AbuseIPDB indicators: {e}")

        return indicators


class MalwareBazaarFeed(ThreatIntelFeed):
    """MalwareBazaar threat intelligence feed (free)"""

    name = "malwarebazaar"
    display_name = "MalwareBazaar"
    feed_type = "free"

    BASE_URL = "https://mb-api.abuse.ch/api/v1"

    async def fetch_indicators(self) -> list[dict]:
        """Fetch malware hashes from MalwareBazaar"""
        indicators = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.BASE_URL}/",
                    data={"query": "get_recent", "selector": "100"},
                    timeout=30.0,
                )

                if response.status_code != 200:
                    logger.error(f"MalwareBazaar API error: {response.status_code}")
                    return []

                data = response.json()
                for entry in data.get("data", []):
                    indicators.append({
                        "value": entry.get("sha256_hash"),
                        "ioc_type": "file_hash",
                        "threat_level": "critical",
                        "description": f"Malware: {entry.get('signature', 'Unknown')}",
                        "tags": entry.get("tags", []) + ["malwarebazaar"],
                    })

        except Exception as e:
            logger.error(f"Failed to fetch MalwareBazaar indicators: {e}")

        return indicators


class URLhausFeed(ThreatIntelFeed):
    """URLhaus threat intelligence feed (free)"""

    name = "urlhaus"
    display_name = "URLhaus"
    feed_type = "free"

    FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    async def fetch_indicators(self) -> list[dict]:
        """Fetch malicious URLs from URLhaus"""
        indicators = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.FEED_URL, timeout=30.0)

                if response.status_code != 200:
                    logger.error(f"URLhaus API error: {response.status_code}")
                    return []

                # Parse CSV
                content = response.text
                reader = csv.reader(io.StringIO(content))

                for row in reader:
                    if row and not row[0].startswith("#"):
                        try:
                            indicators.append({
                                "value": row[2],  # URL
                                "ioc_type": "url",
                                "threat_level": "high",
                                "description": f"Threat: {row[4] if len(row) > 4 else 'Unknown'}",
                                "tags": ["urlhaus", "malicious_url"],
                            })
                        except IndexError:
                            continue

        except Exception as e:
            logger.error(f"Failed to fetch URLhaus indicators: {e}")

        return indicators[:500]  # Limit to 500 most recent


class FeodoTrackerFeed(ThreatIntelFeed):
    """Feodo Tracker feed for botnet C2 servers (free)"""

    name = "feodotracker"
    display_name = "Feodo Tracker"
    feed_type = "free"

    FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

    async def fetch_indicators(self) -> list[dict]:
        """Fetch botnet C2 IPs from Feodo Tracker"""
        indicators = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.FEED_URL, timeout=30.0)

                if response.status_code != 200:
                    logger.error(f"Feodo Tracker API error: {response.status_code}")
                    return []

                data = response.json()
                for entry in data:
                    indicators.append({
                        "value": entry.get("ip_address"),
                        "ioc_type": "ip_address",
                        "threat_level": "critical",
                        "description": f"Botnet C2: {entry.get('malware', 'Unknown')}",
                        "tags": ["feodotracker", "botnet", "c2", entry.get("malware", "").lower()],
                    })

        except Exception as e:
            logger.error(f"Failed to fetch Feodo Tracker indicators: {e}")

        return indicators


class ThreatIntelService:
    """Service for managing threat intelligence feeds"""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.feeds: list[ThreatIntelFeed] = []
        self._initialize_feeds()

    def _initialize_feeds(self):
        """Initialize configured feeds"""
        feed_classes = {
            "alienvault_otx": AlienVaultOTXFeed,
            "abuseipdb": AbuseIPDBFeed,
            "malwarebazaar": MalwareBazaarFeed,
            "urlhaus": URLhausFeed,
            "feodotracker": FeodoTrackerFeed,
        }

        for feed_name, feed_config in self.config.get("feeds", {}).items():
            if feed_name in feed_classes and feed_config.get("enabled", False):
                feed = feed_classes[feed_name](feed_config)
                self.feeds.append(feed)
                logger.info(f"Initialized threat intel feed: {feed_name}")

    async def update_all_feeds(self, db: AsyncSession) -> dict[str, int]:
        """Update all enabled feeds"""
        results = {}

        for feed in self.feeds:
            try:
                logger.info(f"Updating feed: {feed.name}")
                indicators = await feed.fetch_indicators()
                imported = await feed.import_to_db(db, indicators)
                feed.last_update = datetime.utcnow()
                results[feed.name] = imported
            except Exception as e:
                logger.error(f"Failed to update feed {feed.name}: {e}")
                results[feed.name] = -1

        return results

    async def update_feed(self, db: AsyncSession, feed_name: str) -> int:
        """Update a specific feed"""
        for feed in self.feeds:
            if feed.name == feed_name:
                indicators = await feed.fetch_indicators()
                imported = await feed.import_to_db(db, indicators)
                feed.last_update = datetime.utcnow()
                return imported
        return -1

    def get_feed_status(self) -> list[dict]:
        """Get status of all feeds"""
        return [
            {
                "name": feed.name,
                "display_name": feed.display_name,
                "feed_type": feed.feed_type,
                "enabled": feed.enabled,
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
            }
            for feed in self.feeds
        ]
