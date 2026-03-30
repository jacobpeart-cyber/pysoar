"""GeoIP enrichment service for IP geolocation and IP intelligence data."""

import ipaddress
import json
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class GeoIPResult:
    """Result of GeoIP lookup for an IP address."""

    ip: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    as_org: Optional[str] = None
    is_private: bool = False
    is_reserved: bool = False
    cloud_provider: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "region": self.region,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "as_org": self.as_org,
            "is_private": self.is_private,
            "is_reserved": self.is_reserved,
            "cloud_provider": self.cloud_provider,
        }


class GeoIPService:
    """
    GeoIP enrichment service using MaxMind GeoLite2 or fallback IP ranges.

    Provides IP geolocation, ASN lookup, and cloud provider identification.
    Falls back to built-in mappings if maxminddb is not available.
    """

    # Known cloud provider IP ranges
    CLOUD_PROVIDER_RANGES = {
        "AWS": [
            "3.0.0.0/8",
            "13.32.0.0/11",
            "13.54.0.0/15",
            "13.56.0.0/13",
            "13.64.0.0/11",
            "13.104.0.0/14",
            "13.224.0.0/12",
            "18.0.0.0/8",
            "34.64.0.0/10",
            "35.158.0.0/15",
            "35.176.0.0/13",
            "35.184.0.0/13",
            "35.192.0.0/11",
            "52.0.0.0/8",
        ],
        "Azure": [
            "13.64.0.0/11",
            "13.96.0.0/13",
            "13.104.0.0/14",
            "20.0.0.0/7",
            "40.64.0.0/10",
        ],
        "GCP": [
            "34.64.0.0/10",
            "35.184.0.0/13",
            "35.192.0.0/11",
            "35.220.0.0/14",
            "35.224.0.0/13",
            "35.232.0.0/14",
            "35.236.0.0/14",
        ],
        "DigitalOcean": [
            "104.131.0.0/16",
            "104.236.0.0/13",
            "107.170.0.0/15",
            "159.65.0.0/16",
            "159.89.0.0/16",
            "165.22.0.0/16",
            "167.99.0.0/16",
            "174.138.0.0/16",
        ],
    }

    # RFC1918 and RFC4193 private ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local
        ipaddress.ip_network("fe80::/10"),  # IPv6 Link-Local
    ]

    # Bogon ranges (invalid/reserved addresses)
    BOGON_RANGES = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("192.88.99.0/24"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("255.255.255.255/32"),
    ]

    # Built-in country code mappings for major geographic regions
    BUILTIN_GEO_DATA = {
        "8.8.8.0/24": {
            "country_code": "US",
            "country_name": "United States",
            "city": "Mountain View",
            "region": "California",
            "latitude": 37.386,
            "longitude": -122.084,
            "asn": "AS15169",
            "as_org": "Google LLC",
        },
        "1.1.1.0/24": {
            "country_code": "AU",
            "country_name": "Australia",
            "city": "Sydney",
            "region": "New South Wales",
            "latitude": -33.874,
            "longitude": 151.210,
            "asn": "AS13335",
            "as_org": "Cloudflare Inc",
        },
    }

    def __init__(self, db_path: Optional[str] = None, cache_size: int = 10000):
        """
        Initialize GeoIP service.

        Args:
            db_path: Path to MaxMind GeoLite2 database. If None, uses built-in mappings.
            cache_size: LRU cache size for lookups.
        """
        self.db_path = db_path
        self.cache_size = cache_size
        self.mmdb = None

        # Try to load MaxMind database if available
        if db_path:
            self._load_maxmind_db(db_path)
        else:
            self._check_default_locations()

        # Build cloud provider CIDR networks
        self.cloud_cidrs = {}
        for provider, ranges in self.CLOUD_PROVIDER_RANGES.items():
            self.cloud_cidrs[provider] = [
                ipaddress.ip_network(cidr) for cidr in ranges
            ]

        # Build bogon networks
        self.bogon_networks = self.BOGON_RANGES

        logger.info(f"GeoIP service initialized (db_path={db_path})")

    def _load_maxmind_db(self, db_path: str) -> None:
        """Load MaxMind GeoLite2 database if available."""
        try:
            import maxminddb

            self.mmdb = maxminddb.open_database(db_path)
            logger.info(f"Loaded MaxMind GeoLite2 database from {db_path}")
        except ImportError:
            logger.warning(
                "maxminddb module not installed. Falling back to built-in IP ranges."
            )
            self.mmdb = None
        except Exception as e:
            logger.warning(f"Failed to load MaxMind database: {e}. Using built-in ranges.")
            self.mmdb = None

    def _check_default_locations(self) -> None:
        """Check default MaxMind database locations."""
        default_paths = [
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
            "/var/lib/GeoIP/GeoLite2-City.mmdb",
            "/opt/geolite2/GeoLite2-City.mmdb",
        ]

        for path in default_paths:
            try:
                self._load_maxmind_db(path)
                self.db_path = path
                return
            except (FileNotFoundError, Exception):
                continue

    def lookup(self, ip: str) -> Optional[GeoIPResult]:
        """
        Look up IP location and geolocation data.

        Args:
            ip: IPv4 or IPv6 address to look up.

        Returns:
            GeoIPResult with location data, or None if IP cannot be resolved.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return None

        # Check if private or bogon
        is_private = self.is_private_ip(ip)
        is_bogon = self.is_bogon(ip)

        result = GeoIPResult(ip=ip, is_private=is_private, is_reserved=is_bogon)

        # Return early for private/reserved IPs
        if is_private or is_bogon:
            return result

        # Try MaxMind database first
        if self.mmdb:
            try:
                data = self.mmdb.get(ip)
                if data:
                    result.country_code = data.get("country", {}).get("iso_code")
                    result.country_name = data.get("country", {}).get("names", {}).get("en")
                    result.city = data.get("city", {}).get("names", {}).get("en")
                    result.region = data.get("subdivisions", [{}])[0].get("names", {}).get("en")
                    result.latitude = data.get("location", {}).get("latitude")
                    result.longitude = data.get("location", {}).get("longitude")
                    result.asn = data.get("autonomous_system_number")
                    result.as_org = data.get("autonomous_system_organization")
                    return result
            except Exception as e:
                logger.warning(f"MaxMind lookup failed for {ip}: {e}")

        # Try built-in geolocation data
        geo_data = self._lookup_builtin_geo(ip)
        if geo_data:
            for key, value in geo_data.items():
                setattr(result, key, value)
            return result

        # Check for cloud provider
        cloud_provider = self.get_known_cloud_provider(ip)
        if cloud_provider:
            result.cloud_provider = cloud_provider
            return result

        return result

    def _lookup_builtin_geo(self, ip: str) -> Optional[Dict]:
        """Look up IP in built-in geolocation data."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for cidr_str, geo_data in self.BUILTIN_GEO_DATA.items():
            cidr = ipaddress.ip_network(cidr_str)
            if ip_obj in cidr:
                return geo_data

        return None

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in RFC1918 or RFC4193 private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def is_bogon(self, ip: str) -> bool:
        """Check if IP is a bogon (invalid/reserved address)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.bogon_networks)
        except ValueError:
            return False

    def get_known_cloud_provider(self, ip: str) -> Optional[str]:
        """
        Identify known cloud provider from IP address.

        Args:
            ip: IP address to check.

        Returns:
            Cloud provider name (AWS, Azure, GCP, DigitalOcean) or None.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for provider, cidrs in self.cloud_cidrs.items():
            if any(ip_obj in cidr for cidr in cidrs):
                return provider

        return None

    def enrich_log_entry(self, log_fields: dict) -> dict:
        """
        Enrich log entry with GeoIP data for source and destination addresses.

        Args:
            log_fields: Dictionary of log fields.

        Returns:
            Dictionary with added geo_source and geo_destination keys.
        """
        enriched = log_fields.copy()

        # Enrich source address
        if "source_address" in log_fields:
            source_result = self.lookup(log_fields["source_address"])
            if source_result:
                enriched["geo_source"] = source_result.to_dict()

        # Enrich destination address
        if "destination_address" in log_fields:
            dest_result = self.lookup(log_fields["destination_address"])
            if dest_result:
                enriched["geo_destination"] = dest_result.to_dict()

        return enriched

    def batch_lookup(self, ips: List[str]) -> Dict[str, GeoIPResult]:
        """
        Perform batch lookups for multiple IP addresses.

        Args:
            ips: List of IP addresses to look up.

        Returns:
            Dictionary mapping IP to GeoIPResult.
        """
        results = {}
        for ip in ips:
            result = self.lookup(ip)
            if result:
                results[ip] = result

        return results

    def __del__(self):
        """Clean up MaxMind database connection."""
        if self.mmdb:
            try:
                self.mmdb.close()
            except Exception:
                pass


# Global singleton instance
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service(db_path: Optional[str] = None) -> GeoIPService:
    """Get or create global GeoIP service instance."""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService(db_path=db_path)
    return _geoip_service
