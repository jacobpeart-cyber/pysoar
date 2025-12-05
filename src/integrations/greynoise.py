"""GreyNoise integration for IP context"""

from typing import Any

from src.core.config import settings
from src.integrations.base import ThreatIntelProvider


class GreyNoiseProvider(ThreatIntelProvider):
    """GreyNoise threat intelligence provider"""

    name = "greynoise"
    base_url = "https://api.greynoise.io/v3"
    rate_limit = 50  # Community tier

    def __init__(self):
        super().__init__(api_key=settings.greynoise_api_key)

    def _get_headers(self) -> dict[str, str]:
        headers = super()._get_headers()
        if self.api_key:
            headers["key"] = self.api_key
        return headers

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP address in GreyNoise"""
        if not self.is_configured:
            return {"error": "GreyNoise API key not configured"}

        data = await self._make_request("GET", f"/community/{ip}")

        return {
            "provider": self.name,
            "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }

    async def lookup_ip_full(self, ip: str) -> dict[str, Any]:
        """Full IP context lookup (requires paid API)"""
        if not self.is_configured:
            return {"error": "GreyNoise API key not configured"}

        data = await self._make_request("GET", f"/v2/noise/context/{ip}")

        return {
            "provider": self.name,
            "ip": ip,
            "seen": data.get("seen", False),
            "classification": data.get("classification"),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "actor": data.get("actor"),
            "tags": data.get("tags", []),
            "cve": data.get("cve", []),
            "metadata": {
                "asn": data.get("metadata", {}).get("asn"),
                "city": data.get("metadata", {}).get("city"),
                "country": data.get("metadata", {}).get("country"),
                "country_code": data.get("metadata", {}).get("country_code"),
                "organization": data.get("metadata", {}).get("organization"),
                "os": data.get("metadata", {}).get("os"),
                "category": data.get("metadata", {}).get("category"),
                "tor": data.get("metadata", {}).get("tor"),
                "rdns": data.get("metadata", {}).get("rdns"),
            },
            "raw_data": data.get("raw_data", {}),
        }

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """GreyNoise doesn't support domain lookup"""
        return {"error": "GreyNoise does not support domain lookup"}

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """GreyNoise doesn't support hash lookup"""
        return {"error": "GreyNoise does not support file hash lookup"}

    async def check_riot(self, ip: str) -> dict[str, Any]:
        """Check if IP is in RIOT dataset (benign services)"""
        if not self.is_configured:
            return {"error": "GreyNoise API key not configured"}

        data = await self._make_request("GET", f"/v2/riot/{ip}")

        return {
            "provider": self.name,
            "ip": ip,
            "riot": data.get("riot", False),
            "name": data.get("name"),
            "description": data.get("description"),
            "category": data.get("category"),
            "explanation": data.get("explanation"),
            "reference": data.get("reference"),
            "trust_level": data.get("trust_level"),
            "last_updated": data.get("last_updated"),
        }
