"""AbuseIPDB integration for IP reputation"""

from typing import Any

from src.core.config import settings
from src.integrations.base import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider"""

    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"
    rate_limit = 1000  # Free tier: 1000 requests per day

    def __init__(self):
        super().__init__(api_key=settings.abuseipdb_api_key)

    def _get_headers(self) -> dict[str, str]:
        headers = super()._get_headers()
        if self.api_key:
            headers["Key"] = self.api_key
        return headers

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP address in AbuseIPDB"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        data = await self._make_request(
            "GET",
            "/check",
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            },
        )

        result = data.get("data", {})

        return {
            "provider": self.name,
            "ip": ip,
            "is_public": result.get("isPublic"),
            "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
            "is_whitelisted": result.get("isWhitelisted"),
            "country_code": result.get("countryCode"),
            "usage_type": result.get("usageType"),
            "isp": result.get("isp"),
            "domain": result.get("domain"),
            "total_reports": result.get("totalReports", 0),
            "num_distinct_users": result.get("numDistinctUsers", 0),
            "last_reported_at": result.get("lastReportedAt"),
            "hostnames": result.get("hostnames", []),
        }

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """AbuseIPDB doesn't support domain lookup directly"""
        return {"error": "AbuseIPDB does not support domain lookup"}

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """AbuseIPDB doesn't support hash lookup"""
        return {"error": "AbuseIPDB does not support file hash lookup"}

    async def report_ip(
        self,
        ip: str,
        categories: list[int],
        comment: str = "",
    ) -> dict[str, Any]:
        """Report an IP address to AbuseIPDB"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        data = await self._make_request(
            "POST",
            "/report",
            json_data={
                "ip": ip,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment,
            },
        )

        result = data.get("data", {})

        return {
            "provider": self.name,
            "ip": ip,
            "abuse_confidence_score": result.get("abuseConfidenceScore"),
            "reported": True,
        }
