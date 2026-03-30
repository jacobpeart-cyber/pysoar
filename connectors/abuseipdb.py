"""AbuseIPDB API connector for IP reputation and abuse reporting"""

from typing import Any, Dict

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class AbuseIPDBConnector(BaseConnector):
    """AbuseIPDB connector for IP abuse checking and reporting"""

    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    def _get_headers(self) -> Dict[str, str]:
        """Add AbuseIPDB API key to headers"""
        headers = super()._get_headers()
        if api_key := self.credentials.get("api_key"):
            headers["Key"] = api_key
        headers["Accept"] = "application/json"
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute AbuseIPDB action"""
        actions = {
            "check_ip": self.check_ip,
            "report_ip": self.report_ip,
            "get_blacklist": self.get_blacklist,
            "check_block": self.check_block,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Check IP reputation - GET /check"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            data = await self._make_request(
                "GET",
                "/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                }
            )

            ip_data = data.get("data", {})
            return {
                "provider": self.name,
                "ip": ip,
                "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                "usage_type": ip_data.get("usageType"),
                "isp": ip_data.get("isp"),
                "domain": ip_data.get("domain"),
                "country_code": ip_data.get("countryCode"),
                "is_whitelisted": ip_data.get("isWhitelisted", False),
                "reports_count": ip_data.get("totalReports", 0),
                "last_reported": ip_data.get("lastReportedAt"),
                "reports": ip_data.get("reports", [])[:10],
            }
        except Exception as e:
            logger.error(f"AbuseIPDB check_ip error: {e}")
            return {"error": str(e), "ip": ip}

    async def report_ip(
        self,
        ip: str,
        categories: list,
        comment: str = ""
    ) -> Dict[str, Any]:
        """Report abusive IP - POST /report"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/report",
                params={
                    "ip": ip,
                    "category": ",".join(map(str, categories)),
                    "comment": comment,
                }
            )

            report_data = data.get("data", {})
            return {
                "provider": self.name,
                "ip": ip,
                "success": True,
                "abuse_confidence_score": report_data.get("abuseConfidenceScore"),
                "report_id": report_data.get("id"),
            }
        except Exception as e:
            logger.error(f"AbuseIPDB report_ip error: {e}")
            return {"error": str(e), "ip": ip}

    async def get_blacklist(self, limit: int = 10000) -> Dict[str, Any]:
        """Get blacklist - GET /blacklist"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            data = await self._make_request(
                "GET",
                "/blacklist",
                params={"limit": limit, "plaintext": True}
            )

            return {
                "provider": self.name,
                "blacklist_size": len(data.get("data", [])),
                "blacklist": data.get("data", [])[:100],
                "generated_at": data.get("meta", {}).get("generatedAt"),
            }
        except Exception as e:
            logger.error(f"AbuseIPDB get_blacklist error: {e}")
            return {"error": str(e)}

    async def check_block(self, cidr: str) -> Dict[str, Any]:
        """Check CIDR block - GET /check-block"""
        if not self.is_configured:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            data = await self._make_request(
                "GET",
                "/check-block",
                params={
                    "network": cidr,
                    "maxAgeInDays": 90,
                }
            )

            block_data = data.get("data", {})
            return {
                "provider": self.name,
                "cidr": cidr,
                "abuse_confidence_score": block_data.get("abuseConfidenceScore"),
                "total_reports": block_data.get("totalReports", 0),
                "num_unique_abusers": block_data.get("numUniqueAbusers", 0),
                "addresses_in_block": block_data.get("addressInBlockCount", 0),
            }
        except Exception as e:
            logger.error(f"AbuseIPDB check_block error: {e}")
            return {"error": str(e), "cidr": cidr}
