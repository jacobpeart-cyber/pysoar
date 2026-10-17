"""AbuseIPDB API v2 connector (https://docs.abuseipdb.com/).

Authentication is the ``Key`` header; responses are JSON with
``Accept: application/json``.
"""

from typing import Any, Dict, List

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
)

logger = get_logger(__name__)


class AbuseIPDBConnector(BaseConnector):
    """AbuseIPDB connector for IP abuse checking and reporting"""

    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    CREDENTIAL_FIELDS = [
        field_spec("api_key", "API key", "AbuseIPDB API key (sent as the Key header)", secret=True),
    ]
    TEST_CALL = "GET /api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1"
    ACTIONS = {
        "check_ip": ActionSpec(
            "Abuse reputation of one IP (GET /check).",
            object_schema({
                "ip": {"type": "string", "minLength": 1},
                "max_age_days": {"type": "integer", "minimum": 1, "maximum": 365},
            }, ["ip"]),
            "abuseConfidenceScore, usage type, ISP, country, report count, last 10 reports",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Check IP",
        ),
        "report_ip": ActionSpec(
            "Report an abusive IP to AbuseIPDB (POST /report); the report is public and attributed to the key owner.",
            object_schema({
                "ip": {"type": "string", "minLength": 1},
                "categories": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
                "comment": {"type": "string"},
            }, ["ip", "categories"]),
            "ipAddress and updated abuseConfidenceScore",
            idempotent=False, side_effect=True, action_type="create", display_name="Report IP",
        ),
        "get_blacklist": ActionSpec(
            "The AbuseIPDB blacklist (GET /blacklist).",
            object_schema({
                "limit": {"type": "integer", "minimum": 1, "maximum": 500000},
                "confidence_minimum": {"type": "integer", "minimum": 25, "maximum": 100},
            }),
            "list size, first 100 entries, generatedAt",
            idempotent=True, side_effect=False, action_type="query", display_name="Blacklist",
        ),
        "check_block": ActionSpec(
            "Reported addresses inside a CIDR block (GET /check-block).",
            object_schema({
                "cidr": {"type": "string", "minLength": 1},
                "max_age_days": {"type": "integer", "minimum": 1, "maximum": 365},
            }, ["cidr"]),
            "network address, netmask, possible hosts, reported addresses",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Check CIDR block",
        ),
    }

    def _get_headers(self) -> Dict[str, str]:
        """Add AbuseIPDB API key to headers"""
        headers = super()._get_headers()
        if api_key := self.credentials.get("api_key"):
            headers["Key"] = api_key
        headers["Accept"] = "application/json"
        return headers

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(
            self.TEST_CALL,
            lambda: self._make_request("GET", "/check", params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1}),
        )

    async def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Check IP reputation - GET /check (``verbose`` adds the reports list)"""
        data = await self._make_request(
            "GET", "/check", params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": "true"},
        )
        ip_data = data.get("data") or {}
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
            "reports": (ip_data.get("reports") or [])[:10],
        }

    async def report_ip(self, ip: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
        """Report abusive IP - POST /report with form fields ip, categories (comma-separated), comment"""
        form = {"ip": ip, "categories": ",".join(str(c) for c in categories)}
        if comment:
            form["comment"] = comment
        data = await self._make_request("POST", "/report", form_data=form)
        report_data = data.get("data") or {}
        return {
            "provider": self.name,
            "ip": report_data.get("ipAddress", ip),
            "success": True,
            "abuse_confidence_score": report_data.get("abuseConfidenceScore"),
        }

    async def get_blacklist(self, limit: int = 10000, confidence_minimum: int = 100) -> Dict[str, Any]:
        """Get blacklist - GET /blacklist (JSON form; plaintext would not decode)"""
        data = await self._make_request(
            "GET", "/blacklist", params={"limit": limit, "confidenceMinimum": confidence_minimum},
        )
        entries = data.get("data") or []
        return {
            "provider": self.name,
            "blacklist_size": len(entries),
            "blacklist": entries[:100],
            "generated_at": (data.get("meta") or {}).get("generatedAt"),
        }

    async def check_block(self, cidr: str, max_age_days: int = 30) -> Dict[str, Any]:
        """Check CIDR block - GET /check-block"""
        data = await self._make_request(
            "GET", "/check-block", params={"network": cidr, "maxAgeInDays": max_age_days},
        )
        block = data.get("data") or {}
        reported = block.get("reportedAddress") or []
        return {
            "provider": self.name,
            "cidr": cidr,
            "network_address": block.get("networkAddress"),
            "netmask": block.get("netmask"),
            "num_possible_hosts": block.get("numPossibleHosts"),
            "reported_address_count": len(reported),
            "reported_addresses": reported[:100],
        }
