"""VirusTotal integration for threat intelligence"""

from typing import Any

from src.core.config import settings
from src.integrations.base import ThreatIntelProvider


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal threat intelligence provider"""

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"
    rate_limit = 4  # Free tier: 4 requests per minute

    def __init__(self):
        super().__init__(api_key=settings.virustotal_api_key)

    def _get_headers(self) -> dict[str, str]:
        headers = super()._get_headers()
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP address in VirusTotal"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        data = await self._make_request("GET", f"/ip_addresses/{ip}")

        # Parse response
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "provider": self.name,
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "network": attributes.get("network"),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Lookup domain in VirusTotal"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        data = await self._make_request("GET", f"/domains/{domain}")

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "provider": self.name,
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """Lookup file hash in VirusTotal"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        data = await self._make_request("GET", f"/files/{file_hash}")

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "provider": self.name,
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "type_unsupported": stats.get("type-unsupported", 0),
            "file_type": attributes.get("type_description"),
            "file_name": attributes.get("meaningful_name"),
            "file_size": attributes.get("size"),
            "sha256": attributes.get("sha256"),
            "sha1": attributes.get("sha1"),
            "md5": attributes.get("md5"),
            "tags": attributes.get("tags", []),
            "names": attributes.get("names", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    async def lookup_url(self, url: str) -> dict[str, Any]:
        """Lookup URL in VirusTotal"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        import base64

        # URL needs to be base64 encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        data = await self._make_request("GET", f"/urls/{url_id}")

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "provider": self.name,
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "final_url": attributes.get("last_final_url"),
            "title": attributes.get("title"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
