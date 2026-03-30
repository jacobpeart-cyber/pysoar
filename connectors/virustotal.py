"""VirusTotal API connector for threat intelligence"""

import base64
from typing import Any, Dict, Optional

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class VirusTotalConnector(BaseConnector):
    """VirusTotal API connector for file, URL, IP, and domain scanning"""

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def _get_headers(self) -> Dict[str, str]:
        """Add VirusTotal API key to headers"""
        headers = super()._get_headers()
        if api_key := self.credentials.get("api_key"):
            headers["x-apikey"] = api_key
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute VirusTotal action"""
        actions = {
            "scan_file": self.scan_file,
            "scan_url": self.scan_url,
            "scan_ip": self.scan_ip,
            "scan_domain": self.scan_domain,
            "get_behavior": self.get_behavior,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def scan_file(self, file_hash: str) -> Dict[str, Any]:
        """Scan file hash - GET /files/{hash}"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        try:
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
                "vendors": len(stats),
                "score": sum([stats.get("malicious", 0), stats.get("suspicious", 0)]),
                "file_type": attributes.get("type_description"),
                "file_size": attributes.get("size"),
                "names": attributes.get("names", []),
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
        except Exception as e:
            logger.error(f"VirusTotal scan_file error: {e}")
            return {"error": str(e), "hash": file_hash}

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL - POST /urls then GET analysis"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            data = await self._make_request("GET", f"/urls/{url_id}")
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "provider": self.name,
                "url": url,
                "reputation": attributes.get("reputation", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attributes.get("categories", {}),
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
        except Exception as e:
            logger.error(f"VirusTotal scan_url error: {e}")
            return {"error": str(e), "url": url}

    async def scan_ip(self, ip: str) -> Dict[str, Any]:
        """Scan IP address - GET /ip_addresses/{ip}"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        try:
            data = await self._make_request("GET", f"/ip_addresses/{ip}")
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "provider": self.name,
                "ip": ip,
                "reputation": attributes.get("reputation", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
        except Exception as e:
            logger.error(f"VirusTotal scan_ip error: {e}")
            return {"error": str(e), "ip": ip}

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Scan domain - GET /domains/{domain}"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        try:
            data = await self._make_request("GET", f"/domains/{domain}")
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            # Get subdomains
            subdomains = []
            relationships = data.get("data", {}).get("relationships", {})
            if subdomains_rel := relationships.get("subdomains"):
                subdomains = [s.get("id") for s in subdomains_rel.get("data", [])]

            return {
                "provider": self.name,
                "domain": domain,
                "reputation": attributes.get("reputation", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "registrar": attributes.get("registrar"),
                "creation_date": attributes.get("creation_date"),
                "categories": attributes.get("categories", {}),
                "subdomains": subdomains,
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
        except Exception as e:
            logger.error(f"VirusTotal scan_domain error: {e}")
            return {"error": str(e), "domain": domain}

    async def get_behavior(self, file_hash: str) -> Dict[str, Any]:
        """Get file behavior - GET /files/{hash}/behaviours"""
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured"}

        try:
            data = await self._make_request("GET", f"/files/{file_hash}/behaviours")
            behaviors = []

            for behavior in data.get("data", []):
                attributes = behavior.get("attributes", {})
                behaviors.append({
                    "sandbox": attributes.get("sandbox_name"),
                    "behavior": attributes.get("behavior"),
                    "severity": attributes.get("severity"),
                })

            return {
                "provider": self.name,
                "hash": file_hash,
                "behavior_count": len(behaviors),
                "behaviors": behaviors,
            }
        except Exception as e:
            logger.error(f"VirusTotal get_behavior error: {e}")
            return {"error": str(e), "hash": file_hash}
