"""VirusTotal API v3 connector (https://docs.virustotal.com/reference/overview).

Authentication is the ``x-apikey`` header on every request.
"""

import base64
from typing import Any, Dict

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
)
from src.integrations.connectors.base import (
    path_segment as _segment,
)

logger = get_logger(__name__)

_HASH = {"type": "string", "minLength": 1, "description": "MD5, SHA-1 or SHA-256 of the file"}


class VirusTotalConnector(BaseConnector):
    """VirusTotal API connector for file, URL, IP, and domain reports"""

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    CREDENTIAL_FIELDS = [
        field_spec("api_key", "API key", "VirusTotal API key (sent as the x-apikey header)", secret=True),
    ]
    TEST_CALL = "GET /api/v3/ip_addresses/8.8.8.8"
    ACTIONS = {
        "scan_file": ActionSpec(
            "Look up the existing VirusTotal report for a file hash (GET /files/{id}); does not upload a file.",
            object_schema({"file_hash": _HASH}, ["file_hash"]),
            "last_analysis_stats counts, type, size, names, tags",
            idempotent=True, side_effect=False, action_type="enrich", display_name="File hash report",
        ),
        "scan_url": ActionSpec(
            "Look up the existing VirusTotal report for a URL (GET /urls/{id}); does not submit the URL for analysis.",
            object_schema({"url": {"type": "string", "minLength": 1}}, ["url"]),
            "reputation, last_analysis_stats counts, categories, tags",
            idempotent=True, side_effect=False, action_type="enrich", display_name="URL report",
        ),
        "scan_ip": ActionSpec(
            "IP address report (GET /ip_addresses/{ip}).",
            object_schema({"ip": {"type": "string", "minLength": 1}}, ["ip"]),
            "reputation, last_analysis_stats counts, country, ASN, network, tags",
            idempotent=True, side_effect=False, action_type="enrich", display_name="IP report",
        ),
        "scan_domain": ActionSpec(
            "Domain report with its subdomains relationship (GET /domains/{domain}?relationships=subdomains).",
            object_schema({"domain": {"type": "string", "minLength": 1}}, ["domain"]),
            "reputation, last_analysis_stats counts, registrar, categories, subdomains",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Domain report",
        ),
        "get_behavior": ActionSpec(
            "Sandbox behaviour reports for a file (GET /files/{id}/behaviours).",
            object_schema({"file_hash": _HASH}, ["file_hash"]),
            "per-sandbox name, verdicts and tags",
            idempotent=True, side_effect=False, action_type="enrich", display_name="File behaviour",
        ),
    }

    def _get_headers(self) -> Dict[str, str]:
        """Add VirusTotal API key to headers"""
        headers = super()._get_headers()
        if api_key := self.credentials.get("api_key"):
            headers["x-apikey"] = api_key
        return headers

    async def test_connection(self) -> ConnectionTestResult:
        # A read of a public IP's report needs a valid key and consumes one
        # request of quota; /users/{id} would put the key in the URL path.
        return await self._probe(self.TEST_CALL, lambda: self._make_request("GET", "/ip_addresses/8.8.8.8"))

    @staticmethod
    def _stats(attributes: Dict[str, Any]) -> Dict[str, int]:
        return attributes.get("last_analysis_stats") or {}

    async def scan_file(self, file_hash: str) -> Dict[str, Any]:
        """File report - GET /files/{id}"""
        data = await self._make_request("GET", f"/files/{_segment(file_hash)}")
        attributes = (data.get("data") or {}).get("attributes") or {}
        stats = self._stats(attributes)
        return {
            "provider": self.name,
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            # Engines that returned any verdict category.
            "vendors": sum(v for v in stats.values() if isinstance(v, int)),
            "score": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "names": attributes.get("names", []),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """URL report - GET /urls/{url_id}, url_id = unpadded urlsafe base64 of the URL"""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = await self._make_request("GET", f"/urls/{url_id}")
        attributes = (data.get("data") or {}).get("attributes") or {}
        stats = self._stats(attributes)
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

    async def scan_ip(self, ip: str) -> Dict[str, Any]:
        """IP report - GET /ip_addresses/{ip}"""
        data = await self._make_request("GET", f"/ip_addresses/{_segment(ip)}")
        attributes = (data.get("data") or {}).get("attributes") or {}
        stats = self._stats(attributes)
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

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Domain report - GET /domains/{domain}; relationships are only returned when requested"""
        data = await self._make_request(
            "GET", f"/domains/{_segment(domain)}", params={"relationships": "subdomains"},
        )
        obj = data.get("data") or {}
        attributes = obj.get("attributes") or {}
        stats = self._stats(attributes)
        subdomains_rel = (obj.get("relationships") or {}).get("subdomains") or {}
        subdomains = [s.get("id") for s in subdomains_rel.get("data") or [] if isinstance(s, dict)]
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

    async def get_behavior(self, file_hash: str) -> Dict[str, Any]:
        """File behaviour reports - GET /files/{id}/behaviours"""
        data = await self._make_request("GET", f"/files/{_segment(file_hash)}/behaviours")
        behaviors = []
        for behavior in data.get("data") or []:
            attributes = behavior.get("attributes") or {}
            behaviors.append({
                "sandbox": attributes.get("sandbox_name"),
                "verdicts": attributes.get("verdicts", []),
                "tags": attributes.get("tags", []),
            })
        return {
            "provider": self.name,
            "hash": file_hash,
            "behavior_count": len(behaviors),
            "behaviors": behaviors,
        }

