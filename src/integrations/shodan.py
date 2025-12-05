"""Shodan integration for network intelligence"""

from typing import Any

from src.core.config import settings
from src.integrations.base import ThreatIntelProvider


class ShodanProvider(ThreatIntelProvider):
    """Shodan threat intelligence provider"""

    name = "shodan"
    base_url = "https://api.shodan.io"
    rate_limit = 1  # Free tier: 1 request per second

    def __init__(self):
        super().__init__(api_key=settings.shodan_api_key)

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP address in Shodan"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        data = await self._make_request(
            "GET",
            f"/shodan/host/{ip}",
            params={"key": self.api_key},
        )

        return {
            "provider": self.name,
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "city": data.get("city"),
            "region_code": data.get("region_code"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
            "services": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "cpe": s.get("cpe", []),
                }
                for s in data.get("data", [])
            ],
        }

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Lookup domain in Shodan"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        data = await self._make_request(
            "GET",
            f"/dns/domain/{domain}",
            params={"key": self.api_key},
        )

        return {
            "provider": self.name,
            "domain": domain,
            "tags": data.get("tags", []),
            "subdomains": data.get("subdomains", []),
            "records": [
                {
                    "subdomain": r.get("subdomain"),
                    "type": r.get("type"),
                    "value": r.get("value"),
                    "last_seen": r.get("last_seen"),
                }
                for r in data.get("data", [])
            ],
        }

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """Shodan doesn't support hash lookup"""
        return {"error": "Shodan does not support file hash lookup"}

    async def search(self, query: str, limit: int = 100) -> dict[str, Any]:
        """Search Shodan"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        data = await self._make_request(
            "GET",
            "/shodan/host/search",
            params={
                "key": self.api_key,
                "query": query,
                "limit": limit,
            },
        )

        return {
            "provider": self.name,
            "query": query,
            "total": data.get("total", 0),
            "matches": [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "hostnames": m.get("hostnames", []),
                    "product": m.get("product"),
                    "version": m.get("version"),
                }
                for m in data.get("matches", [])
            ],
        }
