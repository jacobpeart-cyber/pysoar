"""Shodan API connector for internet-wide scanning and reconnaissance"""

from typing import Any, Dict

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class ShodanConnector(BaseConnector):
    """Shodan API connector for host lookup, search, and exploit discovery"""

    name = "shodan"
    base_url = "https://api.shodan.io"

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute Shodan action"""
        actions = {
            "host_lookup": self.host_lookup,
            "search": self.search,
            "dns_resolve": self.dns_resolve,
            "dns_reverse": self.dns_reverse,
            "exploits_search": self.exploits_search,
            "get_ports": self.get_ports,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def host_lookup(self, ip: str) -> Dict[str, Any]:
        """Lookup host - GET /shodan/host/{ip}"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        try:
            api_key = self.credentials.get("api_key")
            data = await self._make_request(
                "GET",
                f"/shodan/host/{ip}",
                params={"key": api_key}
            )

            ports = [p for p in data.get("ports", [])]
            vulns = data.get("vulns", [])
            os = data.get("os")
            org = data.get("org")
            banners = data.get("data", [])

            return {
                "provider": self.name,
                "ip": ip,
                "ports": ports,
                "vulnerabilities": vulns,
                "os": os,
                "organization": org,
                "banner_count": len(banners),
                "banners": [b.get("data") for b in banners[:5]],
                "last_update": data.get("last_update"),
            }
        except Exception as e:
            logger.error(f"Shodan host_lookup error: {e}")
            return {"error": str(e), "ip": ip}

    async def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search hosts - GET /shodan/host/search"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        try:
            api_key = self.credentials.get("api_key")
            data = await self._make_request(
                "GET",
                "/shodan/host/search",
                params={"key": api_key, "query": query, "limit": limit}
            )

            matches = data.get("matches", [])
            results = []
            for match in matches:
                results.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "os": match.get("os"),
                    "data": match.get("data"),
                })

            return {
                "provider": self.name,
                "query": query,
                "total": data.get("total", 0),
                "matches": results,
                "facets": data.get("facets", {}),
            }
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
            return {"error": str(e), "query": query}

    async def dns_resolve(self, hostnames: list) -> Dict[str, Any]:
        """Resolve hostnames - GET /dns/resolve"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        try:
            api_key = self.credentials.get("api_key")
            data = await self._make_request(
                "GET",
                "/dns/resolve",
                params={"key": api_key, "hostnames": ",".join(hostnames)}
            )

            return {
                "provider": self.name,
                "hostnames": hostnames,
                "mappings": data,
            }
        except Exception as e:
            logger.error(f"Shodan dns_resolve error: {e}")
            return {"error": str(e), "hostnames": hostnames}

    async def dns_reverse(self, ips: list) -> Dict[str, Any]:
        """Reverse DNS lookup - GET /dns/reverse"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        try:
            api_key = self.credentials.get("api_key")
            data = await self._make_request(
                "GET",
                "/dns/reverse",
                params={"key": api_key, "ips": ",".join(ips)}
            )

            return {
                "provider": self.name,
                "ips": ips,
                "hostnames": data,
            }
        except Exception as e:
            logger.error(f"Shodan dns_reverse error: {e}")
            return {"error": str(e), "ips": ips}

    async def exploits_search(self, query: str) -> Dict[str, Any]:
        """Search exploits - GET /api-ms/exploits/search"""
        if not self.is_configured:
            return {"error": "Shodan API key not configured"}

        try:
            api_key = self.credentials.get("api_key")
            data = await self._make_request(
                "GET",
                "/api-ms/exploits/search",
                params={"key": api_key, "query": query}
            )

            exploits = []
            for exploit in data.get("matches", []):
                exploits.append({
                    "id": exploit.get("_id"),
                    "title": exploit.get("title"),
                    "source": exploit.get("source"),
                    "url": exploit.get("url"),
                    "published": exploit.get("published"),
                })

            return {
                "provider": self.name,
                "query": query,
                "total": data.get("total", 0),
                "exploits": exploits,
            }
        except Exception as e:
            logger.error(f"Shodan exploits_search error: {e}")
            return {"error": str(e), "query": query}

    async def get_ports(self, ip: str) -> Dict[str, Any]:
        """Extract open ports from host lookup"""
        try:
            host_data = await self.host_lookup(ip)
            ports = host_data.get("ports", [])

            return {
                "provider": self.name,
                "ip": ip,
                "port_count": len(ports),
                "ports": sorted(ports),
            }
        except Exception as e:
            logger.error(f"Shodan get_ports error: {e}")
            return {"error": str(e), "ip": ip}
