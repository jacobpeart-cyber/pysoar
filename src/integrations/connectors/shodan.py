"""Shodan REST API connector (https://developer.shodan.io/api).

Authentication is the ``key`` query parameter on every request. The Exploits
API lives on its own host (https://exploits.shodan.io/api).
"""

from typing import Any, Dict, List

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)

logger = get_logger(__name__)

EXPLOITS_SEARCH_URL = "https://exploits.shodan.io/api/search"


class ShodanConnector(BaseConnector):
    """Shodan API connector for host lookup, search, and exploit discovery"""

    name = "shodan"
    base_url = "https://api.shodan.io"

    CREDENTIAL_FIELDS = [
        field_spec("api_key", "API key", "Shodan API key (sent as the key query parameter)", secret=True),
    ]
    TEST_CALL = "GET /api-info"
    ACTIONS = {
        "host_lookup": ActionSpec(
            "All services Shodan has seen on an IP (GET /shodan/host/{ip}).",
            object_schema({"ip": {"type": "string", "minLength": 1}}, ["ip"]),
            "ports, vulns, os, org, up to 5 banners, last_update",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Host lookup",
        ),
        "search": ActionSpec(
            "Search Shodan with a query (GET /shodan/host/search); consumes query credits for filters and pages.",
            object_schema({
                "query": {"type": "string", "minLength": 1},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            }, ["query"]),
            "total and matches (ip, port, org, os, banner)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search",
        ),
        "dns_resolve": ActionSpec(
            "Resolve hostnames to IPs (GET /dns/resolve).",
            object_schema({"hostnames": {"type": "array", "items": {"type": "string"}, "minItems": 1}}, ["hostnames"]),
            "hostname -> IP mapping",
            idempotent=True, side_effect=False, action_type="enrich", display_name="DNS resolve",
        ),
        "dns_reverse": ActionSpec(
            "Reverse DNS for IPs (GET /dns/reverse).",
            object_schema({"ips": {"type": "array", "items": {"type": "string"}, "minItems": 1}}, ["ips"]),
            "IP -> hostnames mapping",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Reverse DNS",
        ),
        "exploits_search": ActionSpec(
            "Search the Shodan Exploits database (GET https://exploits.shodan.io/api/search).",
            object_schema({"query": {"type": "string", "minLength": 1}}, ["query"]),
            "total and exploits (id, description, source, cve, type, date)",
            idempotent=True, side_effect=False, action_type="query", display_name="Exploit search",
        ),
        "get_ports": ActionSpec(
            "Open ports Shodan has seen on an IP (from GET /shodan/host/{ip}).",
            object_schema({"ip": {"type": "string", "minLength": 1}}, ["ip"]),
            "sorted port list",
            idempotent=True, side_effect=False, action_type="enrich", display_name="Open ports",
        ),
    }

    def _key(self) -> Dict[str, str]:
        return {"key": str(self.credentials.get("api_key") or "")}

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(self.TEST_CALL, lambda: self._make_request("GET", "/api-info", params=self._key()))

    async def host_lookup(self, ip: str) -> Dict[str, Any]:
        """Lookup host - GET /shodan/host/{ip}"""
        data = await self._make_request("GET", f"/shodan/host/{path_segment(ip)}", params=self._key())
        banners = data.get("data") or []
        return {
            "provider": self.name,
            "ip": ip,
            "ports": list(data.get("ports") or []),
            "vulnerabilities": data.get("vulns", []),
            "os": data.get("os"),
            "organization": data.get("org"),
            "banner_count": len(banners),
            "banners": [b.get("data") for b in banners[:5] if isinstance(b, dict)],
            "last_update": data.get("last_update"),
        }

    async def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search hosts - GET /shodan/host/search (the API pages 100 results; ``limit`` trims locally)"""
        data = await self._make_request("GET", "/shodan/host/search", params={**self._key(), "query": query})
        results = []
        for match in (data.get("matches") or [])[:limit]:
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

    async def dns_resolve(self, hostnames: List[str]) -> Dict[str, Any]:
        """Resolve hostnames - GET /dns/resolve?hostnames=a,b"""
        data = await self._make_request(
            "GET", "/dns/resolve", params={**self._key(), "hostnames": ",".join(hostnames)},
        )
        return {"provider": self.name, "hostnames": hostnames, "mappings": data}

    async def dns_reverse(self, ips: List[str]) -> Dict[str, Any]:
        """Reverse DNS lookup - GET /dns/reverse?ips=a,b"""
        data = await self._make_request("GET", "/dns/reverse", params={**self._key(), "ips": ",".join(ips)})
        return {"provider": self.name, "ips": ips, "hostnames": data}

    async def exploits_search(self, query: str) -> Dict[str, Any]:
        """Search exploits - GET https://exploits.shodan.io/api/search"""
        data = await self._make_request("GET", EXPLOITS_SEARCH_URL, params={**self._key(), "query": query})
        exploits = []
        for exploit in data.get("matches") or []:
            exploits.append({
                "id": exploit.get("_id"),
                "description": exploit.get("description"),
                "source": exploit.get("source"),
                "cve": exploit.get("cve", []),
                "type": exploit.get("type"),
                "date": exploit.get("date"),
            })
        return {"provider": self.name, "query": query, "total": data.get("total", 0), "exploits": exploits}

    async def get_ports(self, ip: str) -> Dict[str, Any]:
        """Open ports from the host lookup"""
        host_data = await self.host_lookup(ip)
        ports = [p for p in host_data.get("ports", []) if isinstance(p, int)]
        return {"provider": self.name, "ip": ip, "port_count": len(ports), "ports": sorted(ports)}
