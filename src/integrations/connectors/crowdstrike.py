"""CrowdStrike Falcon API connector (Falcon API documentation, developer.crowdstrike.com).

Authentication: OAuth2 client credentials. ``POST /oauth2/token`` takes
``client_id`` and ``client_secret`` as an ``application/x-www-form-urlencoded``
body and answers 201 with ``access_token`` / ``expires_in``; every other call
carries ``Authorization: Bearer <token>``. The API host depends on the Falcon
cloud of the tenant (``cloud`` config field).
"""

import time
from typing import Any, Dict, Optional

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
)

logger = get_logger(__name__)

# Falcon cloud -> API host (Falcon "API clients and keys" documentation).
FALCON_CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

_FQL = {"type": "string", "description": "Falcon Query Language filter"}
_DEVICE_ID = {"type": "string", "minLength": 1, "description": "Falcon device (agent) id"}


class CrowdStrikeConnector(BaseConnector):
    """CrowdStrike Falcon API connector for EDR and threat hunting"""

    name = "crowdstrike"
    base_url = FALCON_CLOUDS["us-1"]
    _token: Optional[str] = None
    _token_expiry: float = 0

    CREDENTIAL_FIELDS = [
        field_spec("client_id", "Client ID", "Falcon API client id"),
        field_spec("client_secret", "Client secret", "Falcon API client secret", secret=True),
    ]
    CONFIG_FIELDS = [
        field_spec(
            "cloud", "Falcon cloud", f"Falcon cloud of the tenant: one of {', '.join(FALCON_CLOUDS)}",
            required=False, default="us-1",
        ),
    ]
    TEST_CALL = "POST /oauth2/token (client credentials)"
    ACTIONS = {
        "search_detections": ActionSpec(
            "Search Falcon alerts (Alerts API v2, the successor of the retired Detects API): "
            "GET /alerts/queries/alerts/v2 then POST /alerts/entities/alerts/v2.",
            object_schema({"filter_query": _FQL, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}}),
            "alert count and alerts (composite id, name, status, severity, device id, created)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search alerts",
        ),
        "get_device": ActionSpec(
            "Device details (GET /devices/entities/devices/v2).",
            object_schema({"device_id": _DEVICE_ID}, ["device_id"]),
            "hostname, platform, OS version, agent version, last seen, groups, tags",
            idempotent=True, side_effect=False, action_type="query", display_name="Get device",
        ),
        "search_hosts": ActionSpec(
            "Device ids matching an FQL filter (GET /devices/queries/devices-scroll/v1).",
            object_schema({"filter_query": _FQL, "limit": {"type": "integer", "minimum": 1, "maximum": 5000}}),
            "host count and device ids",
            idempotent=True, side_effect=False, action_type="query", display_name="Search hosts",
        ),
        "contain_host": ActionSpec(
            "Network-contain a host (POST /devices/entities/devices-actions/v2?action_name=contain).",
            object_schema({"device_id": _DEVICE_ID}, ["device_id"]),
            "success flag and vendor errors",
            idempotent=True, side_effect=True, action_type="contain", display_name="Contain host",
        ),
        "lift_containment": ActionSpec(
            "Lift network containment (POST /devices/entities/devices-actions/v2?action_name=lift_containment).",
            object_schema({"device_id": _DEVICE_ID}, ["device_id"]),
            "success flag and vendor errors",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Lift containment",
        ),
        "get_indicators": ActionSpec(
            "Custom IOCs (GET /iocs/combined/indicator/v1).",
            object_schema({"filter_query": _FQL, "limit": {"type": "integer", "minimum": 1, "maximum": 2000}}),
            "indicator count and indicators (id, type, value, severity, created)",
            idempotent=True, side_effect=False, action_type="query", display_name="Get indicators",
        ),
        "search_incidents": ActionSpec(
            "Incident ids matching an FQL filter (GET /incidents/queries/incidents/v1).",
            object_schema({"filter_query": _FQL, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}),
            "incident count and ids",
            idempotent=True, side_effect=False, action_type="query", display_name="Search incidents",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        cloud = str(self.config.get("cloud") or "us-1").strip().lower()
        if cloud not in FALCON_CLOUDS:
            raise ValueError(f"unknown Falcon cloud {cloud!r}; expected one of {sorted(FALCON_CLOUDS)}")
        self.base_url = FALCON_CLOUDS[cloud]

    async def _get_oauth_token(self) -> str:
        """OAuth2 client credentials - POST /oauth2/token (form-encoded)"""
        if self._token and time.time() < self._token_expiry:
            return self._token
        data = await self._make_request(
            "POST",
            "/oauth2/token",
            form_data={
                "client_id": str(self.credentials.get("client_id") or ""),
                "client_secret": str(self.credentials.get("client_secret") or ""),
            },
            auth=False,
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise ValueError("token response carried no access_token")
        self._token = token
        self._token_expiry = time.time() + int(data.get("expires_in", 1800)) - 60
        return token

    def _get_headers(self) -> Dict[str, str]:
        """Add bearer token to headers"""
        headers = super()._get_headers()
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _api(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        await self._get_oauth_token()
        return await self._make_request(method, endpoint, **kwargs)

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(self.TEST_CALL, self._get_oauth_token)

    @staticmethod
    def _query(filter_query: str, limit: int) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit}
        if filter_query:
            params["filter"] = filter_query
        return params

    async def search_detections(self, filter_query: str = "", limit: int = 50) -> Dict[str, Any]:
        """Alerts v2 - GET /alerts/queries/alerts/v2, POST /alerts/entities/alerts/v2"""
        query_data = await self._api(
            "GET", "/alerts/queries/alerts/v2", params=self._query(filter_query or "status:'new'", limit),
        )
        ids = query_data.get("resources") or []
        alerts = []
        if ids:
            detail = await self._api("POST", "/alerts/entities/alerts/v2", json_data={"composite_ids": ids})
            for alert in detail.get("resources") or []:
                alerts.append({
                    "id": alert.get("composite_id"),
                    "name": alert.get("name") or alert.get("display_name"),
                    "status": alert.get("status"),
                    "severity": alert.get("severity_name") or alert.get("severity"),
                    "device_id": (alert.get("device") or {}).get("device_id"),
                    "created": alert.get("created_timestamp"),
                })
        return {"provider": self.name, "detection_count": len(alerts), "detections": alerts}

    async def get_device(self, device_id: str) -> Dict[str, Any]:
        """Device details - GET /devices/entities/devices/v2?ids=<id>"""
        data = await self._api("GET", "/devices/entities/devices/v2", params={"ids": device_id})
        resources = data.get("resources") or []
        if not resources:
            return {"error": f"device {device_id} not found", "http_status": 404, "device_id": device_id}
        device = resources[0]
        return {
            "provider": self.name,
            "device_id": device_id,
            "hostname": device.get("hostname"),
            "os": device.get("platform_name"),
            "os_version": device.get("os_version"),
            "agent_version": device.get("agent_version"),
            "last_seen": device.get("last_seen"),
            "groups": device.get("groups", []),
            "tags": device.get("tags", []),
        }

    async def search_hosts(self, filter_query: str = "", limit: int = 100) -> Dict[str, Any]:
        """Search hosts - GET /devices/queries/devices-scroll/v1"""
        data = await self._api(
            "GET", "/devices/queries/devices-scroll/v1", params=self._query(filter_query or "status:'normal'", limit),
        )
        host_ids = data.get("resources") or []
        return {
            "provider": self.name,
            "host_count": len(host_ids),
            "hosts": host_ids,
            "pagination": (data.get("meta") or {}).get("pagination", {}),
        }

    async def _device_action(self, action_name: str, device_id: str) -> Dict[str, Any]:
        data = await self._api(
            "POST",
            "/devices/entities/devices-actions/v2",
            params={"action_name": action_name},
            json_data={"ids": [device_id]},
        )
        errors = data.get("errors") or []
        return {
            "provider": self.name,
            "action": action_name,
            "device_id": device_id,
            "success": not errors,
            "errors": errors,
        }

    async def contain_host(self, device_id: str) -> Dict[str, Any]:
        """Contain host - POST /devices/entities/devices-actions/v2?action_name=contain"""
        return await self._device_action("contain", device_id)

    async def lift_containment(self, device_id: str) -> Dict[str, Any]:
        """Lift containment - POST /devices/entities/devices-actions/v2?action_name=lift_containment"""
        return await self._device_action("lift_containment", device_id)

    async def get_indicators(self, filter_query: str = "", limit: int = 100) -> Dict[str, Any]:
        """Custom IOCs - GET /iocs/combined/indicator/v1"""
        data = await self._api("GET", "/iocs/combined/indicator/v1", params=self._query(filter_query, limit))
        indicators = [
            {
                "id": ioc.get("id"),
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "severity": ioc.get("severity"),
                "created": ioc.get("created_on") or ioc.get("created_timestamp"),
            }
            for ioc in data.get("resources") or []
        ]
        return {"provider": self.name, "indicator_count": len(indicators), "indicators": indicators}

    async def search_incidents(self, filter_query: str = "", limit: int = 50) -> Dict[str, Any]:
        """Incident ids - GET /incidents/queries/incidents/v1"""
        data = await self._api("GET", "/incidents/queries/incidents/v1", params=self._query(filter_query, limit))
        incident_ids = data.get("resources") or []
        return {"provider": self.name, "incident_count": len(incident_ids), "incidents": incident_ids}
