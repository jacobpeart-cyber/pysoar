"""CrowdStrike Falcon API connector for endpoint detection and response"""

import time
from typing import Any, Dict, Optional

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class CrowdStrikeConnector(BaseConnector):
    """CrowdStrike Falcon API connector for EDR and threat hunting"""

    name = "crowdstrike"
    base_url = "https://api.crowdstrike.com"
    _token: Optional[str] = None
    _token_expiry: float = 0

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute CrowdStrike action"""
        actions = {
            "search_detections": self.search_detections,
            "get_device": self.get_device,
            "search_hosts": self.search_hosts,
            "contain_host": self.contain_host,
            "lift_containment": self.lift_containment,
            "get_indicators": self.get_indicators,
            "search_incidents": self.search_incidents,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def _get_oauth_token(self) -> str:
        """Get OAuth2 bearer token - POST /oauth2/token"""
        if self._token and time.time() < self._token_expiry:
            return self._token

        try:
            client_id = self.credentials.get("client_id")
            client_secret = self.credentials.get("client_secret")

            data = await self._make_request(
                "POST",
                "/oauth2/token",
                json_data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            )

            self._token = data.get("access_token")
            expires_in = data.get("expires_in", 1800)
            self._token_expiry = time.time() + expires_in - 60

            return self._token
        except Exception as e:
            logger.error(f"CrowdStrike OAuth2 error: {e}")
            raise

    def _get_headers(self) -> Dict[str, str]:
        """Add bearer token to headers"""
        headers = super()._get_headers()
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def search_detections(self, filter_query: str = "", limit: int = 50) -> Dict[str, Any]:
        """Search detections - GET /detects/queries/detects/v1"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            # Search for detections
            query_data = await self._make_request(
                "GET",
                "/detects/queries/detects/v1",
                params={
                    "filter": filter_query or "status:'new'",
                    "limit": limit,
                },
                headers=headers
            )

            detection_ids = query_data.get("resources", [])

            # Get detection details
            detections = []
            if detection_ids:
                detail_data = await self._make_request(
                    "POST",
                    "/detects/entities/summaries/GET/v1",
                    json_data={"ids": detection_ids},
                    headers=headers
                )

                for det in detail_data.get("resources", []):
                    detections.append({
                        "id": det.get("detection_id"),
                        "type": det.get("detection_type"),
                        "status": det.get("status"),
                        "device_id": det.get("device_id"),
                        "created": det.get("created_timestamp"),
                    })

            return {
                "provider": self.name,
                "detection_count": len(detections),
                "detections": detections,
            }
        except Exception as e:
            logger.error(f"CrowdStrike search_detections error: {e}")
            return {"error": str(e)}

    async def get_device(self, device_id: str) -> Dict[str, Any]:
        """Get device details - GET /devices/entities/devices/v2"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "GET",
                "/devices/entities/devices/v2",
                params={"ids": device_id},
                headers=headers
            )

            device = data.get("resources", [{}])[0]
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
        except Exception as e:
            logger.error(f"CrowdStrike get_device error: {e}")
            return {"error": str(e), "device_id": device_id}

    async def search_hosts(self, filter_query: str = "", limit: int = 100) -> Dict[str, Any]:
        """Search hosts - GET /devices/queries/devices-scroll/v1"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "GET",
                "/devices/queries/devices-scroll/v1",
                params={
                    "filter": filter_query or "status:'normal'",
                    "limit": limit,
                },
                headers=headers
            )

            host_ids = data.get("resources", [])
            return {
                "provider": self.name,
                "host_count": len(host_ids),
                "hosts": host_ids,
                "pagination": data.get("pagination", {}),
            }
        except Exception as e:
            logger.error(f"CrowdStrike search_hosts error: {e}")
            return {"error": str(e)}

    async def contain_host(self, device_id: str) -> Dict[str, Any]:
        """Contain host - POST /devices/entities/devices-actions/v2"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "POST",
                "/devices/entities/devices-actions/v2",
                params={"action_name": "contain"},
                json_data={"ids": [device_id]},
                headers=headers
            )

            return {
                "provider": self.name,
                "action": "contain",
                "device_id": device_id,
                "success": not data.get("errors"),
                "errors": data.get("errors", []),
            }
        except Exception as e:
            logger.error(f"CrowdStrike contain_host error: {e}")
            return {"error": str(e), "device_id": device_id}

    async def lift_containment(self, device_id: str) -> Dict[str, Any]:
        """Lift containment - POST with action_name=lift_containment"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "POST",
                "/devices/entities/devices-actions/v2",
                params={"action_name": "lift_containment"},
                json_data={"ids": [device_id]},
                headers=headers
            )

            return {
                "provider": self.name,
                "action": "lift_containment",
                "device_id": device_id,
                "success": not data.get("errors"),
                "errors": data.get("errors", []),
            }
        except Exception as e:
            logger.error(f"CrowdStrike lift_containment error: {e}")
            return {"error": str(e), "device_id": device_id}

    async def get_indicators(self, filter_query: str = "", limit: int = 100) -> Dict[str, Any]:
        """Get indicators - GET /iocs/combined/indicator/v1"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "GET",
                "/iocs/combined/indicator/v1",
                params={
                    "filter": filter_query,
                    "limit": limit,
                },
                headers=headers
            )

            indicators = []
            for ioc in data.get("resources", []):
                indicators.append({
                    "id": ioc.get("id"),
                    "type": ioc.get("type"),
                    "value": ioc.get("value"),
                    "severity": ioc.get("severity"),
                    "created": ioc.get("created_timestamp"),
                })

            return {
                "provider": self.name,
                "indicator_count": len(indicators),
                "indicators": indicators,
            }
        except Exception as e:
            logger.error(f"CrowdStrike get_indicators error: {e}")
            return {"error": str(e)}

    async def search_incidents(self, filter_query: str = "", limit: int = 50) -> Dict[str, Any]:
        """Search incidents - GET /incidents/queries/incidents/v1"""
        if not self.is_configured:
            return {"error": "CrowdStrike credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            data = await self._make_request(
                "GET",
                "/incidents/queries/incidents/v1",
                params={
                    "filter": filter_query,
                    "limit": limit,
                },
                headers=headers
            )

            incident_ids = data.get("resources", [])
            return {
                "provider": self.name,
                "incident_count": len(incident_ids),
                "incidents": incident_ids,
            }
        except Exception as e:
            logger.error(f"CrowdStrike search_incidents error: {e}")
            return {"error": str(e)}
