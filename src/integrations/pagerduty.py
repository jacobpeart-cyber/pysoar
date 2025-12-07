"""PagerDuty integration for incident management"""

import logging
from typing import Any, Optional

import httpx

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class PagerDutyIntegration(BaseIntegration):
    """PagerDuty integration for incident alerting"""

    name = "pagerduty"
    display_name = "PagerDuty"
    description = "Create and manage incidents in PagerDuty"

    EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
    REST_API_URL = "https://api.pagerduty.com"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.routing_key = config.get("routing_key", "")
        self.api_key = config.get("api_key", "")
        self.service_id = config.get("service_id", "")

    async def test_connection(self) -> bool:
        """Test the PagerDuty connection"""
        if self.api_key:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{self.REST_API_URL}/services/{self.service_id}",
                        headers={
                            "Authorization": f"Token token={self.api_key}",
                            "Content-Type": "application/json",
                        },
                        timeout=10.0,
                    )
                    return response.status_code == 200
            except Exception as e:
                logger.error(f"PagerDuty connection test failed: {e}")
                return False
        return bool(self.routing_key)

    async def trigger_alert(
        self,
        title: str,
        severity: str,
        description: Optional[str] = None,
        dedup_key: Optional[str] = None,
        source: str = "PySOAR",
        custom_details: Optional[dict] = None,
    ) -> Optional[str]:
        """Trigger a PagerDuty alert"""
        pd_severity = self._map_severity(severity)

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": pd_severity,
                "source": source,
                "custom_details": custom_details or {},
            },
        }

        if dedup_key:
            payload["dedup_key"] = dedup_key

        if description:
            payload["payload"]["custom_details"]["description"] = description

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload,
                    timeout=10.0,
                )

                if response.status_code == 202:
                    data = response.json()
                    logger.info(f"PagerDuty alert triggered: {data.get('dedup_key')}")
                    return data.get("dedup_key")
                else:
                    logger.error(f"PagerDuty API error: {response.status_code} - {response.text}")
                    return None
        except Exception as e:
            logger.error(f"Failed to trigger PagerDuty alert: {e}")
            return None

    async def acknowledge_alert(self, dedup_key: str) -> bool:
        """Acknowledge a PagerDuty alert"""
        payload = {
            "routing_key": self.routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload,
                    timeout=10.0,
                )
                success = response.status_code == 202
                if success:
                    logger.info(f"PagerDuty alert acknowledged: {dedup_key}")
                return success
        except Exception as e:
            logger.error(f"Failed to acknowledge PagerDuty alert: {e}")
            return False

    async def resolve_alert(self, dedup_key: str) -> bool:
        """Resolve a PagerDuty alert"""
        payload = {
            "routing_key": self.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload,
                    timeout=10.0,
                )
                success = response.status_code == 202
                if success:
                    logger.info(f"PagerDuty alert resolved: {dedup_key}")
                return success
        except Exception as e:
            logger.error(f"Failed to resolve PagerDuty alert: {e}")
            return False

    async def create_incident(
        self,
        title: str,
        urgency: str = "high",
        body: Optional[str] = None,
        escalation_policy_id: Optional[str] = None,
    ) -> Optional[str]:
        """Create a PagerDuty incident via REST API"""
        if not self.api_key or not self.service_id:
            logger.error("API key and service ID required for REST API")
            return None

        payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": self.service_id, "type": "service_reference"},
                "urgency": urgency,
            }
        }

        if body:
            payload["incident"]["body"] = {"type": "incident_body", "details": body}

        if escalation_policy_id:
            payload["incident"]["escalation_policy"] = {
                "id": escalation_policy_id,
                "type": "escalation_policy_reference",
            }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.REST_API_URL}/incidents",
                    json=payload,
                    headers={
                        "Authorization": f"Token token={self.api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=10.0,
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    incident_id = data.get("incident", {}).get("id")
                    logger.info(f"PagerDuty incident created: {incident_id}")
                    return incident_id
                else:
                    logger.error(f"PagerDuty API error: {response.status_code} - {response.text}")
                    return None
        except Exception as e:
            logger.error(f"Failed to create PagerDuty incident: {e}")
            return None

    async def get_incident(self, incident_id: str) -> Optional[dict]:
        """Get PagerDuty incident details"""
        if not self.api_key:
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.REST_API_URL}/incidents/{incident_id}",
                    headers={
                        "Authorization": f"Token token={self.api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    return response.json().get("incident")
                return None
        except Exception as e:
            logger.error(f"Failed to get PagerDuty incident: {e}")
            return None

    async def list_oncall(self, escalation_policy_id: Optional[str] = None) -> list:
        """List on-call users"""
        if not self.api_key:
            return []

        params = {}
        if escalation_policy_id:
            params["escalation_policy_ids[]"] = escalation_policy_id

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.REST_API_URL}/oncalls",
                    params=params,
                    headers={
                        "Authorization": f"Token token={self.api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    return response.json().get("oncalls", [])
                return []
        except Exception as e:
            logger.error(f"Failed to list on-call users: {e}")
            return []

    def _map_severity(self, severity: str) -> str:
        """Map PySOAR severity to PagerDuty severity"""
        mapping = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }
        return mapping.get(severity.lower(), "warning")
