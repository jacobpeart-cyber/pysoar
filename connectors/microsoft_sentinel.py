"""Microsoft Sentinel API connector for security logs and incident management"""

import time
from typing import Any, Dict, Optional

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class MicrosoftSentinelConnector(BaseConnector):
    """Microsoft Sentinel connector for KQL queries and incident management"""

    name = "microsoft_sentinel"
    base_url = "https://management.azure.com"
    _token: Optional[str] = None
    _token_expiry: float = 0

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute Microsoft Sentinel action"""
        actions = {
            "query_logs": self.query_logs,
            "list_incidents": self.list_incidents,
            "update_incident": self.update_incident,
            "list_alerts": self.list_alerts,
            "create_bookmark": self.create_bookmark,
            "run_playbook": self.run_playbook,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def _get_oauth_token(self) -> str:
        """Get Azure AD OAuth2 token"""
        if self._token and time.time() < self._token_expiry:
            return self._token

        try:
            tenant_id = self.credentials.get("tenant_id")
            client_id = self.credentials.get("client_id")
            client_secret = self.credentials.get("client_secret")

            login_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

            data = await self._make_request(
                "POST",
                login_url,
                params={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://management.azure.com/.default",
                }
            )

            self._token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)
            self._token_expiry = time.time() + expires_in - 60

            return self._token
        except Exception as e:
            logger.error(f"Microsoft Sentinel OAuth2 error: {e}")
            raise

    def _get_headers(self) -> Dict[str, str]:
        """Add bearer token to headers"""
        headers = super()._get_headers()
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def query_logs(
        self,
        query: str,
        timespan: str = "PT24H"
    ) -> Dict[str, Any]:
        """Query logs with KQL - POST to Log Analytics API"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            workspace_id = self.credentials.get("workspace_id")
            resource_group = self.credentials.get("resource_group")
            subscription_id = self.credentials.get("subscription_id")

            api_url = (
                f"{self.base_url}/subscriptions/{subscription_id}"
                f"/resourcegroups/{resource_group}"
                f"/providers/microsoft.operationalinsights/workspaces/{workspace_id}"
                f"/query"
            )

            data = await self._make_request(
                "POST",
                api_url,
                json_data={
                    "query": query,
                    "timespan": timespan,
                },
                headers=headers
            )

            results = []
            for table in data.get("tables", []):
                for row in table.get("rows", []):
                    results.append(row)

            return {
                "provider": self.name,
                "query": query,
                "timespan": timespan,
                "result_count": len(results),
                "results": results[:100],
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel query_logs error: {e}")
            return {"error": str(e)}

    async def list_incidents(self, filter_query: str = "") -> Dict[str, Any]:
        """List incidents - GET /providers/Microsoft.SecurityInsights/incidents"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            subscription_id = self.credentials.get("subscription_id")
            resource_group = self.credentials.get("resource_group")
            workspace_name = self.credentials.get("workspace_id")

            api_url = (
                f"{self.base_url}/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                f"/providers/Microsoft.SecurityInsights/incidents"
            )

            data = await self._make_request(
                "GET",
                api_url,
                params={"api-version": "2021-09-01-preview"},
                headers=headers
            )

            incidents = []
            for incident in data.get("value", []):
                properties = incident.get("properties", {})
                incidents.append({
                    "id": incident.get("id"),
                    "name": incident.get("name"),
                    "title": properties.get("title"),
                    "severity": properties.get("severity"),
                    "status": properties.get("status"),
                    "created": properties.get("createdTimeUtc"),
                    "modified": properties.get("lastModifiedTimeUtc"),
                })

            return {
                "provider": self.name,
                "incident_count": len(incidents),
                "incidents": incidents,
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel list_incidents error: {e}")
            return {"error": str(e)}

    async def update_incident(
        self,
        incident_id: str,
        data: Dict
    ) -> Dict[str, Any]:
        """Update incident - PUT incident"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            subscription_id = self.credentials.get("subscription_id")

            api_url = f"{self.base_url}{incident_id}"

            update_data = {
                "properties": {
                    "title": data.get("title"),
                    "description": data.get("description"),
                    "severity": data.get("severity"),
                    "status": data.get("status"),
                    "owner": data.get("owner"),
                }
            }

            await self._make_request(
                "PUT",
                api_url,
                json_data=update_data,
                headers=headers
            )

            return {
                "provider": self.name,
                "success": True,
                "incident_id": incident_id,
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel update_incident error: {e}")
            return {"error": str(e), "incident_id": incident_id}

    async def list_alerts(self, filter_query: str = "") -> Dict[str, Any]:
        """List alerts - GET /providers/Microsoft.SecurityInsights/alertRules"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            subscription_id = self.credentials.get("subscription_id")
            resource_group = self.credentials.get("resource_group")
            workspace_name = self.credentials.get("workspace_id")

            api_url = (
                f"{self.base_url}/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                f"/providers/Microsoft.SecurityInsights/alertRules"
            )

            data = await self._make_request(
                "GET",
                api_url,
                params={"api-version": "2021-09-01-preview"},
                headers=headers
            )

            alerts = []
            for alert in data.get("value", []):
                kind = alert.get("kind", "")
                properties = alert.get("properties", {})

                if kind == "Scheduled":
                    alerts.append({
                        "id": alert.get("id"),
                        "name": alert.get("name"),
                        "display_name": properties.get("displayName"),
                        "description": properties.get("description"),
                        "enabled": properties.get("enabled"),
                        "severity": properties.get("severity"),
                        "query": properties.get("query", "")[:100],
                    })

            return {
                "provider": self.name,
                "alert_count": len(alerts),
                "alerts": alerts,
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel list_alerts error: {e}")
            return {"error": str(e)}

    async def create_bookmark(self, data: Dict) -> Dict[str, Any]:
        """Create bookmark - POST bookmark"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            subscription_id = self.credentials.get("subscription_id")
            resource_group = self.credentials.get("resource_group")
            workspace_name = self.credentials.get("workspace_id")

            api_url = (
                f"{self.base_url}/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                f"/providers/Microsoft.SecurityInsights/bookmarks"
            )

            bookmark_data = {
                "properties": {
                    "displayName": data.get("name"),
                    "notes": data.get("notes", ""),
                    "query": data.get("query"),
                    "queryResult": data.get("query_result"),
                    "labels": data.get("labels", []),
                }
            }

            result = await self._make_request(
                "POST",
                api_url,
                json_data=bookmark_data,
                params={"api-version": "2021-09-01-preview"},
                headers=headers
            )

            return {
                "provider": self.name,
                "success": True,
                "bookmark_id": result.get("id"),
                "name": data.get("name"),
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel create_bookmark error: {e}")
            return {"error": str(e)}

    async def run_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Run playbook - POST trigger Logic App"""
        if not self.is_configured:
            return {"error": "Microsoft Sentinel credentials not configured"}

        try:
            token = await self._get_oauth_token()
            headers = {**self._get_headers(), "Authorization": f"Bearer {token}"}

            api_url = (
                f"{self.base_url}{playbook_id}"
                f"/triggers/manual/listCallbackUrl"
            )

            result = await self._make_request(
                "POST",
                api_url,
                params={"api-version": "2016-06-01"},
                headers=headers
            )

            callback_url = result.get("value")

            if callback_url:
                trigger_result = await self._make_request(
                    "POST",
                    callback_url,
                    json_data={}
                )

                return {
                    "provider": self.name,
                    "success": True,
                    "playbook_id": playbook_id,
                    "run_id": trigger_result.get("id"),
                }

            return {
                "provider": self.name,
                "success": False,
                "error": "No callback URL generated",
            }
        except Exception as e:
            logger.error(f"Microsoft Sentinel run_playbook error: {e}")
            return {"error": str(e), "playbook_id": playbook_id}
