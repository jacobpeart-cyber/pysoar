"""ServiceNow API connector for incident and change management"""

import base64
from typing import Any, Dict, Optional

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class ServiceNowConnector(BaseConnector):
    """ServiceNow connector for ITSM and change management integration"""

    name = "servicenow"

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with ServiceNow instance URL"""
        super().__init__(config, credentials)
        instance = credentials.get("instance", "dev")
        self.base_url = f"https://{instance}.service-now.com/api/now"

    def _get_headers(self) -> Dict[str, str]:
        """Add basic auth to headers"""
        headers = super()._get_headers()
        if username := self.credentials.get("username"):
            if password := self.credentials.get("password"):
                auth_str = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {auth_str}"
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute ServiceNow action"""
        actions = {
            "create_incident": self.create_incident,
            "update_incident": self.update_incident,
            "get_incident": self.get_incident,
            "search_incidents": self.search_incidents,
            "create_change_request": self.create_change_request,
            "get_cmdb_ci": self.get_cmdb_ci,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def create_incident(self, data: Dict) -> Dict[str, Any]:
        """Create incident - POST /table/incident"""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            incident_data = {
                "short_description": data.get("short_description"),
                "description": data.get("description", ""),
                "impact": data.get("impact", "3"),
                "urgency": data.get("urgency", "3"),
                "assignment_group": data.get("assignment_group", ""),
                "assigned_to": data.get("assigned_to", ""),
                "category": data.get("category", ""),
                "state": data.get("state", "1"),
            }

            result = await self._make_request(
                "POST",
                "/table/incident",
                json_data=incident_data
            )

            record = result.get("result", {})
            return {
                "provider": self.name,
                "success": True,
                "sys_id": record.get("sys_id"),
                "number": record.get("number"),
                "state": record.get("state"),
                "url": f"{self.base_url.replace('/api/now', '')}/incident.do?sys_id={record.get('sys_id')}",
            }
        except Exception as e:
            logger.error(f"ServiceNow create_incident error: {e}")
            return {"error": str(e)}

    async def update_incident(self, sys_id: str, data: Dict) -> Dict[str, Any]:
        """Update incident - PATCH /table/incident/{sys_id}"""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            update_data = {
                "short_description": data.get("short_description"),
                "description": data.get("description"),
                "state": data.get("state"),
                "assignment_group": data.get("assignment_group"),
                "assigned_to": data.get("assigned_to"),
                "work_notes": data.get("work_notes"),
                "impact": data.get("impact"),
                "urgency": data.get("urgency"),
            }

            result = await self._make_request(
                "PATCH",
                f"/table/incident/{sys_id}",
                json_data={k: v for k, v in update_data.items() if v is not None}
            )

            record = result.get("result", {})
            return {
                "provider": self.name,
                "success": True,
                "sys_id": sys_id,
                "number": record.get("number"),
                "state": record.get("state"),
            }
        except Exception as e:
            logger.error(f"ServiceNow update_incident error: {e}")
            return {"error": str(e), "sys_id": sys_id}

    async def get_incident(self, sys_id: str) -> Dict[str, Any]:
        """Get incident - GET /table/incident/{sys_id}"""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            result = await self._make_request(
                "GET",
                f"/table/incident/{sys_id}"
            )

            record = result.get("result", {})
            return {
                "provider": self.name,
                "sys_id": sys_id,
                "number": record.get("number"),
                "short_description": record.get("short_description"),
                "description": record.get("description"),
                "state": record.get("state"),
                "impact": record.get("impact"),
                "urgency": record.get("urgency"),
                "assigned_to": record.get("assigned_to", {}).get("display_value"),
                "assignment_group": record.get("assignment_group", {}).get("display_value"),
                "created": record.get("sys_created_on"),
                "updated": record.get("sys_updated_on"),
            }
        except Exception as e:
            logger.error(f"ServiceNow get_incident error: {e}")
            return {"error": str(e), "sys_id": sys_id}

    async def search_incidents(self, query: str) -> Dict[str, Any]:
        """Search incidents - GET /table/incident?sysparm_query=..."""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            result = await self._make_request(
                "GET",
                "/table/incident",
                params={"sysparm_query": query, "limit": 100}
            )

            incidents = []
            for record in result.get("result", []):
                incidents.append({
                    "sys_id": record.get("sys_id"),
                    "number": record.get("number"),
                    "short_description": record.get("short_description"),
                    "state": record.get("state"),
                    "impact": record.get("impact"),
                    "urgency": record.get("urgency"),
                    "created": record.get("sys_created_on"),
                })

            return {
                "provider": self.name,
                "query": query,
                "incident_count": len(incidents),
                "incidents": incidents,
            }
        except Exception as e:
            logger.error(f"ServiceNow search_incidents error: {e}")
            return {"error": str(e), "query": query}

    async def create_change_request(self, data: Dict) -> Dict[str, Any]:
        """Create change request - POST /table/change_request"""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            change_data = {
                "short_description": data.get("short_description"),
                "description": data.get("description", ""),
                "type": data.get("type", "normal"),
                "impact": data.get("impact", "3"),
                "risk": data.get("risk", "3"),
                "assignment_group": data.get("assignment_group", ""),
                "assigned_to": data.get("assigned_to", ""),
                "start_date": data.get("start_date"),
                "end_date": data.get("end_date"),
                "status": data.get("status", "1"),
            }

            result = await self._make_request(
                "POST",
                "/table/change_request",
                json_data={k: v for k, v in change_data.items() if v is not None}
            )

            record = result.get("result", {})
            return {
                "provider": self.name,
                "success": True,
                "sys_id": record.get("sys_id"),
                "number": record.get("number"),
                "type": record.get("type"),
            }
        except Exception as e:
            logger.error(f"ServiceNow create_change_request error: {e}")
            return {"error": str(e)}

    async def get_cmdb_ci(self, query: str) -> Dict[str, Any]:
        """Get CMDB CI - GET /table/cmdb_ci"""
        if not self.is_configured:
            return {"error": "ServiceNow credentials not configured"}

        try:
            result = await self._make_request(
                "GET",
                "/table/cmdb_ci",
                params={"sysparm_query": query, "limit": 50}
            )

            assets = []
            for record in result.get("result", []):
                assets.append({
                    "sys_id": record.get("sys_id"),
                    "name": record.get("name"),
                    "ci_type": record.get("sys_class_name"),
                    "status": record.get("install_status"),
                    "location": record.get("location", {}).get("display_value"),
                    "owner": record.get("owner", {}).get("display_value"),
                })

            return {
                "provider": self.name,
                "query": query,
                "asset_count": len(assets),
                "assets": assets,
            }
        except Exception as e:
            logger.error(f"ServiceNow get_cmdb_ci error: {e}")
            return {"error": str(e), "query": query}
