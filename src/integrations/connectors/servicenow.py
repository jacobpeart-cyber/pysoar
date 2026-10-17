"""ServiceNow Table API connector (docs.servicenow.com, "Table API").

Authentication is HTTP basic. Requests go to
``https://<instance>.service-now.com/api/now/table/<table>``; ``sysparm_limit``
bounds a list and ``sysparm_display_value=true`` returns reference fields
(assigned_to, assignment_group, location, ...) as display strings.
"""

import base64
import re
from typing import Any, Dict, List, Optional

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

_INSTANCE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SYS_ID = {"type": "string", "minLength": 1, "description": "record sys_id"}


def servicenow_instance(value: Any) -> str:
    """``acme`` or ``acme.service-now.com`` -> ``acme``; anything else is refused."""
    text = str(value or "").strip().lower()
    if text.startswith("https://"):
        text = text[len("https://"):]
    text = text.rstrip("/")
    if text.endswith(".service-now.com"):
        text = text[: -len(".service-now.com")]
    if not _INSTANCE_RE.fullmatch(text):
        raise ValueError("instance must be the ServiceNow instance name (the part before .service-now.com)")
    return text


def _display(value: Any) -> Any:
    """A reference field: a display string, or {display_value, value, link}."""
    if isinstance(value, dict):
        return value.get("display_value") or value.get("value")
    return value


class ServiceNowConnector(BaseConnector):
    """ServiceNow connector for ITSM and change management integration"""

    name = "servicenow"

    CREDENTIAL_FIELDS = [
        field_spec("instance", "Instance", "ServiceNow instance name, the part before .service-now.com"),
        field_spec("username", "Username", "ServiceNow user with the itil role (or table ACLs) for incident and change_request"),
        field_spec("password", "Password", "Password of that user", secret=True),
    ]
    TEST_CALL = "GET /api/now/table/sys_user?sysparm_limit=1"
    ACTIONS = {
        "create_incident": ActionSpec(
            "Create an incident (POST /api/now/table/incident).",
            object_schema({"data": {"type": "object", "description": "incident fields; short_description is required"}}, ["data"]),
            "sys_id, number, state, record URL",
            idempotent=False, side_effect=True, action_type="create", display_name="Create incident",
        ),
        "update_incident": ActionSpec(
            "Update an incident (PATCH /api/now/table/incident/{sys_id}).",
            object_schema({"sys_id": _SYS_ID, "data": {"type": "object"}}, ["sys_id", "data"]),
            "sys_id, number, state",
            idempotent=True, side_effect=True, action_type="update", display_name="Update incident",
        ),
        "get_incident": ActionSpec(
            "Read an incident (GET /api/now/table/incident/{sys_id}).",
            object_schema({"sys_id": _SYS_ID}, ["sys_id"]),
            "number, descriptions, state, impact, urgency, assignee, group, dates",
            idempotent=True, side_effect=False, action_type="query", display_name="Get incident",
        ),
        "search_incidents": ActionSpec(
            "Incidents matching an encoded query (GET /api/now/table/incident?sysparm_query=..., up to 100).",
            object_schema({"query": {"type": "string", "description": "encoded query, e.g. active=true^priority=1"}}, ["query"]),
            "incident count and incidents",
            idempotent=True, side_effect=False, action_type="query", display_name="Search incidents",
        ),
        "create_change_request": ActionSpec(
            "Create a change request (POST /api/now/table/change_request).",
            object_schema({"data": {"type": "object", "description": "change fields; short_description is required"}}, ["data"]),
            "sys_id, number, type",
            idempotent=False, side_effect=True, action_type="create", display_name="Create change request",
        ),
        "get_cmdb_ci": ActionSpec(
            "Configuration items matching an encoded query (GET /api/now/table/cmdb_ci, up to 50).",
            object_schema({"query": {"type": "string"}}, ["query"]),
            "asset count and CIs (sys_id, name, class, install status, location, owner)",
            idempotent=True, side_effect=False, action_type="query", display_name="Find CMDB CIs",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with ServiceNow instance URL"""
        super().__init__(config, credentials)
        instance = self.credentials.get("instance")
        self.instance = servicenow_instance(instance) if instance else ""
        self.base_url = f"https://{self.instance}.service-now.com/api/now" if self.instance else ""

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        instance = (credentials or {}).get("instance")
        if instance:
            try:
                servicenow_instance(instance)
            except ValueError:
                return ["instance"]
        return []

    def _get_headers(self) -> Dict[str, str]:
        """Add basic auth to headers"""
        headers = super()._get_headers()
        username, password = self.credentials.get("username"), self.credentials.get("password")
        if username and password:
            auth_str = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {auth_str}"
        return headers

    def _secret_values(self) -> List[str]:
        values = super()._secret_values()
        username, password = self.credentials.get("username"), self.credentials.get("password")
        if username and password:
            values.append(base64.b64encode(f"{username}:{password}".encode()).decode())
        return values

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(
            self.TEST_CALL,
            lambda: self._make_request("GET", "/table/sys_user", params={"sysparm_limit": 1, "sysparm_fields": "sys_id"}),
        )

    def _record_url(self, table: str, sys_id: Optional[str]) -> str:
        return f"https://{self.instance}.service-now.com/{table}.do?sys_id={sys_id}"

    async def create_incident(self, data: Dict) -> Dict[str, Any]:
        """Create incident - POST /table/incident"""
        if not data.get("short_description"):
            raise ValueError("data.short_description is required")
        allowed = ("short_description", "description", "impact", "urgency", "assignment_group",
                   "assigned_to", "category", "caller_id", "work_notes")
        body = {k: data[k] for k in allowed if data.get(k) not in (None, "")}
        result = await self._make_request("POST", "/table/incident", json_data=body)
        record = result.get("result") or {}
        return {
            "provider": self.name,
            "success": True,
            "sys_id": record.get("sys_id"),
            "number": record.get("number"),
            "state": record.get("state"),
            "url": self._record_url("incident", record.get("sys_id")),
        }

    async def update_incident(self, sys_id: str, data: Dict) -> Dict[str, Any]:
        """Update incident - PATCH /table/incident/{sys_id}"""
        allowed = ("short_description", "description", "state", "assignment_group", "assigned_to",
                   "work_notes", "comments", "impact", "urgency", "close_code", "close_notes")
        body = {k: data[k] for k in allowed if data.get(k) is not None}
        if not body:
            raise ValueError(f"data has nothing to update ({', '.join(allowed)})")
        result = await self._make_request("PATCH", f"/table/incident/{path_segment(sys_id)}", json_data=body)
        record = result.get("result") or {}
        return {
            "provider": self.name,
            "success": True,
            "sys_id": sys_id,
            "number": record.get("number"),
            "state": record.get("state"),
        }

    async def get_incident(self, sys_id: str) -> Dict[str, Any]:
        """Get incident - GET /table/incident/{sys_id}"""
        result = await self._make_request(
            "GET", f"/table/incident/{path_segment(sys_id)}", params={"sysparm_display_value": "true"},
        )
        record = result.get("result") or {}
        return {
            "provider": self.name,
            "sys_id": sys_id,
            "number": record.get("number"),
            "short_description": record.get("short_description"),
            "description": record.get("description"),
            "state": record.get("state"),
            "impact": record.get("impact"),
            "urgency": record.get("urgency"),
            "assigned_to": _display(record.get("assigned_to")),
            "assignment_group": _display(record.get("assignment_group")),
            "created": record.get("sys_created_on"),
            "updated": record.get("sys_updated_on"),
        }

    async def search_incidents(self, query: str) -> Dict[str, Any]:
        """Search incidents - GET /table/incident?sysparm_query=...&sysparm_limit=100"""
        result = await self._make_request(
            "GET", "/table/incident",
            params={"sysparm_query": query, "sysparm_limit": 100, "sysparm_display_value": "true"},
        )
        incidents = [
            {
                "sys_id": r.get("sys_id"),
                "number": r.get("number"),
                "short_description": r.get("short_description"),
                "state": r.get("state"),
                "impact": r.get("impact"),
                "urgency": r.get("urgency"),
                "created": r.get("sys_created_on"),
            }
            for r in result.get("result") or []
        ]
        return {"provider": self.name, "query": query, "incident_count": len(incidents), "incidents": incidents}

    async def create_change_request(self, data: Dict) -> Dict[str, Any]:
        """Create change request - POST /table/change_request"""
        if not data.get("short_description"):
            raise ValueError("data.short_description is required")
        allowed = ("short_description", "description", "type", "impact", "risk", "assignment_group",
                   "assigned_to", "start_date", "end_date", "justification", "implementation_plan",
                   "backout_plan", "test_plan")
        body = {k: data[k] for k in allowed if data.get(k) not in (None, "")}
        result = await self._make_request("POST", "/table/change_request", json_data=body)
        record = result.get("result") or {}
        return {
            "provider": self.name,
            "success": True,
            "sys_id": record.get("sys_id"),
            "number": record.get("number"),
            "type": record.get("type"),
            "url": self._record_url("change_request", record.get("sys_id")),
        }

    async def get_cmdb_ci(self, query: str) -> Dict[str, Any]:
        """CMDB CIs - GET /table/cmdb_ci?sysparm_query=...&sysparm_limit=50"""
        result = await self._make_request(
            "GET", "/table/cmdb_ci",
            params={"sysparm_query": query, "sysparm_limit": 50, "sysparm_display_value": "true"},
        )
        assets = [
            {
                "sys_id": r.get("sys_id"),
                "name": r.get("name"),
                "ci_type": r.get("sys_class_name"),
                "status": r.get("install_status"),
                "location": _display(r.get("location")),
                "owner": _display(r.get("owned_by") or r.get("owner")),
            }
            for r in result.get("result") or []
        ]
        return {"provider": self.name, "query": query, "asset_count": len(assets), "assets": assets}
