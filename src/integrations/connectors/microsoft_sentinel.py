"""Microsoft Sentinel connector (Azure Resource Manager REST API).

Authentication: Microsoft identity platform client-credentials grant,
``POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`` with a
form-encoded body and ``scope=https://management.azure.com/.default``; ARM
calls carry ``Authorization: Bearer <token>``.

Endpoints (learn.microsoft.com/rest/api):
* Workspaces - Get (Microsoft.OperationalInsights, api-version 2022-10-01).
* Log Analytics query through ARM: ``POST .../workspaces/<name>/api/query``
  (api-version 2017-01-01-preview), so one management-scope token serves
  every call and the workspace is addressed by its resource name.
* Microsoft.SecurityInsights incidents, alertRules and bookmarks
  (api-version 2024-03-01).
* Logic Apps workflow trigger ``listCallbackUrl`` (api-version 2016-06-01).
"""

import re
import time
import uuid
from typing import Any, Dict, List, Optional

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
)

logger = get_logger(__name__)

SENTINEL_API_VERSION = "2024-03-01"
WORKSPACE_API_VERSION = "2022-10-01"
QUERY_API_VERSION = "2017-01-01-preview"
LOGIC_API_VERSION = "2016-06-01"

_AZURE_RESOURCE_PATH_RE = re.compile(r"^/subscriptions/[A-Za-z0-9-]+(?:/[A-Za-z0-9._~-]+)+$")
_FIELD_RES = {
    "tenant_id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$"),
    "subscription_id": re.compile(r"^[A-Za-z0-9-]{1,64}$"),
    "resource_group": re.compile(r"^[-\w.()]{0,89}[-\w()]$"),
    "workspace_id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,62}$"),
}


def azure_resource_path(value: str) -> str:
    """Return ``value`` when it is a plain ARM resource path, else raise ValueError.

    Incident and playbook ids come from action parameters and are appended to
    ``base_url``; a value such as ``@evil.example/x`` or one carrying ``?``/``#``
    would redirect the request (and its bearer token) to another host. Only
    ``/subscriptions/<id>/<segment>/...`` with safe segment characters is
    accepted; no ``..``, ``//``, ``@``, ``?``, ``#`` or whitespace.
    """
    text = str(value or "").strip()
    if not _AZURE_RESOURCE_PATH_RE.fullmatch(text) or "/../" in text or text.endswith("/.."):
        raise ValueError("invalid Azure resource path")
    return text


class MicrosoftSentinelConnector(BaseConnector):
    """Microsoft Sentinel connector for KQL queries and incident management"""

    name = "microsoft_sentinel"
    base_url = "https://management.azure.com"
    _token: Optional[str] = None
    _token_expiry: float = 0

    CREDENTIAL_FIELDS = [
        field_spec("tenant_id", "Tenant id", "Microsoft Entra tenant id (GUID) or primary domain"),
        field_spec("client_id", "Client id", "Application (client) id of the app registration"),
        field_spec("client_secret", "Client secret", "Client secret of the app registration", secret=True),
        field_spec("subscription_id", "Subscription id", "Azure subscription holding the Sentinel workspace"),
        field_spec("resource_group", "Resource group", "Resource group of the Log Analytics workspace"),
        field_spec(
            "workspace_id", "Workspace name",
            "Log Analytics workspace resource name (the name in the ARM path, not the workspace GUID)",
        ),
    ]
    TEST_CALL = "POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token, then GET the workspace (Workspaces - Get)"
    ACTIONS = {
        "query_logs": ActionSpec(
            "Run a KQL query against the workspace (POST .../workspaces/{name}/api/query).",
            object_schema({
                "query": {"type": "string", "minLength": 1},
                "timespan": {"type": "string", "description": "ISO 8601 duration, e.g. PT24H"},
            }, ["query"]),
            "row count and the first 100 rows of each table",
            idempotent=True, side_effect=False, action_type="query", display_name="Query logs",
        ),
        "list_incidents": ActionSpec(
            "Sentinel incidents (GET .../providers/Microsoft.SecurityInsights/incidents).",
            object_schema({
                "filter_query": {"type": "string", "description": "OData $filter, e.g. properties/status eq 'New'"},
                "top": {"type": "integer", "minimum": 1, "maximum": 1000},
            }),
            "incidents (ARM id, name, title, severity, status, dates)",
            idempotent=True, side_effect=False, action_type="query", display_name="List incidents",
        ),
        "update_incident": ActionSpec(
            "Update an incident: reads it, merges title/description/severity/status/classification/owner, "
            "writes it back with its etag (GET then PUT .../incidents/{id}).",
            object_schema({
                "incident_id": {"type": "string", "minLength": 1, "description": "ARM resource id of the incident"},
                "data": {"type": "object"},
            }, ["incident_id", "data"]),
            "incident id and new status",
            idempotent=True, side_effect=True, action_type="update", display_name="Update incident",
        ),
        "list_alert_rules": ActionSpec(
            "Scheduled analytics rules (GET .../providers/Microsoft.SecurityInsights/alertRules).",
            object_schema({}),
            "rules (ARM id, name, display name, enabled, severity, first 100 chars of the query)",
            idempotent=True, side_effect=False, action_type="query", display_name="List analytics rules",
        ),
        "create_bookmark": ActionSpec(
            "Create a hunting bookmark (PUT .../providers/Microsoft.SecurityInsights/bookmarks/{new id}).",
            object_schema({"data": {"type": "object", "description": "name, query (required), notes, query_result, labels"}}, ["data"]),
            "bookmark ARM id",
            idempotent=False, side_effect=True, action_type="create", display_name="Create bookmark",
        ),
        "run_playbook": ActionSpec(
            "Fire a Logic Apps playbook's manual (HTTP request) trigger (listCallbackUrl, then POST to it).",
            object_schema({
                "playbook_id": {"type": "string", "minLength": 1, "description": "ARM resource id of the Logic App workflow"},
                "trigger_name": {"type": "string", "minLength": 1},
                "payload": {"type": "object"},
            }, ["playbook_id"]),
            "accepted flag and the workflow run id when the trigger returns one",
            idempotent=False, side_effect=True, action_type="remediate", display_name="Run playbook",
        ),
    }

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        bad = []
        for key, rx in _FIELD_RES.items():
            value = (credentials or {}).get(key)
            if value and not rx.fullmatch(str(value).strip()):
                bad.append(key)
        return bad

    def _cred(self, key: str) -> str:
        value = str(self.credentials.get(key) or "").strip()
        rx = _FIELD_RES.get(key)
        if rx is not None and not rx.fullmatch(value):
            raise ValueError(f"credential field {key} has an invalid format")
        return value

    def _workspace_path(self) -> str:
        return (
            f"/subscriptions/{self._cred('subscription_id')}"
            f"/resourceGroups/{self._cred('resource_group')}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._cred('workspace_id')}"
        )

    def _sentinel_path(self, collection: str) -> str:
        return f"{self._workspace_path()}/providers/Microsoft.SecurityInsights/{collection}"

    async def _get_oauth_token(self) -> str:
        """Client-credentials token - POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token (form body)"""
        if self._token and time.time() < self._token_expiry:
            return self._token
        login_url = f"https://login.microsoftonline.com/{self._cred('tenant_id')}/oauth2/v2.0/token"
        data = await self._make_request(
            "POST",
            login_url,
            form_data={
                "grant_type": "client_credentials",
                "client_id": str(self.credentials.get("client_id") or ""),
                "client_secret": str(self.credentials.get("client_secret") or ""),
                "scope": "https://management.azure.com/.default",
            },
            auth=False,
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise ValueError("token response carried no access_token")
        self._token = token
        self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
        return token

    def _get_headers(self) -> Dict[str, str]:
        """Add bearer token to headers"""
        headers = super()._get_headers()
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _arm(self, method: str, path: str, api_version: str, **kwargs: Any) -> Any:
        await self._get_oauth_token()
        params = {"api-version": api_version, **(kwargs.pop("params", None) or {})}
        return await self._make_request(method, path, params=params, **kwargs)

    async def test_connection(self) -> ConnectionTestResult:
        async def _check() -> Any:
            return await self._arm("GET", self._workspace_path(), WORKSPACE_API_VERSION)

        return await self._probe(self.TEST_CALL, _check)

    async def query_logs(self, query: str, timespan: str = "PT24H") -> Dict[str, Any]:
        """KQL query - POST .../workspaces/{name}/api/query"""
        data = await self._arm(
            "POST", f"{self._workspace_path()}/api/query", QUERY_API_VERSION,
            json_data={"query": query, "timespan": timespan},
        )
        rows: List[Any] = []
        for table in data.get("tables") or []:
            rows.extend(table.get("rows") or [])
        columns = [c.get("name") for c in ((data.get("tables") or [{}])[0].get("columns") or [])]
        return {
            "provider": self.name,
            "query": query,
            "timespan": timespan,
            "columns": columns,
            "result_count": len(rows),
            "results": rows[:100],
        }

    async def list_incidents(self, filter_query: str = "", top: int = 50) -> Dict[str, Any]:
        """List incidents - GET .../Microsoft.SecurityInsights/incidents"""
        params: Dict[str, Any] = {"$top": top, "$orderby": "properties/createdTimeUtc desc"}
        if filter_query:
            params["$filter"] = filter_query
        data = await self._arm("GET", self._sentinel_path("incidents"), SENTINEL_API_VERSION, params=params)
        incidents = []
        for incident in data.get("value") or []:
            p = incident.get("properties") or {}
            incidents.append({
                "id": incident.get("id"),
                "name": incident.get("name"),
                "title": p.get("title"),
                "severity": p.get("severity"),
                "status": p.get("status"),
                "created": p.get("createdTimeUtc"),
                "modified": p.get("lastModifiedTimeUtc"),
            })
        return {"provider": self.name, "incident_count": len(incidents), "incidents": incidents}

    async def update_incident(self, incident_id: str, data: Dict) -> Dict[str, Any]:
        """Update incident - GET then PUT the incident resource with its etag"""
        try:
            resource_path = azure_resource_path(incident_id)
        except ValueError:
            return {"error": "invalid incident_id: expected an ARM resource path", "incident_id": incident_id}
        current = await self._arm("GET", resource_path, SENTINEL_API_VERSION)
        props = dict(current.get("properties") or {})
        for key in ("title", "description", "severity", "status", "classification",
                    "classificationReason", "classificationComment"):
            if data.get(key) is not None:
                props[key] = data[key]
        if data.get("owner") is not None:
            owner = data["owner"]
            props["owner"] = owner if isinstance(owner, dict) else {"userPrincipalName": owner}
        body: Dict[str, Any] = {"properties": props}
        if current.get("etag"):
            body["etag"] = current["etag"]
        updated = await self._arm("PUT", resource_path, SENTINEL_API_VERSION, json_data=body)
        return {
            "provider": self.name,
            "success": True,
            "incident_id": incident_id,
            "status": (updated.get("properties") or {}).get("status"),
        }

    async def list_alert_rules(self) -> Dict[str, Any]:
        """Analytics rules - GET .../Microsoft.SecurityInsights/alertRules (Scheduled kind)"""
        data = await self._arm("GET", self._sentinel_path("alertRules"), SENTINEL_API_VERSION)
        rules = []
        for rule in data.get("value") or []:
            if rule.get("kind") != "Scheduled":
                continue
            p = rule.get("properties") or {}
            rules.append({
                "id": rule.get("id"),
                "name": rule.get("name"),
                "display_name": p.get("displayName"),
                "description": p.get("description"),
                "enabled": p.get("enabled"),
                "severity": p.get("severity"),
                "query": (p.get("query") or "")[:100],
            })
        return {"provider": self.name, "rule_count": len(rules), "rules": rules}

    async def create_bookmark(self, data: Dict) -> Dict[str, Any]:
        """Create bookmark - PUT .../Microsoft.SecurityInsights/bookmarks/{bookmarkId}"""
        if not data.get("name") or not data.get("query"):
            raise ValueError("data.name and data.query are required")
        bookmark_id = str(uuid.uuid4())
        props: Dict[str, Any] = {"displayName": data["name"], "query": data["query"]}
        for src_key, dst_key in (("notes", "notes"), ("query_result", "queryResult"), ("labels", "labels")):
            if data.get(src_key):
                props[dst_key] = data[src_key]
        result = await self._arm(
            "PUT", f"{self._sentinel_path('bookmarks')}/{bookmark_id}", SENTINEL_API_VERSION,
            json_data={"properties": props},
        )
        return {"provider": self.name, "success": True, "bookmark_id": result.get("id"), "name": data["name"]}

    async def run_playbook(self, playbook_id: str, trigger_name: str = "manual", payload: Optional[Dict] = None) -> Dict[str, Any]:
        """Run playbook - POST {workflow}/triggers/{trigger}/listCallbackUrl, then POST the callback URL"""
        try:
            resource_path = azure_resource_path(playbook_id)
        except ValueError:
            return {"error": "invalid playbook_id: expected an ARM resource path", "playbook_id": playbook_id}
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", trigger_name or ""):
            return {"error": "invalid trigger_name", "playbook_id": playbook_id}
        result = await self._arm(
            "POST", f"{resource_path}/triggers/{trigger_name}/listCallbackUrl", LOGIC_API_VERSION,
        )
        callback_url = result.get("value")
        if not callback_url:
            return {"error": "Logic App returned no callback URL", "playbook_id": playbook_id}
        # The callback URL carries its own SAS signature: no ARM bearer token.
        response = await self._request("POST", callback_url, json_data=payload or {}, auth=False)
        return {
            "provider": self.name,
            "success": True,
            "playbook_id": playbook_id,
            "accepted_status": response.status_code,
            "run_id": response.headers.get("x-ms-workflow-run-id"),
        }
