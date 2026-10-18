"""Microsoft Defender for Endpoint connector (learn.microsoft.com/defender-endpoint/api/apis-intro).

Authentication: Microsoft identity platform client-credentials grant
(learn.microsoft.com/defender-endpoint/api/exposed-apis-create-app-webapp),
``POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`` with a
form-encoded body and ``scope=https://api.securitycenter.microsoft.com/.default``;
API calls carry ``Authorization: Bearer <token>``. The app registration needs
the WindowsDefenderATP *application* permissions named in each action's
description, granted with admin consent.

API host: ``api.securitycenter.microsoft.com``, or the regional
``api-<geo>.securitycenter.microsoft.com`` for ``geo`` us / eu / uk / au
(learn.microsoft.com/defender-endpoint/api/exposed-apis-list, "Supported
Microsoft Defender for Endpoint APIs").

Machine actions (isolate, scan, restrict, collect) are asynchronous: the POST
returns a machineAction whose ``status`` starts as ``Pending``;
``get_machine_action`` reads its progress.
"""

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
from src.integrations.connectors.entra_id import (
    MICROSOFT_APP_FIELDS,
    MicrosoftClientCredentials,
    guid,
    odata_string,
)

logger = get_logger(__name__)

DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"
GEOS = ("", "us", "eu", "uk", "au")

_MACHINE = {"type": "string", "minLength": 1, "description": "machine id (from search_machines)"}
_COMMENT = {"type": "string", "minLength": 1, "description": "reason, recorded in the Defender action center"}
_TOP = {"type": "integer", "minimum": 1, "maximum": 10000}


def defender_host(geo: Any) -> str:
    """API host for ``geo`` ('' = global); anything else is refused."""
    text = "" if geo is None else str(geo)
    if text not in GEOS:
        raise ValueError(f"geo must be one of {list(GEOS)}")
    return f"api-{text}.securitycenter.microsoft.com" if text else "api.securitycenter.microsoft.com"


def _machine_action_spec(description: str, display: str, extra: Optional[Dict[str, Any]] = None) -> ActionSpec:
    props: Dict[str, Any] = {"machine_id": _MACHINE, "comment": _COMMENT, **(extra or {})}
    return ActionSpec(
        description, object_schema(props, ["machine_id", "comment"]),
        "machineAction id, type and status (Pending until the device reports back)",
        idempotent=False, side_effect=True, action_type="remediate", display_name=display,
    )


class MicrosoftDefenderConnector(MicrosoftClientCredentials, BaseConnector):
    """Microsoft Defender for Endpoint: devices, alerts, response actions."""

    name = "microsoft_defender"
    TOKEN_SCOPE = DEFENDER_SCOPE

    CONFIG_FIELDS = [
        field_spec(
            "geo", "API region",
            "Empty for api.securitycenter.microsoft.com; us, eu, uk or au for api-<geo>.securitycenter.microsoft.com",
            required=False, default="",
        ),
    ]
    CREDENTIAL_FIELDS = list(MICROSOFT_APP_FIELDS)
    TEST_CALL = "POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token, then GET /api/machines?$top=1"
    ACTIONS = {
        "get_machine": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/get-machine-by-id
            "Read one device (GET /api/machines/{id}). Permission: Machine.Read.All.",
            object_schema({"machine_id": _MACHINE}, ["machine_id"]),
            "id, computerDnsName, osPlatform, health, risk score, exposure level, last IP, last seen, machine tags",
            idempotent=True, side_effect=False, action_type="query", display_name="Get machine",
        ),
        "search_machines": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/get-machines (OData $filter)
            "Devices whose computerDnsName or lastIpAddress equals the value "
            "(GET /api/machines?$filter=computerDnsName eq 'x' or lastIpAddress eq 'x'&$top=). Permission: Machine.Read.All.",
            object_schema({"query": {"type": "string", "minLength": 1}, "top": _TOP}, ["query"]),
            "machine count and machines (id, computerDnsName, lastIpAddress, osPlatform, healthStatus, riskScore)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search machines",
        ),
        "list_alerts": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/get-alerts
            "Alerts (GET /api/alerts?$top=&$filter=), e.g. filter_query status eq 'New'. Permission: Alert.Read.All.",
            object_schema({"filter_query": {"type": "string", "description": "OData $filter"}, "top": _TOP}),
            "alert count and alerts (id, title, severity, status, category, machineId, created)",
            idempotent=True, side_effect=False, action_type="query", display_name="List alerts",
        ),
        "get_machine_alerts": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/get-machine-related-alerts
            "Alerts of one device (GET /api/machines/{id}/alerts). Permission: Alert.Read.All.",
            object_schema({"machine_id": _MACHINE}, ["machine_id"]),
            "alert count and alerts (id, title, severity, status, category, created)",
            idempotent=True, side_effect=False, action_type="query", display_name="Get machine alerts",
        ),
        "get_machine_action": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/get-machineaction-object
            "Status of an earlier response action (GET /api/machineactions/{id}). Permission: Machine.Read.All.",
            object_schema({"action_id": {"type": "string", "minLength": 1, "description": "machineAction id (GUID)"}}, ["action_id"]),
            "machineAction id, type, status, machine id, requestor, comment, dates",
            idempotent=True, side_effect=False, action_type="query", display_name="Get machine action",
        ),
        # learn.microsoft.com/defender-endpoint/api/isolate-machine
        "isolate_machine": _machine_action_spec(
            "Network-isolate a device; Selective keeps Outlook / Teams / Skype connectivity "
            "(POST /api/machines/{id}/isolate). Permission: Machine.Isolate.",
            "Isolate machine",
            {"isolation_type": {"type": "string", "enum": ["Full", "Selective"]}},
        ),
        # learn.microsoft.com/defender-endpoint/api/unisolate-machine
        "unisolate_machine": _machine_action_spec(
            "Release a device from isolation (POST /api/machines/{id}/unisolate). Permission: Machine.Isolate.",
            "Release from isolation",
        ),
        # learn.microsoft.com/defender-endpoint/api/run-av-scan
        "run_antivirus_scan": _machine_action_spec(
            "Start a Microsoft Defender Antivirus scan (POST /api/machines/{id}/runAntiVirusScan). Permission: Machine.Scan.",
            "Run antivirus scan",
            {"scan_type": {"type": "string", "enum": ["Quick", "Full"]}},
        ),
        # learn.microsoft.com/defender-endpoint/api/restrict-code-execution
        "restrict_app_execution": _machine_action_spec(
            "Allow only Microsoft-signed executables to run (POST /api/machines/{id}/restrictCodeExecution). "
            "Permission: Machine.RestrictExecution.",
            "Restrict app execution",
        ),
        # learn.microsoft.com/defender-endpoint/api/unrestrict-code-execution
        "unrestrict_app_execution": _machine_action_spec(
            "Lift the app execution restriction (POST /api/machines/{id}/unrestrictCodeExecution). "
            "Permission: Machine.RestrictExecution.",
            "Remove app restriction",
        ),
        # learn.microsoft.com/defender-endpoint/api/collect-investigation-package
        "collect_investigation_package": _machine_action_spec(
            "Collect a forensic investigation package from the device (POST /api/machines/{id}/collectInvestigationPackage). "
            "Permission: Machine.CollectForensics.",
            "Collect investigation package",
        ),
        "update_alert": ActionSpec(
            # learn.microsoft.com/defender-endpoint/api/update-alert
            "Update an alert's status, assignee, classification, determination or add a comment "
            "(PATCH /api/alerts/{id}). Permission: Alert.ReadWrite.All.",
            object_schema({
                "alert_id": {"type": "string", "minLength": 1},
                "status": {"type": "string", "enum": ["New", "InProgress", "Resolved"]},
                "assigned_to": {"type": "string", "description": "user principal name"},
                "classification": {"type": "string", "description": "e.g. TruePositive, InformationalExpectedActivity, FalsePositive"},
                "determination": {"type": "string", "description": "e.g. Malware, Phishing, SecurityTesting, Other"},
                "comment": {"type": "string"},
            }, ["alert_id"]),
            "alert id, status, assignedTo, classification, determination",
            idempotent=True, side_effect=True, action_type="update", display_name="Update alert",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        self.base_url = f"https://{defender_host(self.config.get('geo') or '')}"

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        bad = cls.tenant_invalid(credentials)
        try:
            defender_host((config or {}).get("geo") or "")
        except ValueError:
            bad.append("geo")
        return bad

    def _get_headers(self) -> Dict[str, str]:
        return self._bearer(super()._get_headers())

    async def _get_oauth_token(self) -> str:
        return await self._client_credentials_token(
            str(self.credentials.get("tenant_id") or ""),
            str(self.credentials.get("client_id") or ""),
            str(self.credentials.get("client_secret") or ""),
        )

    async def _api(self, method: str, path: str, **kwargs: Any) -> Any:
        await self._get_oauth_token()
        return await self._make_request(method, path, **kwargs)

    async def test_connection(self) -> ConnectionTestResult:
        async def _check() -> Any:
            return await self._api("GET", "/api/machines", params={"$top": 1})

        return await self._probe(self.TEST_CALL, _check)

    @staticmethod
    def _machine(m: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": m.get("id"),
            "computer_dns_name": m.get("computerDnsName"),
            "os_platform": m.get("osPlatform"),
            "health_status": m.get("healthStatus"),
            "risk_score": m.get("riskScore"),
            "exposure_level": m.get("exposureLevel"),
            "last_ip_address": m.get("lastIpAddress"),
            "last_external_ip_address": m.get("lastExternalIpAddress"),
            "last_seen": m.get("lastSeen"),
            "machine_tags": m.get("machineTags"),
        }

    @staticmethod
    def _alert(a: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": a.get("id"),
            "title": a.get("title"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "category": a.get("category"),
            "machine_id": a.get("machineId"),
            "classification": a.get("classification"),
            "determination": a.get("determination"),
            "assigned_to": a.get("assignedTo"),
            "created": a.get("alertCreationTime"),
        }

    @staticmethod
    def _machine_action(data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "action_id": data.get("id"),
            "type": data.get("type"),
            "status": data.get("status"),
            "machine_id": data.get("machineId"),
            "requestor": data.get("requestor"),
            "comment": data.get("requestorComment"),
            "created": data.get("creationDateTimeUtc"),
            "updated": data.get("lastUpdateDateTimeUtc"),
        }

    async def get_machine(self, machine_id: str) -> Dict[str, Any]:
        """Get machine by id - GET /api/machines/{id}"""
        data = await self._api("GET", f"/api/machines/{path_segment(machine_id)}")
        return {"provider": self.name, **self._machine(data)}

    async def search_machines(self, query: str, top: int = 50) -> Dict[str, Any]:
        """List machines - GET /api/machines?$filter=computerDnsName eq 'x' or lastIpAddress eq 'x'"""
        q = odata_string(query)
        data = await self._api("GET", "/api/machines", params={
            "$filter": f"computerDnsName eq '{q}' or lastIpAddress eq '{q}'", "$top": top,
        })
        machines = [self._machine(m) for m in data.get("value") or [] if isinstance(m, dict)]
        return {"provider": self.name, "machine_count": len(machines), "machines": machines}

    async def list_alerts(self, filter_query: str = "", top: int = 100) -> Dict[str, Any]:
        """List alerts - GET /api/alerts?$top=&$filter="""
        params: Dict[str, Any] = {"$top": top}
        if filter_query:
            params["$filter"] = filter_query
        data = await self._api("GET", "/api/alerts", params=params)
        alerts = [self._alert(a) for a in data.get("value") or [] if isinstance(a, dict)]
        return {"provider": self.name, "alert_count": len(alerts), "alerts": alerts}

    async def get_machine_alerts(self, machine_id: str) -> Dict[str, Any]:
        """Machine alerts - GET /api/machines/{id}/alerts"""
        data = await self._api("GET", f"/api/machines/{path_segment(machine_id)}/alerts")
        alerts = [self._alert(a) for a in data.get("value") or [] if isinstance(a, dict)]
        return {"provider": self.name, "machine_id": machine_id, "alert_count": len(alerts), "alerts": alerts}

    async def get_machine_action(self, action_id: str) -> Dict[str, Any]:
        """Get machineAction - GET /api/machineactions/{id}"""
        data = await self._api("GET", f"/api/machineactions/{guid(action_id, 'action_id')}")
        return {"provider": self.name, **self._machine_action(data)}

    async def _respond(self, machine_id: str, operation: str, body: Dict[str, Any]) -> Dict[str, Any]:
        data = await self._api("POST", f"/api/machines/{path_segment(machine_id)}/{operation}", json_data=body)
        return {"provider": self.name, "success": True, "machine_id": machine_id, **self._machine_action(data)}

    async def isolate_machine(self, machine_id: str, comment: str, isolation_type: str = "Full") -> Dict[str, Any]:
        """Isolate - POST /api/machines/{id}/isolate {"Comment", "IsolationType"}"""
        return await self._respond(machine_id, "isolate", {"Comment": comment, "IsolationType": isolation_type})

    async def unisolate_machine(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Release from isolation - POST /api/machines/{id}/unisolate {"Comment"}"""
        return await self._respond(machine_id, "unisolate", {"Comment": comment})

    async def run_antivirus_scan(self, machine_id: str, comment: str, scan_type: str = "Quick") -> Dict[str, Any]:
        """Run AV scan - POST /api/machines/{id}/runAntiVirusScan {"Comment", "ScanType"}"""
        return await self._respond(machine_id, "runAntiVirusScan", {"Comment": comment, "ScanType": scan_type})

    async def restrict_app_execution(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Restrict app execution - POST /api/machines/{id}/restrictCodeExecution {"Comment"}"""
        return await self._respond(machine_id, "restrictCodeExecution", {"Comment": comment})

    async def unrestrict_app_execution(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Remove app restriction - POST /api/machines/{id}/unrestrictCodeExecution {"Comment"}"""
        return await self._respond(machine_id, "unrestrictCodeExecution", {"Comment": comment})

    async def collect_investigation_package(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Collect investigation package - POST /api/machines/{id}/collectInvestigationPackage {"Comment"}"""
        return await self._respond(machine_id, "collectInvestigationPackage", {"Comment": comment})

    async def update_alert(
        self,
        alert_id: str,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        classification: Optional[str] = None,
        determination: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update alert - PATCH /api/alerts/{id}"""
        body = {
            key: value for key, value in (
                ("status", status), ("assignedTo", assigned_to), ("classification", classification),
                ("determination", determination), ("comment", comment),
            ) if value is not None
        }
        if not body:
            raise ValueError("nothing to update (status, assigned_to, classification, determination, comment)")
        data = await self._api("PATCH", f"/api/alerts/{path_segment(alert_id)}", json_data=body)
        return {"provider": self.name, "success": True, **{k: v for k, v in self._alert(data).items() if k in (
            "id", "status", "assigned_to", "classification", "determination")}}
