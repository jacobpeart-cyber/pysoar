"""AWS Security Hub / GuardDuty / CloudTrail connector (boto3).

Calls go through boto3 (SigV4 signing, AWS-owned regional endpoints), run in
a worker thread so the event loop is not blocked. Endpoints are derived by
botocore from the region, which is validated against the AWS region format so
a crafted value cannot steer the endpoint host. Each call is documented in the
boto3 reference (SecurityHub.Client, GuardDuty.Client, CloudTrail.Client).
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from src.core.exceptions import IntegrationError
from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    ConnectorHTTPError,
    field_spec,
    object_schema,
)

logger = get_logger(__name__)

_REGION_RE = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$")
_WORKFLOW_STATUSES = ["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"]


def aws_region(value: Any) -> str:
    text = str(value or "us-east-1").strip().lower()
    if not _REGION_RE.fullmatch(text):
        raise ValueError("region is not an AWS region name (e.g. us-east-1)")
    return text


class AWSSecurityHubConnector(BaseConnector):
    """AWS Security Hub connector using boto3 for security findings"""

    name = "aws_security_hub"
    base_url = "https://securityhub.amazonaws.com"

    CREDENTIAL_FIELDS = [
        field_spec("access_key_id", "Access key id", "IAM access key id", secret=True),
        field_spec("secret_access_key", "Secret access key", "IAM secret access key", secret=True),
        field_spec("region", "Region", "AWS region of the Security Hub administrator account", required=False, default="us-east-1"),
    ]
    TEST_CALL = "securityhub:DescribeHub"
    ACTIONS = {
        "get_findings": ActionSpec(
            "Security Hub findings (GetFindings, up to 100; default filter RecordState=ACTIVE).",
            object_schema({"filters": {"type": "object", "description": "AwsSecurityFindingFilters"}}),
            "finding count and findings (id, product ARN, title, severity, types, resource type, dates)",
            idempotent=True, side_effect=False, action_type="query", display_name="Get findings",
        ),
        "batch_import_findings": ActionSpec(
            "Import findings in ASFF (BatchImportFindings).",
            object_schema({"findings": {"type": "array", "items": {"type": "object"}, "minItems": 1}}, ["findings"]),
            "success and failure counts",
            idempotent=True, side_effect=True, action_type="create", display_name="Import findings",
        ),
        "update_findings": ActionSpec(
            "Set the workflow status (and an optional note) of findings (BatchUpdateFindings).",
            object_schema({
                "findings": {
                    "type": "array", "items": {"type": "object"}, "minItems": 1,
                    "description": "[{id, product_arn}] finding identifiers",
                },
                "status": {"type": "string", "enum": _WORKFLOW_STATUSES},
                "note": {"type": "string"},
            }, ["findings"]),
            "processed and unprocessed counts",
            idempotent=True, side_effect=True, action_type="update", display_name="Update findings",
        ),
        "get_insight_results": ActionSpec(
            "Results of a Security Hub insight (GetInsightResults).",
            object_schema({"insight_arn": {"type": "string", "minLength": 1}}, ["insight_arn"]),
            "grouped attribute values and counts",
            idempotent=True, side_effect=False, action_type="query", display_name="Insight results",
        ),
        "list_enabled_standards": ActionSpec(
            "Enabled security standards (GetEnabledStandards).",
            object_schema({}),
            "standards (ARN, name, status)",
            idempotent=True, side_effect=False, action_type="query", display_name="Enabled standards",
        ),
        "get_guardduty_findings": ActionSpec(
            "GuardDuty findings with severity >= 4 (ListFindings + GetFindings, up to 50).",
            object_schema({"detector_id": {"type": "string"}}),
            "detector id and findings (id, type, severity, resource type, dates)",
            idempotent=True, side_effect=False, action_type="query", display_name="GuardDuty findings",
        ),
        "get_cloudtrail_events": ActionSpec(
            "Recent CloudTrail management events, optionally by event name (LookupEvents, up to 50).",
            object_schema({"lookup_query": {"type": "string", "description": "EventName to filter on"}}),
            "events (id, name, time, user, resource type)",
            idempotent=True, side_effect=False, action_type="query", display_name="CloudTrail events",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with AWS credentials"""
        super().__init__(config, credentials)
        self.region = aws_region(self.credentials.get("region"))
        self._boto: Dict[str, Any] = {}

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        try:
            aws_region((credentials or {}).get("region"))
        except ValueError:
            return ["region"]
        return []

    def _client_for(self, service: str) -> Any:
        if service not in self._boto:
            import boto3

            self._boto[service] = boto3.client(
                service,
                aws_access_key_id=self.credentials.get("access_key_id"),
                aws_secret_access_key=self.credentials.get("secret_access_key"),
                region_name=self.region,
            )
        return self._boto[service]

    async def _aws(self, service: str, operation: str, **kwargs: Any) -> Dict[str, Any]:
        """Run one boto3 operation in a thread; AWS errors become ConnectorHTTPError."""
        from botocore.exceptions import BotoCoreError, ClientError

        def _call() -> Dict[str, Any]:
            return getattr(self._client_for(service), operation)(**kwargs)

        try:
            return await asyncio.to_thread(_call)
        except ClientError as exc:
            err = exc.response.get("Error", {}) if hasattr(exc, "response") else {}
            status_code = int((exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 400)
            message = f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip(": ")
            raise ConnectorHTTPError(self.name, status_code, self.sanitize(message)) from None
        except BotoCoreError as exc:
            raise IntegrationError(self.name, self.sanitize(type(exc).__name__)) from None

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(self.TEST_CALL, lambda: self._aws("securityhub", "describe_hub"))

    async def get_findings(self, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """GetFindings"""
        response = await self._aws(
            "securityhub", "get_findings",
            Filters=filters or {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
            MaxResults=100,
        )
        findings = []
        for finding in response.get("Findings", []):
            resources = finding.get("Resources") or [{}]
            findings.append({
                "id": finding.get("Id"),
                "product_arn": finding.get("ProductArn"),
                "title": finding.get("Title"),
                "severity": (finding.get("Severity") or {}).get("Label"),
                "type": finding.get("Types", []),
                "resource_type": resources[0].get("Type"),
                "workflow_status": (finding.get("Workflow") or {}).get("Status"),
                "created": finding.get("FirstObservedAt") or finding.get("CreatedAt"),
                "updated": finding.get("LastObservedAt") or finding.get("UpdatedAt"),
            })
        return {"provider": self.name, "finding_count": len(findings), "findings": findings}

    async def batch_import_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """BatchImportFindings"""
        response = await self._aws("securityhub", "batch_import_findings", Findings=findings)
        return {
            "provider": self.name,
            "success_count": response.get("SuccessCount", 0),
            "failure_count": response.get("FailureCount", 0),
            "failures": response.get("FailedFindings", []),
        }

    async def update_findings(
        self, findings: List[Dict], status: str = "RESOLVED", note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """BatchUpdateFindings: FindingIdentifiers need Id and ProductArn; Workflow.Status sets the state."""
        identifiers = []
        for f in findings:
            fid, arn = f.get("id"), f.get("product_arn")
            if not fid or not arn:
                raise ValueError("each finding needs id and product_arn")
            identifiers.append({"Id": fid, "ProductArn": arn})
        kwargs: Dict[str, Any] = {"FindingIdentifiers": identifiers, "Workflow": {"Status": status}}
        if note:
            kwargs["Note"] = {"Text": note, "UpdatedBy": "PySOAR"}
        response = await self._aws("securityhub", "batch_update_findings", **kwargs)
        return {
            "provider": self.name,
            "processed_count": len(response.get("ProcessedFindings", [])),
            "unprocessed_count": len(response.get("UnprocessedFindings", [])),
            "unprocessed": response.get("UnprocessedFindings", []),
        }

    async def get_insight_results(self, insight_arn: str) -> Dict[str, Any]:
        """GetInsightResults"""
        response = await self._aws("securityhub", "get_insight_results", InsightArn=insight_arn)
        results = [
            {"attribute": r.get("GroupByAttributeValue"), "count": r.get("Count")}
            for r in (response.get("InsightResults") or {}).get("ResultValues", [])
        ]
        return {"provider": self.name, "insight_arn": insight_arn, "result_count": len(results), "results": results}

    async def list_enabled_standards(self) -> Dict[str, Any]:
        """GetEnabledStandards"""
        response = await self._aws("securityhub", "get_enabled_standards")
        standards = [
            {
                "arn": s.get("StandardsArn"),
                "name": (s.get("StandardsArn") or "").split("/")[-3] if (s.get("StandardsArn") or "").count("/") >= 3 else (s.get("StandardsArn") or "").split("/")[-1],
                "status": s.get("StandardsStatus"),
            }
            for s in response.get("StandardsSubscriptions", [])
        ]
        return {"provider": self.name, "standard_count": len(standards), "standards": standards}

    async def get_guardduty_findings(self, detector_id: str = "") -> Dict[str, Any]:
        """GuardDuty ListDetectors / ListFindings / GetFindings"""
        if not detector_id:
            detectors = (await self._aws("guardduty", "list_detectors")).get("DetectorIds") or []
            if not detectors:
                return {"error": "no GuardDuty detector in this region", "http_status": 404}
            detector_id = detectors[0]
        listed = await self._aws(
            "guardduty", "list_findings",
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"severity": {"GreaterThanOrEqual": 4}}},
            MaxResults=50,
        )
        finding_ids = listed.get("FindingIds") or []
        findings = []
        if finding_ids:
            got = await self._aws("guardduty", "get_findings", DetectorId=detector_id, FindingIds=finding_ids)
            for f in got.get("Findings", []):
                findings.append({
                    "id": f.get("Id"),
                    "type": f.get("Type"),
                    "severity": f.get("Severity"),
                    "created": f.get("CreatedAt"),
                    "updated": f.get("UpdatedAt"),
                    "resource_type": (f.get("Resource") or {}).get("ResourceType"),
                })
        return {"provider": self.name, "detector_id": detector_id, "finding_count": len(findings), "findings": findings}

    async def get_cloudtrail_events(self, lookup_query: str = "") -> Dict[str, Any]:
        """CloudTrail LookupEvents (filtering goes through LookupAttributes)"""
        kwargs: Dict[str, Any] = {"MaxResults": 50}
        if lookup_query:
            kwargs["LookupAttributes"] = [{"AttributeKey": "EventName", "AttributeValue": lookup_query}]
        response = await self._aws("cloudtrail", "lookup_events", **kwargs)
        events = []
        for event in response.get("Events", []):
            resources = event.get("Resources") or [{}]
            when = event.get("EventTime")
            events.append({
                "event_id": event.get("EventId"),
                "event_name": event.get("EventName"),
                "event_time": when.isoformat() if hasattr(when, "isoformat") else when,
                "username": event.get("Username"),
                "resource_type": resources[0].get("ResourceType"),
            })
        return {"provider": self.name, "event_count": len(events), "events": events}
