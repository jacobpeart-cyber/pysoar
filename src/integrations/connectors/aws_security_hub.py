"""AWS Security Hub connector for security findings and compliance"""

from typing import Any, Dict, Optional, List

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class AWSSecurityHubConnector(BaseConnector):
    """AWS Security Hub connector using boto3 for security findings"""

    name = "aws_security_hub"
    base_url = "https://securityhub.amazonaws.com"

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with AWS credentials"""
        super().__init__(config, credentials)
        self._client = None
        self._guardduty_client = None
        self._cloudtrail_client = None

    async def _get_boto_client(self, service: str = "securityhub"):
        """Get or create boto3 client"""
        if service == "securityhub" and self._client:
            return self._client
        if service == "guardduty" and self._guardduty_client:
            return self._guardduty_client
        if service == "cloudtrail" and self._cloudtrail_client:
            return self._cloudtrail_client

        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            return None

        try:
            access_key = self.credentials.get("access_key_id")
            secret_key = self.credentials.get("secret_access_key")
            region = self.credentials.get("region", "us-east-1")

            if service == "securityhub":
                self._client = boto3.client(
                    "securityhub",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region,
                )
                return self._client
            elif service == "guardduty":
                self._guardduty_client = boto3.client(
                    "guardduty",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region,
                )
                return self._guardduty_client
            elif service == "cloudtrail":
                self._cloudtrail_client = boto3.client(
                    "cloudtrail",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region,
                )
                return self._cloudtrail_client

        except Exception as e:
            logger.error(f"Failed to create boto3 client: {e}")
            return None

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute AWS Security Hub action"""
        actions = {
            "get_findings": self.get_findings,
            "batch_import_findings": self.batch_import_findings,
            "update_findings": self.update_findings,
            "get_insight_results": self.get_insight_results,
            "list_enabled_standards": self.list_enabled_standards,
            "get_guardduty_findings": self.get_guardduty_findings,
            "get_cloudtrail_events": self.get_cloudtrail_events,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def get_findings(self, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """Get findings - securityhub.get_findings()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("securityhub")
            if not client:
                return {"error": "Failed to create securityhub client"}

            params = {}
            if filters:
                params["Filters"] = filters
            else:
                params["Filters"] = {
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
                }

            response = client.get_findings(
                MaxResults=100,
                **params
            )

            findings = []
            for finding in response.get("Findings", []):
                findings.append({
                    "id": finding.get("Id"),
                    "title": finding.get("Title"),
                    "severity": finding.get("Severity", {}).get("Label"),
                    "type": finding.get("Types", []),
                    "resource_type": finding.get("Resources", [{}])[0].get("Type"),
                    "created": finding.get("FirstObservedAt"),
                    "updated": finding.get("LastObservedAt"),
                })

            return {
                "provider": self.name,
                "finding_count": len(findings),
                "findings": findings,
            }
        except Exception as e:
            logger.error(f"AWS Security Hub get_findings error: {e}")
            return {"error": str(e)}

    async def batch_import_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Import findings - securityhub.batch_import_findings()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("securityhub")
            if not client:
                return {"error": "Failed to create securityhub client"}

            response = client.batch_import_findings(Findings=findings)

            return {
                "provider": self.name,
                "success_count": response.get("SuccessCount", 0),
                "failure_count": response.get("FailureCount", 0),
                "failures": response.get("FailedFindings", []),
            }
        except Exception as e:
            logger.error(f"AWS Security Hub batch_import_findings error: {e}")
            return {"error": str(e)}

    async def update_findings(
        self,
        finding_ids: List[str],
        note: Optional[str] = None,
        status: str = "RESOLVED"
    ) -> Dict[str, Any]:
        """Update findings - securityhub.batch_update_findings()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("securityhub")
            if not client:
                return {"error": "Failed to create securityhub client"}

            finding_updates = []
            for finding_id in finding_ids:
                update = {
                    "FindingIdentifiers": {
                        "Id": finding_id,
                    },
                    "RecordState": "ARCHIVED" if status == "RESOLVED" else "ACTIVE",
                }
                if note:
                    update["Note"] = {
                        "Text": note,
                        "UpdatedBy": "PySOAR",
                    }
                finding_updates.append(update)

            response = client.batch_update_findings(FindingUpdates=finding_updates)

            return {
                "provider": self.name,
                "processed_count": response.get("ProcessedFindings", 0),
                "unprocessed_count": len(response.get("UnprocessedFindings", [])),
            }
        except Exception as e:
            logger.error(f"AWS Security Hub update_findings error: {e}")
            return {"error": str(e)}

    async def get_insight_results(self, insight_arn: str) -> Dict[str, Any]:
        """Get insight results - securityhub.get_insight_results()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("securityhub")
            if not client:
                return {"error": "Failed to create securityhub client"}

            response = client.get_insight_results(InsightArn=insight_arn)

            results = []
            for result in response.get("InsightResults", {}).get("ResultAttributes", []):
                results.append({
                    "attribute": result.get("AttributeKey"),
                    "value": result.get("AttributeValue"),
                    "count": result.get("Count"),
                })

            return {
                "provider": self.name,
                "insight_arn": insight_arn,
                "result_count": len(results),
                "results": results,
            }
        except Exception as e:
            logger.error(f"AWS Security Hub get_insight_results error: {e}")
            return {"error": str(e)}

    async def list_enabled_standards(self) -> Dict[str, Any]:
        """List enabled standards - securityhub.get_enabled_standards()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("securityhub")
            if not client:
                return {"error": "Failed to create securityhub client"}

            response = client.get_enabled_standards()

            standards = []
            for standard in response.get("StandardsSubscriptions", []):
                standards.append({
                    "arn": standard.get("StandardsArn"),
                    "name": standard.get("StandardsArn", "").split("/")[-1],
                    "status": standard.get("StandardsStatus"),
                })

            return {
                "provider": self.name,
                "standard_count": len(standards),
                "standards": standards,
            }
        except Exception as e:
            logger.error(f"AWS Security Hub list_enabled_standards error: {e}")
            return {"error": str(e)}

    async def get_guardduty_findings(self, detector_id: str = "") -> Dict[str, Any]:
        """Get GuardDuty findings - guardduty.list_findings() + get_findings()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("guardduty")
            if not client:
                return {"error": "Failed to create guardduty client"}

            if not detector_id:
                detectors = client.list_detectors()
                detector_id = detectors.get("DetectorIds", [""])[0]
                if not detector_id:
                    return {"error": "No GuardDuty detector found"}

            list_response = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gte": 4},
                    }
                },
                MaxResults=50,
            )

            finding_ids = list_response.get("FindingIds", [])
            findings = []

            if finding_ids:
                get_response = client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids,
                )

                for finding in get_response.get("Findings", []):
                    findings.append({
                        "id": finding.get("Id"),
                        "type": finding.get("Type"),
                        "severity": finding.get("Severity"),
                        "created": finding.get("CreatedAt"),
                        "updated": finding.get("UpdatedAt"),
                        "resource_type": finding.get("Resource", {}).get("ResourceType"),
                    })

            return {
                "provider": self.name,
                "detector_id": detector_id,
                "finding_count": len(findings),
                "findings": findings,
            }
        except Exception as e:
            logger.error(f"AWS GuardDuty get_guardduty_findings error: {e}")
            return {"error": str(e)}

    async def get_cloudtrail_events(self, lookup_query: str = "") -> Dict[str, Any]:
        """Get CloudTrail events - cloudtrail.lookup_events()"""
        if not self.is_configured:
            return {"error": "AWS credentials not configured"}

        try:
            client = await self._get_boto_client("cloudtrail")
            if not client:
                return {"error": "Failed to create cloudtrail client"}

            response = client.lookup_events(
                MaxResults=50,
                **{"EventName": lookup_query} if lookup_query else {}
            )

            events = []
            for event in response.get("Events", []):
                events.append({
                    "event_id": event.get("EventId"),
                    "event_name": event.get("EventName"),
                    "event_time": event.get("EventTime"),
                    "username": event.get("Username"),
                    "resource_type": event.get("Resources", [{}])[0].get("ResourceType"),
                })

            return {
                "provider": self.name,
                "event_count": len(events),
                "events": events,
            }
        except Exception as e:
            logger.error(f"AWS CloudTrail get_cloudtrail_events error: {e}")
            return {"error": str(e)}
