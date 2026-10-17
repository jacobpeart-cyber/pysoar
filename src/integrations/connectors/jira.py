"""Jira Cloud REST API v3 connector (developer.atlassian.com/cloud/jira/platform/rest/v3).

Authentication is HTTP basic with the account email and an API token.
Rich-text fields (description, comment body) are Atlassian Document Format.
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

_SITE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_KEY = {"type": "string", "minLength": 1, "description": "issue key (PROJ-123) or id"}


def jira_site(domain: Any) -> str:
    """The Atlassian site name: ``acme`` or ``acme.atlassian.net`` -> ``acme``; anything else is refused."""
    text = str(domain or "").strip().lower()
    if text.startswith("https://"):
        text = text[len("https://"):]
    text = text.rstrip("/")
    if text.endswith(".atlassian.net"):
        text = text[: -len(".atlassian.net")]
    if not _SITE_RE.fullmatch(text):
        raise ValueError("domain must be the Atlassian site name (the part before .atlassian.net)")
    return text


def _adf(text: str) -> Dict[str, Any]:
    """A one-paragraph Atlassian Document Format document (ADF text nodes must not be empty)."""
    content = [{"type": "text", "text": text}] if text else []
    return {"version": 1, "type": "doc", "content": [{"type": "paragraph", "content": content}]}


class JiraConnector(BaseConnector):
    """Jira connector for issue and project management"""

    name = "jira"

    CREDENTIAL_FIELDS = [
        field_spec("domain", "Site", "Atlassian site name, the part before .atlassian.net"),
        field_spec("email", "Account email", "Email of the Atlassian account that owns the API token"),
        field_spec("api_token", "API token", "Atlassian API token", secret=True),
    ]
    TEST_CALL = "GET /rest/api/3/myself"
    ACTIONS = {
        "create_issue": ActionSpec(
            "Create an issue (POST /rest/api/3/issue).",
            object_schema({
                "project": {"type": "string", "minLength": 1, "description": "project key"},
                "summary": {"type": "string", "minLength": 1},
                "description": {"type": "string"},
                "issue_type": {"type": "string", "minLength": 1},
                "priority": {"type": "string", "description": "priority name; omitted when the project has no priority field"},
            }, ["project", "summary"]),
            "issue id, key and browse URL",
            idempotent=False, side_effect=True, action_type="create", display_name="Create issue",
        ),
        "update_issue": ActionSpec(
            "Edit issue fields (PUT /rest/api/3/issue/{key}); status changes go through transition_issue.",
            object_schema({
                "key": _KEY,
                "fields": {"type": "object", "description": "summary, description, priority, assignee (accountId), labels"},
            }, ["key", "fields"]),
            "issue key",
            idempotent=True, side_effect=True, action_type="update", display_name="Update issue",
        ),
        "transition_issue": ActionSpec(
            "Move an issue through its workflow (POST /rest/api/3/issue/{key}/transitions).",
            object_schema({"key": _KEY, "transition_id": {"type": "string", "minLength": 1}}, ["key", "transition_id"]),
            "issue key and transition id",
            idempotent=False, side_effect=True, action_type="update", display_name="Transition issue",
        ),
        "add_comment": ActionSpec(
            "Add a comment (POST /rest/api/3/issue/{key}/comment).",
            object_schema({"key": _KEY, "body": {"type": "string", "minLength": 1}}, ["key", "body"]),
            "comment id",
            idempotent=False, side_effect=True, action_type="update", display_name="Add comment",
        ),
        "search_issues": ActionSpec(
            "Search issues with JQL (POST /rest/api/3/search/jql; the old /search endpoint is removed).",
            object_schema({
                "jql": {"type": "string", "minLength": 1},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 100},
            }, ["jql"]),
            "issue count and issues (key, summary, status, priority, assignee, created, updated)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search issues",
        ),
        "get_issue": ActionSpec(
            "Read one issue (GET /rest/api/3/issue/{key}).",
            object_schema({"key": _KEY}, ["key"]),
            "summary, status, priority, type, assignee, reporter, dates, resolution",
            idempotent=True, side_effect=False, action_type="query", display_name="Get issue",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with the Jira Cloud site"""
        super().__init__(config, credentials)
        self.site = jira_site(self.credentials.get("domain")) if self.credentials.get("domain") else ""
        self.base_url = f"https://{self.site}.atlassian.net/rest/api/3" if self.site else ""

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        domain = (credentials or {}).get("domain")
        if domain:
            try:
                jira_site(domain)
            except ValueError:
                return ["domain"]
        return []

    def _get_headers(self) -> Dict[str, str]:
        """Add Jira basic auth to headers"""
        headers = super()._get_headers()
        email = self.credentials.get("email")
        api_token = self.credentials.get("api_token")
        if email and api_token:
            auth_str = base64.b64encode(f"{email}:{api_token}".encode()).decode()
            headers["Authorization"] = f"Basic {auth_str}"
        return headers

    def _secret_values(self) -> List[str]:
        values = super()._secret_values()
        email, token = self.credentials.get("email"), self.credentials.get("api_token")
        if email and token:
            values.append(base64.b64encode(f"{email}:{token}".encode()).decode())
        return values

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(self.TEST_CALL, lambda: self._make_request("GET", "/myself"))

    async def create_issue(
        self,
        project: str,
        summary: str,
        description: str = "",
        issue_type: str = "Task",
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create issue - POST /issue"""
        fields: Dict[str, Any] = {
            "project": {"key": project},
            "summary": summary,
            "issuetype": {"name": issue_type},
        }
        if description:
            fields["description"] = _adf(description)
        if priority:
            fields["priority"] = {"name": priority}
        data = await self._make_request("POST", "/issue", json_data={"fields": fields})
        return {
            "provider": self.name,
            "success": True,
            "issue_id": data.get("id"),
            "issue_key": data.get("key"),
            "url": f"https://{self.site}.atlassian.net/browse/{data.get('key')}",
        }

    async def update_issue(self, key: str, fields: Dict) -> Dict[str, Any]:
        """Edit issue - PUT /issue/{key} (204 No Content)"""
        update_fields: Dict[str, Any] = {}
        if summary := fields.get("summary"):
            update_fields["summary"] = summary
        if description := fields.get("description"):
            update_fields["description"] = _adf(str(description))
        if priority := fields.get("priority"):
            update_fields["priority"] = {"name": priority}
        if assignee := fields.get("assignee"):
            # Jira Cloud identifies users by accountId (user names were removed for GDPR).
            update_fields["assignee"] = {"accountId": assignee}
        if labels := fields.get("labels"):
            update_fields["labels"] = labels
        if not update_fields:
            raise ValueError("fields has nothing to update (summary, description, priority, assignee, labels)")
        await self._make_request("PUT", f"/issue/{path_segment(key)}", json_data={"fields": update_fields})
        return {"provider": self.name, "success": True, "issue_key": key}

    async def transition_issue(self, key: str, transition_id: str) -> Dict[str, Any]:
        """Transition issue - POST /issue/{key}/transitions (204 No Content)"""
        await self._make_request(
            "POST", f"/issue/{path_segment(key)}/transitions", json_data={"transition": {"id": transition_id}},
        )
        return {"provider": self.name, "success": True, "issue_key": key, "transition_id": transition_id}

    async def add_comment(self, key: str, body: str) -> Dict[str, Any]:
        """Add comment - POST /issue/{key}/comment"""
        data = await self._make_request("POST", f"/issue/{path_segment(key)}/comment", json_data={"body": _adf(body)})
        return {"provider": self.name, "success": True, "issue_key": key, "comment_id": data.get("id")}

    async def search_issues(self, jql: str, max_results: int = 100) -> Dict[str, Any]:
        """Search issues - POST /search/jql (enhanced search; returns nextPageToken, no total)"""
        data = await self._make_request(
            "POST",
            "/search/jql",
            json_data={
                "jql": jql,
                "maxResults": max_results,
                "fields": ["summary", "status", "priority", "assignee", "created", "updated"],
            },
        )
        issues = []
        for issue in data.get("issues") or []:
            f = issue.get("fields") or {}
            issues.append({
                "key": issue.get("key"),
                "summary": f.get("summary"),
                "status": (f.get("status") or {}).get("name"),
                "priority": (f.get("priority") or {}).get("name"),
                "assignee": (f.get("assignee") or {}).get("displayName"),
                "created": f.get("created"),
                "updated": f.get("updated"),
            })
        return {
            "provider": self.name,
            "jql": jql,
            "issue_count": len(issues),
            "issues": issues,
            "next_page_token": data.get("nextPageToken"),
        }

    async def get_issue(self, key: str) -> Dict[str, Any]:
        """Get issue - GET /issue/{key}"""
        data = await self._make_request("GET", f"/issue/{path_segment(key)}")
        f = data.get("fields") or {}
        return {
            "provider": self.name,
            "key": data.get("key", key),
            "summary": f.get("summary"),
            "description": f.get("description"),
            "status": (f.get("status") or {}).get("name"),
            "priority": (f.get("priority") or {}).get("name"),
            "issue_type": (f.get("issuetype") or {}).get("name"),
            "assignee": (f.get("assignee") or {}).get("displayName"),
            "reporter": (f.get("reporter") or {}).get("displayName"),
            "created": f.get("created"),
            "updated": f.get("updated"),
            "resolution": (f.get("resolution") or {}).get("name"),
        }
