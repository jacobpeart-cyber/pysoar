"""Jira API connector for issue tracking and project management"""

import base64
from typing import Any, Dict, Optional, List

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class JiraConnector(BaseConnector):
    """Jira connector for issue and project management"""

    name = "jira"

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize with Jira cloud domain"""
        super().__init__(config, credentials)
        domain = credentials.get("domain", "")
        self.base_url = f"https://{domain}.atlassian.net/rest/api/3"

    def _get_headers(self) -> Dict[str, str]:
        """Add Jira basic auth to headers"""
        headers = super()._get_headers()
        if email := self.credentials.get("email"):
            if api_token := self.credentials.get("api_token"):
                auth_str = base64.b64encode(f"{email}:{api_token}".encode()).decode()
                headers["Authorization"] = f"Basic {auth_str}"
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute Jira action"""
        actions = {
            "create_issue": self.create_issue,
            "update_issue": self.update_issue,
            "transition_issue": self.transition_issue,
            "add_comment": self.add_comment,
            "search_issues": self.search_issues,
            "get_issue": self.get_issue,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def create_issue(
        self,
        project: str,
        summary: str,
        description: str = "",
        issue_type: str = "Task",
        priority: str = "Medium"
    ) -> Dict[str, Any]:
        """Create issue - POST /issue"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/issue",
                json_data={
                    "fields": {
                        "project": {
                            "key": project,
                        },
                        "summary": summary,
                        "description": {
                            "version": 1,
                            "type": "doc",
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": description,
                                        }
                                    ],
                                }
                            ],
                        },
                        "issuetype": {
                            "name": issue_type,
                        },
                        "priority": {
                            "name": priority,
                        },
                    }
                }
            )

            return {
                "provider": self.name,
                "success": True,
                "issue_id": data.get("id"),
                "issue_key": data.get("key"),
                "url": f"{self.base_url.replace('/rest/api/3', '')}/browse/{data.get('key')}",
            }
        except Exception as e:
            logger.error(f"Jira create_issue error: {e}")
            return {"error": str(e)}

    async def update_issue(self, key: str, fields: Dict) -> Dict[str, Any]:
        """Update issue - PUT /issue/{key}"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            update_fields = {}

            if summary := fields.get("summary"):
                update_fields["summary"] = summary
            if description := fields.get("description"):
                update_fields["description"] = {
                    "version": 1,
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                }
            if status := fields.get("status"):
                update_fields["status"] = status
            if priority := fields.get("priority"):
                update_fields["priority"] = {"name": priority}
            if assignee := fields.get("assignee"):
                update_fields["assignee"] = {"name": assignee}
            if labels := fields.get("labels"):
                update_fields["labels"] = labels

            await self._make_request(
                "PUT",
                f"/issue/{key}",
                json_data={"fields": update_fields}
            )

            return {
                "provider": self.name,
                "success": True,
                "issue_key": key,
            }
        except Exception as e:
            logger.error(f"Jira update_issue error: {e}")
            return {"error": str(e), "issue_key": key}

    async def transition_issue(
        self,
        key: str,
        transition_id: str
    ) -> Dict[str, Any]:
        """Transition issue - POST /issue/{key}/transitions"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            await self._make_request(
                "POST",
                f"/issue/{key}/transitions",
                json_data={
                    "transition": {
                        "id": transition_id,
                    }
                }
            )

            return {
                "provider": self.name,
                "success": True,
                "issue_key": key,
                "transition_id": transition_id,
            }
        except Exception as e:
            logger.error(f"Jira transition_issue error: {e}")
            return {"error": str(e), "issue_key": key}

    async def add_comment(self, key: str, body: str) -> Dict[str, Any]:
        """Add comment - POST /issue/{key}/comment"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            data = await self._make_request(
                "POST",
                f"/issue/{key}/comment",
                json_data={
                    "body": {
                        "version": 1,
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {"type": "text", "text": body}
                                ],
                            }
                        ],
                    }
                }
            )

            return {
                "provider": self.name,
                "success": True,
                "issue_key": key,
                "comment_id": data.get("id"),
            }
        except Exception as e:
            logger.error(f"Jira add_comment error: {e}")
            return {"error": str(e), "issue_key": key}

    async def search_issues(self, jql: str) -> Dict[str, Any]:
        """Search issues - POST /search"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/search",
                json_data={
                    "jql": jql,
                    "maxResults": 100,
                    "fields": [
                        "key",
                        "summary",
                        "status",
                        "priority",
                        "assignee",
                        "created",
                        "updated",
                    ],
                }
            )

            issues = []
            for issue in data.get("issues", []):
                fields = issue.get("fields", {})
                issues.append({
                    "key": issue.get("key"),
                    "summary": fields.get("summary"),
                    "status": fields.get("status", {}).get("name"),
                    "priority": fields.get("priority", {}).get("name"),
                    "assignee": fields.get("assignee", {}).get("displayName"),
                    "created": fields.get("created"),
                    "updated": fields.get("updated"),
                })

            return {
                "provider": self.name,
                "jql": jql,
                "issue_count": len(issues),
                "issues": issues,
                "total": data.get("total", 0),
            }
        except Exception as e:
            logger.error(f"Jira search_issues error: {e}")
            return {"error": str(e), "jql": jql}

    async def get_issue(self, key: str) -> Dict[str, Any]:
        """Get issue - GET /issue/{key}"""
        if not self.is_configured:
            return {"error": "Jira credentials not configured"}

        try:
            data = await self._make_request(
                "GET",
                f"/issue/{key}"
            )

            fields = data.get("fields", {})
            return {
                "provider": self.name,
                "key": key,
                "summary": fields.get("summary"),
                "description": fields.get("description"),
                "status": fields.get("status", {}).get("name"),
                "priority": fields.get("priority", {}).get("name"),
                "issue_type": fields.get("issuetype", {}).get("name"),
                "assignee": fields.get("assignee", {}).get("displayName"),
                "reporter": fields.get("reporter", {}).get("displayName"),
                "created": fields.get("created"),
                "updated": fields.get("updated"),
                "resolution": fields.get("resolution", {}).get("name"),
            }
        except Exception as e:
            logger.error(f"Jira get_issue error: {e}")
            return {"error": str(e), "key": key}
