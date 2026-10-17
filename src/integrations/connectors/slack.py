"""Slack Web API connector (https://api.slack.com/web).

Authentication is ``Authorization: Bearer <bot token>``. The Web API answers
HTTP 200 with ``{"ok": false, "error": "<code>"}`` for most failures, so every
call checks ``ok`` and turns ``ok: false`` into a failed action.
"""

from typing import Any, Dict, List, Optional

from src.core.exceptions import IntegrationError
from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
)

logger = get_logger(__name__)

_CHANNEL = {"type": "string", "minLength": 1, "description": "channel id (C...) or name"}


class SlackAPIError(IntegrationError):
    """``ok: false`` from the Slack Web API."""

    def __init__(self, message: str):
        super().__init__(service="slack", message=message)


class SlackConnector(BaseConnector):
    """Slack connector for sending alerts and managing incident channels"""

    name = "slack"
    base_url = "https://slack.com/api"

    CREDENTIAL_FIELDS = [
        field_spec("bot_token", "Bot token", "Slack bot user OAuth token (xoxb-...)", secret=True),
    ]
    TEST_CALL = "POST /api/auth.test"
    ACTIONS = {
        "send_message": ActionSpec(
            "Post a message to a channel (POST chat.postMessage; scope chat:write).",
            object_schema({
                "channel": _CHANNEL,
                "text": {"type": "string", "minLength": 1},
                "blocks": {"type": "array", "items": {"type": "object"}},
            }, ["channel", "text"]),
            "channel and message ts",
            idempotent=False, side_effect=True, action_type="notify", display_name="Send message",
        ),
        "send_alert_notification": ActionSpec(
            "Post a Block Kit formatted alert (POST chat.postMessage).",
            object_schema({"channel": _CHANNEL, "alert_data": {"type": "object"}}, ["channel", "alert_data"]),
            "channel and message ts",
            idempotent=False, side_effect=True, action_type="notify", display_name="Send alert notification",
        ),
        "create_channel": ActionSpec(
            "Create a channel (POST conversations.create; scope channels:manage or groups:write).",
            object_schema({"name": {"type": "string", "minLength": 1}, "is_private": {"type": "boolean"}}, ["name"]),
            "channel id and name",
            idempotent=False, side_effect=True, action_type="create", display_name="Create channel",
        ),
        "invite_users": ActionSpec(
            "Invite users to a channel (POST conversations.invite).",
            object_schema({
                "channel": {"type": "string", "minLength": 1, "description": "channel id"},
                "users": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            }, ["channel", "users"]),
            "channel id",
            idempotent=False, side_effect=True, action_type="update", display_name="Invite users",
        ),
        "upload_file": ActionSpec(
            "Upload text content as a file to a channel (files.getUploadURLExternal, upload, "
            "files.completeUploadExternal; files.upload is retired).",
            object_schema({
                "channel": {"type": "string", "minLength": 1, "description": "channel id"},
                "content": {"type": "string"},
                "filename": {"type": "string", "minLength": 1},
            }, ["channel", "content", "filename"]),
            "file id",
            idempotent=False, side_effect=True, action_type="create", display_name="Upload file",
        ),
        "list_channels": ActionSpec(
            "List channels (GET conversations.list, first 100).",
            object_schema({"exclude_archived": {"type": "boolean"}}),
            "channel count and channels (id, name, private, members)",
            idempotent=True, side_effect=False, action_type="query", display_name="List channels",
        ),
    }

    def _get_headers(self) -> Dict[str, str]:
        """Add Slack bearer token to headers"""
        headers = super()._get_headers()
        if token := self.credentials.get("bot_token"):
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _call(self, method: str, api_method: str, **kwargs: Any) -> Dict[str, Any]:
        data = await self._make_request(method, f"/{api_method}", **kwargs)
        if not isinstance(data, dict) or data.get("ok") is not True:
            code = data.get("error") if isinstance(data, dict) else None
            raise SlackAPIError(f"{api_method}: {code or 'ok=false'}")
        return data

    async def test_connection(self) -> ConnectionTestResult:
        async def _auth_test() -> Dict[str, Any]:
            return await self._make_request("POST", "/auth.test")

        def _verdict(body: Any) -> Optional[str]:
            if isinstance(body, dict) and body.get("ok") is True:
                return None
            return f"auth.test: {(body or {}).get('error', 'ok=false') if isinstance(body, dict) else 'ok=false'}"

        return await self._probe(self.TEST_CALL, _auth_test, _verdict)

    async def send_message(self, channel: str, text: str, blocks: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Send message - POST chat.postMessage"""
        body: Dict[str, Any] = {"channel": channel, "text": text}
        if blocks:
            body["blocks"] = blocks
        data = await self._call("POST", "chat.postMessage", json_data=body)
        return {"provider": self.name, "success": True, "channel": data.get("channel", channel), "message_ts": data.get("ts")}

    async def send_alert_notification(self, channel: str, alert_data: Dict) -> Dict[str, Any]:
        """Send formatted alert notification with Block Kit"""
        severity = str(alert_data.get("severity", "medium")).lower()
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "Security Alert"}},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert_data.get('title', 'No Title')}*\n{alert_data.get('description', '')}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Source*\n{alert_data.get('source', 'Unknown')}"},
                    {"type": "mrkdwn", "text": f"*Status*\n{alert_data.get('status', 'Open')}"},
                    {"type": "mrkdwn", "text": f"*ID*\n{alert_data.get('id', 'N/A')}"},
                ],
            },
            {"type": "divider"},
        ]
        return await self.send_message(channel, str(alert_data.get("title", "Alert")), blocks)

    async def create_channel(self, name: str, is_private: bool = False) -> Dict[str, Any]:
        """Create channel - POST conversations.create"""
        data = await self._call(
            "POST", "conversations.create",
            json_data={"name": name.lower().replace(" ", "-"), "is_private": is_private},
        )
        channel = data.get("channel") or {}
        return {"provider": self.name, "success": True, "channel_id": channel.get("id"), "channel_name": channel.get("name")}

    async def invite_users(self, channel: str, users: List[str]) -> Dict[str, Any]:
        """Invite users - POST conversations.invite; ``users`` is a comma-separated id list"""
        data = await self._call("POST", "conversations.invite", json_data={"channel": channel, "users": ",".join(users)})
        return {
            "provider": self.name,
            "success": True,
            "channel": (data.get("channel") or {}).get("id", channel),
            "invited_count": len(users),
        }

    async def upload_file(self, channel: str, content: str, filename: str) -> Dict[str, Any]:
        """Upload file - files.getUploadURLExternal, POST bytes to upload_url, files.completeUploadExternal"""
        payload = content.encode("utf-8")
        ticket = await self._call(
            "POST", "files.getUploadURLExternal", form_data={"filename": filename, "length": str(len(payload))},
        )
        upload_url = ticket.get("upload_url")
        file_id = ticket.get("file_id")
        if not upload_url or not file_id:
            raise SlackAPIError("files.getUploadURLExternal: no upload_url")
        # The upload URL is pre-signed on files.slack.com: no bearer token.
        await self._request("POST", upload_url, content=payload, auth=False)
        await self._call(
            "POST", "files.completeUploadExternal",
            json_data={"files": [{"id": file_id, "title": filename}], "channel_id": channel},
        )
        return {"provider": self.name, "success": True, "file_id": file_id, "channel": channel}

    async def list_channels(self, exclude_archived: bool = True) -> Dict[str, Any]:
        """List channels - GET conversations.list"""
        data = await self._call(
            "GET", "conversations.list",
            params={"exclude_archived": "true" if exclude_archived else "false", "limit": 100},
        )
        channels = [
            {
                "id": c.get("id"),
                "name": c.get("name"),
                "is_private": c.get("is_private"),
                "member_count": c.get("num_members", 0),
            }
            for c in data.get("channels") or []
        ]
        return {"provider": self.name, "channel_count": len(channels), "channels": channels}
