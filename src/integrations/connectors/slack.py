"""Slack API connector for alert notifications and incident communication"""

from typing import Any, Dict, Optional, List

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class SlackConnector(BaseConnector):
    """Slack connector for sending alerts and managing incident channels"""

    name = "slack"
    base_url = "https://slack.com/api"

    def _get_headers(self) -> Dict[str, str]:
        """Add Slack bearer token to headers"""
        headers = super()._get_headers()
        if token := self.credentials.get("bot_token"):
            headers["Authorization"] = f"Bearer {token}"
        headers["Content-Type"] = "application/json"
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute Slack action"""
        actions = {
            "send_message": self.send_message,
            "send_alert_notification": self.send_alert_notification,
            "create_channel": self.create_channel,
            "invite_users": self.invite_users,
            "upload_file": self.upload_file,
            "list_channels": self.list_channels,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def send_message(
        self,
        channel: str,
        text: str,
        blocks: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """Send message - POST /chat.postMessage"""
        if not self.is_configured:
            return {"error": "Slack token not configured"}

        try:
            json_data = {
                "channel": channel,
                "text": text,
            }
            if blocks:
                json_data["blocks"] = blocks

            data = await self._make_request(
                "POST",
                "/chat.postMessage",
                json_data=json_data
            )

            return {
                "provider": self.name,
                "success": data.get("ok", False),
                "channel": channel,
                "message_ts": data.get("ts"),
                "error": data.get("error"),
            }
        except Exception as e:
            logger.error(f"Slack send_message error: {e}")
            return {"error": str(e), "channel": channel}

    async def send_alert_notification(
        self,
        channel: str,
        alert_data: Dict
    ) -> Dict[str, Any]:
        """Send formatted alert notification with Block Kit"""
        severity = alert_data.get("severity", "medium").lower()
        severity_color = {
            "critical": "#FF0000",
            "high": "#FF6B00",
            "medium": "#FFA500",
            "low": "#0066CC",
            "info": "#0099CC",
        }.get(severity, "#808080")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Security Alert",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert_data.get('title', 'No Title')}*\n{alert_data.get('description', '')}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity*\n{severity.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source*\n{alert_data.get('source', 'Unknown')}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status*\n{alert_data.get('status', 'Open')}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ID*\n{alert_data.get('id', 'N/A')}",
                    },
                ]
            },
            {
                "type": "divider",
            },
        ]

        return await self.send_message(channel, alert_data.get("title", "Alert"), blocks)

    async def create_channel(self, name: str, is_private: bool = False) -> Dict[str, Any]:
        """Create channel - POST /conversations.create"""
        if not self.is_configured:
            return {"error": "Slack token not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/conversations.create",
                json_data={
                    "name": name.lower().replace(" ", "-"),
                    "is_private": is_private,
                }
            )

            return {
                "provider": self.name,
                "success": data.get("ok", False),
                "channel_id": data.get("channel", {}).get("id"),
                "channel_name": data.get("channel", {}).get("name"),
                "error": data.get("error"),
            }
        except Exception as e:
            logger.error(f"Slack create_channel error: {e}")
            return {"error": str(e), "name": name}

    async def invite_users(
        self,
        channel: str,
        users: List[str]
    ) -> Dict[str, Any]:
        """Invite users - POST /conversations.invite"""
        if not self.is_configured:
            return {"error": "Slack token not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/conversations.invite",
                json_data={
                    "channel": channel,
                    "users": users,
                }
            )

            return {
                "provider": self.name,
                "success": data.get("ok", False),
                "channel": channel,
                "invited_count": len(data.get("channel", {}).get("members", [])),
                "error": data.get("error"),
            }
        except Exception as e:
            logger.error(f"Slack invite_users error: {e}")
            return {"error": str(e), "channel": channel}

    async def upload_file(
        self,
        channel: str,
        content: str,
        filename: str
    ) -> Dict[str, Any]:
        """Upload file - POST /files.upload"""
        if not self.is_configured:
            return {"error": "Slack token not configured"}

        try:
            data = await self._make_request(
                "POST",
                "/files.upload",
                json_data={
                    "channels": channel,
                    "content": content,
                    "filename": filename,
                }
            )

            return {
                "provider": self.name,
                "success": data.get("ok", False),
                "file_id": data.get("file", {}).get("id"),
                "channel": channel,
                "error": data.get("error"),
            }
        except Exception as e:
            logger.error(f"Slack upload_file error: {e}")
            return {"error": str(e), "channel": channel}

    async def list_channels(self, exclude_archived: bool = True) -> Dict[str, Any]:
        """List channels - GET /conversations.list"""
        if not self.is_configured:
            return {"error": "Slack token not configured"}

        try:
            data = await self._make_request(
                "GET",
                "/conversations.list",
                params={
                    "exclude_archived": exclude_archived,
                    "limit": 100,
                }
            )

            channels = []
            for channel in data.get("channels", []):
                channels.append({
                    "id": channel.get("id"),
                    "name": channel.get("name"),
                    "is_private": channel.get("is_private"),
                    "member_count": channel.get("num_members", 0),
                })

            return {
                "provider": self.name,
                "channel_count": len(channels),
                "channels": channels,
            }
        except Exception as e:
            logger.error(f"Slack list_channels error: {e}")
            return {"error": str(e)}
