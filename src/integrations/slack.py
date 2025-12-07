"""Slack integration for notifications and alerts"""

import logging
from typing import Any, Optional

import httpx

from src.integrations.base import BaseIntegration, IntegrationConfig

logger = logging.getLogger(__name__)


class SlackConfig(IntegrationConfig):
    """Slack-specific configuration"""

    webhook_url: str
    channel: Optional[str] = None
    username: str = "PySOAR"
    icon_emoji: str = ":shield:"


class SlackIntegration(BaseIntegration):
    """Slack integration for sending notifications"""

    name = "slack"
    display_name = "Slack"
    description = "Send alerts and notifications to Slack channels"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", "")
        self.channel = config.get("channel")
        self.username = config.get("username", "PySOAR")
        self.icon_emoji = config.get("icon_emoji", ":shield:")

    async def test_connection(self) -> bool:
        """Test the Slack webhook connection"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json={
                        "text": "PySOAR connection test successful!",
                        "username": self.username,
                        "icon_emoji": self.icon_emoji,
                    },
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack connection test failed: {e}")
            return False

    async def send_alert(
        self,
        title: str,
        severity: str,
        description: Optional[str] = None,
        alert_id: Optional[str] = None,
        source: Optional[str] = None,
    ) -> bool:
        """Send an alert notification to Slack"""
        color = self._severity_to_color(severity)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {severity.upper()} Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                ],
            },
        ]

        if description:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Description:*\n{description[:500]}"},
                }
            )

        if alert_id or source:
            fields = []
            if alert_id:
                fields.append({"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert_id}`"})
            if source:
                fields.append({"type": "mrkdwn", "text": f"*Source:*\n{source}"})
            blocks.append({"type": "section", "fields": fields})

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if self.channel:
            payload["channel"] = self.channel

        return await self._send_message(payload)

    async def send_incident(
        self,
        title: str,
        severity: str,
        incident_id: str,
        status: str = "open",
        alert_count: int = 0,
    ) -> bool:
        """Send an incident notification to Slack"""
        color = self._severity_to_color(severity)
        status_emoji = {
            "open": "🔴",
            "investigating": "🟡",
            "containment": "🟠",
            "eradication": "🔵",
            "recovery": "🟢",
            "closed": "⚪",
        }.get(status, "⚪")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔥 Incident Created",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status_emoji} {status.title()}"},
                    {"type": "mrkdwn", "text": f"*Related Alerts:*\n{alert_count}"},
                ],
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Incident ID: `{incident_id}`"}],
            },
        ]

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if self.channel:
            payload["channel"] = self.channel

        return await self._send_message(payload)

    async def send_playbook_result(
        self,
        playbook_name: str,
        status: str,
        execution_id: str,
        error_message: Optional[str] = None,
    ) -> bool:
        """Send playbook execution result to Slack"""
        if status == "completed":
            color = "good"
            emoji = "✅"
            title = "Playbook Completed Successfully"
        elif status == "failed":
            color = "danger"
            emoji = "❌"
            title = "Playbook Failed"
        else:
            color = "warning"
            emoji = "⏳"
            title = "Playbook Running"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Playbook:*\n{playbook_name}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status.title()}"},
                ],
            },
        ]

        if error_message:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Error:*\n```{error_message[:500]}```"},
                }
            )

        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Execution ID: `{execution_id}`"}],
            }
        )

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if self.channel:
            payload["channel"] = self.channel

        return await self._send_message(payload)

    async def send_custom_message(self, message: str, blocks: Optional[list] = None) -> bool:
        """Send a custom message to Slack"""
        payload = {
            "text": message,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
        }

        if blocks:
            payload["blocks"] = blocks

        if self.channel:
            payload["channel"] = self.channel

        return await self._send_message(payload)

    async def _send_message(self, payload: dict) -> bool:
        """Send message to Slack webhook"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    logger.info("Slack message sent successfully")
                    return True
                else:
                    logger.error(f"Slack API error: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False

    def _severity_to_color(self, severity: str) -> str:
        """Convert severity to Slack attachment color"""
        colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280",
        }
        return colors.get(severity.lower(), "#6b7280")
