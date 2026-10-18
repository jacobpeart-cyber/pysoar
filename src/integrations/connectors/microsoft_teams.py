"""Microsoft Teams connector (incoming webhook; posts Adaptive Cards to one channel).

Two webhook kinds are accepted, both a single secret URL with no other
credential:

* Workflows (Power Automate "Post to a channel when a webhook request is
  received"), hosted on ``*.logic.azure.com``: the replacement Microsoft
  announced for Office 365 connectors (learn.microsoft.com/microsoftteams/
  platform/webhooks-and-connectors/how-to/add-incoming-webhook). Answers 202.
* Office 365 connector incoming webhooks on ``*.webhook.office.com`` (being
  retired by Microsoft). Answer 200 with body ``1``; some delivery failures are
  reported as 200 with an error text, which is treated as a failure.

The message body is the documented webhook envelope
``{"type": "message", "attachments": [{"contentType":
"application/vnd.microsoft.card.adaptive", "content": <AdaptiveCard>}]}``
(learn.microsoft.com/microsoftteams/platform/task-modules-and-cards/cards/
cards-reference#adaptive-card). No Authorization header is sent: the URL's
signature is the credential, so it is a secret field and is redacted from
every error.

The webhook has no read-only endpoint: the connection test posts a visible
"PySOAR connection test" card.
"""

from typing import Any, Dict, List, Optional

import httpx

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

ALLOWED_HOST_SUFFIXES = (".webhook.office.com", ".logic.azure.com")
ADAPTIVE_CARD = "application/vnd.microsoft.card.adaptive"
_SEVERITY_STYLE = {"critical": "attention", "high": "attention", "medium": "warning", "low": "good", "informational": "default"}


def teams_webhook_url(value: Any) -> str:
    """The webhook URL when it is https on an allowed Microsoft host, else ValueError (never echoes the URL)."""
    text = str(value or "").strip()
    try:
        url = httpx.URL(text)
    except (httpx.InvalidURL, TypeError, ValueError):
        raise ValueError("webhook_url is not a valid URL") from None
    host = (url.host or "").lower().rstrip(".")
    if (
        url.scheme != "https"
        or url.userinfo
        or url.port not in (None, 443)
        or any(c.isspace() for c in text)
        or not any(host.endswith(suffix) and len(host) > len(suffix) for suffix in ALLOWED_HOST_SUFFIXES)
    ):
        raise ValueError("webhook_url must be an https Teams webhook on *.webhook.office.com or *.logic.azure.com")
    return text


def adaptive_card(
    title: str,
    text: str,
    facts: Optional[List[Dict[str, Any]]] = None,
    link: str = "",
    style: str = "default",
) -> Dict[str, Any]:
    """The webhook message envelope around one Adaptive Card (schema 1.4)."""
    body: List[Dict[str, Any]] = []
    if title:
        body.append({
            "type": "Container", "style": style,
            "items": [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True}],
        })
    body.append({"type": "TextBlock", "text": text, "wrap": True})
    if facts:
        body.append({
            "type": "FactSet",
            "facts": [{"title": str(f.get("title", "")), "value": str(f.get("value", ""))} for f in facts],
        })
    content: Dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if link:
        content["actions"] = [{"type": "Action.OpenUrl", "title": "Open in PySOAR", "url": link}]
    return {"type": "message", "attachments": [{"contentType": ADAPTIVE_CARD, "contentUrl": None, "content": content}]}


_FACTS = {
    "type": "array",
    "items": {"type": "object"},
    "description": "list of {title, value} pairs shown as a FactSet",
}


class MicrosoftTeamsConnector(BaseConnector):
    """Microsoft Teams incoming webhook: post messages and alert cards to one channel."""

    name = "microsoft_teams"

    CREDENTIAL_FIELDS = [
        field_spec(
            "webhook_url", "Webhook URL",
            "Teams Workflows (*.logic.azure.com) or incoming webhook (*.webhook.office.com) URL; it is the credential",
            secret=True,
        ),
    ]
    TEST_CALL = "POST a 'PySOAR connection test' card (visible in the channel)"
    ACTIONS = {
        "send_message": ActionSpec(
            "Post a message as an Adaptive Card: text, optional title and facts (POST to the webhook URL).",
            object_schema({
                "text": {"type": "string", "minLength": 1},
                "title": {"type": "string"},
                "facts": _FACTS,
            }, ["text"]),
            "posted flag and the webhook's HTTP status",
            idempotent=False, side_effect=True, action_type="notify", display_name="Send message",
        ),
        "send_alert_notification": ActionSpec(
            "Post an alert card: title, severity, summary and a link back to the alert (POST to the webhook URL).",
            object_schema({
                "title": {"type": "string", "minLength": 1},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
                "summary": {"type": "string", "minLength": 1},
                "link": {"type": "string", "description": "https URL of the alert in PySOAR"},
            }, ["title", "severity", "summary"]),
            "posted flag and the webhook's HTTP status",
            idempotent=False, side_effect=True, action_type="notify", display_name="Send alert notification",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        url = self.credentials.get("webhook_url")
        self.webhook_url = teams_webhook_url(url) if url else ""

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        url = (credentials or {}).get("webhook_url")
        if url:
            try:
                teams_webhook_url(url)
            except ValueError:
                return ["webhook_url"]
        return []

    async def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST the card; 200 / 202 is delivered, anything else (or a 200 error text) fails."""
        response = await self._request("POST", self.webhook_url, json_data=payload, auth=False)
        if response.status_code not in (200, 202):
            raise ConnectorHTTPError(self.name, response.status_code, "webhook did not accept the message")
        body = response.text.strip()
        if response.status_code == 200 and body not in ("", "1") and ("error" in body.lower() or "fail" in body.lower()):
            raise ConnectorHTTPError(self.name, 200, self.sanitize(body))
        return {"provider": self.name, "success": True, "posted": True, "http_status": response.status_code}

    async def test_connection(self) -> ConnectionTestResult:
        payload = adaptive_card("PySOAR connection test", "PySOAR can post to this channel.")
        return await self._probe(self.TEST_CALL, lambda: self._post(payload))

    async def send_message(self, text: str, title: str = "", facts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Post a message card to the webhook"""
        return await self._post(adaptive_card(title, text, facts))

    async def send_alert_notification(self, title: str, severity: str, summary: str, link: str = "") -> Dict[str, Any]:
        """Post an alert card to the webhook"""
        if link and not link.lower().startswith("https://"):
            raise ValueError("link must be an https URL")
        card = adaptive_card(
            f"[{severity.upper()}] {title}", summary, [{"title": "Severity", "value": severity}],
            link=link, style=_SEVERITY_STYLE.get(severity, "default"),
        )
        return await self._post(card)
