"""WebSocket Manager - Real-time notifications"""

import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import WebSocket

from src.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasts"""

    # Default channel prefixes. Every connection is auto-joined to its own
    # tenant's ``<prefix>:<org scope>`` channel for each of these (wave 1:
    # the bare ``alerts`` / ``incidents`` / ``playbooks`` / ``system``
    # channels used to broadcast every tenant's events to everyone).
    # Additional channels (per-org ``agents:<org_id>``, per-simulation
    # ``purple:<org>:<sim>``) are opened on demand via subscribe().
    _DEFAULT_CHANNELS = ("alerts", "incidents", "playbooks", "system")

    # Every channel carries one tenant's events and is named
    # ``<prefix>:<org scope>[:<sub id>]``. The org scope is the
    # organisation id, or ``global`` for rows that have no organisation
    # (see src/agents/service.py). Maps prefix -> number of ``:`` parts.
    _ORG_SCOPED_CHANNEL_PARTS = {
        "agents": 2,
        "purple": 3,
        "alerts": 2,
        "incidents": 2,
        "playbooks": 2,
        "system": 2,
    }
    _GLOBAL_SCOPE = "global"

    @classmethod
    def tenant_channel(cls, prefix: str, organization_id: Optional[str]) -> str:
        """The per-tenant channel name for ``prefix`` (``global`` when org-less)."""
        return f"{prefix}:{organization_id or cls._GLOBAL_SCOPE}"

    def __init__(self):
        # Active connections by user ID
        self.active_connections: dict[str, list[WebSocket]] = {}
        # Tenant scope of each connected user, recorded at connect():
        # user_id -> (organization_id, is_superuser). subscribe() refuses
        # users with no recorded scope.
        self._user_scope: dict[str, tuple[Optional[str], bool]] = {}
        # Connections by channel/room. Starts with the defaults but
        # new channels are auto-created by subscribe/broadcast so
        # dynamic channels like `agents:<org>` or
        # `purple:<org>:<sim>` work without a hardcoded allowlist.
        self.channels: dict[str, set[str]] = {}

    @classmethod
    def authorize_channel(
        cls,
        channel: str,
        *,
        organization_id: Optional[str],
        is_superuser: bool,
    ) -> bool:
        """Return True if a user in ``organization_id`` may join ``channel``.

        Every channel is org-scoped and must name the caller's own
        organisation (``global`` for users without one); superusers may join
        any well-formed org channel. Bare default names (``alerts``) and
        anything else are refused.
        """
        if not isinstance(channel, str) or not channel:
            return False
        parts = channel.split(":")
        expected_parts = cls._ORG_SCOPED_CHANNEL_PARTS.get(parts[0])
        if expected_parts is None or len(parts) != expected_parts or not all(parts):
            return False
        if is_superuser:
            return True
        own_scope = organization_id or cls._GLOBAL_SCOPE
        return parts[1] == own_scope

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        organization_id: Optional[str] = None,
        is_superuser: bool = False,
    ):
        """Accept a new WebSocket connection"""
        await websocket.accept()

        self._user_scope[user_id] = (organization_id, bool(is_superuser))
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

        # Auto-subscribe to the caller's own tenant default channels only;
        # dynamic channels require an explicit subscribe message.
        own_channels = [self.tenant_channel(p, organization_id) for p in self._DEFAULT_CHANNELS]
        for channel in own_channels:
            self.channels.setdefault(channel, set()).add(user_id)

        logger.info("websocket_connected", user_id=user_id, organization_id=organization_id)

        # Send welcome message
        await self.send_personal(user_id, {
            "type": "connected",
            "message": "Connected to PySOAR real-time updates",
            "channels": own_channels,
        })

    def disconnect(self, websocket: WebSocket, user_id: str):
        """Remove a WebSocket connection"""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)

            # If no more connections for this user, remove from channels
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                self._user_scope.pop(user_id, None)
                for channel in self.channels.values():
                    channel.discard(user_id)
                for name in [n for n, subs in self.channels.items() if not subs]:
                    del self.channels[name]

        logger.info(f"WebSocket disconnected: user {user_id}")

    async def subscribe(self, user_id: str, channel: str) -> bool:
        """Subscribe a user to a channel the user's tenant may read.

        Returns False (and subscribes nothing) when the channel belongs to
        another organisation, is malformed, or the user has no recorded
        scope from connect().
        """
        scope = self._user_scope.get(user_id)
        if scope is None or not self.authorize_channel(
            channel, organization_id=scope[0], is_superuser=scope[1]
        ):
            logger.warning("websocket_subscribe_denied", user_id=user_id, channel=channel[:200])
            return False
        self.channels.setdefault(channel, set()).add(user_id)
        logger.info(f"User {user_id} subscribed to {channel}")
        return True

    async def unsubscribe(self, user_id: str, channel: str):
        """Unsubscribe a user from a channel."""
        if channel in self.channels:
            self.channels[channel].discard(user_id)
            if not self.channels[channel]:
                # Garbage-collect empty channels so the dict doesn't grow
                # unboundedly with per-tenant / per-simulation ids.
                del self.channels[channel]
            logger.info(f"User {user_id} unsubscribed from {channel}")

    async def send_personal(self, user_id: str, message: dict[str, Any]):
        """Send a message to a specific user"""
        if user_id in self.active_connections:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send to user {user_id}: {e}")

    async def broadcast_channel(self, channel: str, message: dict[str, Any]):
        """Broadcast a message to all users subscribed to a channel.

        No-op if no one is listening — we intentionally do NOT drop the
        message on unknown channels here (unlike earlier revisions),
        because arbitrary dynamic channels like ``agents:<org>`` and
        ``purple:<org>:<sim>`` are valid first-class channels created on
        subscribe. Auto-creating the channel here keeps things
        symmetrical: if subscribe() would accept it, broadcast() must too.
        """
        subscribers = self.channels.get(channel)
        if not subscribers:
            return

        message["channel"] = channel
        message["timestamp"] = datetime.now(timezone.utc).isoformat()

        for user_id in list(subscribers):
            await self.send_personal(user_id, message)

    async def broadcast_all(self, message: dict[str, Any]):
        """Broadcast a message to all connected users"""
        message["timestamp"] = datetime.now(timezone.utc).isoformat()

        for user_id in self.active_connections:
            await self.send_personal(user_id, message)


# Global connection manager instance
manager = ConnectionManager()


# Event notification functions. Each takes the tenant the event belongs to
# and publishes only to that tenant's channel (``<prefix>:<org>``); events
# without an organisation go to the ``global`` scope, which only org-less
# users (and superusers who subscribe explicitly) receive.
async def notify_new_alert(alert_data: dict[str, Any], organization_id: Optional[str] = None) -> None:
    """Notify the alert's tenant about a new alert.

    ``organization_id`` defaults to ``alert_data["organization_id"]``.
    """
    org = organization_id or alert_data.get("organization_id")
    await manager.broadcast_channel(manager.tenant_channel("alerts", org), {
        "type": "alert_created",
        "data": alert_data,
    })


async def notify_alert_updated(
    alert_id: str, updates: dict[str, Any], organization_id: Optional[str],
) -> None:
    """Notify the alert's tenant about an alert update"""
    await manager.broadcast_channel(manager.tenant_channel("alerts", organization_id), {
        "type": "alert_updated",
        "alert_id": alert_id,
        "updates": updates,
    })


async def notify_new_incident(incident_data: dict[str, Any], organization_id: Optional[str] = None) -> None:
    """Notify the incident's tenant about a new incident.

    ``organization_id`` defaults to ``incident_data["organization_id"]``.
    """
    org = organization_id or incident_data.get("organization_id")
    await manager.broadcast_channel(manager.tenant_channel("incidents", org), {
        "type": "incident_created",
        "data": incident_data,
    })


async def notify_incident_updated(
    incident_id: str, updates: dict[str, Any], organization_id: Optional[str],
) -> None:
    """Notify the incident's tenant about an incident update"""
    await manager.broadcast_channel(manager.tenant_channel("incidents", organization_id), {
        "type": "incident_updated",
        "incident_id": incident_id,
        "updates": updates,
    })


async def notify_playbook_execution(
    event_type: str, data: dict[str, Any], organization_id: Optional[str],
) -> None:
    """Notify the execution's tenant about playbook execution events"""
    await manager.broadcast_channel(manager.tenant_channel("playbooks", organization_id), {
        "type": f"playbook_{event_type}",
        "data": data,
    })


async def notify_system_event(
    event_type: str,
    message: str,
    data: Optional[dict[str, Any]] = None,
    *,
    organization_id: Optional[str],
) -> None:
    """Notify one tenant about a system event"""
    await manager.broadcast_channel(manager.tenant_channel("system", organization_id), {
        "type": f"system_{event_type}",
        "message": message,
        "data": data or {},
    })


# Callback creator for services
def create_notification_callback(
    channel: str, organization_id: Optional[str],
) -> Callable[[str, dict[str, Any]], Awaitable[None]]:
    """Create a notification callback that publishes to one tenant's channel.

    ``channel`` is a default prefix (``alerts``, ``incidents``, ``playbooks``,
    ``system``); the callback publishes to ``<channel>:<organization_id>``.
    """
    target = manager.tenant_channel(channel, organization_id)

    async def callback(event_type: str, data: dict[str, Any]) -> None:
        await manager.broadcast_channel(target, {
            "type": event_type,
            "data": data,
        })
    return callback
