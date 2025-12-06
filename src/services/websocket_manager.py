"""WebSocket Manager - Real-time notifications"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import WebSocket

from src.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasts"""

    def __init__(self):
        # Active connections by user ID
        self.active_connections: dict[str, list[WebSocket]] = {}
        # Connections by channel/room
        self.channels: dict[str, set[str]] = {
            "alerts": set(),
            "incidents": set(),
            "playbooks": set(),
            "system": set(),
        }

    async def connect(self, websocket: WebSocket, user_id: str):
        """Accept a new WebSocket connection"""
        await websocket.accept()

        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

        # Subscribe to all channels by default
        for channel in self.channels:
            self.channels[channel].add(user_id)

        logger.info(f"WebSocket connected: user {user_id}")

        # Send welcome message
        await self.send_personal(user_id, {
            "type": "connected",
            "message": "Connected to PySOAR real-time updates",
            "channels": list(self.channels.keys()),
        })

    def disconnect(self, websocket: WebSocket, user_id: str):
        """Remove a WebSocket connection"""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)

            # If no more connections for this user, remove from channels
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                for channel in self.channels.values():
                    channel.discard(user_id)

        logger.info(f"WebSocket disconnected: user {user_id}")

    async def subscribe(self, user_id: str, channel: str):
        """Subscribe a user to a channel"""
        if channel in self.channels:
            self.channels[channel].add(user_id)
            logger.info(f"User {user_id} subscribed to {channel}")

    async def unsubscribe(self, user_id: str, channel: str):
        """Unsubscribe a user from a channel"""
        if channel in self.channels:
            self.channels[channel].discard(user_id)
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
        """Broadcast a message to all users in a channel"""
        if channel not in self.channels:
            return

        message["channel"] = channel
        message["timestamp"] = datetime.now(timezone.utc).isoformat()

        for user_id in self.channels[channel]:
            await self.send_personal(user_id, message)

    async def broadcast_all(self, message: dict[str, Any]):
        """Broadcast a message to all connected users"""
        message["timestamp"] = datetime.now(timezone.utc).isoformat()

        for user_id in self.active_connections:
            await self.send_personal(user_id, message)


# Global connection manager instance
manager = ConnectionManager()


# Event notification functions
async def notify_new_alert(alert_data: dict[str, Any]):
    """Notify subscribers about a new alert"""
    await manager.broadcast_channel("alerts", {
        "type": "alert_created",
        "data": alert_data,
    })


async def notify_alert_updated(alert_id: str, updates: dict[str, Any]):
    """Notify subscribers about an alert update"""
    await manager.broadcast_channel("alerts", {
        "type": "alert_updated",
        "alert_id": alert_id,
        "updates": updates,
    })


async def notify_new_incident(incident_data: dict[str, Any]):
    """Notify subscribers about a new incident"""
    await manager.broadcast_channel("incidents", {
        "type": "incident_created",
        "data": incident_data,
    })


async def notify_incident_updated(incident_id: str, updates: dict[str, Any]):
    """Notify subscribers about an incident update"""
    await manager.broadcast_channel("incidents", {
        "type": "incident_updated",
        "incident_id": incident_id,
        "updates": updates,
    })


async def notify_playbook_execution(event_type: str, data: dict[str, Any]):
    """Notify subscribers about playbook execution events"""
    await manager.broadcast_channel("playbooks", {
        "type": f"playbook_{event_type}",
        "data": data,
    })


async def notify_system_event(event_type: str, message: str, data: Optional[dict] = None):
    """Notify subscribers about system events"""
    await manager.broadcast_channel("system", {
        "type": f"system_{event_type}",
        "message": message,
        "data": data or {},
    })


# Callback creator for services
def create_notification_callback(channel: str):
    """Create a notification callback for services"""
    async def callback(event_type: str, data: dict[str, Any]):
        await manager.broadcast_channel(channel, {
            "type": event_type,
            "data": data,
        })
    return callback
