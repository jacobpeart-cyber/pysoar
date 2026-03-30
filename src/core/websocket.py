"""Production WebSocket manager with Redis Pub/Sub support"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import aioredis
from fastapi import WebSocket

from src.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections with org isolation and Redis Pub/Sub"""

    def __init__(self):
        # active_connections: dict[str, dict[str, WebSocket]]
        # org_id -> { user_id: ws }
        self.active_connections: dict[str, dict[str, WebSocket]] = {}

        # channels: dict[str, set[str]]
        # channel_name -> set of user_ids
        self.channels: dict[str, set[str]] = {}

        # Track user org mapping: user_id -> org_id
        self.user_org_mapping: dict[str, str] = {}

        # Redis clients
        self.redis_publisher: Optional["RedisPublisher"] = None
        self.redis_subscriber: Optional["RedisSubscriber"] = None

        # Heartbeat tracking: user_id -> last_ping_timestamp
        self.last_pings: dict[str, float] = {}

    async def initialize_redis(self, redis_url: str):
        """Initialize Redis pub/sub connections"""
        try:
            self.redis_publisher = await RedisPublisher.create(redis_url)
            self.redis_subscriber = RedisSubscriber(redis_url, self)
            await self.redis_subscriber.start()
            logger.info("Redis Pub/Sub initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        org_id: str
    ):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()

        # Create org entry if needed
        if org_id not in self.active_connections:
            self.active_connections[org_id] = {}

        # Store connection
        self.active_connections[org_id][user_id] = websocket
        self.user_org_mapping[user_id] = org_id
        self.last_pings[user_id] = datetime.now(timezone.utc).timestamp()

        logger.info(f"WebSocket connected: user {user_id} org {org_id}")

        # Send welcome message
        await self.send_personal(
            user_id,
            org_id,
            {
                "type": "connected",
                "message": "Connected to PySOAR real-time updates",
                "user_id": user_id,
                "org_id": org_id,
            }
        )

    def disconnect(self, user_id: str, org_id: str):
        """Remove a WebSocket connection and clean up"""
        if org_id in self.active_connections:
            if user_id in self.active_connections[org_id]:
                del self.active_connections[org_id][user_id]

            # Clean up empty org
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]

        # Remove from channel subscriptions
        for channel_subscribers in self.channels.values():
            channel_subscribers.discard(user_id)

        # Clean up mappings
        self.user_org_mapping.pop(user_id, None)
        self.last_pings.pop(user_id, None)

        logger.info(f"WebSocket disconnected: user {user_id} org {org_id}")

    async def subscribe(self, user_id: str, channel: str):
        """Subscribe a user to a channel"""
        if channel not in self.channels:
            self.channels[channel] = set()

        self.channels[channel].add(user_id)
        logger.info(f"User {user_id} subscribed to {channel}")

    async def unsubscribe(self, user_id: str, channel: str):
        """Unsubscribe a user from a channel"""
        if channel in self.channels:
            self.channels[channel].discard(user_id)
            logger.info(f"User {user_id} unsubscribed from {channel}")

    async def send_personal(
        self,
        user_id: str,
        org_id: str,
        message: dict[str, Any]
    ):
        """Send a direct message to a specific user"""
        if "timestamp" not in message:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "message_id" not in message:
            message["message_id"] = str(uuid.uuid4())

        if org_id not in self.active_connections:
            logger.warning(f"Org {org_id} not found for user {user_id}")
            return

        ws = self.active_connections[org_id].get(user_id)
        if not ws:
            logger.warning(f"User {user_id} not connected in org {org_id}")
            return

        try:
            await ws.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send to user {user_id}: {e}")
            self.disconnect(user_id, org_id)

    async def broadcast_to_org(self, org_id: str, message: dict[str, Any]):
        """Broadcast to all users in an organization"""
        if "timestamp" not in message:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "message_id" not in message:
            message["message_id"] = str(uuid.uuid4())

        if org_id not in self.active_connections:
            return

        disconnected = []
        for user_id, ws in self.active_connections[org_id].items():
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to user {user_id} in org {org_id}: {e}")
                disconnected.append(user_id)

        # Clean up disconnected users
        for user_id in disconnected:
            self.disconnect(user_id, org_id)

    async def broadcast_to_channel(self, channel: str, message: dict[str, Any]):
        """Broadcast to all users subscribed to a channel"""
        if "timestamp" not in message:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "message_id" not in message:
            message["message_id"] = str(uuid.uuid4())
        if "channel" not in message:
            message["channel"] = channel

        if channel not in self.channels:
            return

        for user_id in list(self.channels[channel]):
            org_id = self.user_org_mapping.get(user_id)
            if org_id:
                await self.send_personal(user_id, org_id, message)

    async def broadcast_alert(self, org_id: str, alert_data: dict[str, Any]):
        """Broadcast real-time alert notification"""
        message = {
            "type": "alert_created",
            "channel": "alerts",
            "data": alert_data,
        }

        # Broadcast to org
        await self.broadcast_to_org(org_id, message)

        # Also publish to Redis for other instances
        if self.redis_publisher:
            await self.redis_publisher.publish(
                f"org:{org_id}:alerts",
                message
            )

    async def broadcast_incident_update(
        self,
        org_id: str,
        incident_data: dict[str, Any]
    ):
        """Broadcast incident update notification"""
        message = {
            "type": "incident_updated",
            "channel": "incidents",
            "data": incident_data,
        }

        await self.broadcast_to_org(org_id, message)

        if self.redis_publisher:
            await self.redis_publisher.publish(
                f"org:{org_id}:incidents",
                message
            )

    async def broadcast_warroom_message(
        self,
        room_id: str,
        message_data: dict[str, Any]
    ):
        """Broadcast message in a warroom"""
        message = {
            "type": "warroom_message",
            "channel": f"warroom:{room_id}",
            "data": message_data,
        }

        await self.broadcast_to_channel(f"warroom:{room_id}", message)

        if self.redis_publisher:
            await self.redis_publisher.publish(
                f"warroom:{room_id}",
                message
            )

    def get_online_users(self, org_id: str) -> list[str]:
        """Get list of connected user IDs in organization"""
        if org_id not in self.active_connections:
            return []
        return list(self.active_connections[org_id].keys())

    async def handle_ping(self, user_id: str, org_id: str):
        """Handle heartbeat ping"""
        self.last_pings[user_id] = datetime.now(timezone.utc).timestamp()
        await self.send_personal(user_id, org_id, {"type": "pong"})

    async def cleanup_stale_connections(self, timeout_seconds: int = 300):
        """Remove connections that haven't pinged in timeout_seconds"""
        current_time = datetime.now(timezone.utc).timestamp()
        stale_users = [
            (user_id, org_id)
            for user_id, org_id in self.user_org_mapping.items()
            if current_time - self.last_pings.get(user_id, current_time) > timeout_seconds
        ]

        for user_id, org_id in stale_users:
            logger.info(f"Removing stale connection: user {user_id}")
            self.disconnect(user_id, org_id)


class RedisPublisher:
    """Publish events to Redis Pub/Sub for multi-instance broadcasting"""

    def __init__(self, redis_client: aioredis.Redis):
        self.client = redis_client

    @classmethod
    async def create(cls, redis_url: str) -> "RedisPublisher":
        """Create a RedisPublisher instance"""
        client = await aioredis.from_url(redis_url)
        return cls(client)

    async def publish(self, channel: str, message: dict[str, Any]):
        """Publish a message to a Redis channel"""
        try:
            await self.client.publish(channel, json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to publish to Redis channel {channel}: {e}")

    async def close(self):
        """Close Redis connection"""
        await self.client.close()


class RedisSubscriber:
    """Subscribe to Redis Pub/Sub and forward to local WebSocket connections"""

    def __init__(self, redis_url: str, connection_manager: ConnectionManager):
        self.redis_url = redis_url
        self.connection_manager = connection_manager
        self.client: Optional[aioredis.Redis] = None
        self.pubsub: Optional[aioredis.client.PubSub] = None
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        """Start listening to Redis Pub/Sub"""
        try:
            self.client = await aioredis.from_url(self.redis_url)
            self.pubsub = self.client.pubsub()

            # Subscribe to org and warroom patterns
            await self.pubsub.psubscribe(
                "org:*",
                "warroom:*",
                "system:*"
            )

            self.task = asyncio.create_task(self._listen())
            logger.info("RedisSubscriber started")
        except Exception as e:
            logger.error(f"Failed to start RedisSubscriber: {e}")

    async def _listen(self):
        """Listen to incoming Redis messages"""
        if not self.pubsub:
            return

        try:
            async for message in self.pubsub.listen():
                if message["type"] == "pmessage":
                    await self._handle_redis_message(
                        message["pattern"].decode(),
                        message["data"]
                    )
        except Exception as e:
            logger.error(f"Error in RedisSubscriber listen loop: {e}")

    async def _handle_redis_message(
        self,
        pattern: str,
        data: bytes
    ):
        """Handle incoming Redis message"""
        try:
            message = json.loads(data)

            # Route based on pattern
            if pattern.startswith("org:"):
                # Format: org:org_id:type
                parts = pattern.split(":")
                if len(parts) >= 2:
                    org_id = parts[1]
                    await self.connection_manager.broadcast_to_org(org_id, message)

            elif pattern.startswith("warroom:"):
                # Format: warroom:room_id
                await self.connection_manager.broadcast_to_channel(pattern, message)

            elif pattern == "system:*":
                # Broadcast to all orgs
                for org_id in self.connection_manager.active_connections:
                    await self.connection_manager.broadcast_to_org(org_id, message)

        except Exception as e:
            logger.error(f"Error handling Redis message: {e}")

    async def close(self):
        """Close Redis subscription"""
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        if self.pubsub:
            await self.pubsub.unsubscribe()

        if self.client:
            await self.client.close()


# Global connection manager instance
manager = ConnectionManager()
