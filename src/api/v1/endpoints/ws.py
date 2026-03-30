"""Enhanced WebSocket endpoints with authentication and streaming"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from src.core.config import settings
from src.core.logging import get_logger
from src.core.websocket import manager

logger = get_logger(__name__)

router = APIRouter(tags=["WebSocket"])


async def get_user_from_token(token: str) -> Optional[tuple[str, str]]:
    """Extract user_id and org_id from JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
        )
        user_id: str = payload.get("sub")
        org_id: str = payload.get("org_id", "default")
        return (user_id, org_id) if user_id else None
    except JWTError:
        return None


@router.websocket("/ws/connect")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time updates.

    Connect with: ws://host/api/v1/ws/connect?token=<jwt_token>

    Authenticated connection will receive real-time:
    - Alerts and updates
    - Incidents and escalations
    - Playbook execution events
    - Warroom messages
    - System notifications

    Commands you can send:
    - {"action": "subscribe", "channel": "alerts"}
    - {"action": "unsubscribe", "channel": "incidents"}
    - {"action": "ping"}
    - {"action": "warroom_message", "room_id": "room123", "text": "..."}
    """
    # Authenticate via token
    auth_result = None
    if token:
        auth_result = await get_user_from_token(token)

    if not auth_result:
        await websocket.close(code=4001, reason="Authentication required")
        return

    user_id, org_id = auth_result

    # Connect and accept
    await manager.connect(websocket, user_id, org_id)

    try:
        while True:
            # Receive and handle messages from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                action = message.get("action", "")

                if action == "ping":
                    await manager.handle_ping(user_id, org_id)

                elif action == "subscribe":
                    channel = message.get("channel", "")
                    if channel:
                        await manager.subscribe(user_id, channel)
                        await manager.send_personal(
                            user_id,
                            org_id,
                            {
                                "type": "subscribed",
                                "channel": channel,
                            }
                        )

                elif action == "unsubscribe":
                    channel = message.get("channel", "")
                    if channel:
                        await manager.unsubscribe(user_id, channel)
                        await manager.send_personal(
                            user_id,
                            org_id,
                            {
                                "type": "unsubscribed",
                                "channel": channel,
                            }
                        )

                elif action == "warroom_message":
                    room_id = message.get("room_id", "")
                    text = message.get("text", "")
                    if room_id and text:
                        message_data = {
                            "user_id": user_id,
                            "room_id": room_id,
                            "text": text,
                        }
                        await manager.broadcast_warroom_message(room_id, message_data)

                else:
                    await manager.send_personal(
                        user_id,
                        org_id,
                        {
                            "type": "error",
                            "message": f"Unknown action: {action}",
                        }
                    )

            except json.JSONDecodeError:
                await manager.send_personal(
                    user_id,
                    org_id,
                    {
                        "type": "error",
                        "message": "Invalid JSON",
                    }
                )

    except WebSocketDisconnect:
        manager.disconnect(user_id, org_id)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        manager.disconnect(user_id, org_id)


@router.get("/ws/status")
async def websocket_status():
    """
    Get WebSocket connection status.

    Returns:
    - total_connections: Total connected users
    - organizations: Dict with org_id -> user_count
    - channels: Dict with channel -> subscriber_count
    - active_channels: List of channels with subscribers
    """
    total_connections = sum(
        len(users) for users in manager.active_connections.values()
    )

    org_stats = {
        org_id: len(users)
        for org_id, users in manager.active_connections.items()
    }

    channel_stats = {
        channel: len(subscribers)
        for channel, subscribers in manager.channels.items()
        if subscribers
    }

    return {
        "status": "ok",
        "total_connections": total_connections,
        "organizations": org_stats,
        "channels": channel_stats,
        "active_channels": list(channel_stats.keys()),
    }
