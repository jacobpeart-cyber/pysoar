"""Enhanced WebSocket endpoints with authentication and streaming"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from src.api.deps import CurrentUser
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
async def websocket_status(current_user: CurrentUser = None):
    """
    Get WebSocket connection status.

    **Auth**: JWT required. Previously this endpoint omitted the
    ``current_user`` parameter, which means if it were ever mounted
    in api/v1/router.py it would have leaked org_ids, per-channel
    subscriber counts, and the full set of active subscription
    channel names to anonymous callers — operational intelligence
    an attacker would use to profile tenants.

    This file is currently orphaned (not imported by router.py) so
    the endpoint returns 404 in production, but we're adding the
    auth declaration defensively in case anyone wires it up later.
    Non-superusers see only their own organization's stats.
    """
    org_stats_all = {
        org_id: len(users)
        for org_id, users in manager.active_connections.items()
    }

    channel_stats_all = {
        channel: len(subscribers)
        for channel, subscribers in manager.channels.items()
        if subscribers
    }

    is_super = bool(getattr(current_user, "is_superuser", False))
    user_org_id = getattr(current_user, "organization_id", None)

    if is_super:
        org_stats = org_stats_all
        channel_stats = channel_stats_all
        total_connections = sum(org_stats_all.values())
    else:
        # Scope to caller's org only
        org_stats = (
            {user_org_id: org_stats_all[user_org_id]}
            if user_org_id in org_stats_all
            else {}
        )
        total_connections = sum(org_stats.values())
        # Channels are global-namespace but we only surface ones
        # this caller could plausibly see (filter hint: the caller's
        # org id appears in the channel name — agents:<org>, etc.)
        if user_org_id:
            channel_stats = {
                c: n for c, n in channel_stats_all.items() if user_org_id in c
            }
        else:
            channel_stats = {}

    return {
        "status": "ok",
        "total_connections": total_connections,
        "organizations": org_stats,
        "channels": channel_stats,
        "active_channels": list(channel_stats.keys()),
    }
