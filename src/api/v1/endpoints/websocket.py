"""WebSocket endpoints for real-time updates"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from src.core.config import settings
from src.services.websocket_manager import manager

router = APIRouter(tags=["WebSocket"])


async def get_user_from_token(token: str) -> Optional[str]:
    """Extract user ID from JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
        )
        user_id: str = payload.get("sub")
        return user_id
    except JWTError:
        return None


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time updates.

    Connect with: ws://host/api/v1/ws?token=<jwt_token>

    Message types received:
    - alert_created: New alert created
    - alert_updated: Alert was updated
    - incident_created: New incident created
    - incident_updated: Incident was updated
    - playbook_execution_started: Playbook started executing
    - playbook_step_started: Playbook step started
    - playbook_step_completed: Playbook step completed
    - playbook_execution_completed: Playbook finished executing
    - playbook_execution_failed: Playbook execution failed
    - system_*: System events

    Commands you can send:
    - {"action": "subscribe", "channel": "alerts"}
    - {"action": "unsubscribe", "channel": "alerts"}
    - {"action": "ping"}
    """
    # Authenticate
    user_id = None
    if token:
        user_id = await get_user_from_token(token)

    if not user_id:
        await websocket.close(code=4001, reason="Authentication required")
        return

    await manager.connect(websocket, user_id)

    try:
        while True:
            # Receive and handle messages from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                action = message.get("action", "")

                if action == "ping":
                    await manager.send_personal(user_id, {"type": "pong"})

                elif action == "subscribe":
                    channel = message.get("channel", "")
                    await manager.subscribe(user_id, channel)
                    await manager.send_personal(user_id, {
                        "type": "subscribed",
                        "channel": channel,
                    })

                elif action == "unsubscribe":
                    channel = message.get("channel", "")
                    await manager.unsubscribe(user_id, channel)
                    await manager.send_personal(user_id, {
                        "type": "unsubscribed",
                        "channel": channel,
                    })

                else:
                    await manager.send_personal(user_id, {
                        "type": "error",
                        "message": f"Unknown action: {action}",
                    })

            except json.JSONDecodeError:
                await manager.send_personal(user_id, {
                    "type": "error",
                    "message": "Invalid JSON",
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
