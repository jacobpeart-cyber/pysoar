"""WebSocket endpoints for real-time updates"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from src.core.config import settings
from src.core.logging import get_logger
from src.services.websocket_manager import manager

logger = get_logger(__name__)
router = APIRouter(tags=["WebSocket"])


async def get_user_from_token(token: str) -> Optional[str]:
    """Extract user ID from JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
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
        await websocket.accept()
        await websocket.close(code=4001, reason="Authentication required")
        return

    try:
        await manager.connect(websocket, user_id)
    except Exception as e:
        logger.error(f"WebSocket connect failed for {user_id}: {e}")
        return

    try:
        while True:
            try:
                # Receive and handle messages from client
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                break

            try:
                message = json.loads(data)
                action = message.get("action", "")

                if action == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                    })

                elif action == "subscribe":
                    channel = message.get("channel", "")
                    await manager.subscribe(user_id, channel)
                    await websocket.send_json({
                        "type": "subscribed",
                        "channel": channel,
                    })

                elif action == "unsubscribe":
                    channel = message.get("channel", "")
                    await manager.unsubscribe(user_id, channel)
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "channel": channel,
                    })

                else:
                    await websocket.send_json({
                        "type": "ack",
                        "message": f"Received: {action}",
                    })

            except json.JSONDecodeError:
                try:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid JSON",
                    })
                except Exception:
                    break
            except Exception as e:
                logger.error(f"WebSocket message handling error: {e}")
                break

    finally:
        manager.disconnect(websocket, user_id)
