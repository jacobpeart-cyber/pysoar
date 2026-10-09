"""WebSocket endpoints for real-time updates"""

import json
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.exc import SQLAlchemyError

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.core.security import verify_token
from src.models.audit import AuditLog
from src.models.user import User
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
    except jwt.PyJWTError:
        return None


@dataclass(frozen=True)
class WsPrincipal:
    """The authenticated WebSocket user and the tenant scope it may read."""

    user_id: str
    organization_id: Optional[str]
    is_superuser: bool


async def resolve_ws_principal(token: str) -> Optional[WsPrincipal]:
    """Resolve an access token to an active user and its organisation.

    Channel authorisation needs the user's organisation, which is not in the
    token, so the user row is loaded. Returns None for an invalid token or a
    missing / disabled user.
    """
    user_id = verify_token(token, token_type="access") if token else None
    if not user_id:
        return None
    try:
        async with async_session_factory() as db:
            user = await db.get(User, str(user_id))
    except SQLAlchemyError as exc:
        logger.warning("websocket_principal_lookup_failed", error_class=exc.__class__.__name__)
        return None
    if user is None or not user.is_active:
        return None
    return WsPrincipal(
        user_id=str(user.id),
        organization_id=user.organization_id,
        is_superuser=bool(user.is_superuser),
    )


async def audit_denied_subscription(principal: WsPrincipal, channel: str) -> None:
    """Record a refused channel subscription in the audit log (best effort)."""
    logger.warning(
        "websocket_subscribe_refused",
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        channel=str(channel)[:200],
    )
    try:
        async with async_session_factory() as db:
            db.add(AuditLog(
                user_id=principal.user_id,
                action="websocket_subscribe_denied",
                resource_type="websocket_channel",
                description=f"Refused subscription to channel {str(channel)[:200]!r}",
                new_value=json.dumps({
                    "channel": str(channel)[:200],
                    "organization_id": principal.organization_id,
                }),
                success=False,
                error_message="channel_not_permitted",
            ))
            await db.commit()
    except SQLAlchemyError as exc:
        logger.warning("websocket_subscribe_audit_failed", error_class=exc.__class__.__name__)


async def handle_subscribe(websocket: WebSocket, principal: WsPrincipal, channel: object) -> bool:
    """Subscribe if the channel belongs to the caller's tenant, else send an error frame."""
    channel_name = channel if isinstance(channel, str) else ""
    if await manager.subscribe(principal.user_id, channel_name):
        await websocket.send_json({"type": "subscribed", "channel": channel_name})
        return True
    await audit_denied_subscription(principal, channel_name)
    await websocket.send_json({
        "type": "error",
        "error": "channel_not_permitted",
        "channel": channel_name[:200],
        "message": "You may only subscribe to your own organization's channels",
    })
    return False


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
    principal = await resolve_ws_principal(token) if token else None

    if principal is None:
        await websocket.accept()
        await websocket.close(code=4001, reason="Authentication required")
        return
    user_id = principal.user_id

    try:
        await manager.connect(
            websocket,
            user_id,
            organization_id=principal.organization_id,
            is_superuser=principal.is_superuser,
        )
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
                    await handle_subscribe(websocket, principal, message.get("channel", ""))

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
