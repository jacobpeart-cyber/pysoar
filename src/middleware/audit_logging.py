"""ASGI audit logging middleware for capturing and logging API operations"""

import json
import re
import time
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.core.logging import get_logger

logger = get_logger(__name__)

# Sensitive fields that should be redacted from logs
SENSITIVE_FIELDS = {
    "password",
    "current_password",
    "new_password",
    "token",
    "access_token",
    "refresh_token",
    "mfa_token",
    "mfa_secret",
    "secret",
    "api_key",
    "api_secret",
    "code",
    "backup_codes",
    "authorization",
}


def _sanitize_body(body: dict) -> dict:
    """
    Recursively redact sensitive fields in request body to [REDACTED]

    Args:
        body: Dictionary containing request body data

    Returns:
        Dictionary with sensitive fields redacted
    """
    if not isinstance(body, dict):
        return body

    sanitized = {}
    for key, value in body.items():
        if key.lower() in SENSITIVE_FIELDS:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_body(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_body(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value

    return sanitized


def _sanitize_path(path: str) -> str:
    """
    Strip non-printable characters and newlines from URL path to prevent log injection

    Args:
        path: URL path string

    Returns:
        Sanitized path string
    """
    # Remove non-printable characters and newlines
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f\n\r]', '', path)
    return sanitized


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all POST/PUT/PATCH/DELETE operations with sanitization"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log audit information"""
        # Only log mutation operations
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return await call_next(request)

        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", "unknown")
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = _sanitize_path(request.url.path)

        # Get user_id from request state if available
        user_id = getattr(request.state, "user_id", None)

        # Capture request body for mutation methods
        body_summary = None
        try:
            if request.method in ("POST", "PUT", "PATCH"):
                body = await request.body()
                if body:
                    try:
                        body_dict = json.loads(body)
                        sanitized_body = _sanitize_body(body_dict)
                        # Log field names only, not values
                        body_summary = list(sanitized_body.keys())
                    except json.JSONDecodeError:
                        body_summary = "unparseable"
        except Exception as e:
            logger.warning(
                f"Failed to capture request body: {str(e)}",
                extra={"request_id": request_id},
            )

        # Call the next middleware/route handler
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Log the audit entry
        log_data = {
            "method": method,
            "path": path,
            "status_code": response.status_code,
            "user_id": user_id,
            "request_id": request_id,
            "client_ip": client_ip,
            "duration_seconds": round(duration, 3),
        }

        if body_summary:
            log_data["request_fields"] = body_summary

        logger.info(
            f"API audit: {method} {path} - {response.status_code}",
            extra=log_data,
        )

        return response
