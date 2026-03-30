"""Production middleware stack for security and observability"""

import time
import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Add unique X-Request-ID header to every request/response

    Enables tracing and correlation of logs across services
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID to request and response headers"""
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Store in request state for use in handlers
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response


class TimingMiddleware(BaseHTTPMiddleware):
    """Track request duration and log slow requests"""

    SLOW_REQUEST_THRESHOLD = 5.0  # seconds

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track request timing"""
        start_time = time.time()
        request.state.start_time = start_time

        response = await call_next(request)

        duration = time.time() - start_time
        response.headers["X-Response-Time"] = str(duration)

        # Log slow requests
        if duration > self.SLOW_REQUEST_THRESHOLD:
            logger.warning(
                f"Slow request detected",
                method=request.method,
                path=request.url.path,
                duration_seconds=round(duration, 2),
                status_code=response.status_code,
            )

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers"""
        response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Enforce HTTPS
        if not settings.is_development:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all requests with method, path, status, duration, and user_id

    Structured logging for audit trail and debugging
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request details"""
        start_time = time.time()
        request_id = getattr(request.state, "request_id", "unknown")

        # Get user ID if authenticated
        user_id = None
        if hasattr(request.state, "user_id"):
            user_id = request.state.user_id

        response = await call_next(request)

        duration = time.time() - start_time

        # Determine log level based on status code
        log_level = "info"
        if response.status_code >= 500:
            log_level = "error"
        elif response.status_code >= 400:
            log_level = "warning"

        # Log structured request data
        log_func = getattr(logger, log_level)
        log_func(
            f"{request.method} {request.url.path}",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_seconds=round(duration, 3),
            request_id=request_id,
            user_id=user_id,
            client_ip=request.client.host if request.client else "unknown",
            query_string=request.url.query or "",
        )

        return response


class CORSProductionConfig:
    """CORS configuration for production"""

    @staticmethod
    def get_cors_config(settings_obj):
        """Get production-safe CORS configuration"""
        return {
            "allow_origins": settings_obj.cors_origins,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": [
                "Content-Type",
                "Authorization",
                "X-Request-ID",
                "X-Requested-With",
            ],
            "expose_headers": [
                "X-Request-ID",
                "X-Response-Time",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
            ],
            "max_age": 600,  # 10 minutes
        }


def get_middleware_stack():
    """
    Get the complete middleware stack for production

    Order matters: innermost -> outermost
    1. RequestIdMiddleware (add IDs first)
    2. TimingMiddleware (track time)
    3. SecurityHeadersMiddleware (add security headers)
    4. RequestLoggingMiddleware (log final state)
    """
    return [
        RequestIdMiddleware,
        TimingMiddleware,
        SecurityHeadersMiddleware,
        RequestLoggingMiddleware,
    ]


def apply_production_middleware(app):
    """
    Apply all production middleware to FastAPI app

    Args:
        app: FastAPI application instance
    """
    middleware_stack = get_middleware_stack()

    # Add in reverse order (last in list is applied first)
    for middleware_class in reversed(middleware_stack):
        app.add_middleware(middleware_class)

    logger.info("Production middleware stack applied")
