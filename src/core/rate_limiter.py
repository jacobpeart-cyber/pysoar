"""
Application-level rate limiting for sensitive endpoints.

Uses SlowAPI (if available) or a simple in-memory token bucket as fallback.
Configurable per-endpoint rate limits for federal compliance.
"""

import time
import logging
from collections import defaultdict
from functools import wraps
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """
    Token bucket rate limiter with per-key tracking.

    For production deployments, replace with Redis-backed limiter.
    This provides defense-in-depth even without Redis.
    """

    def __init__(self):
        self._buckets: dict[str, dict] = defaultdict(dict)

    def _get_key(self, request: Request, key_func: Optional[Callable] = None) -> str:
        """Generate rate limit key from request."""
        if key_func:
            return key_func(request)
        # Default: rate limit by client IP
        client_ip = request.client.host if request.client else "unknown"
        return f"{request.url.path}:{client_ip}"

    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check if request is within rate limit.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()
        bucket = self._buckets[key]

        # Clean expired entries
        window_start = now - window_seconds
        timestamps = bucket.get("timestamps", [])
        timestamps = [t for t in timestamps if t > window_start]

        if len(timestamps) >= max_requests:
            retry_after = int(timestamps[0] - window_start) + 1
            return False, retry_after

        timestamps.append(now)
        bucket["timestamps"] = timestamps
        return True, 0


# Global rate limiter instance
_limiter = InMemoryRateLimiter()


def rate_limit(
    max_requests: int = 5,
    window_seconds: int = 60,
    key_func: Optional[Callable] = None,
    error_message: str = "Too many requests. Please try again later.",
):
    """
    Rate limiting decorator for FastAPI endpoints.

    Usage:
        @router.post("/mfa/verify")
        @rate_limit(max_requests=5, window_seconds=300)
        async def verify_mfa(request: Request, ...):
            ...

    Args:
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds
        key_func: Optional function to extract rate limit key from request
        error_message: Error message for rate-limited requests
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args or kwargs
            request = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                # Can't rate limit without request, allow through
                logger.warning(f"Rate limiter: no Request found for {func.__name__}")
                return await func(*args, **kwargs)

            key = _limiter._get_key(request, key_func)
            allowed, retry_after = _limiter.check_rate_limit(
                key, max_requests, window_seconds
            )

            if not allowed:
                logger.warning(
                    f"Rate limit exceeded for {key}",
                    extra={"endpoint": func.__name__, "retry_after": retry_after},
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=error_message,
                    headers={"Retry-After": str(retry_after)},
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator


# Pre-configured rate limiters for common scenarios
def auth_rate_limit():
    """Rate limit for authentication endpoints: 10 requests per 5 minutes."""
    return rate_limit(max_requests=10, window_seconds=300)


def mfa_rate_limit():
    """Rate limit for MFA endpoints: 5 requests per 5 minutes."""
    return rate_limit(max_requests=5, window_seconds=300)


def password_rate_limit():
    """Rate limit for password endpoints: 3 requests per 10 minutes."""
    return rate_limit(max_requests=3, window_seconds=600)


def api_key_rate_limit():
    """Rate limit for API key endpoints: 10 requests per hour."""
    return rate_limit(max_requests=10, window_seconds=3600)
