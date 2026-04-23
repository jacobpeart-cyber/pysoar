"""Zero Trust session gate middleware.

Per-request enforcement of the 'continuous verification' pillar from
NIST SP 800-207. Every authenticated API request is checked against the
current session's Zero Trust state, so a revoked session is shut out
within one Redis-cache-TTL instead of waiting for the 5-minute Celery
sweep.

Design:

1. Runs AFTER RequestLoggingMiddleware (so audit log still captures
   denied attempts) but BEFORE the route handler.
2. Extracts the JWT's jti claim as the session id.
3. Looks up 'zt:session:<jti>' in Redis. Cached values:
     'allow'          - session recently evaluated, fresh
     'deny'           - session revoked or isolated
     'expired'        - older than 8 hours
     (missing)        - cache miss, fall through to DB
4. On cache miss, queries AccessDecision. Caches the result with TTL:
     30s for allow
     24h for deny/expired (revocation should be sticky)
5. On Redis failure: fail-open with warn. The JWT layer above already
   fails closed, so this middleware is strictly additive — we prefer
   availability over a second line of defense outage.
6. Exempt paths: anything that shouldn't be subject to ZT (login,
   health, metrics, agent-token-auth endpoints).

Revocation flow: when PolicyDecisionPoint emits a new deny/isolate
decision, call `invalidate_session_cache(jti, decision)` to push the
state into Redis immediately instead of waiting for the next miss.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)

# Paths excluded from the ZT gate. Each is a prefix match.
EXEMPT_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/refresh",
    "/api/v1/auth/mfa",
    "/api/v1/auth/me",           # returns just the user — needed to render any page
    "/api/v1/health",
    "/api/v1/metrics",
    "/api/v1/ws",                # websocket
    "/api/v1/ws/",
    "/api/v1/agents/_agent/",    # agent-token auth, not user JWT
    "/docs",
    "/redoc",
    "/openapi.json",
)

CACHE_TTL_ALLOW = 30      # seconds — revocation propagates within 30s
CACHE_TTL_DENY = 86400    # seconds — revocation sticks for 24h

_redis_client = None


async def _get_redis():
    """Lazy-connect to Redis once per process. Returns None on failure
    so callers fall back to the fail-open path."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        from redis import asyncio as aioredis
        _redis_client = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )
        await _redis_client.ping()
        return _redis_client
    except Exception as exc:  # noqa: BLE001
        logger.warning("zt_session_gate_redis_unavailable", error=str(exc))
        return None


async def invalidate_session_cache(
    jti: str,
    decision: str,
    ttl_seconds: Optional[int] = None,
) -> None:
    """Push a fresh verdict into the Redis cache so the next request is
    evaluated against it without a DB hit. Called from the PDP on every
    allow/deny decision so revocation propagates instantly, not at the
    next cache miss."""
    if not jti:
        return
    r = await _get_redis()
    if r is None:
        return
    verdict = "allow" if decision in ("allow", "challenge", "step_up") else "deny"
    ttl = ttl_seconds or (CACHE_TTL_ALLOW if verdict == "allow" else CACHE_TTL_DENY)
    try:
        await r.setex(f"zt:session:{jti}", ttl, verdict)
    except Exception as exc:  # noqa: BLE001
        logger.warning("zt_session_cache_write_failed", jti=jti[:8], error=str(exc))


class ZeroTrustSessionMiddleware(BaseHTTPMiddleware):
    """Per-request session gate enforcing Zero Trust continuous verification."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""

        # Fast path: exempt paths and non-API requests skip the gate.
        if not path.startswith("/api/"):
            return await call_next(request)
        for prefix in EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        # Extract the bearer JWT. If there is no token, the downstream
        # auth layer will handle 401. This middleware only gates
        # authenticated sessions.
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return await call_next(request)

        token = auth.split(" ", 1)[1].strip()
        try:
            # Decode without verifying expiry here — the auth dep checks
            # signature + exp. We only need the jti to key the cache.
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=["HS256"],
                options={"verify_exp": False, "verify_signature": True},
            )
        except JWTError:
            return await call_next(request)

        jti = payload.get("jti")
        if not jti:
            return await call_next(request)

        verdict = await self._resolve_verdict(jti)
        if verdict == "deny":
            logger.info("zt_session_gate_denied", jti=jti[:8], path=path)
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        "Zero Trust session revoked. Re-authenticate and "
                        "re-evaluate access via /api/v1/zerotrust/evaluate."
                    )
                },
            )
        if verdict == "expired":
            logger.info("zt_session_gate_expired", jti=jti[:8], path=path)
            return JSONResponse(
                status_code=401,
                content={"detail": "Zero Trust session expired (>8h since last decision)."},
            )

        return await call_next(request)

    async def _resolve_verdict(self, jti: str) -> str:
        """Returns 'allow' | 'deny' | 'expired' | 'unknown'. Prefer cache.
        Falls through to DB on miss. Fail-open on Redis outage."""
        r = await _get_redis()
        cached: Optional[str] = None
        if r is not None:
            try:
                cached = await r.get(f"zt:session:{jti}")
            except Exception as exc:  # noqa: BLE001
                logger.warning("zt_session_cache_read_failed", jti=jti[:8], error=str(exc))
                cached = None
        if cached in ("allow", "deny", "expired"):
            return cached

        # Cache miss → consult AccessDecision via a throwaway DB session.
        # Any DB error fails open (avoids locking everyone out of a
        # healthy platform because ZT telemetry is degraded).
        verdict = "unknown"
        try:
            from sqlalchemy import and_, desc, select
            from src.core.database import async_session_factory
            from src.zerotrust.models import AccessDecision

            async with async_session_factory() as db:
                row = (await db.execute(
                    select(AccessDecision)
                    .where(AccessDecision.session_id == jti)
                    .order_by(desc(AccessDecision.created_at))
                    .limit(1)
                )).scalar_one_or_none()

            if row is None:
                # No decision logged for this session yet — the PDP has
                # not been consulted. Default allow; the PDP creates a
                # decision on first /evaluate call.
                verdict = "allow"
            elif row.decision in ("deny", "isolate"):
                verdict = "deny"
            elif row.created_at and (datetime.now(timezone.utc) - row.created_at) > timedelta(hours=8):
                verdict = "expired"
            else:
                verdict = "allow"
        except Exception as exc:  # noqa: BLE001
            logger.warning("zt_session_gate_db_failed", jti=jti[:8], error=str(exc))
            # Fail open on DB outage.
            return "allow"

        # Cache the result.
        if r is not None:
            try:
                ttl = CACHE_TTL_ALLOW if verdict == "allow" else CACHE_TTL_DENY
                await r.setex(f"zt:session:{jti}", ttl, verdict)
            except Exception:  # noqa: BLE001
                pass

        return verdict
