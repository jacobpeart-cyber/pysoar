"""Health check endpoints"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter
from sqlalchemy import text

from src import __version__
from src.api.deps import AdminUser, CurrentUser, DatabaseSession, RedisClient
from src.core import metrics as agentic_metrics
from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.schemas.common import HealthResponse
from src.schemas.settings import LLMHealthResponse

logger = get_logger(__name__)

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Health check endpoint for load balancers.
    Returns minimal status only (no internal details).
    """
    db_ok = False
    redis_ok = False

    try:
        async with async_session_factory() as db:
            await db.execute(text("SELECT 1"))
            db_ok = True
    except Exception:
        pass

    try:
        from redis import asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        redis_ok = True
        await r.aclose()
    except Exception:
        pass

    status = "healthy" if (db_ok and redis_ok) else "degraded"
    return {"status": status}


@router.get("/health/detailed", response_model=HealthResponse)
async def health_check_detailed(admin: AdminUser = None):
    """
    Detailed health check endpoint for authenticated admins.
    """
    health = await health_check()
    return HealthResponse(
        status=health["status"],
        version=__version__,
        environment=settings.app_env,
        database=health["database"],
        redis=health["redis"],
    )


@router.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": __version__,
        "docs": f"{settings.api_v1_prefix}/docs",
    }


# ---------------------------------------------------------------------------
# GET /health/llm  (design v2 section 9)
#
# Per-organization provider reachability WITHOUT calling the provider: it
# resolves the stored configuration, reads the newest successful call out of
# llm_call_logs and asks the quota breaker whether it is open. The answer is
# cached in-process for 60 seconds per organization so a dashboard polling it
# costs at most one resolution per minute per worker.
# ---------------------------------------------------------------------------

_LLM_HEALTH_TTL_SECONDS = 60.0
# org_id -> (monotonic_deadline, payload)
_llm_health_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_llm_health_lock = asyncio.Lock()

#: The breaker read is a Redis round-trip; past this it is reported as unknown
#: rather than delaying a health response.
_BREAKER_READ_TIMEOUT_SECONDS = 2.0


async def _breaker_open(
    redis: Any, provider: str, credential_source: str, org_id: str
) -> Optional[bool]:
    """Whether the provider breaker is open for this org; None when unknown."""
    from src.llm.quota import CircuitOpen, TokenQuota

    quota = TokenQuota(redis_factory=lambda: redis)
    try:
        async with asyncio.timeout(_BREAKER_READ_TIMEOUT_SECONDS):
            await quota.breaker_check(provider, credential_source, org_id)
        return False
    except CircuitOpen:
        return True
    except (TimeoutError, OSError) as exc:
        logger.warning(
            "llm_health_breaker_unreadable", organization_id=org_id, error=type(exc).__name__
        )
        return None


async def _compute_llm_health(db: Any, redis: Any, org_id: str) -> Dict[str, Any]:
    """Resolve configuration + last call + breaker for one organization."""
    from src.api.v1.endpoints.settings import last_successful_llm_call_at
    from src.llm.base import LLMNotConfigured
    from src.llm.factory import resolve_llm_config

    payload: Dict[str, Any] = {
        "status": "not_configured",
        "organization_id": org_id,
        "configured": False,
        "provider": None,
        "model": None,
        "source": "none",
        "reason": None,
        "last_successful_call_at": None,
        "breaker_open": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
    }
    try:
        resolved, _api_key = await resolve_llm_config(db, org_id)
    except LLMNotConfigured as exc:
        payload["reason"] = getattr(exc, "reason", "ai_not_configured")
        payload["last_successful_call_at"] = await last_successful_llm_call_at(db, org_id)
        return payload

    payload.update(
        {
            "configured": True,
            "provider": resolved.provider,
            "model": resolved.model,
            "source": resolved.credential_source,
            "last_successful_call_at": await last_successful_llm_call_at(db, org_id),
        }
    )
    open_state = await _breaker_open(redis, resolved.provider, resolved.credential_source, org_id)
    payload["breaker_open"] = open_state
    payload["status"] = "degraded" if open_state else "ok"
    return payload


@router.get("/health/llm", response_model=LLMHealthResponse)
async def health_llm(
    db: DatabaseSession = None,
    redis: RedisClient = None,
    current_user: CurrentUser = None,
) -> LLMHealthResponse:
    """LLM provider health for the caller's organization (authenticated).

    Never calls the provider: configuration resolution, the newest successful
    ``llm_call_logs`` row and the circuit-breaker flag are all local reads.
    Cached for 60 s per organization in this process.
    """
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        # Honest answer rather than a 400: a user outside any organization has
        # no per-org provider to report on.
        return LLMHealthResponse(
            status="not_configured",
            organization_id=None,
            configured=False,
            source="none",
            reason="no_organization",
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    org_id = str(org_id)
    now = time.monotonic()
    async with _llm_health_lock:
        cached = _llm_health_cache.get(org_id)
    if cached and cached[0] > now:
        payload = dict(cached[1])
        payload["cached"] = True
        return LLMHealthResponse(**payload)

    payload = await _compute_llm_health(db, redis, org_id)
    async with _llm_health_lock:
        _llm_health_cache[org_id] = (now + _LLM_HEALTH_TTL_SECONDS, dict(payload))
        if len(_llm_health_cache) > 512:
            for stale in [k for k, (deadline, _v) in _llm_health_cache.items() if deadline <= now]:
                _llm_health_cache.pop(stale, None)
    return LLMHealthResponse(**payload)


@router.get("/metrics/agentic")
async def agentic_metrics_snapshot(admin: AdminUser = None) -> Dict[str, Any]:
    """The agentic counters for THIS process as JSON (admin).

    ``prometheus_client`` is not a dependency and there is no scrape endpoint,
    so ``src/core/metrics.py`` keeps the three counters the design names in a
    process-local registry and this route exposes them. Per-process and reset
    on restart by construction -- ``llm_call_logs`` and ``audit_trails`` remain
    the durable record. See the module docstring for where the runtime wires
    the increments.
    """
    return agentic_metrics.snapshot()
