"""Health check endpoints"""

from fastapi import APIRouter
from sqlalchemy import text

from src import __version__
from src.api.deps import AdminUser
from src.core.config import settings
from src.core.database import async_session_factory
from src.schemas.common import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Health check endpoint for load balancers.
    Verifies actual database and Redis connectivity.
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
    return {
        "status": status,
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected",
    }


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
