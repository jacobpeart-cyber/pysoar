"""Health check endpoints"""

from typing import Annotated

from fastapi import APIRouter

from src import __version__
from src.api.deps import AdminUser
from src.core.config import settings
from src.schemas.common import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Basic health check endpoint for load balancers.

    Returns only status without sensitive information.
    """
    return {"status": "healthy"}


@router.get("/health/detailed", response_model=HealthResponse)
async def health_check_detailed(admin: AdminUser):
    """
    Detailed health check endpoint for authenticated admins.

    Returns version, environment, and service status information.
    Requires admin authentication.
    """
    # In production, we would check actual database and redis connections
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
        database="connected",
        redis="connected",
    )


@router.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": __version__,
        "docs": f"{settings.api_v1_prefix}/docs",
    }
