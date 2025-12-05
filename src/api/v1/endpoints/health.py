"""Health check endpoints"""

from fastapi import APIRouter

from src import __version__
from src.core.config import settings
from src.schemas.common import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
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
