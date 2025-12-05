"""PySOAR - Security Orchestration, Automation and Response Platform

Main FastAPI application entry point.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src import __version__
from src.api.v1.router import api_router
from src.core.config import settings
from src.core.database import close_db, init_db
from src.core.exceptions import PySOARException
from src.core.logging import get_logger, setup_logging
from src.services.user_service import UserService

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan events"""
    # Startup
    setup_logging()
    logger.info(
        "Starting PySOAR",
        version=__version__,
        environment=settings.app_env,
    )

    # Initialize database
    await init_db()
    logger.info("Database initialized")

    # Create first admin user if needed
    await create_first_admin()

    yield

    # Shutdown
    logger.info("Shutting down PySOAR")
    await close_db()


async def create_first_admin():
    """Create the first admin user if no users exist"""
    from src.core.database import async_session_factory

    async with async_session_factory() as db:
        user_service = UserService(db)
        users, total = await user_service.list_users(page=1, size=1)

        if total == 0:
            try:
                await user_service.create(
                    email=settings.first_admin_email,
                    password=settings.first_admin_password,
                    full_name="Admin User",
                    role="admin",
                    is_superuser=True,
                )
                await db.commit()
                logger.info(
                    "Created first admin user",
                    email=settings.first_admin_email,
                )
            except Exception as e:
                logger.error(f"Failed to create admin user: {e}")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Security Orchestration, Automation and Response Platform",
    version=__version__,
    docs_url=f"{settings.api_v1_prefix}/docs",
    redoc_url=f"{settings.api_v1_prefix}/redoc",
    openapi_url=f"{settings.api_v1_prefix}/openapi.json",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handlers
@app.exception_handler(PySOARException)
async def pysoar_exception_handler(request: Request, exc: PySOARException):
    """Handle custom PySOAR exceptions"""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": exc.__class__.__name__,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": "Request validation failed",
            "details": {"errors": exc.errors()},
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred",
        },
    )


# Include API router
app.include_router(api_router, prefix=settings.api_v1_prefix)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": settings.app_name,
        "version": __version__,
        "description": "Security Orchestration, Automation and Response Platform",
        "docs": f"{settings.api_v1_prefix}/docs",
        "api": settings.api_v1_prefix,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.is_development,
        workers=settings.workers,
    )
