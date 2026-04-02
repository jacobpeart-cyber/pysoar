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
from src.core.middleware import RequestLoggingMiddleware as AuditLoggingMiddleware
from src.core.encryption import init_encryption
from src.services.user_service import UserService

logger = get_logger(__name__)


def _validate_production_secrets() -> None:
    """Validate production secrets configuration"""
    warnings = settings.validate_production_secrets()

    if settings.is_production:
        if warnings:
            raise RuntimeError(
                f"Production secrets validation failed: {'; '.join(warnings)}"
            )
    else:
        for warning in warnings:
            logger.critical(f"Security warning (development): {warning}")


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

    # Validate production secrets
    _validate_production_secrets()

    # Initialize encryption
    encryption_master_key = settings.encryption_master_key
    if encryption_master_key:
        init_encryption(master_key=encryption_master_key)
    elif settings.is_production:
        raise RuntimeError(
            "ENCRYPTION_MASTER_KEY must be set in production environment"
        )
    else:
        logger.warning("No ENCRYPTION_MASTER_KEY set - using generated key for development")
        init_encryption()

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
                    force_password_change=True,
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

# Add rate limiting middleware
from starlette.middleware.base import BaseHTTPMiddleware
from src.core.rate_limiter import InMemoryRateLimiter

_global_limiter = InMemoryRateLimiter()

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global API rate limiting - 100 requests per minute per IP."""
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/api/"):
            client_ip = request.client.host if request.client else "unknown"
            key = f"global:{client_ip}"
            allowed, info = _global_limiter.check_rate_limit(key, max_requests=100, window_seconds=60)
            if not allowed:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please slow down."},
                    headers={"Retry-After": str(info.get("retry_after", 60))},
                )
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

# Add audit logging middleware
app.add_middleware(AuditLoggingMiddleware)

# Add CORS middleware
cors_origins = settings.cors_origins
if settings.is_production:
    # Strip localhost origins in production
    cors_origins = [origin for origin in cors_origins if "localhost" not in origin and "127.0.0.1" not in origin]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
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
