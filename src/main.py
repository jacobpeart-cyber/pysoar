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

    # Register built-in threat feeds (idempotent — safe to run every boot)
    try:
        from src.intel.feeds import FeedManager
        created = await FeedManager().register_builtin_feeds()
        if created:
            logger.info("Registered built-in threat feeds", count=created)
    except Exception as e:  # noqa: BLE001
        logger.warning("Built-in feed registration failed", error=str(e))

    # Seed compliance frameworks (idempotent). Populates FedRAMP Moderate
    # w/ 191 NIST 800-53 Rev 5 controls, plus NIST 800-171, CMMC 2 L2,
    # PCI DSS v4, HIPAA, SOC 2, and ISO 27001:2022 for every organization.
    try:
        from src.compliance.seeder import seed_all_compliance_frameworks
        result = await seed_all_compliance_frameworks()
        if result.get("frameworks_created", 0) or result.get("controls_added", 0):
            logger.info(
                "Seeded compliance frameworks",
                orgs=result.get("organizations", 0),
                frameworks_created=result.get("frameworks_created", 0),
                controls_added=result.get("controls_added", 0),
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("Compliance framework seeding failed", error=str(e))

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
    """Global API rate limiting. SOC dashboards load many widgets in
    parallel on every page switch, so the per-IP cap has to be generous
    enough that a single operator browsing doesn't get throttled —
    600/min ≈ 10/s, which still blunts a runaway client or scraper.
    Authenticated per-endpoint throttles tighten down the sensitive ops
    (see @rate_limit decorators in src/core/rate_limiter.py)."""
    async def dispatch(self, request, call_next):
        # Skip WebSocket connections — BaseHTTPMiddleware breaks them
        if request.url.path.endswith("/ws"):
            return await call_next(request)
        if request.url.path.startswith("/api/"):
            client_ip = request.client.host if request.client else "unknown"
            key = f"global:{client_ip}"
            allowed, retry_after = _global_limiter.check_rate_limit(key, max_requests=600, window_seconds=60)
            if not allowed:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please slow down."},
                    headers={"Retry-After": str(retry_after or 60)},
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
    # Sanitize errors — convert any non-serializable objects to strings
    import json as _json
    safe_errors = []
    for err in exc.errors():
        safe_err = {}
        for k, v in err.items():
            try:
                _json.dumps(v)
                safe_err[k] = v
            except (TypeError, ValueError):
                safe_err[k] = str(v)
        safe_errors.append(safe_err)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": "Request validation failed",
            "details": {"errors": safe_errors},
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


# Direct WebSocket mount — bypasses BaseHTTPMiddleware which breaks WS
from fastapi import WebSocket, Query as WSQuery
from src.services.websocket_manager import manager as ws_manager
from src.api.v1.endpoints.websocket import get_user_from_token

@app.websocket("/api/v1/ws")
async def ws_direct(websocket: WebSocket, token: str = WSQuery(default="")):
    """WebSocket endpoint mounted directly on app to bypass middleware."""
    user_id = await get_user_from_token(token) if token else None
    if not user_id:
        await websocket.accept()
        await websocket.close(code=4001, reason="Authentication required")
        return
    try:
        await ws_manager.connect(websocket, user_id)
        while True:
            try:
                data = await websocket.receive_json()
                action = data.get("action", "")
                if action == "ping":
                    await websocket.send_json({"type": "pong"})
                elif action == "subscribe":
                    await ws_manager.subscribe(user_id, data.get("channel", ""))
                elif action == "unsubscribe":
                    await ws_manager.unsubscribe(user_id, data.get("channel", ""))
            except Exception:
                break
    except Exception:
        pass
    finally:
        ws_manager.disconnect(user_id)


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
