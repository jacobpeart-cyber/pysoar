"""API v1 router aggregating all endpoint routers"""

from fastapi import APIRouter

from src.api.v1.endpoints import (
    alerts,
    api_keys,
    assets,
    audit,
    auth,
    case_management,
    health,
    incidents,
    iocs,
    metrics,
    organizations,
    playbooks,
    settings,
    users,
    websocket,
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(playbooks.router)
api_router.include_router(iocs.router)
api_router.include_router(assets.router)
api_router.include_router(websocket.router)
api_router.include_router(settings.router)
api_router.include_router(audit.router)
api_router.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["api-keys"])
api_router.include_router(organizations.router, tags=["organizations"])
api_router.include_router(case_management.router, tags=["case-management"])
