"""API router aggregate."""

from fastapi import APIRouter

from .routes_assets import router as assets_router
from .routes_auth import router as auth_router
from .routes_clients import router as clients_router
from .routes_controls import router as controls_router
from .routes_engagements import router as engagements_router
from .routes_insight import router as insight_router
from .routes_remediation import router as remediation_router
from .routes_risks import router as risks_router
from .routes_system import router as system_router
from .routes_users import router as users_router

api_router = APIRouter()
api_router.include_router(system_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(clients_router)
api_router.include_router(engagements_router)
api_router.include_router(assets_router)
api_router.include_router(risks_router)
api_router.include_router(controls_router)
api_router.include_router(remediation_router)
api_router.include_router(insight_router)

__all__ = ["api_router"]
