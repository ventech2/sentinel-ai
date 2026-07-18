"""Root router for the API gateway."""

from fastapi import APIRouter

from app.api.routes.auth import router as auth_router
from app.api.routes.findings import router as findings_router
from app.api.routes.health import router as health_router
from app.api.routes.projects import router as projects_router
from app.api.routes.reports import router as reports_router
from app.api.routes.remediations import router as remediations_router
from app.api.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(auth_router, tags=["auth"])
api_router.include_router(health_router, tags=["health"])
api_router.include_router(projects_router, tags=["projects"])
api_router.include_router(scans_router, tags=["scans"])
api_router.include_router(findings_router, tags=["findings"])
api_router.include_router(remediations_router, tags=["remediations"])
api_router.include_router(reports_router, tags=["reports"])
