"""Operational health endpoint."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="API liveness check")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
