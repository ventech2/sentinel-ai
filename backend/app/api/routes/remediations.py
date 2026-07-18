"""Human approval and status endpoints for remediation proposals."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import Scan
from app.remediation.service import RemediationService
from app.schemas.remediation import RemediationResponse

router = APIRouter(prefix="/remediations")


@router.post(
    "/{remediation_id}/approve",
    response_model=RemediationResponse,
    summary="Approve a Tier 2 remediation and begin safe branch preparation",
)
async def approve_remediation(
    remediation_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RemediationResponse:
    remediation = await _load_remediation(db, remediation_id)
    user_id = _session_user_id(request)
    _ensure_owner(remediation.finding, user_id)
    try:
        return await RemediationService(db).approve(remediation, remediation.finding, user_id)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get(
    "/{remediation_id}",
    response_model=RemediationResponse,
    summary="Get remediation status, proposed diff, and verification result",
)
async def get_remediation(
    remediation_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RemediationResponse:
    remediation = await _load_remediation(db, remediation_id)
    _ensure_owner(remediation.finding, _session_user_id(request))
    return remediation


async def _load_remediation(db: AsyncSession, remediation_id: UUID) -> Remediation:
    statement = (
        select(Remediation)
        .where(Remediation.id == remediation_id)
        .options(
            selectinload(Remediation.finding)
            .selectinload(Finding.scan)
            .selectinload(Scan.project)
        )
    )
    remediation = await db.scalar(statement)
    if remediation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found.")
    return remediation


def _session_user_id(request: Request) -> UUID:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="GitHub login is required.")
    try:
        return UUID(str(user_id))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.") from error


def _ensure_owner(finding: Finding, user_id: UUID) -> None:
    if finding.scan is None or finding.scan.project is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Finding lacks project context.")
    if finding.scan.project.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to access this remediation.")
