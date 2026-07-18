"""Finding-review route contracts."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.remediation.service import FlaggedOnlyRemediationError, RemediationService
from app.schemas.remediation import RemediationResponse

router = APIRouter(prefix="/findings")


class FindingFalsePositiveUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_false_positive: bool


class FindingFalsePositiveResponse(BaseModel):
    id: UUID
    is_false_positive: bool


@router.post(
    "/{finding_id}/remediate",
    response_model=RemediationResponse,
    summary="Generate a tiered remediation proposal for a finding",
)
async def remediate_finding(
    finding_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RemediationResponse:
    statement = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.scan).selectinload(Scan.project))
    )
    finding = await db.scalar(statement)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    # Reuse the remediation route's same-session ownership policy without
    # accepting any arbitrary local repository path from the client.
    from app.api.routes.remediations import _ensure_owner, _session_user_id

    _ensure_owner(finding, _session_user_id(request))
    try:
        return await RemediationService(db).remediate(finding)
    except FlaggedOnlyRemediationError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error


@router.patch(
    "/{finding_id}",
    response_model=FindingFalsePositiveResponse,
    summary="Mark or unmark a finding as a false positive",
)
async def update_finding_false_positive(
    finding_id: UUID,
    payload: FindingFalsePositiveUpdate,
    db: AsyncSession = Depends(get_db),
) -> FindingFalsePositiveResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    finding.is_false_positive = payload.is_false_positive
    await db.commit()
    await db.refresh(finding)
    return FindingFalsePositiveResponse(id=finding.id, is_false_positive=finding.is_false_positive)
