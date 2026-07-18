"""Connected GitHub project and scan-queue endpoints."""

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.models.project import Project
from app.queue.redis import RedisScanQueue, get_redis
from app.schemas.project import ProjectResponse
from app.services.github_repository import GitHubRepositoryError, get_repository_default_branch
from app.schemas.scan import ScanResponse
from app.services.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/projects")
GITHUB_REPOSITORY_URL = re.compile(r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str = Field(min_length=1)


@router.get("", response_model=list[ProjectResponse], summary="List the current user's projects")
async def list_projects(request: Request, db: AsyncSession = Depends(get_db)) -> list[Project]:
    user_id = _session_user_id(request)
    return list((await db.scalars(select(Project).where(Project.user_id == user_id).order_by(Project.created_at.desc()))).all())


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, summary="Connect a GitHub repository")
async def create_project(
    payload: ProjectCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Project:
    owner, repository = _parse_github_repository(payload.repo_url)
    user_id = _session_user_id(request)
    try:
        default_branch = await get_repository_default_branch(
            db,
            user_id=user_id,
            owner=owner,
            repository=repository,
            settings=get_settings(),
        )
    except GitHubRepositoryError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to read the selected repository's default branch: {error}",
        ) from error
    project = Project(
        user_id=user_id,
        repo_url=f"https://github.com/{owner}/{repository}",
        repo_owner=owner,
        repo_name=repository,
        default_branch=default_branch,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse, summary="Get project detail")
async def get_project(project_id: UUID, request: Request, db: AsyncSession = Depends(get_db)) -> Project:
    return await _owned_project(db, project_id, _session_user_id(request))


@router.post(
    "/{project_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a new project scan",
)
async def trigger_project_scan(
    project_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> ScanResponse:
    project = await _owned_project(db, project_id, _session_user_id(request))
    try:
        return await ScanOrchestrator(db, queue=RedisScanQueue(redis)).create_and_enqueue(project)
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Unable to queue scan: {error}") from error


async def _owned_project(db: AsyncSession, project_id: UUID, user_id: UUID) -> Project:
    project = await db.scalar(select(Project).where(Project.id == project_id, Project.user_id == user_id))
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return project


def _session_user_id(request: Request) -> UUID:
    raw_user_id = request.session.get("user_id")
    if not raw_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="GitHub login is required.")
    try:
        return UUID(str(raw_user_id))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.") from error


def _parse_github_repository(repo_url: str) -> tuple[str, str]:
    match = GITHUB_REPOSITORY_URL.fullmatch(repo_url.strip())
    if match is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Use a https://github.com/{owner}/{repository} URL.",
        )
    return match.group("owner"), match.group("name")
