"""API response contract for connected GitHub projects."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    repo_url: str
    repo_owner: str
    repo_name: str
    default_branch: str
    created_at: datetime
