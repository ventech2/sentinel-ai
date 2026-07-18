"""API response shape for persisted remediation proposals."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RemediationResponse(BaseModel):
    """A remediation proposal and its safe workflow state."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    tier: int
    status: str
    diff: str | None
    verification_result: dict[str, Any] | None
    pr_url: str | None
    approved_by: UUID | None
    created_at: datetime
