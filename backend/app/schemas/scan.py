"""API contracts for queued scans and persisted detector findings."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    commit_sha: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    files_scanned: int
    duration_ms: int | None
    created_at: datetime


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    detector: str
    category: str
    severity: str
    confidence: Decimal
    file_path: str
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    title: str
    description: str
    ai_explanation: str | None
    fix_suggestion: str | None
    is_false_positive: bool
    created_at: datetime
