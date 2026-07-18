"""API contracts for final scan reports and their remediation context."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.scan import FindingResponse


class FindingRemediationStatus(BaseModel):
    id: UUID
    tier: int
    status: str
    pr_url: str | None


class ReportFindingResponse(FindingResponse):
    remediation: FindingRemediationStatus | None


class ScanReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    overall_risk_score: Decimal
    summary: str
    finding_counts: dict[str, Any]
    export_url: str | None
    created_at: datetime
    findings: list[ReportFindingResponse]
