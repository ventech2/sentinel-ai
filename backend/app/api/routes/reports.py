"""Final report retrieval and local Markdown export endpoints."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.remediation import Remediation
from app.models.report import Report
from app.models.scan import Scan
from app.schemas.report import FindingRemediationStatus, ReportFindingResponse, ScanReportResponse
from app.services.report_service import ReportFinding, ReportService

router = APIRouter(prefix="/scans")


@router.get("/{scan_id}/report", response_model=ScanReportResponse, summary="Get the final prioritized scan report")
async def get_scan_report(scan_id: UUID, request: Request, db: AsyncSession = Depends(get_db)) -> ScanReportResponse:
    report, findings = await _owned_report_and_findings(db, scan_id, _session_user_id(request))
    return _report_response(report, findings)


@router.get("/{scan_id}/report/export", summary="Download the final report as Markdown")
async def export_scan_report(scan_id: UUID, request: Request, db: AsyncSession = Depends(get_db)) -> FileResponse:
    report, findings = await _owned_report_and_findings(db, scan_id, _session_user_id(request))
    export_items = [ReportFinding(finding, _latest_remediation(finding).status if _latest_remediation(finding) else None) for finding in findings]
    path = await ReportService(db).export_markdown(report, export_items)
    return FileResponse(
        path,
        media_type="text/markdown; charset=utf-8",
        filename=f"sentinel-scan-{scan_id}-report.md",
    )


async def _owned_report_and_findings(
    db: AsyncSession,
    scan_id: UUID,
    user_id: UUID,
) -> tuple[Report, list[Finding]]:
    scan = await db.scalar(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.project))
    )
    if scan is None or scan.project.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    report = await db.scalar(select(Report).where(Report.scan_id == scan_id))
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report is not available until the scan has completed.",
        )
    findings = list(
        (
            await db.scalars(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .options(selectinload(Finding.remediations))
                .order_by(Finding.created_at.asc())
            )
        ).all()
    )
    return report, findings


def _report_response(report: Report, findings: list[Finding]) -> ScanReportResponse:
    return ScanReportResponse(
        id=report.id,
        scan_id=report.scan_id,
        overall_risk_score=report.overall_risk_score,
        summary=report.summary,
        finding_counts=report.finding_counts,
        export_url=report.export_url,
        created_at=report.created_at,
        findings=[_report_finding_response(finding) for finding in findings],
    )


def _report_finding_response(finding: Finding) -> ReportFindingResponse:
    remediation = _latest_remediation(finding)
    return ReportFindingResponse(
        **{
            field: getattr(finding, field)
            for field in FindingResponseFields
        },
        remediation=(
            FindingRemediationStatus(
                id=remediation.id,
                tier=remediation.tier,
                status=remediation.status,
                pr_url=remediation.pr_url,
            )
            if remediation is not None
            else None
        ),
    )


FindingResponseFields = (
    "id",
    "scan_id",
    "detector",
    "category",
    "severity",
    "confidence",
    "file_path",
    "line_start",
    "line_end",
    "code_snippet",
    "title",
    "description",
    "ai_explanation",
    "fix_suggestion",
    "is_false_positive",
    "created_at",
)


def _latest_remediation(finding: Finding) -> Remediation | None:
    if not finding.remediations:
        return None
    baseline = datetime.min.replace(tzinfo=timezone.utc)
    return max(finding.remediations, key=lambda remediation: remediation.created_at or baseline)


def _session_user_id(request: Request) -> UUID:
    raw_user_id = request.session.get("user_id")
    if not raw_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="GitHub login is required.")
    try:
        return UUID(str(raw_user_id))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.") from error
