"""Risk scoring and portable Markdown report tests."""

import asyncio
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.detectors.models import DetectorFinding
from app.models.report import Report
from app.services.report_service import (
    ReportFinding,
    ReportService,
    calculate_risk_score,
    finding_counts,
    render_markdown,
)


def _finding(severity: str, confidence: str, *, title: str = "Example finding") -> DetectorFinding:
    return DetectorFinding(
        detector="test",
        category="test_category",
        severity=severity,  # type: ignore[arg-type]
        confidence=Decimal(confidence),
        file_path="app.py",
        line_start=7,
        line_end=7,
        code_snippet=None,
        title=title,
        description="A finding used to test the report service.",
        ai_explanation="Existing AI context.",
        fix_suggestion="Apply the documented fix.",
    )


def test_confidence_weighted_risk_score_prioritizes_critical_findings() -> None:
    one_critical = [_finding("critical", "1.00", title="Critical issue")]
    five_low = [_finding("low", "1.00", title=f"Low {index}") for index in range(5)]
    low_confidence_critical = [_finding("critical", "0.20")]
    three_critical = [_finding("critical", "1.00") for _ in range(3)]

    assert calculate_risk_score(one_critical) == Decimal("35.0")
    assert calculate_risk_score(five_low) == Decimal("15.0")
    assert calculate_risk_score(low_confidence_critical) == Decimal("7.0")
    assert calculate_risk_score(three_critical) == Decimal("100.0")


def test_markdown_export_has_required_sections_and_remediation_context(tmp_path: Path) -> None:
    scan_id = uuid4()
    report = Report(
        id=uuid4(),
        scan_id=scan_id,
        overall_risk_score=Decimal("35.0"),
        summary="Sentinel AI scanned 1 eligible files and recorded 1 security findings. The overall risk score is 35.0/100, with 1 critical findings.",
        finding_counts=finding_counts([_finding("critical", "1.00", title="Hardcoded credential")]),
    )
    item = ReportFinding(_finding("critical", "1.00", title="Hardcoded credential"), "pending_approval")
    markdown = render_markdown(report, [item])

    assert "## Executive Summary" in markdown
    assert "## Risk Score" in markdown
    assert "## Findings by Severity" in markdown
    assert "## Recommendations" in markdown
    assert "Hardcoded credential" in markdown
    assert "Remediation status: pending_approval" in markdown
    assert "critical=35" in markdown

    session = _ExportSession()
    path = asyncio.run(ReportService(session, settings=Settings(report_export_directory=tmp_path)).export_markdown(report, [item]))

    assert path == tmp_path / f"scan-{scan_id}-security-report.md"
    assert path.read_text(encoding="utf-8") == markdown
    assert report.export_url == f"/scans/{scan_id}/report/export"
    assert session.commits == 1


class _ExportSession:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1
