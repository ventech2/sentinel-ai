"""Prioritized, finding-grounded security report generation and Markdown export."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan

SEVERITIES = ("critical", "high", "medium", "low", "info")
# Per-finding base impact points. Each is multiplied by the static/AI-adjusted
# confidence (0.00-1.00), summed, capped at 100, and rounded to one decimal.
RISK_WEIGHTS = {
    "critical": Decimal("35"),
    "high": Decimal("18"),
    "medium": Decimal("8"),
    "low": Decimal("3"),
    "info": Decimal("0"),
}
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}


class FindingLike(Protocol):
    severity: str
    confidence: Decimal
    title: str
    description: str
    file_path: str
    line_start: int | None
    ai_explanation: str | None
    fix_suggestion: str | None


@dataclass(frozen=True, slots=True)
class ReportFinding:
    finding: FindingLike
    remediation_status: str | None = None


class ReportService:
    """Create durable reports exclusively from findings already persisted for a scan."""

    def __init__(self, db: AsyncSession, *, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()

    async def create(self, scan: Scan, findings: list[Finding]) -> Report:
        """Persist one complete report after detector and AI results have been stored."""
        counts = finding_counts(findings)
        report = Report(
            scan_id=scan.id,
            overall_risk_score=calculate_risk_score(findings),
            summary=build_executive_summary(scan.files_scanned, findings, counts),
            finding_counts=counts,
        )
        self.db.add(report)
        await self.db.flush()
        return report

    async def export_markdown(self, report: Report, findings: list[ReportFinding]) -> Path:
        """Write a local Markdown report and store its API download URL."""
        output_dir = self.settings.report_export_directory.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"scan-{report.scan_id}-security-report.md"
        path.write_text(render_markdown(report, findings), encoding="utf-8")
        report.export_url = f"/scans/{report.scan_id}/report/export"
        await self.db.commit()
        return path


def finding_counts(findings: Iterable[FindingLike]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def calculate_risk_score(findings: Iterable[FindingLike]) -> Decimal:
    """Return ``min(100, sum(base_weight × confidence))`` rounded to one decimal."""
    score = sum(
        (
            RISK_WEIGHTS.get(finding.severity, Decimal("0")) * Decimal(finding.confidence)
            for finding in findings
        ),
        Decimal("0"),
    )
    return min(Decimal("100"), score).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)


def build_executive_summary(files_scanned: int, findings: list[FindingLike], counts: dict[str, int]) -> str:
    """Produce 2–3 grounded sentences without inventing risks beyond the finding list."""
    total = len(findings)
    score = calculate_risk_score(findings)
    summary = [f"Sentinel AI scanned {files_scanned} eligible files and recorded {total} security findings."]
    nonzero = [f"{counts.get(severity, 0)} {severity}" for severity in SEVERITIES if counts.get(severity, 0)]
    if nonzero:
        summary.append(f"The overall risk score is {score}/100, with " + ", ".join(nonzero) + " findings.")
        highest = min(findings, key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), -float(finding.confidence)))
        location = f" in {highest.file_path}" + (f" line {highest.line_start}" if highest.line_start else "")
        summary.append(f"Prioritize {highest.title}{location}, then review the linked remediation recommendations.")
    else:
        summary.append("No static findings were persisted for this scan; continue normal secure-development review.")
    return " ".join(summary)


def render_markdown(report: Report, findings: list[ReportFinding]) -> str:
    """Render a portable Markdown report without embedding sensitive source snippets."""
    sections = [
        "# Sentinel AI Security Report",
        "",
        "## Executive Summary",
        "",
        report.summary,
        "",
        "## Risk Score",
        "",
        f"**{report.overall_risk_score}/100**",
        "",
        "Formula: `min(100, Σ severity weight × confidence)` using critical=35, high=18, medium=8, low=3, info=0.",
        "",
        "## Findings by Severity",
        "",
    ]
    for severity in SEVERITIES:
        severity_findings = [item for item in findings if item.finding.severity == severity]
        sections.extend([f"### {severity.title()} ({len(severity_findings)})", ""])
        if not severity_findings:
            sections.extend(["None.", ""])
            continue
        for item in severity_findings:
            finding = item.finding
            location = finding.file_path + (f":{finding.line_start}" if finding.line_start else "")
            sections.extend(
                [
                    f"- **{finding.title}** — `{location}` (confidence: {finding.confidence})",
                    f"  - {finding.description}",
                    f"  - Remediation status: {item.remediation_status or 'not proposed'}",
                    "",
                ]
            )

    recommendations = _recommendations(findings)
    sections.extend(["## Recommendations", ""])
    if recommendations:
        sections.extend([f"{index}. {recommendation}" for index, recommendation in enumerate(recommendations, start=1)])
    else:
        sections.append("No remediation recommendations were generated for this scan.")
    sections.append("")
    return "\n".join(sections)


def _recommendations(findings: list[ReportFinding]) -> list[str]:
    unique: list[str] = []
    for item in sorted(findings, key=lambda item: SEVERITY_ORDER.get(item.finding.severity, 99)):
        suggestion = item.finding.fix_suggestion
        if suggestion and suggestion not in unique:
            unique.append(suggestion)
    return unique
