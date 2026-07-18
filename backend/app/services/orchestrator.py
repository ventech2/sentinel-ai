"""Queued scan lifecycle: ingestion, deterministic detection, AI enrichment, and persistence."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.db.session import SessionLocal
from app.detectors import (
    ast_rules,
    backdoor_heuristics,
    config_auditor,
    dependency_auditor,
    js_pattern_rules,
    model_security_rules,
    prompt_injection_rules,
    secret_scanner,
)
from app.detectors.models import DetectorFinding
from app.models.constants import ScanStatus
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.queue.redis import RedisScanQueue, redis_client
from app.reasoning.ai_reasoning import AIReasoningLayer
from app.services.ingestion import RepositoryIngestionService, RepositorySnapshot
from app.services.report_service import ReportService

logger = logging.getLogger(__name__)

Detector = Callable[[Path], list[DetectorFinding]]
STATIC_DETECTORS: tuple[tuple[str, Detector], ...] = (
    ("secret_scanner", secret_scanner.scan_repository),
    ("config_auditor", config_auditor.scan_repository),
    ("dependency_auditor", dependency_auditor.scan_repository),
    ("ast_rules", ast_rules.scan_repository),
    # JS/TS is intentionally separate because it uses pattern matching rather
    # than Python AST traversal.
    ("js_pattern_rules", js_pattern_rules.scan_repository),
    ("backdoor_heuristics", backdoor_heuristics.scan_repository),
    ("prompt_injection_rules", prompt_injection_rules.scan_repository),
    ("model_security_rules", model_security_rules.scan_repository),
)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ScanEventPublisher(Protocol):
    async def publish(self, scan_id: UUID, event: dict[str, object]) -> None:
        """Publish one JSON-serializable live scan event."""


class IngestionService(Protocol):
    async def ingest(self, db: AsyncSession, project: Project) -> RepositorySnapshot:
        """Return a temporary repository snapshot."""

    def cleanup(self, snapshot: RepositorySnapshot) -> None:
        """Release a snapshot when its scan is complete."""


class ReasoningLayer(Protocol):
    def enrich_finding(self, finding: DetectorFinding, repository_root: Path) -> DetectorFinding:
        """Explain an existing static finding without creating new findings."""


@dataclass(frozen=True, slots=True)
class DetectorRun:
    name: str
    findings: list[DetectorFinding]
    warning: str | None = None


class ScanOrchestrator:
    """Run one persisted scan through every lifecycle stage safely."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        queue: RedisScanQueue | None = None,
        event_publisher: ScanEventPublisher | None = None,
        ingestion: IngestionService | None = None,
        reasoning_layer: ReasoningLayer | None = None,
        report_service: ReportService | None = None,
        detectors: tuple[tuple[str, Detector], ...] = STATIC_DETECTORS,
    ) -> None:
        self.db = db
        self.queue = queue
        self.events = event_publisher or queue
        self.ingestion = ingestion or RepositoryIngestionService()
        self.reasoning_layer = reasoning_layer or AIReasoningLayer.from_settings()
        self.report_service = report_service or ReportService(db)
        self.detectors = detectors

    async def create_and_enqueue(self, project: Project) -> Scan:
        """Persist a queued scan before offering its ID to Redis."""
        scan = Scan(project_id=project.id, commit_sha="pending", status=str(ScanStatus.QUEUED))
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        try:
            if self.queue is None:
                raise RuntimeError("Scan queue is unavailable.")
            await self.queue.enqueue(scan.id)
            await self._publish_status(scan, "Scan queued.")
        except Exception as error:
            scan.status = str(ScanStatus.FAILED)
            scan.error_message = f"Unable to enqueue scan: {error}"[:1000]
            scan.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            await self._publish_status(scan, "Scan could not be queued.")
            raise
        return scan

    async def run(self, scan: Scan) -> Scan:
        """Execute a full scan. Only fatal lifecycle failures mark it failed."""
        snapshot: RepositorySnapshot | None = None
        warnings: list[str] = []
        try:
            await self._transition(scan, ScanStatus.CLONING, "Cloning repository and building file inventory.")
            snapshot = await self.ingestion.ingest(self.db, scan.project)
            scan.commit_sha = snapshot.commit_sha
            scan.files_scanned = snapshot.files_scanned
            await self.db.commit()
            await self._publish_status(
                scan,
                "Repository inventory complete.",
                languages=snapshot.languages,
                total_bytes=snapshot.total_bytes,
            )

            await self._transition(scan, ScanStatus.STATIC_SCAN, "Running deterministic static detectors.")
            detector_runs = await self._run_detectors(snapshot.root)
            static_findings: list[DetectorFinding] = []
            for run in detector_runs:
                static_findings.extend(run.findings)
                if run.warning:
                    warnings.append(run.warning)
            await self._publish_status(scan, f"Static scan produced {len(static_findings)} findings.")

            await self._transition(scan, ScanStatus.AI_REVIEW, "Explaining static findings with the AI reasoning layer.")
            enriched_findings = await self._enrich_findings(static_findings, snapshot.root)

            await self._transition(scan, ScanStatus.MERGING, "Deduplicating, ranking, and persisting findings.")
            merged_findings = _deduplicate_and_rank(enriched_findings)
            persisted_findings = await self._persist_findings(scan, merged_findings)
            await self.report_service.create(scan, persisted_findings)
            if warnings:
                scan.error_message = "Partial scan warnings: " + "; ".join(warnings)[:900]
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_ms = _duration_ms(scan.started_at, scan.completed_at)
            scan.status = str(ScanStatus.COMPLETE)
            await self.db.commit()
            await self._publish_status(scan, f"Scan complete with {len(merged_findings)} findings.")
        except Exception as error:
            logger.exception("Scan %s failed", scan.id)
            scan.status = str(ScanStatus.FAILED)
            scan.error_message = _safe_error_message(error)
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_ms = _duration_ms(scan.started_at, scan.completed_at)
            await self.db.commit()
            await self._publish_status(scan, "Scan failed.")
        finally:
            if snapshot is not None:
                self.ingestion.cleanup(snapshot)
        return scan

    async def _transition(self, scan: Scan, status: ScanStatus, detail: str) -> None:
        scan.status = str(status)
        if status is ScanStatus.CLONING and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self._publish_status(scan, detail)

    async def _run_detectors(self, root: Path) -> list[DetectorRun]:
        async def run_one(name: str, detector: Detector) -> DetectorRun:
            try:
                findings = await asyncio.to_thread(detector, root)
                return DetectorRun(name=name, findings=findings)
            except Exception as error:
                logger.exception("Detector %s failed for %s", name, root)
                return DetectorRun(name=name, findings=[], warning=f"{name} failed: {_safe_error_message(error)}")

        return list(await asyncio.gather(*(run_one(name, detector) for name, detector in self.detectors)))

    async def _enrich_findings(self, findings: list[DetectorFinding], root: Path) -> list[DetectorFinding]:
        # Deliberately sequential: it respects provider rate limits and the
        # reasoning layer already falls back to the unchanged static finding.
        enriched: list[DetectorFinding] = []
        for finding in findings:
            try:
                enriched.append(await asyncio.to_thread(self.reasoning_layer.enrich_finding, finding, root))
            except Exception:
                logger.exception("Unexpected AI enrichment failure for %s:%s", finding.file_path, finding.line_start)
                enriched.append(finding)
        return enriched

    async def _persist_findings(self, scan: Scan, findings: list[DetectorFinding]) -> list[Finding]:
        persisted: list[Finding] = []
        for finding in findings:
            record = Finding(
                scan_id=scan.id,
                detector=finding.detector,
                category=finding.category,
                severity=finding.severity,
                confidence=finding.confidence,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                code_snippet=finding.code_snippet,
                title=finding.title,
                description=finding.description,
                ai_explanation=finding.ai_explanation,
                fix_suggestion=finding.fix_suggestion,
                is_false_positive=finding.is_false_positive,
            )
            self.db.add(record)
            await self.db.flush()
            persisted.append(record)
            await self._publish(
                scan.id,
                {
                    "type": "finding",
                    "scan_id": str(scan.id),
                    "finding_id": str(record.id) if record.id else None,
                    "detector": record.detector,
                    "category": record.category,
                    "severity": record.severity,
                    "confidence": float(record.confidence),
                    "file_path": record.file_path,
                    "line_start": record.line_start,
                    "title": record.title,
                },
            )
        return persisted

    async def _publish_status(self, scan: Scan, detail: str, **extra: object) -> None:
        await self._publish(
            scan.id,
            {
                "type": "status",
                "scan_id": str(scan.id),
                "status": scan.status,
                "detail": detail,
                "files_scanned": scan.files_scanned,
                **extra,
            },
        )

    async def _publish(self, scan_id: UUID, event: dict[str, object]) -> None:
        if self.events is None:
            return
        try:
            await self.events.publish(scan_id, event)
        except Exception:
            # Redis progress should never turn an otherwise valid scan into a
            # failed one; polling endpoints still expose durable DB state.
            logger.exception("Could not publish live event for scan %s", scan_id)


async def process_queued_scan(
    scan_id: UUID,
    *,
    session_factory: async_sessionmaker[AsyncSession] = SessionLocal,
    queue: RedisScanQueue | None = None,
) -> Scan | None:
    """Worker entry point: load one scan with project context and execute it."""
    async with session_factory() as db:
        scan = await db.scalar(
            select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.project))
        )
        if scan is None:
            logger.warning("Discarding queued job for unknown scan %s", scan_id)
            return None
        active_queue = queue or RedisScanQueue(redis_client)
        return await ScanOrchestrator(db, queue=active_queue).run(scan)


def _deduplicate_and_rank(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    unique: dict[tuple[str, str, int | None, str], DetectorFinding] = {}
    for finding in findings:
        key = (finding.category, finding.file_path, finding.line_start, finding.title)
        existing = unique.get(key)
        if existing is None or finding.confidence > existing.confidence:
            unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), -float(finding.confidence), finding.file_path),
    )


def _duration_ms(started_at: datetime | None, completed_at: datetime) -> int | None:
    if started_at is None:
        return None
    return max(0, int((completed_at - started_at).total_seconds() * 1000))


def _safe_error_message(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"[:1000]
