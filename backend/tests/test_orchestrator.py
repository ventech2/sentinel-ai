"""End-to-end orchestration test against the intentionally vulnerable demo app."""

import asyncio
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from app.detectors.models import DetectorFinding
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.services.ingestion import RepositorySnapshot, inventory_existing_repository
from app.services.orchestrator import STATIC_DETECTORS, ScanOrchestrator

SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "sample-data" / "vulnerable-demo-app"


def test_static_detector_registry_includes_model_security_and_prompt_injection_rules() -> None:
    detector_names = {name for name, _detector in STATIC_DETECTORS}

    assert {"prompt_injection_rules", "model_security_rules"}.issubset(detector_names)


class FixtureIngestion:
    def __init__(self, snapshot: RepositorySnapshot) -> None:
        self.snapshot = snapshot
        self.cleaned = False

    async def ingest(self, _db, _project) -> RepositorySnapshot:
        return self.snapshot

    def cleanup(self, _snapshot: RepositorySnapshot) -> None:
        self.cleaned = True


class MockReasoningLayer:
    def __init__(self) -> None:
        self.calls = 0

    def enrich_finding(self, finding: DetectorFinding, _root: Path) -> DetectorFinding:
        self.calls += 1
        return replace(
            finding,
            ai_explanation=f"Mock AI explanation for {finding.category}.",
            fix_suggestion=f"Mock AI fix for {finding.category}.",
        )


class CapturingEvents:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    async def publish(self, _scan_id, event: dict[str, object]) -> None:
        self.events.append(event)


class CapturingSession:
    """Minimal AsyncSession substitute that captures actual ORM records added by the pipeline."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.commits = 0

    def add(self, value: object) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        for value in self.added:
            if isinstance(value, (Finding, Report)) and value.id is None:
                value.id = uuid4()

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, _value: object) -> None:
        return None


def test_full_pipeline_persists_demo_findings_with_scan_linkage() -> None:
    snapshot = inventory_existing_repository(SAMPLE_ROOT)
    ingestion = FixtureIngestion(snapshot)
    reasoning = MockReasoningLayer()
    events = CapturingEvents()
    db = CapturingSession()
    project = Project(
        id=uuid4(),
        user_id=uuid4(),
        repo_url="https://github.com/example/vulnerable-demo-app",
        repo_owner="example",
        repo_name="vulnerable-demo-app",
        default_branch="main",
    )
    scan = Scan(id=uuid4(), project_id=project.id, commit_sha="pending", status="queued")
    scan.project = project

    result = asyncio.run(
        ScanOrchestrator(
            db,
            ingestion=ingestion,
            reasoning_layer=reasoning,
            event_publisher=events,
        ).run(scan)
    )

    persisted = [record for record in db.added if isinstance(record, Finding)]
    reports = [record for record in db.added if isinstance(record, Report)]
    assert result.status == "complete"
    assert result.files_scanned == snapshot.files_scanned
    assert result.commit_sha == "local-fixture"
    assert result.duration_ms is not None
    assert ingestion.cleaned is True
    assert reasoning.calls == len(persisted)
    assert reports and reports[0].scan_id == scan.id
    assert persisted and all(finding.scan_id == scan.id for finding in persisted)
    assert all(finding.ai_explanation and finding.ai_explanation.startswith("Mock AI explanation") for finding in persisted)

    actual = {(finding.category, finding.file_path, finding.line_start) for finding in persisted}
    assert ("hardcoded_secret", "app/main.py", 41) in actual
    assert ("insecure_config", "app/main.py", 26) in actual
    assert ("insecure_config", "app/main.py", 30) in actual
    assert ("hardcoded_auth_bypass", "app/main.py", 69) in actual
    assert ("obfuscated_dynamic_execution", "app/main.py", 97) in actual
    assert ("typosquatted_dependency", "requirements.txt", 10) in actual
    assert ("committed_env_file", ".env", 1) in actual
    assert ("suspicious_outbound_connection", "app/main.py", 113) in actual
    assert [event["status"] for event in events.events if event["type"] == "status"] == [
        "cloning",
        "cloning",
        "static_scan",
        "static_scan",
        "ai_review",
        "merging",
        "complete",
    ]
    assert any(event["type"] == "finding" for event in events.events)


def test_detector_failure_is_recorded_but_other_detectors_complete() -> None:
    snapshot = inventory_existing_repository(SAMPLE_ROOT)
    ingestion = FixtureIngestion(snapshot)
    db = CapturingSession()
    project = Project(
        id=uuid4(),
        user_id=uuid4(),
        repo_url="https://github.com/example/vulnerable-demo-app",
        repo_owner="example",
        repo_name="vulnerable-demo-app",
    )
    scan = Scan(id=uuid4(), project_id=project.id, commit_sha="pending", status="queued")
    scan.project = project

    def broken_detector(_root: Path) -> list[DetectorFinding]:
        raise RuntimeError("fixture detector failure")

    result = asyncio.run(
        ScanOrchestrator(
            db,
            ingestion=ingestion,
            reasoning_layer=MockReasoningLayer(),
            detectors=(("broken", broken_detector),),
        ).run(scan)
    )

    assert result.status == "complete"
    assert result.error_message is not None
    assert "broken failed" in result.error_message
