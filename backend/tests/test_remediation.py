"""Remediation safety tests using the intentionally vulnerable demo fixture."""

import ast
import asyncio
from dataclasses import asdict
from decimal import Decimal
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from uuid import uuid4

import pytest
import httpx

from app.detectors import ast_rules, config_auditor, dependency_auditor, secret_scanner
from app.detectors.models import DetectorFinding
from app.models.constants import RemediationStatus
from app.remediation.classifier import RemediationTier, classify_finding
from app.remediation.fix_generator import FileChange, FixProposal, generate_fix
from app.remediation.github_pr import (
    GitHubIntegrationError,
    PreparedBranch,
    PullRequestResult,
    create_github_pull_request,
    prepare_isolated_branch,
    remediation_branch_name,
    SENTINEL_GIT_AUTHOR_EMAIL,
    SENTINEL_GIT_AUTHOR_NAME,
)
from app.remediation.service import RemediationService
from app.remediation.state_machine import InvalidRemediationTransition, transition
from app.remediation.verifier import verify_proposal
from app.reasoning.ai_reasoning import AIReasoningLayer
from app.services.ingestion import IngestionError, RepositorySnapshot, inventory_existing_repository

SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "sample-data" / "vulnerable-demo-app"


def _finding_with_category(category: str) -> DetectorFinding:
    return DetectorFinding(
        detector="test",
        category=category,
        severity="high",
        confidence=Decimal("0.80"),
        file_path="app/main.py",
        line_start=1,
        line_end=1,
        code_snippet="example",
        title="example",
        description="example",
    )


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("hardcoded_secret", RemediationTier.AUTO_FIXABLE),
        ("insecure_config", RemediationTier.AUTO_FIXABLE),
        ("typosquatted_dependency", RemediationTier.AUTO_FIXABLE),
        ("hardcoded_auth_bypass", RemediationTier.HUMAN_APPROVAL),
        ("obfuscated_dynamic_execution", RemediationTier.HUMAN_APPROVAL),
        ("suspicious_outbound_connection", RemediationTier.FLAGGED_ONLY),
        ("suspicious_install_script", RemediationTier.FLAGGED_ONLY),
        ("unrecognized_dependency", RemediationTier.FLAGGED_ONLY),
    ],
)
def test_classifies_remediation_tiers_conservatively(category: str, expected: RemediationTier) -> None:
    assert classify_finding(_finding_with_category(category)) is expected


def test_stripe_secret_template_generates_parseable_patch_with_mocked_ai_context() -> None:
    finding = next(item for item in secret_scanner.scan_repository(SAMPLE_ROOT) if item.file_path == "app/main.py")
    response = json.dumps(
        {
            "severity": "critical",
            "confidence": 0.98,
            "explanation": "A real live Stripe credential in source code can be reused by anyone with repository access.",
            "fix_suggestion": "Load STRIPE_API_KEY from the deployment environment and rotate the exposed key.",
            "exploitability_notes": "Repository readers or build logs can expose the key.",
        }
    )
    fake_client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_: SimpleNamespace(output_text=response)))
    enriched = AIReasoningLayer(provider="openai", client=fake_client).enrich_finding(finding, SAMPLE_ROOT)

    proposal = generate_fix(enriched, SAMPLE_ROOT)

    assert proposal.tier is RemediationTier.AUTO_FIXABLE
    assert proposal.has_changes
    assert 'STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")' in (proposal.diff or "")
    assert "AI fix context: Load STRIPE_API_KEY" in proposal.guidance
    assert verify_proposal(proposal)["valid"] is True
    ast.parse(proposal.changes[0].updated_content)


def test_tier_one_templates_cover_insecure_config_and_typosquat_fixture() -> None:
    config_findings = config_auditor.scan_repository(SAMPLE_ROOT)
    debug = next(item for item in config_findings if item.file_path == "app/main.py" and "Debug mode" in item.title)
    cors = next(item for item in config_findings if item.file_path == "app/main.py" and "Wildcard CORS" in item.title)
    typo = next(item for item in dependency_auditor.scan_repository(SAMPLE_ROOT) if item.category == "typosquatted_dependency")

    debug_proposal = generate_fix(debug, SAMPLE_ROOT)
    cors_proposal = generate_fix(cors, SAMPLE_ROOT)
    typo_proposal = generate_fix(typo, SAMPLE_ROOT)

    assert "DEBUG = False" in (debug_proposal.diff or "")
    assert 'allow_origins=["https://app.example.com"]' in (cors_proposal.diff or "")
    assert "requests==2.31.0" in (typo_proposal.diff or "")
    assert verify_proposal(debug_proposal)["valid"] is True
    assert verify_proposal(cors_proposal)["valid"] is True
    assert verify_proposal(typo_proposal)["valid"] is True


def test_tier_two_auth_and_dynamic_fixes_are_proposals_only() -> None:
    findings = ast_rules.scan_repository(SAMPLE_ROOT)
    auth_bypass = next(item for item in findings if item.category == "hardcoded_auth_bypass")
    dynamic_execution = next(item for item in findings if item.category == "obfuscated_dynamic_execution")

    auth_proposal = generate_fix(auth_bypass, SAMPLE_ROOT)
    dynamic_proposal = generate_fix(dynamic_execution, SAMPLE_ROOT)

    assert auth_proposal.tier is RemediationTier.HUMAN_APPROVAL
    assert "removed hardcoded authentication bypass" in (auth_proposal.diff or "")
    assert "requires explicit human approval" in auth_proposal.guidance
    assert dynamic_proposal.tier is RemediationTier.HUMAN_APPROVAL
    assert 'raise RuntimeError("Disabled by Sentinel pending security review")' in (dynamic_proposal.diff or "")
    assert verify_proposal(auth_proposal)["valid"] is True
    assert verify_proposal(dynamic_proposal)["valid"] is True


def test_tier_three_never_generates_a_patch() -> None:
    network_finding = _finding_with_category("suspicious_outbound_connection")

    proposal = generate_fix(network_finding, SAMPLE_ROOT)

    assert proposal.tier is RemediationTier.FLAGGED_ONLY
    assert proposal.diff is None
    assert not proposal.has_changes


def test_verifier_rejects_invalid_python_before_pr_creation() -> None:
    proposal = FixProposal(
        tier=RemediationTier.AUTO_FIXABLE,
        changes=(FileChange("app/broken.py", "value = 1\n", "def unfinished(\n"),),
        diff="example",
        guidance="example",
    )

    result = verify_proposal(proposal)

    assert result["valid"] is False
    assert result["checks"][0]["parser"] == "python_ast"


def test_status_machine_allows_the_tiered_flow_and_blocks_skips() -> None:
    assert transition("proposed", RemediationStatus.VERIFYING) == "verifying"
    assert transition("proposed", RemediationStatus.PENDING_APPROVAL) == "pending_approval"
    assert transition("pending_approval", RemediationStatus.APPROVED) == "approved"
    assert transition("approved", RemediationStatus.VERIFYING) == "verifying"
    assert transition("verifying", RemediationStatus.PR_OPENED) == "pr_opened"
    with pytest.raises(InvalidRemediationTransition):
        transition("pending_approval", RemediationStatus.PR_OPENED)


def test_branch_name_is_fixed_to_the_non_default_sentinel_namespace() -> None:
    scan_id, finding_id = uuid4(), uuid4()

    assert remediation_branch_name(scan_id, finding_id) == f"sentinel-fix/{scan_id}/{finding_id}"


def test_isolated_branch_commit_never_modifies_default_checkout(tmp_path: Path) -> None:
    """The real Git operation changes a disposable worktree, never ``main``."""
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "sentinel-test@example.invalid")
    _git(tmp_path, "config", "user.name", "Sentinel test")
    source = "SECRET = 'in-source'\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "Initial commit")

    prepared = prepare_isolated_branch(
        tmp_path,
        default_branch="main",
        scan_id=uuid4(),
        finding_id=uuid4(),
        changes=(FileChange("app.py", source, 'SECRET = os.environ.get("SECRET")\n'),),
    )
    try:
        assert prepared.name.startswith("sentinel-fix/")
        assert (tmp_path / "app.py").read_text(encoding="utf-8") == source
        assert 'os.environ.get("SECRET")' in (prepared.worktree_path / "app.py").read_text(encoding="utf-8")
        assert _git(tmp_path, "branch", "--show-current") == "main"
        assert _git(prepared.worktree_path, "log", "-1", "--format=%an <%ae>") == (
            f"{SENTINEL_GIT_AUTHOR_NAME} <{SENTINEL_GIT_AUTHOR_EMAIL}>"
        )
    finally:
        _git(tmp_path, "worktree", "remove", "--force", str(prepared.worktree_path))
        shutil.rmtree(prepared.worktree_path.parent, ignore_errors=True)


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def test_github_pull_request_request_uses_sentinel_branch_and_returns_real_url() -> None:
    project = SimpleNamespace(repo_owner="sentinel-test", repo_name="demo-app", default_branch="main")
    finding = SimpleNamespace(
        title="Hardcoded Stripe key",
        description="A credential was found in source code.",
        ai_explanation="The credential could be copied by repository readers.",
    )
    branch = PreparedBranch("sentinel-fix/scan-1/finding-1", SAMPLE_ROOT)
    observed: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers["authorization"]
        observed["api_version"] = request.headers["x-github-api-version"]
        observed["payload"] = json.loads(request.content)
        return httpx.Response(201, json={"html_url": "https://github.com/sentinel-test/demo-app/pull/42"})

    async def run() -> str:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await create_github_pull_request(
                project=project,
                finding=finding,
                branch=branch,
                access_token="test-oauth-token",
                http_client=client,
            )

    assert asyncio.run(run()) == "https://github.com/sentinel-test/demo-app/pull/42"
    assert observed["url"] == "https://api.github.com/repos/sentinel-test/demo-app/pulls"
    assert observed["authorization"] == "Bearer test-oauth-token"
    assert observed["api_version"] == "2026-03-10"
    assert observed["payload"] == {
        "title": "Sentinel AI: Fix Hardcoded Stripe key",
        "head": "sentinel-fix/scan-1/finding-1",
        "base": "main",
        "body": (
            "## Sentinel AI remediation\n\n"
            "This pull request was generated by Sentinel AI from an existing static finding. "
            "Review it carefully before merging.\n\n"
            "### Finding\nA credential was found in source code.\n\n"
            "### AI explanation\nThe credential could be copied by repository readers.\n\n"
            "Sentinel AI never merges this change automatically."
        ),
    }


def test_github_pull_request_api_failure_is_clear_and_non_crashing() -> None:
    project = SimpleNamespace(repo_owner="sentinel-test", repo_name="demo-app", default_branch="main")
    finding = SimpleNamespace(title="Finding", description="Description", ai_explanation=None)
    branch = PreparedBranch("sentinel-fix/scan-1/finding-1", SAMPLE_ROOT)

    async def run() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(403, json={"message": "API rate limit exceeded"}))
        ) as client:
            await create_github_pull_request(
                project=project,
                finding=finding,
                branch=branch,
                access_token="test-oauth-token",
                http_client=client,
            )

    with pytest.raises(GitHubIntegrationError, match="rate limit"):
        asyncio.run(run())


def test_service_records_pr_opened_or_failed_from_mocked_github_publisher(tmp_path: Path) -> None:
    async def exercise(publisher):
        finding, project = _service_finding()
        db = _FakeDb()
        service = RemediationService(
            db,
            repository_root=SAMPLE_ROOT,
            branch_preparer=lambda *_args, **_kwargs: PreparedBranch(
                f"sentinel-fix/{finding.scan.id}/{finding.id}", tmp_path
            ),
            pr_publisher=publisher,
            worktree_cleaner=lambda *_args: None,
        )
        return await service.remediate(finding)

    async def successful_publisher(*_args, **kwargs) -> PullRequestResult:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(201, json={"html_url": "https://github.com/sentinel-test/demo-app/pull/42"})
            )
        ) as client:
            pr_url = await create_github_pull_request(
                project=kwargs["project"],
                finding=kwargs["finding"],
                branch=kwargs["branch"],
                access_token="test-oauth-token",
                http_client=client,
            )
        return PullRequestResult(pr_url, "Mock GitHub PR created.")

    async def failed_publisher(*_args, **kwargs) -> PullRequestResult:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(401, json={"message": "Bad credentials"}))
        ) as client:
            return await create_github_pull_request(
                project=kwargs["project"],
                finding=kwargs["finding"],
                branch=kwargs["branch"],
                access_token="test-oauth-token",
                http_client=client,
            )

    opened = asyncio.run(exercise(successful_publisher))
    failed = asyncio.run(exercise(failed_publisher))

    assert opened.status == "pr_opened"
    assert opened.pr_url == "https://github.com/sentinel-test/demo-app/pull/42"
    assert opened.verification_result["pr_creation"] == "Mock GitHub PR created."
    assert failed.status == "failed"
    assert "authentication failed" in failed.verification_result["notes"]


def test_service_reclones_and_cleans_a_missing_remediation_workspace(tmp_path: Path) -> None:
    async def successful_publisher(*_args, **_kwargs) -> PullRequestResult:
        return PullRequestResult("https://github.com/sentinel-test/demo-app/pull/77", "Mock GitHub PR created.")

    finding, _project = _service_finding()
    snapshot = inventory_existing_repository(SAMPLE_ROOT)
    ingestion = _OnDemandIngestion(snapshot=snapshot)
    db = _FakeDb()
    service = RemediationService(
        db,
        repository_root=None,
        ingestion=ingestion,
        branch_preparer=lambda *_args, **_kwargs: PreparedBranch(
            f"sentinel-fix/{finding.scan.id}/{finding.id}", tmp_path / "prepared-worktree"
        ),
        pr_publisher=successful_publisher,
        worktree_cleaner=lambda *_args: None,
    )

    remediation = asyncio.run(service.remediate(finding))

    assert remediation.status == "pr_opened"
    assert remediation.pr_url == "https://github.com/sentinel-test/demo-app/pull/77"
    assert ingestion.use_local_overrides == [False]
    assert ingestion.cleaned == [snapshot]


def test_service_records_a_clear_failure_when_on_demand_clone_fails() -> None:
    finding, _project = _service_finding()
    ingestion = _OnDemandIngestion(error=IngestionError("Repository clone failed: access denied."))
    service = RemediationService(
        _FakeDb(),
        repository_root=None,
        ingestion=ingestion,
    )

    remediation = asyncio.run(service.remediate(finding))

    assert remediation.status == "failed"
    assert remediation.verification_result["valid"] is False
    assert "Repository snapshot refresh failed safely" in remediation.verification_result["notes"]
    assert "access denied" in remediation.verification_result["notes"]
    assert ingestion.cleaned == []


def _service_finding():
    project = SimpleNamespace(
        user_id=uuid4(),
        default_branch="main",
        repo_owner="sentinel-test",
        repo_name="demo-app",
    )
    scan = SimpleNamespace(id=uuid4(), project=project)
    finding = next(item for item in secret_scanner.scan_repository(SAMPLE_ROOT) if item.file_path == "app/main.py")
    return SimpleNamespace(**asdict(finding), id=uuid4(), scan=scan), project


class _FakeDb:
    def add(self, value) -> None:
        self.value = value

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def refresh(self, _value) -> None:
        return None


class _OnDemandIngestion:
    def __init__(self, *, snapshot: RepositorySnapshot | None = None, error: Exception | None = None) -> None:
        self.snapshot = snapshot
        self.error = error
        self.use_local_overrides: list[bool] = []
        self.cleaned: list[RepositorySnapshot] = []

    async def ingest(self, _db, _project, *, use_local_override: bool = True) -> RepositorySnapshot:
        self.use_local_overrides.append(use_local_override)
        if self.error is not None:
            raise self.error
        assert self.snapshot is not None
        return self.snapshot

    def cleanup(self, snapshot: RepositorySnapshot) -> None:
        self.cleaned.append(snapshot)
