"""Persistence and safety workflow for remediation proposals."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Protocol
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.models.constants import RemediationStatus
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.remediation.classifier import RemediationTier, classify_finding, tier_guidance
from app.remediation.fix_generator import FixProposal, generate_fix
from app.remediation.github_pr import (
    BranchPreparationError,
    GitHubIntegrationError,
    PreparedBranch,
    PullRequestResult,
    cleanup_prepared_branch,
    prepare_isolated_branch,
    publish_branch_and_create_pull_request,
)
from app.remediation.state_machine import transition
from app.remediation.verifier import verify_proposal
from app.services.ingestion import IngestionError, RepositoryIngestionService, RepositorySnapshot

logger = logging.getLogger(__name__)


class FlaggedOnlyRemediationError(ValueError):
    """Raised for Tier 3 findings which must not receive an automated diff."""


class RepositoryWorkspaceError(RuntimeError):
    """A temporary source checkout could not be obtained for remediation."""


class RemediationIngestionService(Protocol):
    async def ingest(
        self,
        db: AsyncSession,
        project: object,
        *,
        use_local_override: bool = True,
    ) -> RepositorySnapshot:
        """Create an owned temporary repository snapshot."""

    def cleanup(self, snapshot: RepositorySnapshot) -> None:
        """Release an owned repository snapshot."""


@dataclass(frozen=True, slots=True)
class RepositoryWorkspace:
    root: Path
    snapshot: RepositorySnapshot | None = None


class RemediationService:
    """Create, approve, verify, and safely prepare remediation pull-request branches."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        settings: Settings | None = None,
        repository_root: Path | None = None,
        branch_preparer: Callable[..., PreparedBranch] | None = None,
        pr_publisher: Callable[..., Awaitable[PullRequestResult]] | None = None,
        ingestion: RemediationIngestionService | None = None,
        worktree_cleaner: Callable[[Path, PreparedBranch], None] | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.repository_root = repository_root if repository_root is not None else self.settings.remediation_repository_root
        self._branch_preparer = branch_preparer or prepare_isolated_branch
        self._pr_publisher = pr_publisher or publish_branch_and_create_pull_request
        self._ingestion = ingestion or RepositoryIngestionService(settings=self.settings)
        self._worktree_cleaner = worktree_cleaner or cleanup_prepared_branch

    async def remediate(self, finding: Finding) -> Remediation:
        """Create a remediation. Tier 1 verifies immediately; Tier 2 awaits approval."""
        tier = classify_finding(finding)
        if tier is RemediationTier.FLAGGED_ONLY:
            raise FlaggedOnlyRemediationError(tier_guidance(tier))

        remediation = Remediation(
            finding_id=finding.id,
            tier=int(tier),
            status=str(RemediationStatus.PROPOSED),
        )
        self.db.add(remediation)
        await self.db.flush()

        workspace: RepositoryWorkspace | None = None
        try:
            workspace = await self._acquire_workspace(finding)
            proposal = generate_fix(finding, workspace.root)
            remediation.diff = proposal.diff
            if tier is RemediationTier.HUMAN_APPROVAL:
                self._transition(remediation, RemediationStatus.PENDING_APPROVAL)
                remediation.verification_result = {"valid": None, "notes": proposal.guidance}
            else:
                await self._verify_and_prepare(remediation, finding, proposal, workspace.root)
        except RepositoryWorkspaceError as error:
            self._record_workspace_failure(remediation, error)
        finally:
            if workspace is not None:
                await self._release_workspace(workspace)

        await self.db.commit()
        await self.db.refresh(remediation)
        return remediation

    async def approve(self, remediation: Remediation, finding: Finding, approved_by: UUID) -> Remediation:
        """Approve exactly one Tier 2 proposal, then run the same verification/branch flow."""
        if remediation.tier != int(RemediationTier.HUMAN_APPROVAL):
            raise ValueError("Only Tier 2 remediations require approval.")
        if remediation.status != RemediationStatus.PENDING_APPROVAL:
            raise ValueError("Only pending-approval remediations can be approved.")

        self._transition(remediation, RemediationStatus.APPROVED)
        remediation.approved_by = approved_by
        workspace: RepositoryWorkspace | None = None
        try:
            workspace = await self._acquire_workspace(finding)
            proposal = generate_fix(finding, workspace.root)
            remediation.diff = proposal.diff
            await self._verify_and_prepare(remediation, finding, proposal, workspace.root)
        except RepositoryWorkspaceError as error:
            self._record_workspace_failure(remediation, error)
        finally:
            if workspace is not None:
                await self._release_workspace(workspace)
        await self.db.commit()
        await self.db.refresh(remediation)
        return remediation

    async def _verify_and_prepare(
        self,
        remediation: Remediation,
        finding: Finding,
        proposal: FixProposal,
        repository_root: Path,
    ) -> None:
        self._transition(remediation, RemediationStatus.VERIFYING)
        if not proposal.has_changes:
            remediation.verification_result = {"valid": False, "notes": proposal.guidance}
            self._transition(remediation, RemediationStatus.FAILED)
            return

        verification = verify_proposal(proposal)
        remediation.verification_result = verification
        if not verification["valid"]:
            self._transition(remediation, RemediationStatus.FAILED)
            return
        if finding.scan is None or finding.scan.project is None:
            remediation.verification_result = {
                **verification,
                "valid": False,
                "notes": "Finding is missing scan/project context required for an isolated branch.",
            }
            self._transition(remediation, RemediationStatus.FAILED)
            return

        branch: PreparedBranch | None = None
        worktree_cleaned = True
        try:
            branch = await asyncio.to_thread(
                self._branch_preparer,
                repository_root,
                default_branch=finding.scan.project.default_branch,
                scan_id=finding.scan.id,
                finding_id=finding.id,
                changes=proposal.changes,
            )
            pull_request = await self._pr_publisher(
                self.db,
                project=finding.scan.project,
                finding=finding,
                branch=branch,
                settings=self.settings,
            )
        except (BranchPreparationError, GitHubIntegrationError, HTTPException, OSError) as error:
            remediation.verification_result = {
                **verification,
                "valid": False,
                "notes": f"Branch/PR preparation failed safely: {error}",
            }
            self._transition(remediation, RemediationStatus.FAILED)
            return
        finally:
            if branch is not None:
                try:
                    await asyncio.to_thread(self._worktree_cleaner, repository_root, branch)
                except (BranchPreparationError, OSError):
                    worktree_cleaned = False
                    logger.warning("Could not remove temporary remediation worktree %s", branch.worktree_path, exc_info=True)

        remediation.pr_url = pull_request.pr_url
        remediation.verification_result = {
            **verification,
            "branch": branch.name,
            "worktree_cleaned": worktree_cleaned,
            "pr_creation": pull_request.note,
        }
        self._transition(remediation, RemediationStatus.PR_OPENED)

    async def _acquire_workspace(self, finding: Finding) -> RepositoryWorkspace:
        """Use a supplied fresh root or re-clone exactly the finding's project."""
        if self.repository_root is not None and self.repository_root.is_dir():
            return RepositoryWorkspace(root=self.repository_root)
        if finding.scan is None or finding.scan.project is None:
            raise RepositoryWorkspaceError("Finding is missing scan/project context required to refresh its repository snapshot.")
        try:
            # Do not allow the development local-fixture override here: a real
            # remediation must patch the user-selected GitHub project.
            snapshot = await self._ingestion.ingest(
                self.db,
                finding.scan.project,
                use_local_override=False,
            )
        except (IngestionError, OSError, ValueError) as error:
            raise RepositoryWorkspaceError(f"Unable to re-clone the selected repository: {error}") from error
        return RepositoryWorkspace(root=snapshot.root, snapshot=snapshot)

    async def _release_workspace(self, workspace: RepositoryWorkspace) -> None:
        if workspace.snapshot is None:
            return
        try:
            await asyncio.to_thread(self._ingestion.cleanup, workspace.snapshot)
        except (IngestionError, OSError):
            logger.warning("Could not remove temporary remediation clone %s", workspace.snapshot.root, exc_info=True)

    def _record_workspace_failure(self, remediation: Remediation, error: RepositoryWorkspaceError) -> None:
        remediation.verification_result = {
            "valid": False,
            "notes": f"Repository snapshot refresh failed safely: {error}",
        }
        self._transition(remediation, RemediationStatus.FAILED)

    @staticmethod
    def _transition(remediation: Remediation, target: RemediationStatus) -> None:
        remediation.status = transition(remediation.status, target)
