"""Safe isolated-branch preparation and GitHub pull-request publishing."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.token_encryption import decrypt_oauth_token
from app.models.finding import Finding
from app.models.oauth_token import OAuthToken
from app.models.project import Project
from app.remediation.fix_generator import FileChange

GITHUB_API_ROOT = "https://api.github.com"
GITHUB_GIT_ROOT = "https://github.com"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_REQUEST_TIMEOUT_SECONDS = 20.0
REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
SENTINEL_GIT_AUTHOR_NAME = "Sentinel AI"
SENTINEL_GIT_AUTHOR_EMAIL = "sentinel-ai@noreply.github.com"


class BranchPreparationError(RuntimeError):
    """The patch could not be safely committed to an isolated local branch."""


class GitHubIntegrationError(RuntimeError):
    """GitHub rejected or could not receive a Sentinel remediation pull request."""


@dataclass(frozen=True, slots=True)
class PreparedBranch:
    name: str
    worktree_path: Path


@dataclass(frozen=True, slots=True)
class PullRequestResult:
    pr_url: str
    note: str


def remediation_branch_name(scan_id: UUID, finding_id: UUID) -> str:
    return f"sentinel-fix/{scan_id}/{finding_id}"


def prepare_isolated_branch(
    repository_root: Path,
    *,
    default_branch: str,
    scan_id: UUID,
    finding_id: UUID,
    changes: tuple[FileChange, ...],
) -> PreparedBranch:
    """Create and commit a patch only in ``sentinel-fix/<scan>/<finding>``.

    A separate Git worktree is used so this function cannot alter the checked-out
    default branch in the original repository.
    """
    branch_name = remediation_branch_name(scan_id, finding_id)
    if branch_name == default_branch or not branch_name.startswith("sentinel-fix/"):
        raise BranchPreparationError("Remediation must use a sentinel-fix branch, never the default branch.")
    root = repository_root.resolve()
    _git(root, "rev-parse", "--is-inside-work-tree")
    _git(root, "rev-parse", "--verify", default_branch)

    worktree_parent = Path(tempfile.mkdtemp(prefix="sentinel-remediation-"))
    worktree_path = worktree_parent / "repository"
    try:
        _git(root, "worktree", "add", "-b", branch_name, str(worktree_path), default_branch)
        for change in changes:
            _write_checked_change(worktree_path, change)
        _git(worktree_path, "add", "--", *[change.file_path for change in changes])
        # Provide the identity directly to this commit. This does not depend on
        # (or mutate) global container Git configuration, which is absent in a
        # fresh Railway runtime and should not be shared between remediations.
        _git(
            worktree_path,
            "-c",
            f"user.name={SENTINEL_GIT_AUTHOR_NAME}",
            "-c",
            f"user.email={SENTINEL_GIT_AUTHOR_EMAIL}",
            "commit",
            "-m",
            f"Sentinel AI remediation for finding {finding_id}",
        )
    except Exception as error:
        # A failure after ``worktree add`` must not leave a disposable checkout
        # behind. The source checkout/default branch remains untouched.
        if worktree_path.exists():
            try:
                _git(root, "worktree", "remove", "--force", str(worktree_path))
            except BranchPreparationError:
                pass
        shutil.rmtree(worktree_parent, ignore_errors=True)
        raise BranchPreparationError(str(error)) from error
    return PreparedBranch(name=branch_name, worktree_path=worktree_path)


def cleanup_prepared_branch(repository_root: Path, branch: PreparedBranch) -> None:
    """Remove the temporary remediation worktree after push/PR processing.

    The branch remains on GitHub; only the local disposable worktree is
    removed. The directory-name guard prevents this cleanup helper from ever
    deleting an arbitrary repository path.
    """
    root = repository_root.resolve()
    worktree_path = branch.worktree_path.resolve()
    parent = worktree_path.parent
    if worktree_path.name != "repository" or not parent.name.startswith("sentinel-remediation-"):
        raise BranchPreparationError("Refusing to clean a non-Sentinel remediation worktree.")
    try:
        _git(root, "worktree", "remove", "--force", str(worktree_path))
    finally:
        shutil.rmtree(parent, ignore_errors=True)


async def publish_branch_and_create_pull_request(
    db: AsyncSession,
    *,
    project: Project,
    finding: Finding,
    branch: PreparedBranch,
    settings: Settings,
    http_client: httpx.AsyncClient | None = None,
) -> PullRequestResult:
    """Push a Sentinel-only branch and open a PR using the owner's OAuth token.

    The token is decrypted only for this short-lived operation. It is passed to
    Git as an ephemeral HTTP authorization header, never added to a remote URL
    or written into repository configuration.
    """
    token = await db.scalar(select(OAuthToken).where(OAuthToken.user_id == project.user_id))
    if token is None:
        raise GitHubIntegrationError("GitHub PR creation requires an OAuth token for the project owner.")
    access_token = decrypt_oauth_token(token.access_token_encrypted, settings)
    await asyncio.to_thread(push_prepared_branch, branch, project, access_token)
    pr_url = await create_github_pull_request(
        project=project,
        finding=finding,
        branch=branch,
        access_token=access_token,
        http_client=http_client,
    )
    return PullRequestResult(
        pr_url=pr_url,
        note=(
            f"Pushed {branch.name} and opened a GitHub pull request into "
            f"{project.default_branch}. Review is required before merging."
        ),
    )


def push_prepared_branch(branch: PreparedBranch, project: Project, access_token: str) -> None:
    """Push exactly the prepared Sentinel branch without changing any default ref."""
    _assert_sentinel_branch(branch.name, project.default_branch)
    remote_url = _github_git_url(project)
    encoded_credentials = base64.b64encode(f"x-access-token:{access_token}".encode("utf-8")).decode("ascii")
    environment = _git_auth_environment(encoded_credentials)
    refspec = f"refs/heads/{branch.name}:refs/heads/{branch.name}"
    try:
        completed = subprocess.run(
            ["git", "-C", str(branch.worktree_path), "push", remote_url, refspec],
            capture_output=True,
            text=True,
            env=environment,
            timeout=GITHUB_REQUEST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise GitHubIntegrationError("GitHub branch push timed out.") from error
    except OSError as error:
        raise GitHubIntegrationError(f"Unable to start GitHub branch push: {error}") from error
    if completed.returncode != 0:
        detail = _scrub_secret((completed.stderr or completed.stdout).strip(), access_token)
        raise GitHubIntegrationError(f"GitHub branch push failed: {detail or 'Git rejected the push.'}")


async def create_github_pull_request(
    *,
    project: Project,
    finding: Finding,
    branch: PreparedBranch,
    access_token: str,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    """Create a same-repository PR for an already-pushed Sentinel branch."""
    _assert_sentinel_branch(branch.name, project.default_branch)
    endpoint = f"{GITHUB_API_ROOT}/repos/{project.repo_owner}/{project.repo_name}/pulls"
    payload = {
        "title": f"Sentinel AI: Fix {finding.title}"[:256],
        "head": branch.name,
        "base": project.default_branch,
        "body": _pull_request_body(finding),
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if http_client is None:
        try:
            async with httpx.AsyncClient(timeout=GITHUB_REQUEST_TIMEOUT_SECONDS) as client:
                return await _post_pull_request(client, endpoint, headers, payload)
        except httpx.HTTPError as error:
            raise GitHubIntegrationError(f"GitHub API network error: {error}") from error
    try:
        return await _post_pull_request(http_client, endpoint, headers, payload)
    except httpx.HTTPError as error:
        raise GitHubIntegrationError(f"GitHub API network error: {error}") from error


async def _post_pull_request(
    client: httpx.AsyncClient,
    endpoint: str,
    headers: dict[str, str],
    payload: dict[str, str],
) -> str:
    response = await client.post(endpoint, headers=headers, json=payload)
    if response.is_error:
        raise GitHubIntegrationError(_github_api_error(response))
    try:
        response_data: Any = response.json()
    except ValueError as error:
        raise GitHubIntegrationError("GitHub API returned an invalid pull-request response.") from error
    pr_url = response_data.get("html_url") if isinstance(response_data, dict) else None
    if not isinstance(pr_url, str) or not pr_url.startswith("https://"):
        raise GitHubIntegrationError("GitHub API response did not include a valid pull-request URL.")
    return pr_url


def _pull_request_body(finding: Finding) -> str:
    ai_explanation = finding.ai_explanation or "No AI explanation was available; this patch uses deterministic remediation rules."
    return (
        "## Sentinel AI remediation\n\n"
        "This pull request was generated by Sentinel AI from an existing static finding. "
        "Review it carefully before merging.\n\n"
        f"### Finding\n{finding.description}\n\n"
        f"### AI explanation\n{ai_explanation}\n\n"
        "Sentinel AI never merges this change automatically."
    )


def _github_api_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
        message = payload.get("message") if isinstance(payload, dict) else None
    except ValueError:
        message = None
    reason = {
        401: "authentication failed",
        403: "permission denied or API rate limit reached",
        404: "repository was not found or the token lacks access",
        422: "pull request was rejected by GitHub",
    }.get(response.status_code, "request failed")
    suffix = f": {message}" if isinstance(message, str) and message else ""
    return f"GitHub PR API {reason} (HTTP {response.status_code}){suffix}"


def _github_git_url(project: Project) -> str:
    if not REPOSITORY_COMPONENT.fullmatch(project.repo_owner) or not REPOSITORY_COMPONENT.fullmatch(project.repo_name):
        raise GitHubIntegrationError("Project has an invalid GitHub repository owner or name.")
    return f"{GITHUB_GIT_ROOT}/{project.repo_owner}/{project.repo_name}.git"


def _assert_sentinel_branch(branch_name: str, default_branch: str) -> None:
    if branch_name == default_branch or not branch_name.startswith("sentinel-fix/"):
        raise GitHubIntegrationError("Refusing to push or open a PR from a non-Sentinel branch.")


def _git_auth_environment(encoded_credentials: str) -> dict[str, str]:
    """Configure one child Git process without persisting a credential anywhere."""
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {encoded_credentials}",
        }
    )
    return environment


def _scrub_secret(message: str, access_token: str) -> str:
    return message.replace(access_token, "[redacted]")[:500]


def _write_checked_change(worktree_path: Path, change: FileChange) -> None:
    path = (worktree_path / change.file_path).resolve()
    try:
        path.relative_to(worktree_path.resolve())
        current = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        raise BranchPreparationError(f"Unable to read {change.file_path} in isolated worktree.") from error
    if current != change.original_content:
        raise BranchPreparationError(f"{change.file_path} changed after remediation was generated.")
    path.write_text(change.updated_content, encoding="utf-8")


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip() or "git command failed"
        raise BranchPreparationError(detail)
    return completed.stdout.strip()
