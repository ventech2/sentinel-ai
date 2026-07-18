"""GitHub repository metadata lookups scoped to one user-selected project."""

from __future__ import annotations

import re

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.token_encryption import decrypt_oauth_token
from app.models.oauth_token import OAuthToken

GITHUB_API_ROOT = "https://api.github.com"
GITHUB_REQUEST_TIMEOUT_SECONDS = 15.0
REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class GitHubRepositoryError(RuntimeError):
    """GitHub could not return metadata for the explicitly selected repository."""


class GitHubRepositoryClient:
    """Read metadata for one repository; never enumerate repositories on a token."""

    async def get_default_branch(self, owner: str, repository: str, access_token: str) -> str:
        if not REPOSITORY_COMPONENT.fullmatch(owner) or not REPOSITORY_COMPONENT.fullmatch(repository):
            raise GitHubRepositoryError("Project has an invalid GitHub repository owner or name.")

        endpoint = f"{GITHUB_API_ROOT}/repos/{owner}/{repository}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        try:
            async with httpx.AsyncClient(timeout=GITHUB_REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers)
        except httpx.HTTPError as error:
            raise GitHubRepositoryError(f"GitHub repository metadata request failed: {error}") from error

        if response.is_error:
            reason = {
                401: "authentication failed",
                403: "permission denied or API rate limit reached",
                404: "repository was not found or the token lacks access",
            }.get(response.status_code, "request failed")
            raise GitHubRepositoryError(f"GitHub repository metadata {reason} (HTTP {response.status_code}).")

        try:
            payload = response.json()
        except ValueError as error:
            raise GitHubRepositoryError("GitHub repository metadata response was invalid JSON.") from error
        default_branch = payload.get("default_branch") if isinstance(payload, dict) else None
        if not isinstance(default_branch, str) or not default_branch.strip() or "\x00" in default_branch:
            raise GitHubRepositoryError("GitHub repository metadata did not include a valid default branch.")
        return default_branch.strip()


async def get_repository_default_branch(
    db: AsyncSession,
    *,
    user_id: object,
    owner: str,
    repository: str,
    settings: Settings,
    client: GitHubRepositoryClient | None = None,
) -> str:
    """Resolve the default branch using only the selected repository endpoint."""
    access_token = await get_repository_access_token(db, user_id=user_id, settings=settings)
    return await (client or GitHubRepositoryClient()).get_default_branch(owner, repository, access_token)


async def get_repository_access_token(
    db: AsyncSession,
    *,
    user_id: object,
    settings: Settings,
) -> str:
    """Return the authenticated user's decrypted token for one authorized operation."""
    oauth_token = await db.scalar(select(OAuthToken).where(OAuthToken.user_id == user_id))
    if oauth_token is None:
        raise GitHubRepositoryError("A GitHub OAuth token is required to inspect this repository.")
    try:
        access_token = decrypt_oauth_token(oauth_token.access_token_encrypted, settings)
    except Exception as error:
        raise GitHubRepositoryError("The stored GitHub OAuth token could not be decrypted.") from error
    return access_token
