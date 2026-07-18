"""GitHub OAuth code exchange, profile retrieval, and local user persistence."""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.token_encryption import encrypt_oauth_token
from app.models.oauth_token import OAuthToken
from app.models.user import User

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"


@dataclass(frozen=True)
class GitHubOAuthResult:
    profile: dict[str, Any]
    access_token: str
    scope: str


class GitHubOAuthClient:
    """Small OAuth client using HTTPX and GitHub's documented OAuth endpoints."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def authorization_url(self, state: str) -> str:
        self._ensure_configured()
        query = urlencode(
            {
                "client_id": self.settings.github_client_id,
                "redirect_uri": self.settings.github_redirect_uri,
                # ``repo`` is required for the separately user-approved
                # Sentinel remediation branch push and pull-request flow.
                "scope": self.settings.github_oauth_scopes,
                "state": state,
            }
        )
        return f"{GITHUB_AUTHORIZE_URL}?{query}"

    async def exchange_code_and_fetch_profile(self, code: str) -> GitHubOAuthResult:
        """Exchange an authorization code and return its token and GitHub profile."""
        self._ensure_configured()
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                token_response = await client.post(
                    GITHUB_ACCESS_TOKEN_URL,
                    headers={"Accept": "application/json"},
                    data={
                        "client_id": self.settings.github_client_id,
                        "client_secret": self.settings.github_client_secret.get_secret_value(),
                        "code": code,
                        "redirect_uri": self.settings.github_redirect_uri,
                    },
                )
                token_response.raise_for_status()
                token_payload = token_response.json()
                access_token = token_payload.get("access_token")
                if not access_token:
                    raise ValueError("GitHub did not return an access token")

                profile_response = await client.get(
                    GITHUB_USER_URL,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "Authorization": f"Bearer {access_token}",
                    },
                )
                profile_response.raise_for_status()
            except (httpx.HTTPError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="GitHub OAuth exchange failed.",
                ) from exc

        profile = profile_response.json()
        if not profile.get("id") or not profile.get("login"):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="GitHub returned an incomplete user profile.",
            )
        scope = token_payload.get("scope")
        return GitHubOAuthResult(
            profile=profile,
            access_token=access_token,
            scope=scope if isinstance(scope, str) else "",
        )

    def _ensure_configured(self) -> None:
        if (
            not self.settings.github_client_id
            or not self.settings.github_client_secret
            or not self.settings.github_client_secret.get_secret_value()
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.",
            )


async def upsert_github_user(db: AsyncSession, profile: dict[str, Any]) -> User:
    """Create or update the local identity represented by a GitHub profile."""
    try:
        github_id = int(profile["id"])
        username = str(profile["login"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub returned an invalid user profile.",
        ) from exc

    user = await db.scalar(select(User).where(User.github_id == github_id))
    if user is None:
        user = User(github_id=github_id, username=username)
        db.add(user)
    else:
        user.username = username

    user.email = profile.get("email")
    user.avatar_url = profile.get("avatar_url")
    await db.flush()
    return user


async def persist_github_token(
    db: AsyncSession,
    user: User,
    oauth_result: GitHubOAuthResult,
    settings: Settings,
) -> OAuthToken:
    """Encrypt and upsert the single GitHub credential associated with a user."""
    token = await db.scalar(select(OAuthToken).where(OAuthToken.user_id == user.id))
    encrypted_token = encrypt_oauth_token(oauth_result.access_token, settings)
    if token is None:
        token = OAuthToken(
            user_id=user.id,
            access_token_encrypted=encrypted_token,
            scope=oauth_result.scope,
        )
        db.add(token)
    else:
        token.access_token_encrypted = encrypted_token
        token.scope = oauth_result.scope

    await db.commit()
    await db.refresh(token)
    return token
