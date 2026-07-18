"""GitHub OAuth transport contracts."""

from uuid import UUID

from pydantic import BaseModel, Field


class GitHubOAuthCallback(BaseModel):
    code: str = Field(min_length=1)
    state: str = Field(min_length=1)


class AuthenticatedUser(BaseModel):
    id: UUID
    github_id: int
    username: str
    email: str | None
    avatar_url: str | None


class GitHubOAuthSession(BaseModel):
    user: AuthenticatedUser
