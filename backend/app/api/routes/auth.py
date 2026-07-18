"""GitHub OAuth routes and signed browser-session creation."""

from hmac import compare_digest
from secrets import token_urlsafe

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.schemas.auth import AuthenticatedUser, GitHubOAuthCallback, GitHubOAuthSession
from app.services.github_oauth import GitHubOAuthClient, persist_github_token, upsert_github_user

router = APIRouter(prefix="/auth")


@router.get("/github/login", response_class=RedirectResponse, summary="Start GitHub OAuth")
async def start_github_login(request: Request) -> RedirectResponse:
    state = token_urlsafe(32)
    request.session["github_oauth_state"] = state
    redirect_url = GitHubOAuthClient(get_settings()).authorization_url(state)
    return RedirectResponse(redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.post(
    "/github/callback",
    response_model=GitHubOAuthSession,
    summary="Exchange GitHub OAuth code for a session",
)
async def github_callback(
    payload: GitHubOAuthCallback,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> GitHubOAuthSession:
    return await _complete_github_login(request, payload.code, payload.state, db)


@router.get(
    "/github/callback",
    response_class=RedirectResponse,
    include_in_schema=False,
)
async def github_redirect_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    if error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"GitHub OAuth failed: {error}")
    if not code or not state:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Missing OAuth code or state.")
    await _complete_github_login(request, code, state, db)
    frontend_url = get_settings().frontend_url.rstrip("/")
    return RedirectResponse(f"{frontend_url}/dashboard", status_code=status.HTTP_303_SEE_OTHER)


async def _complete_github_login(
    request: Request,
    code: str,
    state: str,
    db: AsyncSession,
) -> GitHubOAuthSession:
    expected_state = request.session.pop("github_oauth_state", None)
    if not expected_state or not compare_digest(state, expected_state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state.")

    settings = get_settings()
    oauth_result = await GitHubOAuthClient(settings).exchange_code_and_fetch_profile(code)
    user = await upsert_github_user(db, oauth_result.profile)
    await persist_github_token(db, user, oauth_result, settings)
    request.session["user_id"] = str(user.id)
    return GitHubOAuthSession(
        user=AuthenticatedUser(
            id=user.id,
            github_id=user.github_id,
            username=user.username,
            email=user.email,
            avatar_url=user.avatar_url,
        )
    )
