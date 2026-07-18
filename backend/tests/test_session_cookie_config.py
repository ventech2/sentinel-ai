"""Regression coverage for browser sessions across frontend/API origins."""

from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app import main as application
from app.core.config import Settings


def test_deployed_session_cookie_and_cors_support_cross_origin_credentials(monkeypatch) -> None:
    settings = Settings(
        allowed_origins=["https://sentinel-ai.vercel.app"],
        session_secret="test-session-secret",
        session_same_site="none",
        session_https_only=True,
    )
    monkeypatch.setattr(application, "get_settings", lambda: settings)

    app = application.create_app()
    session = next(item for item in app.user_middleware if item.cls is SessionMiddleware)
    cors = next(item for item in app.user_middleware if item.cls is CORSMiddleware)

    assert session.kwargs["same_site"] == "none"
    assert session.kwargs["https_only"] is True
    assert cors.kwargs["allow_origins"] == ["https://sentinel-ai.vercel.app"]
    assert cors.kwargs["allow_credentials"] is True
