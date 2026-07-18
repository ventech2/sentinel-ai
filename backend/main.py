"""ASGI entry point used by ``uvicorn main:app --reload``."""

from app.main import app

__all__ = ["app"]
