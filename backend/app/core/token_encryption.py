"""Encryption helpers for sensitive OAuth credentials stored in PostgreSQL."""

from cryptography.fernet import Fernet
from fastapi import HTTPException, status

from app.core.config import Settings


def encrypt_oauth_token(access_token: str, settings: Settings) -> str:
    """Encrypt a token with the deployment-provided Fernet key."""
    key = settings.oauth_token_encryption_key
    if key is None or not key.get_secret_value():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth token encryption is not configured. Set OAUTH_TOKEN_ENCRYPTION_KEY.",
        )
    try:
        cipher = Fernet(key.get_secret_value().encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAUTH_TOKEN_ENCRYPTION_KEY is not a valid Fernet key.",
        ) from exc
    return cipher.encrypt(access_token.encode("utf-8")).decode("utf-8")


def decrypt_oauth_token(encrypted_token: str, settings: Settings) -> str:
    """Decrypt an OAuth token only at the point an authorized GitHub action needs it."""
    key = settings.oauth_token_encryption_key
    if key is None or not key.get_secret_value():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth token encryption is not configured. Set OAUTH_TOKEN_ENCRYPTION_KEY.",
        )
    try:
        cipher = Fernet(key.get_secret_value().encode("utf-8"))
        return cipher.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAUTH_TOKEN_ENCRYPTION_KEY is not a valid Fernet key.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Stored GitHub OAuth token could not be decrypted.",
        ) from exc
