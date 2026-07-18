"""Consistent response for API contracts whose service logic is not built yet."""

from typing import NoReturn

from fastapi import HTTPException, status


def not_implemented(capability: str) -> NoReturn:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"{capability} is scaffolded but not implemented yet.",
    )
