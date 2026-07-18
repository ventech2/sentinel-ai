"""Durable scan retrieval plus Redis-backed live-progress WebSocket."""

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import SessionLocal, get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.queue.redis import get_redis, redis_client, scan_event_channel
from app.schemas.scan import FindingResponse, ScanResponse

router = APIRouter(prefix="/scans")


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan status and progress")
async def get_scan(scan_id: UUID, request: Request, db: AsyncSession = Depends(get_db)) -> Scan:
    return await _owned_scan(db, scan_id, _session_user_id(request))


@router.get("/{scan_id}/findings", response_model=list[FindingResponse], summary="List scan findings")
async def list_scan_findings(scan_id: UUID, request: Request, db: AsyncSession = Depends(get_db)) -> list[Finding]:
    user_id = _session_user_id(request)
    await _owned_scan(db, scan_id, user_id)
    return list(
        (
            await db.scalars(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.created_at.asc())
            )
        ).all()
    )


@router.websocket("/{scan_id}/live")
async def scan_live_progress(websocket: WebSocket, scan_id: UUID) -> None:
    """Stream durable stage events and persisted-finding notifications over Pub/Sub."""
    raw_user_id = websocket.scope.get("session", {}).get("user_id")
    try:
        user_id = UUID(str(raw_user_id))
    except (TypeError, ValueError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    async with SessionLocal() as db:
        try:
            scan = await _owned_scan(db, scan_id, user_id)
        except HTTPException:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await websocket.accept()
    await websocket.send_json(_status_event(scan, "Current persisted scan state."))
    pubsub = redis_client.pubsub()
    try:
        await pubsub.subscribe(scan_event_channel(scan_id))
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("data"):
                try:
                    event = json.loads(message["data"])
                except (TypeError, json.JSONDecodeError):
                    continue
                await websocket.send_json(event)
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        return
    except RedisError:
        await websocket.send_json({"type": "error", "scan_id": str(scan_id), "detail": "Live progress transport is unavailable."})
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
    finally:
        await pubsub.unsubscribe(scan_event_channel(scan_id))
        await pubsub.aclose()


async def _owned_scan(db: AsyncSession, scan_id: UUID, user_id: UUID) -> Scan:
    scan = await db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.project))
    )
    if scan is None or scan.project.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


def _session_user_id(request: Request) -> UUID:
    raw_user_id = request.session.get("user_id")
    if not raw_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="GitHub login is required.")
    try:
        return UUID(str(raw_user_id))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.") from error


def _status_event(scan: Scan, detail: str) -> dict[str, object]:
    return {
        "type": "status",
        "scan_id": str(scan.id),
        "status": scan.status,
        "detail": detail,
        "files_scanned": scan.files_scanned,
    }
