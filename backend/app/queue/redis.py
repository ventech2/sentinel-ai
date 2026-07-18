"""Redis-backed scan queue and live-progress event transport."""

from collections.abc import AsyncIterator
import json
from typing import Any
from uuid import UUID

from redis.asyncio import Redis, from_url

from app.core.config import get_settings

settings = get_settings()
redis_client: Redis = from_url(settings.redis_url, decode_responses=True)
SCAN_QUEUE_KEY = "sentinel:scan-jobs"


def scan_event_channel(scan_id: UUID) -> str:
    return f"sentinel:scan:{scan_id}:events"


class RedisScanQueue:
    """Small Redis list queue; a standalone worker consumes its scan IDs."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def enqueue(self, scan_id: UUID) -> None:
        await self.redis.rpush(SCAN_QUEUE_KEY, str(scan_id))

    async def dequeue(self, *, timeout_seconds: int = 5) -> UUID | None:
        result = await self.redis.brpop(SCAN_QUEUE_KEY, timeout=timeout_seconds)
        if not result:
            return None
        _, raw_scan_id = result
        try:
            return UUID(str(raw_scan_id))
        except ValueError:
            return None

    async def publish(self, scan_id: UUID, event: dict[str, Any]) -> None:
        await self.redis.publish(scan_event_channel(scan_id), json.dumps(event, default=str))


async def get_redis() -> AsyncIterator[Redis]:
    """Provide the shared Redis client without adding queue behavior yet."""
    yield redis_client


async def close_redis() -> None:
    """Close pooled Redis connections during API shutdown."""
    await redis_client.aclose()
