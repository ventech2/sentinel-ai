"""Standalone Redis worker for Sentinel scan jobs.

Run with ``python -m app.workers.scan_worker`` beside the API process.
"""

from __future__ import annotations

import asyncio
import logging

from app.queue.redis import RedisScanQueue, close_redis, redis_client
from app.services.orchestrator import process_queued_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_forever() -> None:
    queue = RedisScanQueue(redis_client)
    try:
        while True:
            scan_id = await queue.dequeue(timeout_seconds=5)
            if scan_id is None:
                continue
            try:
                await process_queued_scan(scan_id, queue=queue)
            except Exception:
                # ``process_queued_scan`` normally persists failures itself;
                # retain this guard so one malformed job cannot kill the worker.
                logger.exception("Unhandled worker failure for scan %s", scan_id)
    finally:
        await close_redis()


def main() -> None:
    try:
        asyncio.run(run_forever())
    except KeyboardInterrupt:
        logger.info("Scan worker stopped")


if __name__ == "__main__":
    main()
