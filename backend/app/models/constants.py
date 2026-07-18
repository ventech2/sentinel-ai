"""Database-backed state values shared across services and workers.

The technical specification models these columns as PostgreSQL ``TEXT`` rather
than database enum types. These constants keep API and worker code consistent
without requiring a schema migration for every new value.
"""

from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    CLONING = "cloning"
    STATIC_SCAN = "static_scan"
    AI_REVIEW = "ai_review"
    MERGING = "merging"
    COMPLETE = "complete"
    FAILED = "failed"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationStatus(StrEnum):
    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    VERIFYING = "verifying"
    PR_OPENED = "pr_opened"
    REJECTED = "rejected"
    FAILED = "failed"
