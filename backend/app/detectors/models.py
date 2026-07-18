"""Transport-neutral finding shape produced by deterministic detectors."""

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class DetectorFinding:
    """Fields map directly to the persisted ``findings`` table columns."""

    detector: str
    category: str
    severity: Severity
    confidence: Decimal
    file_path: str
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    title: str
    description: str
    ai_explanation: str | None = None
    fix_suggestion: str | None = None
    is_false_positive: bool = False
