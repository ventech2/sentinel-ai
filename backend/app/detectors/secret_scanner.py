"""Regex and Shannon-entropy secret detection with no network or AI calls."""

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from math import log2
from pathlib import Path
import re

from app.detectors.file_utils import iter_text_files, line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

GENERIC_SECRET_PATTERN = re.compile(
    r"(?im)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'`#]{16,})"
)


@dataclass(frozen=True)
class SecretSignature:
    name: str
    pattern: re.Pattern[str]
    category: str
    severity: str
    confidence: Decimal
    title: str
    description: str


SECRET_SIGNATURES = (
    SecretSignature(
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
        "hardcoded_secret",
        "critical",
        Decimal("0.99"),
        "AWS access key identifier committed",
        "An AWS access key identifier appears in source control and should be removed or rotated.",
    ),
    SecretSignature(
        "jwt",
        re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"),
        "hardcoded_secret",
        "high",
        Decimal("0.95"),
        "JWT token embedded in source",
        "A JWT-shaped token is embedded in source and may grant access if it is still valid.",
    ),
    SecretSignature(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "hardcoded_secret",
        "critical",
        Decimal("0.99"),
        "Private key material committed",
        "Private key material must not be stored in a repository; revoke and rotate it immediately.",
    ),
    SecretSignature(
        "stripe_secret_key",
        # ``demo`` keeps the committed vulnerable-demo-app fixture safe to
        # publish while exercising the same detector path as Stripe keys.
        re.compile(r"\b(?:sk|rk)_(?:live|test|demo)_[0-9A-Za-z]{16,}\b"),
        "hardcoded_secret",
        "critical",
        Decimal("0.98"),
        "Stripe-style secret key embedded",
        "A Stripe-style secret or restricted key appears in source control and should be rotated.",
    ),
)

PLACEHOLDER_VALUES = {"changeme", "change-me", "example", "placeholder", "your_api_key", "your-key"}
MIN_GENERIC_ENTROPY = 3.5


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Scan all eligible text files beneath ``root`` for likely hardcoded secrets."""
    findings: list[DetectorFinding] = []
    for path in iter_text_files(root):
        contents = read_text_file(path)
        if contents is None:
            continue
        findings.extend(scan_text(contents, relative_path(root, path)))
    return findings


def scan_text(contents: str, file_path: str) -> list[DetectorFinding]:
    """Scan a single text payload; useful for focused unit tests."""
    findings: list[DetectorFinding] = []
    matched_lines: set[int] = set()
    for signature in SECRET_SIGNATURES:
        for match in signature.pattern.finditer(contents):
            line_number = line_number_at(contents, match.start())
            findings.append(
                _finding(
                    signature=signature,
                    file_path=file_path,
                    line_number=line_number,
                    snippet=line_at(contents, line_number),
                )
            )
            matched_lines.add(line_number)

    for match in GENERIC_SECRET_PATTERN.finditer(contents):
        value = match.group("value").strip().rstrip(",;)")
        line_number = line_number_at(contents, match.start())
        if line_number in matched_lines or value.lower() in PLACEHOLDER_VALUES:
            continue
        if shannon_entropy(value) < MIN_GENERIC_ENTROPY:
            continue
        findings.append(
            DetectorFinding(
                detector="secret_scan",
                category="hardcoded_secret",
                severity="high",
                confidence=Decimal("0.82"),
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=line_at(contents, line_number),
                title="High-entropy secret assignment",
                description="A secret-named variable is assigned a high-entropy value directly in source.",
                fix_suggestion="Move the value to a secret manager or environment variable and rotate it.",
            )
        )
    return findings


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character for a candidate token."""
    if not value:
        return 0.0
    frequencies = Counter(value)
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in frequencies.values())


def _finding(signature: SecretSignature, file_path: str, line_number: int, snippet: str) -> DetectorFinding:
    return DetectorFinding(
        detector="secret_scan",
        category=signature.category,
        severity=signature.severity,  # type: ignore[arg-type]
        confidence=signature.confidence,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        code_snippet=snippet,
        title=signature.title,
        description=signature.description,
        fix_suggestion="Move the credential to a secret manager or environment variable and rotate it.",
    )
