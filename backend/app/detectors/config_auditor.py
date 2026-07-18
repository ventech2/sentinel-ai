"""Rule-based checks for unsafe application configuration."""

from decimal import Decimal
from pathlib import Path
import re

from app.detectors.file_utils import iter_text_files, line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

DEBUG_TRUE_PATTERN = re.compile(r"(?im)\bdebug\s*(?:=|:)\s*true\b")
WILDCARD_CORS_PATTERN = re.compile(
    r"(?im)(?:allow_origins|cors[_-]?origins?|origins|alloworigin|allowedorigins|origin)"
    r"\s*[:=]\s*\[?\s*[\"']\*[\"']"
)
CONFIG_FILENAMES = {"settings.py", "next.config.js", "next.config.mjs", "dockerfile", "dockerfile.dev"}
APPLICATION_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Audit common configuration files and committed environment files."""
    findings: list[DetectorFinding] = []
    gitignore_patterns = _read_gitignore_patterns(root)
    for path in iter_text_files(root):
        contents = read_text_file(path)
        if contents is None:
            continue
        repository_path = relative_path(root, path)
        if _is_environment_file(path) and not _is_ignored(repository_path, gitignore_patterns):
            findings.append(_env_file_finding(repository_path))
        if not _should_scan_configuration_rules(path):
            continue
        findings.extend(_config_findings(contents, repository_path))
    return findings


def _config_findings(contents: str, file_path: str) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    for match in DEBUG_TRUE_PATTERN.finditer(contents):
        line_number = line_number_at(contents, match.start())
        findings.append(
            DetectorFinding(
                detector="config_audit",
                category="insecure_config",
                severity="high",
                confidence=Decimal("0.90"),
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=line_at(contents, line_number),
                title="Debug mode enabled in configuration",
                description="DEBUG=True in a deployment-oriented configuration can expose stack traces and sensitive details.",
                fix_suggestion="Disable debug mode outside local development.",
            )
        )
    for match in WILDCARD_CORS_PATTERN.finditer(contents):
        line_number = line_number_at(contents, match.start())
        findings.append(
            DetectorFinding(
                detector="config_audit",
                category="insecure_config",
                severity="high",
                confidence=Decimal("0.92"),
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=line_at(contents, line_number),
                title="Wildcard CORS origin configured",
                description="Allowing every origin can expose authenticated browser-accessible endpoints to untrusted sites.",
                fix_suggestion="Replace '*' with the explicit production frontend origins.",
            )
        )
    return findings


def _env_file_finding(file_path: str) -> DetectorFinding:
    return DetectorFinding(
        detector="config_audit",
        category="committed_env_file",
        severity="high",
        confidence=Decimal("0.88"),
        file_path=file_path,
        line_start=1,
        line_end=1,
        code_snippet=".env file is present and not ignored",
        title="Environment file is committed without .gitignore coverage",
        description="A committed environment file can expose credentials or production settings.",
        fix_suggestion="Remove secrets from the file, rotate exposed values, and add .env to .gitignore.",
    )


def _is_environment_file(path: Path) -> bool:
    return path.name == ".env" or path.name.startswith(".env.")


def _should_scan_configuration_rules(path: Path) -> bool:
    """Scan named config files plus application source that sets config inline."""
    return (
        path.name.lower() in CONFIG_FILENAMES
        or _is_environment_file(path)
        or path.suffix.lower() in APPLICATION_SOURCE_SUFFIXES
    )


def _read_gitignore_patterns(root: Path) -> list[str]:
    gitignore = root / ".gitignore"
    contents = read_text_file(gitignore)
    if contents is None:
        return []
    return [line.strip() for line in contents.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _is_ignored(file_path: str, patterns: list[str]) -> bool:
    normalized = file_path.lstrip("/")
    for pattern in patterns:
        cleaned = pattern.lstrip("/")
        if cleaned == ".env":
            return Path(normalized).name == ".env"
        if cleaned in {".env*", ".env.*"}:
            return Path(normalized).name.startswith(".env")
        if cleaned == normalized:
            return True
    return False
