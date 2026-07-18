"""Deterministic heuristics for network-shaped and dependency-shaped backdoors.

Network destination findings are intentionally moderate or low confidence:
legitimate single-use integrations can look indistinguishable from exfiltration
without runtime behavior or product context. No reputation service or LLM is
consulted here.
"""

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
import ipaddress
import json
from pathlib import Path
import re

from app.detectors.file_utils import iter_text_files, line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
URL_PATTERN = re.compile(
    r"https?://(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?))(?::\d+)?",
    re.IGNORECASE,
)
SOCKET_IP_PATTERN = re.compile(
    r"\b(?:[A-Za-z_][\w]*\.connect|socket\.create_connection)\s*\(\s*\(\s*[\"'](?P<ip>(?:\d{1,3}\.){3}\d{1,3})[\"']\s*,",
    re.IGNORECASE,
)
INSTALL_SCRIPT_NAMES = {"preinstall", "install", "postinstall"}
REMOTE_DOWNLOAD_PATTERN = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:https?://)|\bfetch\s*\(", re.IGNORECASE)
INLINE_NODE_PATTERN = re.compile(r"\bnode\s+(?:-e|--eval)\b", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(r"\b(?:sh|bash|zsh|cmd(?:\.exe)?|powershell)\b", re.IGNORECASE)
SAFE_DESTINATIONS = {"localhost", "127.0.0.1", "0.0.0.0"}


@dataclass(frozen=True)
class UrlReference:
    host: str
    file_path: str
    line_number: int
    snippet: str
    is_source: bool


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Scan a repository for suspicious destinations and install scripts."""
    findings: list[DetectorFinding] = []
    domain_references: dict[str, list[UrlReference]] = defaultdict(list)
    source_domain_candidates: list[UrlReference] = []

    for path in iter_text_files(root):
        contents = read_text_file(path)
        if contents is None:
            continue
        repository_path = relative_path(root, path)
        is_source = path.suffix.lower() in SOURCE_SUFFIXES

        for match in URL_PATTERN.finditer(contents):
            host = match.group("host").lower()
            line_number = line_number_at(contents, match.start())
            reference = UrlReference(host, repository_path, line_number, line_at(contents, line_number), is_source)
            if _is_ip_address(host):
                if is_source:
                    findings.append(_raw_ip_finding(reference, "HTTP client URL"))
            elif host not in SAFE_DESTINATIONS:
                domain_references[host].append(reference)
                if is_source:
                    source_domain_candidates.append(reference)

        if is_source:
            findings.extend(_socket_ip_findings(contents, repository_path))
        if path.name == "package.json":
            findings.extend(_install_script_findings(contents, repository_path))

    findings.extend(_isolated_domain_findings(source_domain_candidates, domain_references))
    return _deduplicate(findings)


def _socket_ip_findings(contents: str, file_path: str) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    for match in SOCKET_IP_PATTERN.finditer(contents):
        address = match.group("ip")
        if not _is_ip_address(address):
            continue
        line_number = line_number_at(contents, match.start())
        reference = UrlReference(address, file_path, line_number, line_at(contents, line_number), True)
        findings.append(_raw_ip_finding(reference, "raw socket connection"))
    return findings


def _raw_ip_finding(reference: UrlReference, transport: str) -> DetectorFinding:
    return DetectorFinding(
        detector="backdoor_heuristics",
        category="suspicious_outbound_connection",
        severity="medium",
        confidence=Decimal("0.68"),
        file_path=reference.file_path,
        line_start=reference.line_number,
        line_end=reference.line_number,
        code_snippet=reference.snippet,
        title="Hardcoded IP address used for outbound connection",
        description=(
            f"A {transport} targets raw IP address {reference.host}. Raw destinations can indicate "
            "exfiltration or command-and-control, but require contextual review."
        ),
        fix_suggestion="Verify the destination is expected and move approved service endpoints into configuration.",
    )


def _isolated_domain_findings(
    candidates: list[UrlReference],
    all_references: dict[str, list[UrlReference]],
) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    for reference in candidates:
        if len(all_references[reference.host]) != 1:
            continue
        findings.append(
            DetectorFinding(
                detector="backdoor_heuristics",
                category="suspicious_outbound_connection",
                severity="low",
                confidence=Decimal("0.42"),
                file_path=reference.file_path,
                line_start=reference.line_number,
                line_end=reference.line_number,
                code_snippet=reference.snippet,
                title="Isolated hardcoded outbound domain",
                description=(
                    f"{reference.host} appears only once in the repository and is not referenced by other "
                    "source or configuration files. This is a noisy heuristic, not a reputation verdict."
                ),
                fix_suggestion="Confirm the destination belongs to an expected integration and document it in configuration.",
            )
        )
    return findings


def _install_script_findings(contents: str, file_path: str) -> list[DetectorFinding]:
    try:
        package = json.loads(contents)
    except json.JSONDecodeError:
        return []
    scripts = package.get("scripts", {})
    if not isinstance(scripts, dict):
        return []

    findings: list[DetectorFinding] = []
    for script_name in INSTALL_SCRIPT_NAMES:
        command = scripts.get(script_name)
        if not isinstance(command, str):
            continue
        reason, confidence = _suspicious_install_reason(command)
        if reason is None:
            continue
        match = re.search(rf'"{re.escape(script_name)}"\s*:', contents)
        line_number = line_number_at(contents, match.start()) if match else 1
        findings.append(
            DetectorFinding(
                detector="backdoor_heuristics",
                category="suspicious_install_script",
                severity="high",
                confidence=confidence,
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=line_at(contents, line_number),
                title="Suspicious package install lifecycle script",
                description=(
                    f"The {script_name} script {reason}. Install lifecycle scripts run automatically and "
                    "can execute a dependency-level backdoor."
                ),
                fix_suggestion="Remove or rewrite the script, then verify the package provenance before installation.",
            )
        )
    return findings


def _suspicious_install_reason(command: str) -> tuple[str | None, Decimal]:
    if INLINE_NODE_PATTERN.search(command):
        return "invokes node with inline code", Decimal("0.90")
    if REMOTE_DOWNLOAD_PATTERN.search(command):
        return "downloads or fetches remote content", Decimal("0.86")
    if SHELL_COMMAND_PATTERN.search(command):
        return "invokes a shell command", Decimal("0.62")
    return None, Decimal("0")


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _deduplicate(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    unique: dict[tuple[str, str, int | None, str], DetectorFinding] = {}
    for finding in findings:
        key = (finding.category, finding.file_path, finding.line_start, finding.title)
        unique[key] = finding
    return list(unique.values())
