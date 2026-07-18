"""Pattern-based JavaScript and TypeScript security rules.

This module intentionally uses regex matching rather than an AST. It is less
precise than ``ast_rules.py`` because JavaScript/TypeScript parsing is deferred
to the Tree-sitter multi-language parsing roadmap for this MVP.
"""

from decimal import Decimal
from pathlib import Path
import re

from app.detectors.file_utils import iter_text_files, line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
EXECUTION_CALL_PATTERN = re.compile(r"\b(?P<call>eval|new\s+Function)\s*\(")
DECODE_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:atob\s*\(|Buffer\.from\s*\([^;\n]*?base64[^;\n]*?\)\s*\.toString)",
    re.IGNORECASE,
)
AUTH_CONDITIONAL_PATTERN = re.compile(
    r"\b(?:if|else\s+if)\s*\(\s*(?P<left>[^()\n]+?)\s*"
    r"(?:===|==|!==|!=)\s*(?P<right>[^)\n]+?)\s*\)",
    re.IGNORECASE,
)
STRING_LITERAL_PATTERN = re.compile(r"^\s*(['\"])(?:\\.|(?!\1).)*\1\s*$")
AUTH_MARKERS = ("auth", "token", "password", "secret", "api_key", "apikey", "key", "admin", "username")


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Apply the MVP regex rules to JavaScript and TypeScript source files."""
    findings: list[DetectorFinding] = []
    for path in iter_text_files(root):
        if path.suffix.lower() not in JAVASCRIPT_SUFFIXES:
            continue
        contents = read_text_file(path)
        if contents is not None:
            findings.extend(scan_javascript(contents, relative_path(root, path)))
    return findings


def scan_javascript(contents: str, file_path: str) -> list[DetectorFinding]:
    """Scan one JavaScript or TypeScript payload using intentionally simple patterns."""
    findings: list[DetectorFinding] = []
    decoded_variables = {match.group("name") for match in DECODE_ASSIGNMENT_PATTERN.finditer(contents)}
    reported_execution_lines: set[int] = set()

    for match in EXECUTION_CALL_PATTERN.finditer(contents):
        line_number = line_number_at(contents, match.start())
        if line_number in reported_execution_lines:
            continue
        snippet = line_at(contents, line_number)
        execution_kind = _execution_kind(snippet, decoded_variables)
        findings.append(
            DetectorFinding(
                detector="js_pattern_rules",
                category="obfuscated_dynamic_execution",
                severity="critical" if execution_kind == "decoded" else "high",
                confidence=Decimal("0.88") if execution_kind == "decoded" else Decimal("0.70"),
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=snippet,
                title="JavaScript dynamic execution pattern",
                description=(
                    f"{match.group('call')}() executes {execution_kind} JavaScript content. "
                    "This regex-based detection should be reviewed with source context."
                ),
                fix_suggestion="Remove eval/new Function and replace it with explicit, validated logic.",
            )
        )
        reported_execution_lines.add(line_number)

    for match in AUTH_CONDITIONAL_PATTERN.finditer(contents):
        left = match.group("left").strip()
        right = match.group("right").strip()
        variable_side = right if _is_string_literal(left) else left
        if not (_is_string_literal(left) or _is_string_literal(right)) or not _mentions_auth_marker(variable_side):
            continue
        line_number = line_number_at(contents, match.start())
        findings.append(
            DetectorFinding(
                detector="js_pattern_rules",
                category="hardcoded_auth_bypass",
                severity="high",
                confidence=Decimal("0.78"),
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                code_snippet=line_at(contents, line_number),
                title="Hardcoded value used in JavaScript authentication conditional",
                description=(
                    "An auth/token/admin-like value is compared to a hardcoded string. "
                    "This may create a static credential or hidden bypass."
                ),
                fix_suggestion="Use verified identity checks and securely managed credentials instead.",
            )
        )
    return findings


def _execution_kind(snippet: str, decoded_variables: set[str]) -> str:
    lowered = snippet.lower()
    if "atob(" in lowered or ("buffer.from(" in lowered and "base64" in lowered):
        return "decoded"
    if any(re.search(rf"\b{re.escape(variable)}\b", snippet) for variable in decoded_variables):
        return "decoded"
    if "+" in snippet:
        return "concatenated"
    return "dynamic"


def _is_string_literal(value: str) -> bool:
    return bool(STRING_LITERAL_PATTERN.match(value))


def _mentions_auth_marker(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    return any(marker in normalized for marker in AUTH_MARKERS)
