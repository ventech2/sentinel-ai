"""Deterministic remediation patches built from already-detected findings.

The generator never discovers issues. It receives one existing finding, uses its
AI explanation/fix suggestion as supporting context, and applies narrow templates
only for categories explicitly designated as auto-fixable or approval-gated.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path
import re
from typing import Protocol

from app.remediation.classifier import RemediationTier, classify_finding, tier_guidance


class FindingForRemediation(Protocol):
    category: str
    file_path: str
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    description: str
    ai_explanation: str | None
    fix_suggestion: str | None


@dataclass(frozen=True, slots=True)
class FileChange:
    file_path: str
    original_content: str
    updated_content: str


@dataclass(frozen=True, slots=True)
class FixProposal:
    tier: RemediationTier
    changes: tuple[FileChange, ...]
    diff: str | None
    guidance: str

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


KNOWN_DEPENDENCY_CORRECTIONS = {
    "requessts": "requests",
    "reqeusts": "requests",
    "lodahs": "lodash",
    "expresss": "express",
}
SECRET_ASSIGNMENT = re.compile(
    r'^(?P<indent>\s*)(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*(?P<literal>["\']).*?(?P=literal)(?P<tail>\s*(?:#.*)?)$',
)
DEBUG_ENABLED = re.compile(r"(?P<prefix>\bDEBUG\s*=\s*)True\b")
WILDCARD_CORS = re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]")
POPULAR_DEPENDENCY_FROM_DESCRIPTION = re.compile(r"'(?P<actual>[\w.-]+)'.*'(?P<intended>[\w.-]+)'", re.IGNORECASE)


def generate_fix(finding: FindingForRemediation, repository_root: Path | None) -> FixProposal:
    """Create a narrow patch proposal for one known finding, never an inferred one."""
    tier = classify_finding(finding)
    ai_context = _ai_context(finding)
    if tier is RemediationTier.FLAGGED_ONLY:
        return FixProposal(tier=tier, changes=(), diff=None, guidance=f"{tier_guidance(tier)} {ai_context}")
    if repository_root is None:
        return FixProposal(
            tier=tier,
            changes=(),
            diff=None,
            guidance=f"Repository snapshot is unavailable, so no patch was generated. {ai_context}",
        )

    source = _read_repository_file(repository_root, finding.file_path)
    if source is None:
        return FixProposal(
            tier=tier,
            changes=(),
            diff=None,
            guidance=f"The flagged source file is unavailable in the repository snapshot. {ai_context}",
        )

    if tier is RemediationTier.AUTO_FIXABLE:
        changes = _tier_one_changes(finding, repository_root, source)
    else:
        changes = _tier_two_changes(finding, source)

    if not changes:
        return FixProposal(
            tier=tier,
            changes=(),
            diff=None,
            guidance=(
                f"No safe template matched this finding. Review manually. {ai_context}"
            ),
        )
    return FixProposal(
        tier=tier,
        changes=tuple(changes),
        diff=_render_diff(changes),
        guidance=f"{tier_guidance(tier)} {ai_context}",
    )


def _tier_one_changes(
    finding: FindingForRemediation,
    repository_root: Path,
    source: str,
) -> list[FileChange]:
    if finding.category == "hardcoded_secret":
        updated = _replace_hardcoded_python_secret(source, finding.line_start)
        return _single_change(finding.file_path, source, updated)
    if finding.category == "insecure_config":
        updated = _replace_insecure_config(source, finding.line_start)
        return _single_change(finding.file_path, source, updated)
    if finding.category == "typosquatted_dependency":
        updated = _replace_typosquatted_dependency(source, finding)
        return _single_change(finding.file_path, source, updated)
    if finding.category == "committed_env_file":
        return _add_env_to_gitignore(repository_root)
    return []


def _tier_two_changes(finding: FindingForRemediation, source: str) -> list[FileChange]:
    if finding.category in {"hardcoded_auth_bypass", "auth_bypass"} and finding.file_path.endswith(".py"):
        updated = _remove_python_auth_bypass(source, finding.line_start)
        return _single_change(finding.file_path, source, updated)
    if finding.category in {"obfuscated_dynamic_execution", "obfuscated_code", "suspicious_dynamic_execution"}:
        updated = _disable_execution_line(source, finding.line_start)
        return _single_change(finding.file_path, source, updated)
    return []


def _replace_hardcoded_python_secret(source: str, line_start: int | None) -> str | None:
    if line_start is None:
        return None
    lines = source.splitlines(keepends=True)
    index = line_start - 1
    if not 0 <= index < len(lines):
        return None
    match = SECRET_ASSIGNMENT.match(lines[index].rstrip("\r\n"))
    if match is None:
        return None
    lines[index] = f'{match.group("indent")}{match.group("name")} = os.environ.get("{match.group("name")}"){_line_ending(lines[index])}'
    updated = "".join(lines)
    if not re.search(r"^\s*(?:import os|from os\b)", updated, flags=re.MULTILINE):
        insertion = _python_import_insertion_index(updated)
        updated_lines = updated.splitlines(keepends=True)
        updated_lines.insert(insertion, f"import os{_preferred_line_ending(updated)}")
        updated = "".join(updated_lines)
    return updated


def _replace_insecure_config(source: str, line_start: int | None) -> str | None:
    lines = source.splitlines(keepends=True)
    candidate_indexes = [line_start - 1] if line_start is not None else range(len(lines))
    for index in candidate_indexes:
        if not isinstance(index, int) or not 0 <= index < len(lines):
            continue
        line = lines[index]
        if DEBUG_ENABLED.search(line):
            lines[index] = DEBUG_ENABLED.sub(r"\g<prefix>False", line)
            return "".join(lines)
        if WILDCARD_CORS.search(line):
            lines[index] = WILDCARD_CORS.sub('allow_origins=["https://app.example.com"]', line)
            return "".join(lines)
    return None


def _replace_typosquatted_dependency(source: str, finding: FindingForRemediation) -> str | None:
    actual = _dependency_name_from_line(finding.code_snippet) or _dependency_name_from_line_at(source, finding.line_start)
    intended = KNOWN_DEPENDENCY_CORRECTIONS.get(actual or "")
    description_match = POPULAR_DEPENDENCY_FROM_DESCRIPTION.search(finding.description)
    if description_match is not None:
        actual = actual or description_match.group("actual")
        intended = intended or description_match.group("intended")
    if not actual or not intended:
        return None
    return re.sub(rf"(?m)^(?P<prefix>\s*){re.escape(actual)}(?P<suffix>(?:\s*(?:==|>=|<=|~=|@).*)?)$", rf"\g<prefix>{intended}\g<suffix>", source, count=1)


def _add_env_to_gitignore(repository_root: Path) -> list[FileChange]:
    gitignore = repository_root / ".gitignore"
    try:
        original = gitignore.read_text(encoding="utf-8")
    except OSError:
        return []
    if any(line.strip() == ".env" for line in original.splitlines()):
        return []
    updated = original.rstrip("\r\n") + f"{_preferred_line_ending(original)}.env{_preferred_line_ending(original)}"
    return [FileChange(file_path=".gitignore", original_content=original, updated_content=updated)]


def _remove_python_auth_bypass(source: str, line_start: int | None) -> str | None:
    if line_start is None:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    target = next((node for node in ast.walk(tree) if isinstance(node, ast.If) and node.lineno == line_start), None)
    if target is None or not target.end_lineno:
        return None
    lines = source.splitlines(keepends=True)
    start, end = target.lineno - 1, target.end_lineno
    indent = re.match(r"\s*", lines[start]).group(0)
    lines[start:end] = [
        f"{indent}# Sentinel proposal: removed hardcoded authentication bypass; normal authentication remains below.{_preferred_line_ending(source)}"
    ]
    return "".join(lines)


def _disable_execution_line(source: str, line_start: int | None) -> str | None:
    if line_start is None:
        return None
    lines = source.splitlines(keepends=True)
    index = line_start - 1
    if not 0 <= index < len(lines):
        return None
    indent = re.match(r"\s*", lines[index]).group(0)
    lines[index] = f'{indent}raise RuntimeError("Disabled by Sentinel pending security review"){_line_ending(lines[index])}'
    return "".join(lines)


def _single_change(file_path: str, original: str, updated: str | None) -> list[FileChange]:
    if updated is None or updated == original:
        return []
    return [FileChange(file_path=file_path, original_content=original, updated_content=updated)]


def _render_diff(changes: list[FileChange]) -> str:
    rendered: list[str] = []
    for change in changes:
        rendered.extend(
            unified_diff(
                change.original_content.splitlines(keepends=True),
                change.updated_content.splitlines(keepends=True),
                fromfile=f"a/{change.file_path}",
                tofile=f"b/{change.file_path}",
            )
        )
    return "".join(rendered)


def _read_repository_file(repository_root: Path, file_path: str) -> str | None:
    try:
        root = repository_root.resolve()
        path = (root / file_path).resolve()
        path.relative_to(root)
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def _dependency_name_from_line(line: str | None) -> str | None:
    if not line:
        return None
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", line)
    return match.group(1).lower() if match else None


def _dependency_name_from_line_at(source: str, line_start: int | None) -> str | None:
    if line_start is None:
        return None
    lines = source.splitlines()
    return _dependency_name_from_line(lines[line_start - 1]) if 0 < line_start <= len(lines) else None


def _python_import_insertion_index(source: str) -> int:
    lines = source.splitlines(keepends=True)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(getattr(tree.body[0], "value", None), ast.Constant):
        if isinstance(tree.body[0].value.value, str) and tree.body[0].end_lineno:
            return tree.body[0].end_lineno
    return 0


def _ai_context(finding: FindingForRemediation) -> str:
    if finding.fix_suggestion:
        return f"AI fix context: {finding.fix_suggestion}"
    if finding.ai_explanation:
        return f"AI explanation context: {finding.ai_explanation}"
    return "No AI explanation was available; deterministic remediation rules were used."


def _line_ending(line: str) -> str:
    return "\r\n" if line.endswith("\r\n") else "\n"


def _preferred_line_ending(source: str) -> str:
    return "\r\n" if "\r\n" in source else "\n"
