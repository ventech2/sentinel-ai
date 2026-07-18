"""Syntax-only verification for generated remediation patches."""

import ast
import json
from pathlib import PurePosixPath

from app.remediation.fix_generator import FileChange, FixProposal


def verify_proposal(proposal: FixProposal) -> dict[str, object]:
    """Verify each patched file without executing application code or tests."""
    checks = [_verify_change(change) for change in proposal.changes]
    valid = bool(checks) and all(check["valid"] for check in checks)
    return {
        "valid": valid,
        "checks": checks,
        "notes": "Syntax verification only; no application code was executed.",
    }


def _verify_change(change: FileChange) -> dict[str, object]:
    suffix = PurePosixPath(change.file_path).suffix.lower()
    try:
        if suffix == ".py":
            ast.parse(change.updated_content, filename=change.file_path)
            parser = "python_ast"
        elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            _verify_balanced_javascript(change.updated_content)
            parser = "javascript_bracket_sanity"
        elif suffix == ".json":
            json.loads(change.updated_content)
            parser = "json"
        else:
            parser = "text"
        return {"file_path": change.file_path, "parser": parser, "valid": True}
    except (SyntaxError, ValueError, json.JSONDecodeError) as error:
        return {
            "file_path": change.file_path,
            "parser": _parser_name(suffix),
            "valid": False,
            "error": str(error),
        }


def _verify_balanced_javascript(source: str) -> None:
    """MVP bracket/quote sanity check; full Tree-sitter parsing is deferred."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    in_line_comment = False
    in_block_comment = False
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                raise ValueError("unbalanced JavaScript brackets")
        index += 1
    if quote or in_block_comment or stack:
        raise ValueError("unclosed JavaScript quote, comment, or bracket")


def _parser_name(suffix: str) -> str:
    if suffix == ".py":
        return "python_ast"
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript_bracket_sanity"
    if suffix == ".json":
        return "json"
    return "text"
