"""Conservative static checks for untrusted data embedded in LLM prompts.

Python uses a small AST/data-flow heuristic. JavaScript and TypeScript use
regex patterns, deliberately mirroring :mod:`js_pattern_rules`; full
Tree-sitter multi-language parsing remains roadmap work. Neither approach can
prove an exploit: a matched flow is a review recommendation, not a confirmed
prompt-injection vulnerability.
"""

from __future__ import annotations

import ast
from decimal import Decimal
from pathlib import Path
import re

from app.detectors.file_utils import iter_text_files, line_at, line_number_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
PROMPT_KEYWORDS = {"prompt", "messages", "message", "content", "input", "query", "instructions"}
PROMPT_NAME_MARKERS = ("prompt", "message", "instruction", "completion", "query")
SANITIZER_MARKERS = ("sanitize", "escape", "validate", "allowlist", "whitelist", "normalize")

# The JavaScript expressions are intentionally narrow enough to require both
# a prompt-shaped construction and an LLM API-shaped call. This is less
# precise than AST data-flow and is explicitly a MVP heuristic.
JS_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expression>[^;\n]+)",
    re.IGNORECASE,
)
JS_LLM_CALL_PATTERN = re.compile(
    r"(?:"
    r"\b[\w$.]*chat\.completions\.create\s*\("
    r"|\b[\w$.]*messages\.create\s*\("
    r"|\b[\w$.]*generateContent\s*\("
    r"|\b(?:llm|model|openai|anthropic|genai|client)[\w$.]*\.(?:generate|complete|chat)\s*\("
    r"|\b(?:fetch|axios(?:\.(?:post|request))?)\s*\(\s*['\"][^'\"]*"
    r"(?:openai|anthropic|generativelanguage|/v1/(?:chat|messages|completions))"
    r")",
    re.IGNORECASE,
)


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Scan eligible Python, JavaScript, and TypeScript files below ``root``."""
    findings: list[DetectorFinding] = []
    for path in iter_text_files(root):
        contents = read_text_file(path)
        if contents is None:
            continue
        file_path = relative_path(root, path)
        if path.suffix.lower() == ".py":
            findings.extend(scan_python(contents, file_path))
        elif path.suffix.lower() in JAVASCRIPT_SUFFIXES:
            findings.extend(scan_javascript(contents, file_path))
    return findings


def scan_python(contents: str, file_path: str) -> list[DetectorFinding]:
    """Find direct AST-visible flows from parameters/request data to LLM calls."""
    try:
        tree = ast.parse(contents)
    except SyntaxError:
        return []
    visitor = _PythonPromptInjectionVisitor(contents, file_path)
    visitor.visit(tree)
    return visitor.findings


def scan_javascript(contents: str, file_path: str) -> list[DetectorFinding]:
    """Find clear JS/TS prompt flows using documented regex-only heuristics."""
    unsafe_prompt_assignments: dict[str, list[int]] = {}
    for assignment in JS_ASSIGNMENT_PATTERN.finditer(contents):
        name = assignment.group("name")
        expression = assignment.group("expression")
        if _looks_like_prompt_name(name) and _js_expression_has_unsanitized_source(expression):
            unsafe_prompt_assignments.setdefault(name, []).append(assignment.start())

    findings: list[DetectorFinding] = []
    reported_lines: set[int] = set()
    for call in JS_LLM_CALL_PATTERN.finditer(contents):
        line_number = line_number_at(contents, call.start())
        if line_number in reported_lines:
            continue
        # A bounded local window permits the common multi-line fetch/SDK
        # payload shape without treating the rest of a source file as prompt.
        window = contents[call.start() : call.start() + 1_500]
        uses_unsafe_variable = _js_uses_nearby_unsafe_prompt_variable(
            window, unsafe_prompt_assignments, call.start()
        )
        inline_unsafe_prompt = _js_expression_has_unsanitized_source(window) and _looks_like_prompt_construction(window)
        if not (uses_unsafe_variable or inline_unsafe_prompt):
            continue
        findings.append(_finding(file_path, line_number, line_at(contents, line_number), Decimal("0.55"), "JavaScript/TypeScript"))
        reported_lines.add(line_number)
    return findings


class _PythonPromptInjectionVisitor(ast.NodeVisitor):
    def __init__(self, contents: str, file_path: str) -> None:
        self.contents = contents
        self.file_path = file_path
        self.findings: list[DetectorFinding] = []
        self._tainted_scopes: list[set[str]] = [set()]
        self._reported_lines: set[int] = set()

    @property
    def _tainted_names(self) -> set[str]:
        return self._tainted_scopes[-1]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parameters = {
            argument.arg
            for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        }
        if node.args.vararg is not None:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            parameters.add(node.args.kwarg.arg)
        self._tainted_scopes.append(parameters)
        for statement in node.body:
            self.visit(statement)
        self._tainted_scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        is_tainted = _python_expression_is_tainted(node.value, self._tainted_names)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_tainted:
                    self._tainted_names.add(target.id)
                else:
                    self._tainted_names.discard(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            if _python_expression_is_tainted(node.value, self._tainted_names):
                self._tainted_names.add(node.target.id)
            else:
                self._tainted_names.discard(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _looks_like_python_llm_call(node) and node.lineno not in self._reported_lines:
            prompt_values = [*node.args, *(keyword.value for keyword in node.keywords if keyword.arg in PROMPT_KEYWORDS)]
            if any(_python_expression_is_tainted(value, self._tainted_names) for value in prompt_values):
                self.findings.append(
                    _finding(
                        self.file_path,
                        node.lineno,
                        line_at(self.contents, node.lineno),
                        Decimal("0.62"),
                        "Python",
                    )
                )
                self._reported_lines.add(node.lineno)
        self.generic_visit(node)


def _looks_like_python_llm_call(node: ast.Call) -> bool:
    call_name = _call_name(node.func).lower()
    if call_name.endswith(("chat.completions.create", "messages.create", "generate_content")):
        return True
    return any(marker in call_name for marker in ("llm.", "model.", "openai.", "anthropic.", "genai.")) and call_name.endswith(
        (".generate", ".complete", ".chat")
    )


def _python_expression_is_tainted(expression: ast.AST, tainted_names: set[str]) -> bool:
    if isinstance(expression, ast.Name):
        return expression.id in tainted_names
    if isinstance(expression, ast.Attribute):
        return _attribute_has_request_source(expression) or _python_expression_is_tainted(expression.value, tainted_names)
    if isinstance(expression, ast.Call):
        call_name = _call_name(expression.func).lower()
        if any(marker in call_name for marker in SANITIZER_MARKERS):
            # This is an intent signal only; teams should still review whether
            # the sanitizer creates a real instruction/data boundary.
            return False
        if call_name in {"input", "os.getenv", "os.environ.get"} or "request" in call_name:
            return True
        return any(_python_expression_is_tainted(argument, tainted_names) for argument in [*expression.args, *(keyword.value for keyword in expression.keywords)])
    if isinstance(expression, ast.JoinedStr):
        return any(_python_expression_is_tainted(value, tainted_names) for value in expression.values)
    if isinstance(expression, ast.FormattedValue):
        return _python_expression_is_tainted(expression.value, tainted_names)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        return _python_expression_is_tainted(expression.left, tainted_names) or _python_expression_is_tainted(expression.right, tainted_names)
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return any(_python_expression_is_tainted(value, tainted_names) for value in expression.elts)
    if isinstance(expression, ast.Dict):
        return any(_python_expression_is_tainted(value, tainted_names) for value in expression.values if value is not None)
    return False


def _attribute_has_request_source(expression: ast.Attribute) -> bool:
    parts = _call_name(expression).lower().split(".")
    return bool(parts) and parts[0] in {"request", "req"} and any(part in {"body", "form", "json", "data", "args", "query", "params"} for part in parts[1:])


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _looks_like_prompt_name(name: str) -> bool:
    return any(marker in name.lower() for marker in PROMPT_NAME_MARKERS)


def _js_expression_has_unsanitized_source(expression: str) -> bool:
    lowered = expression.lower()
    if any(marker in lowered for marker in SANITIZER_MARKERS):
        return False
    return bool(
        re.search(r"\b(?:request|req|form|body|query|params|user|input)[a-z0-9_$]*\b", lowered)
    ) or "process.env" in lowered


def _looks_like_prompt_construction(expression: str) -> bool:
    return "${" in expression or "+" in expression or "messages" in expression.lower() or "prompt" in expression.lower()


def _js_uses_nearby_unsafe_prompt_variable(
    window: str, assignments: dict[str, list[int]], call_offset: int
) -> bool:
    """Resolve a prompt variable to a recent preceding assignment.

    Regex cannot model JavaScript block scope reliably. A short source-distance
    bound avoids treating an unrelated prompt variable in a distant function as
    proof of a flow while retaining ordinary multi-line endpoint handlers.
    """
    for name, positions in assignments.items():
        if not re.search(rf"\b{re.escape(name)}\b", window):
            continue
        earlier = [position for position in positions if position < call_offset]
        if earlier and call_offset - max(earlier) <= 2_000:
            return True
    return False


def _finding(file_path: str, line_number: int, snippet: str, confidence: Decimal, language: str) -> DetectorFinding:
    return DetectorFinding(
        detector="prompt_injection_rules",
        category="prompt_injection_risk",
        severity="medium",
        confidence=confidence,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        code_snippet=snippet,
        title="Untrusted input appears in an LLM prompt",
        description=(
            f"{language} code appears to pass request, user, or environment-derived data into an LLM prompt "
            "without a statically visible instruction/data boundary. Review recommended: verify that user input "
            "is bounded, validated, and separated from trusted instructions."
        ),
        fix_suggestion=(
            "Keep system instructions fixed; pass validated, length-bounded user data in a separate structured "
            "message or clearly delimited data field, and do not let it control instructions or tool permissions."
        ),
    )
