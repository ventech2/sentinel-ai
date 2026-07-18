"""Python AST rules for suspicious dynamic execution and auth comparisons."""

import ast
from decimal import Decimal
from pathlib import Path

from app.detectors.file_utils import iter_text_files, line_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding

DYNAMIC_FUNCTIONS = {"eval", "exec"}
AUTH_MARKERS = {"auth", "token", "password", "secret", "apikey", "api_key", "key", "admin", "username"}
SHELL_EXECUTION_FUNCTIONS = {"subprocess.run", "subprocess.call", "subprocess.popen", "os.system"}
EXTERNAL_INPUT_MARKERS = {"request", "input", "argv", "args", "query", "params", "form", "user"}


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Apply Python AST rules to all eligible Python files below ``root``."""
    findings: list[DetectorFinding] = []
    for path in iter_text_files(root):
        if path.suffix != ".py":
            continue
        contents = read_text_file(path)
        if contents is not None:
            findings.extend(scan_python(contents, relative_path(root, path)))
    return findings


def scan_python(contents: str, file_path: str) -> list[DetectorFinding]:
    """Scan a single Python source payload, skipping malformed files safely."""
    try:
        tree = ast.parse(contents)
    except SyntaxError:
        return []
    visitor = _SecurityVisitor(contents, file_path)
    visitor.visit(tree)
    return visitor.findings


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self, contents: str, file_path: str) -> None:
        self.contents = contents
        self.file_path = file_path
        self.findings: list[DetectorFinding] = []
        self._reported_auth_lines: set[int] = set()
        self._command_value_kinds: dict[str, str] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        value_kind = _command_value_kind(node.value)
        if value_kind:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._command_value_kinds[target.id] = value_kind
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            value_kind = _command_value_kind(node.value)
            if value_kind:
                self._command_value_kinds[node.target.id] = value_kind
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_FUNCTIONS and node.args:
            execution_kind = _dynamic_execution_kind(node.args[0])
            if execution_kind:
                self.findings.append(
                    DetectorFinding(
                        detector="ast_rules",
                        category="obfuscated_dynamic_execution",
                        severity="critical" if execution_kind == "decoded" else "high",
                        confidence=Decimal("0.93") if execution_kind == "decoded" else Decimal("0.82"),
                        file_path=self.file_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=line_at(self.contents, node.lineno),
                        title="Dynamic execution fed by decoded or concatenated data",
                        description=(
                            f"{node.func.id}() executes {execution_kind} content, a common obfuscation and "
                            "backdoor pattern."
                        ),
                        fix_suggestion="Remove dynamic execution or replace it with explicit, validated logic.",
                    )
                )
        shell_function = _call_name(node.func).lower()
        if shell_function in SHELL_EXECUTION_FUNCTIONS:
            command_argument = _shell_command_argument(node)
            execution_kind = _tracked_command_kind(command_argument, self._command_value_kinds)
            if execution_kind:
                self.findings.append(
                    DetectorFinding(
                        detector="ast_rules",
                        category="obfuscated_dynamic_execution",
                        severity="critical" if execution_kind == "decoded" else "high",
                        confidence=Decimal("0.95") if execution_kind == "decoded" else Decimal("0.85"),
                        file_path=self.file_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=line_at(self.contents, node.lineno),
                        title="Shell command execution fed by decoded or external data",
                        description=(
                            f"{shell_function}() executes {execution_kind} command content, a common "
                            "obfuscated backdoor pattern."
                        ),
                        fix_suggestion="Remove shell execution or use a fixed command with validated arguments.",
                    )
                )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        for comparison in (candidate for candidate in ast.walk(node.test) if isinstance(candidate, ast.Compare)):
            if node.lineno in self._reported_auth_lines or not _has_hardcoded_auth_comparison(comparison):
                continue
            self.findings.append(
                DetectorFinding(
                    detector="ast_rules",
                    category="hardcoded_auth_bypass",
                    severity="high",
                    confidence=Decimal("0.84"),
                    file_path=self.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=line_at(self.contents, node.lineno),
                    title="Hardcoded value used in authentication conditional",
                    description=(
                        "An authentication-related conditional compares against a hardcoded string, which may "
                        "create a hidden bypass or static credential."
                    ),
                    fix_suggestion="Use a verified identity provider or securely stored, rotated credentials.",
                )
            )
            self._reported_auth_lines.add(node.lineno)
        self.generic_visit(node)


def _dynamic_execution_kind(argument: ast.AST) -> str | None:
    if isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Add):
        return "concatenated"
    if isinstance(argument, ast.Call):
        call_name = _call_name(argument.func).lower()
        if any(marker in call_name for marker in ("decode", "b64decode", "unhexlify", "fromhex", "atob")):
            return "decoded"
    return None


def _command_value_kind(expression: ast.AST) -> str | None:
    if _is_decode_expression(expression):
        return "decoded"
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add) and _contains_external_input(expression):
        return "concatenated external"
    return None


def _tracked_command_kind(expression: ast.AST | None, tracked_values: dict[str, str]) -> str | None:
    if expression is None:
        return None
    if isinstance(expression, ast.Name):
        return tracked_values.get(expression.id)
    return _command_value_kind(expression)


def _is_decode_expression(expression: ast.AST) -> bool:
    if not isinstance(expression, ast.Call):
        return False
    call_name = _call_name(expression.func).lower()
    return any(marker in call_name for marker in ("decode", "b64decode", "unhexlify", "fromhex", "atob"))


def _contains_external_input(expression: ast.AST) -> bool:
    for node in ast.walk(expression):
        if isinstance(node, ast.Name) and node.id.lower() in EXTERNAL_INPUT_MARKERS:
            return True
        if isinstance(node, ast.Attribute) and node.attr.lower() in EXTERNAL_INPUT_MARKERS:
            return True
        if isinstance(node, ast.Call) and _call_name(node.func).lower() in {"input", "request.args.get", "request.form.get"}:
            return True
    return False


def _shell_command_argument(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"args", "command", "cmd"}:
            return keyword.value
    return None


def _has_hardcoded_auth_comparison(comparison: ast.Compare) -> bool:
    expressions = [comparison.left, *comparison.comparators]
    has_constant = any(isinstance(expression, ast.Constant) and isinstance(expression.value, str) for expression in expressions)
    has_auth_reference = any(_mentions_auth(expression) for expression in expressions)
    return has_constant and has_auth_reference


def _mentions_auth(expression: ast.AST) -> bool:
    for node in ast.walk(expression):
        if isinstance(node, ast.Name) and _contains_auth_marker(node.id):
            return True
        if isinstance(node, ast.Attribute) and _contains_auth_marker(node.attr):
            return True
    return False


def _contains_auth_marker(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    return any(marker in normalized for marker in AUTH_MARKERS)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
