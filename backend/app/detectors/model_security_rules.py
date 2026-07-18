"""Static checks for unsafe deserialization of model artifacts.

These rules inspect source only. They never open, deserialize, or inspect a
model artifact, so model-weight manipulation and data-poisoning analysis stay
outside the scope of this repository scanner.
"""

from __future__ import annotations

import ast
from decimal import Decimal
from pathlib import Path

from app.detectors.file_utils import iter_text_files, line_at, read_text_file, relative_path
from app.detectors.models import DetectorFinding, Severity

MODEL_EXTENSIONS = {".pkl", ".pt", ".pth", ".joblib", ".h5"}


def scan_repository(root: Path) -> list[DetectorFinding]:
    """Scan Python source files for unsafe pickle, PyTorch, and joblib loads."""
    findings: list[DetectorFinding] = []
    for path in iter_text_files(root):
        if path.suffix.lower() != ".py":
            continue
        contents = read_text_file(path)
        if contents is not None:
            findings.extend(scan_python(contents, relative_path(root, path)))
    return findings


def scan_python(contents: str, file_path: str) -> list[DetectorFinding]:
    """Analyze one Python module without evaluating any code or files."""
    try:
        tree = ast.parse(contents)
    except SyntaxError:
        return []
    visitor = _ModelDeserializationVisitor(contents, file_path)
    visitor.visit(tree)
    return visitor.findings


class _ModelDeserializationVisitor(ast.NodeVisitor):
    def __init__(self, contents: str, file_path: str) -> None:
        self.contents = contents
        self.file_path = file_path
        self.findings: list[DetectorFinding] = []
        self._parameter_scopes: list[set[str]] = [set()]
        self._string_values: dict[str, str] = {}

    @property
    def _parameters(self) -> set[str]:
        return self._parameter_scopes[-1]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parameters = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        if node.args.vararg is not None:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            parameters.add(node.args.kwarg.arg)
        self._parameter_scopes.append(parameters)
        for statement in node.body:
            self.visit(statement)
        self._parameter_scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._string_values[target.id] = node.value.value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node.func)
        argument = node.args[0] if node.args else _keyword_value(node, {"file", "filename", "path"})
        if call_name in {"pickle.load", "pickle.loads"}:
            self.findings.append(self._pickle_finding(node, call_name))
        elif call_name == "torch.load" and not _has_weights_only_true(node):
            self.findings.append(self._torch_finding(node))
        elif call_name == "joblib.load" and _is_model_like_or_dynamic(argument, self._parameters, self._string_values):
            self.findings.append(self._joblib_finding(node))
        self.generic_visit(node)

    def _pickle_finding(self, node: ast.Call, call_name: str) -> DetectorFinding:
        return _finding(
            self.file_path,
            node.lineno,
            line_at(self.contents, node.lineno),
            severity="high",
            confidence=Decimal("0.94"),
            title="Unsafe pickle deserialization",
            description=(
                f"{call_name}() can execute attacker-controlled code while deserializing data. Treat model or "
                "artifact input as untrusted unless its source and integrity are verified."
            ),
            fix="Use safetensors or another non-executable model format where possible; otherwise only load artifacts from a verified source with integrity validation.",
        )

    def _torch_finding(self, node: ast.Call) -> DetectorFinding:
        return _finding(
            self.file_path,
            node.lineno,
            line_at(self.contents, node.lineno),
            severity="medium",
            confidence=Decimal("0.67"),
            title="PyTorch model load does not enable weights_only",
            description=(
                "torch.load() is called without weights_only=True, which can permit unsafe pickle-based "
                "deserialization when a model artifact is not fully trusted."
            ),
            fix="Prefer safetensors; when torch.load is required, use torch.load(..., weights_only=True) and verify the artifact source.",
        )

    def _joblib_finding(self, node: ast.Call) -> DetectorFinding:
        return _finding(
            self.file_path,
            node.lineno,
            line_at(self.contents, node.lineno),
            severity="medium",
            confidence=Decimal("0.72"),
            title="Potentially unsafe joblib model deserialization",
            description=(
                "joblib.load() is used with a model-like or dynamically selected artifact. Joblib can deserialize "
                "pickle payloads, so an untrusted artifact may execute code during loading."
            ),
            fix="Use safetensors where supported, or validate the model artifact source and integrity before loading it.",
        )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _keyword_value(node: ast.Call, names: set[str]) -> ast.AST | None:
    return next((keyword.value for keyword in node.keywords if keyword.arg in names), None)


def _has_weights_only_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "weights_only" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in node.keywords
    )


def _is_model_like_or_dynamic(argument: ast.AST | None, parameters: set[str], string_values: dict[str, str]) -> bool:
    if argument is None:
        return False
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return Path(argument.value).suffix.lower() in MODEL_EXTENSIONS
    if isinstance(argument, ast.Name):
        if argument.id in parameters:
            return True
        if argument.id in string_values:
            return Path(string_values[argument.id]).suffix.lower() in MODEL_EXTENSIONS
        return True
    # Calls such as Path(user_path) / os.path.join(...) can be dynamically
    # controlled; retain this conservative review signal for joblib only.
    return True


def _finding(
    file_path: str,
    line_number: int,
    snippet: str,
    *,
    severity: Severity,
    confidence: Decimal,
    title: str,
    description: str,
    fix: str,
) -> DetectorFinding:
    return DetectorFinding(
        detector="model_security_rules",
        category="unsafe_model_deserialization",
        severity=severity,
        confidence=confidence,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        code_snippet=snippet,
        title=title,
        description=description,
        fix_suggestion=fix,
    )
